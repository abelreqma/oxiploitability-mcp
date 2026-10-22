use std::collections::VecDeque;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::{Instant, sleep_until};

/// Permits at most `capacity` acquisitions in any rolling `window`.
pub struct RollingWindow {
    capacity: usize,
    window: Duration,
    hits: Mutex<VecDeque<Instant>>,
}

impl RollingWindow {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            hits: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Waits until a slot is free, then claims it.
    pub async fn acquire(&self) {
        let mut hits = self.hits.lock().await;
        loop {
            let now = Instant::now();
            while hits
                .front()
                .is_some_and(|t| now.duration_since(*t) >= self.window)
            {
                hits.pop_front();
            }
            if hits.len() < self.capacity {
                hits.push_back(now);
                return;
            }
            let oldest = *hits.front().expect("non-empty when at capacity");
            sleep_until(oldest + self.window).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn blocks_until_window_slides() {
        let rl = RollingWindow::new(2, Duration::from_secs(30));
        let start = Instant::now();
        rl.acquire().await;
        rl.acquire().await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        rl.acquire().await;
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }
}
