use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Bounded in-memory cache with a fixed time to live per entry.
pub struct TtlCache<V> {
    ttl: Duration,
    max_entries: usize,
    map: Mutex<HashMap<String, (Instant, V)>>,
}

impl<V: Clone> TtlCache<V> {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl,
            max_entries,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &str) -> Option<V> {
        let map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        map.get(key)
            .filter(|(at, _)| at.elapsed() < self.ttl)
            .map(|(_, v)| v.clone())
    }

    pub fn insert(&self, key: String, value: V) {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= self.max_entries {
            map.retain(|_, (at, _)| at.elapsed() < self.ttl);
        }
        if map.len() >= self.max_entries {
            map.clear();
        }
        map.insert(key, (Instant::now(), value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expires_and_bounds() {
        let c = TtlCache::new(Duration::ZERO, 2);
        c.insert("a".into(), 1);
        assert_eq!(c.get("a"), None);

        let c = TtlCache::new(Duration::from_secs(60), 2);
        c.insert("a".into(), 1);
        c.insert("b".into(), 2);
        c.insert("c".into(), 3);
        assert_eq!(c.get("c"), Some(3));
        assert_eq!(c.get("a"), None);
    }
}
