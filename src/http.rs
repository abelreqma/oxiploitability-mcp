use std::time::Duration;

use reqwest::{Client, Response};
use serde::de::DeserializeOwned;
use thiserror::Error;

pub const USER_AGENT: &str = concat!("oxiploitability/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("{service} returned HTTP {status}")]
    Status { service: &'static str, status: u16 },
    #[error("{service} response exceeded {limit} bytes")]
    TooLarge { service: &'static str, limit: usize },
    #[error("ran out of time waiting for the upstream service")]
    TimedOut,
    #[error("{service} returned malformed JSON: {source}")]
    Decode {
        service: &'static str,
        source: serde_json::Error,
    },
}

pub fn client() -> Client {
    Client::builder()
        .user_agent(USER_AGENT)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .gzip(true)
        .build()
        .expect("static client configuration is valid")
}

/// Reads the body up to `limit` bytes and decodes it as JSON.
pub async fn read_json<T: DeserializeOwned>(
    service: &'static str,
    mut resp: Response,
    limit: usize,
) -> Result<T, HttpError> {
    if resp.content_length().is_some_and(|n| n > limit as u64) {
        return Err(HttpError::TooLarge { service, limit });
    }
    let mut buf = Vec::with_capacity(resp.content_length().unwrap_or(0).min(limit as u64) as usize);
    while let Some(chunk) = resp.chunk().await? {
        if buf.len() + chunk.len() > limit {
            return Err(HttpError::TooLarge { service, limit });
        }
        buf.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&buf).map_err(|source| HttpError::Decode { service, source })
}
