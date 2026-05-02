// Author: Jeff
// Date: 2026-05-01
// Description: Shared HTTP client — UA rotation, rate limiting, retry with backoff

use reqwest::Response;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
];

#[derive(Debug)]
pub enum HttpError {
    Network(reqwest::Error),
    Status(u16),
    MaxRetriesExceeded,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(e) => write!(f, "network: {e}"),
            Self::Status(code) => write!(f, "HTTP {code}"),
            Self::MaxRetriesExceeded => write!(f, "max retries exceeded"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<reqwest::Error> for HttpError {
    fn from(e: reqwest::Error) -> Self { Self::Network(e) }
}

pub struct ClientConfig {
    pub timeout_ms: u64,
    /// Minimum milliseconds between requests; None = no rate limit
    pub rate_limit_ms: Option<u64>,
    pub max_retries: u32,
    pub rotate_ua: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 10_000,
            rate_limit_ms: None,
            max_retries: 3,
            rotate_ua: true,
        }
    }
}

pub struct Client {
    inner: reqwest::Client,
    config: ClientConfig,
    ua_index: AtomicUsize,
    last_req: Arc<Mutex<Instant>>,
}

impl Client {
    pub fn new(config: ClientConfig) -> Result<Self, HttpError> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()?;
        Ok(Self {
            inner,
            config,
            ua_index: AtomicUsize::new(0),
            last_req: Arc::new(Mutex::new(
                // Start far in the past so the first request fires immediately
                Instant::now() - Duration::from_secs(3600),
            )),
        })
    }

    fn next_ua(&self) -> &'static str {
        if !self.config.rotate_ua {
            return USER_AGENTS[0];
        }
        let i = self.ua_index.fetch_add(1, Ordering::Relaxed) % USER_AGENTS.len();
        USER_AGENTS[i]
    }

    async fn throttle(&self) {
        let Some(min_ms) = self.config.rate_limit_ms else { return };
        let min = Duration::from_millis(min_ms);
        let mut last = self.last_req.lock().await;
        let elapsed = last.elapsed();
        if elapsed < min {
            tokio::time::sleep(min - elapsed).await;
        }
        *last = Instant::now();
    }

    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.throttle().await;
        let mut attempt = 0u32;
        loop {
            match self.inner.get(url).header("User-Agent", self.next_ua()).send().await {
                Ok(r) => return Ok(r),
                Err(_) if attempt < self.config.max_retries => {
                    attempt += 1;
                    // Exponential backoff: 600ms, 1200ms, 2400ms
                    tokio::time::sleep(Duration::from_millis(300 * (1 << attempt))).await;
                }
                Err(e) => return Err(HttpError::Network(e)),
            }
        }
    }

    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, HttpError> {
        let resp = self.get(url).await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(HttpError::Status(status));
        }
        Ok(resp.json::<T>().await?)
    }

    pub async fn get_text(&self, url: &str) -> Result<String, HttpError> {
        let resp = self.get(url).await?;
        let status = resp.status().as_u16();
        if status >= 400 {
            return Err(HttpError::Status(status));
        }
        Ok(resp.text().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client(rotate: bool) -> Client {
        Client::new(ClientConfig { rotate_ua: rotate, ..Default::default() }).unwrap()
    }

    #[test]
    fn ua_rotation_cycles_back() {
        let c = test_client(true);
        let first = c.next_ua();
        for _ in 0..USER_AGENTS.len() - 1 {
            c.next_ua();
        }
        assert_eq!(c.next_ua(), first);
    }

    #[test]
    fn ua_disabled_always_returns_same() {
        let c = test_client(false);
        assert_eq!(c.next_ua(), c.next_ua());
    }

    #[test]
    fn default_config_no_rate_limit() {
        assert!(ClientConfig::default().rate_limit_ms.is_none());
    }
}
