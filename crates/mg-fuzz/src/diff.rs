/*******************************************************************
 * Filename:        diff.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     HTTP response capture and diffing — compare a probe response
 *                  against a baseline to surface anomalous behavior
 * Notes:           Comparison metrics: status code, body length, body SHA-256,
 *                  and elapsed response time. A response is flagged as "interesting"
 *                  if any of these deviate beyond configured thresholds.
 *                  This module is used internally by attack.rs — not a standalone tool.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Full snapshot of one HTTP response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub status: u16,
    pub body: String,
    pub body_len: usize,
    pub body_hash: String,
    pub elapsed_ms: u64,
    // selected response headers for analysis
    pub content_type: Option<String>,
    pub location: Option<String>,
}

// Comparison between a probe response and the baseline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    pub status_changed: bool,
    pub baseline_status: u16,
    pub probe_status: u16,
    pub len_delta: i64,
    pub hash_match: bool,
    pub elapsed_delta_ms: i64,
    // true if this response meets the "interesting" criteria
    pub interesting: bool,
}

impl ResponseRecord {
    // Build a ResponseRecord from raw response parts; hashes the body
    pub fn new(
        status: u16,
        body: String,
        elapsed_ms: u64,
        content_type: Option<String>,
        location: Option<String>,
    ) -> Self {
        let body_len = body.len();
        let body_hash = sha256_hex(&body);
        Self { status, body, body_len, body_hash, elapsed_ms, content_type, location }
    }
}

// Compute the diff between a baseline and a probe response
// Thresholds: status change, body length delta > 50 bytes, or different hash
pub fn diff(baseline: &ResponseRecord, probe: &ResponseRecord) -> Diff {
    let status_changed = probe.status != baseline.status;
    let len_delta = probe.body_len as i64 - baseline.body_len as i64;
    let hash_match = probe.body_hash == baseline.body_hash;
    let elapsed_delta_ms = probe.elapsed_ms as i64 - baseline.elapsed_ms as i64;

    // mark interesting if status changed, body differs meaningfully, or large time delta (blind SQLi / sleep)
    let interesting = status_changed
        || !hash_match && len_delta.unsigned_abs() > 50
        || elapsed_delta_ms > 4_000;  // >4s additional delay suggests sleep-based injection

    Diff {
        status_changed,
        baseline_status: baseline.status,
        probe_status: probe.status,
        len_delta,
        hash_match,
        elapsed_delta_ms,
        interesting,
    }
}

// SHA-256 hex digest of a string
fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a minimal ResponseRecord for testing
    fn rec(status: u16, body: &str, elapsed_ms: u64) -> ResponseRecord {
        ResponseRecord::new(status, body.to_string(), elapsed_ms, None, None)
    }

    #[test]
    fn identical_responses_are_not_interesting() {
        let base = rec(200, "hello world", 100);
        let probe = rec(200, "hello world", 105);
        let d = diff(&base, &probe);
        assert!(!d.status_changed);
        assert!(d.hash_match);
        assert!(!d.interesting);
    }

    #[test]
    fn status_change_is_interesting() {
        let base = rec(200, "ok", 100);
        let probe = rec(500, "error", 100);
        let d = diff(&base, &probe);
        assert!(d.status_changed);
        assert!(d.interesting);
    }

    #[test]
    fn large_body_delta_is_interesting() {
        let base = rec(200, "short", 100);
        let long_body = "x".repeat(200);
        let probe = rec(200, &long_body, 100);
        let d = diff(&base, &probe);
        assert!(!d.hash_match);
        assert!(d.interesting);
    }

    #[test]
    fn small_body_delta_not_interesting() {
        let base = rec(200, "hello world", 100);
        let probe = rec(200, "hello world!", 100);  // 1-byte diff, below 50-byte threshold
        let d = diff(&base, &probe);
        assert!(!d.interesting);
    }

    #[test]
    fn long_elapsed_is_interesting() {
        let base = rec(200, "ok", 200);
        let probe = rec(200, "ok", 5000);  // 4.8s additional delay
        let d = diff(&base, &probe);
        assert!(d.interesting);
        assert_eq!(d.elapsed_delta_ms, 4800);
    }
}
