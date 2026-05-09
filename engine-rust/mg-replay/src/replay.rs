/*******************************************************************
 * Filename:        replay.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Execute a CurlRequest via reqwest and compare the response
 *                  against a baseline snapshot to determine if a finding is
 *                  still exploitable
 * Notes:           Verdict logic:
 *                    still_vulnerable  — same status and similar body as original
 *                    appears_fixed     — status changed to 4xx/5xx or body changed significantly
 *                    indeterminate     — request errored or diff is ambiguous
 *                  "Similar body" uses SHA-256 hash for exact match and falls
 *                  back to length delta for heuristic comparison.
 *******************************************************************/

use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::parse::CurlRequest;

// Result of replaying one curl request
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReplayResult {
    pub url: String,
    pub method: String,
    pub original_status: Option<u16>,
    pub replay_status: u16,
    pub body_len: usize,
    pub body_hash: String,
    pub elapsed_ms: u64,
    pub verdict: Verdict,
    pub notes: Vec<String>,
}

// Replay verdict
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    StillVulnerable,
    AppearsFixed,
    Indeterminate,
}

// Optional snapshot from the original finding — used for baseline comparison
#[derive(Debug, Clone)]
pub struct OriginalBaseline {
    pub status: u16,
    pub body_hash: Option<String>,
    pub body_len: Option<usize>,
}

// Send the curl request and return a ReplayResult compared against the optional baseline
pub async fn replay(
    client: &reqwest::Client,
    req: &CurlRequest,
    baseline: Option<&OriginalBaseline>,
) -> Result<ReplayResult> {
    let t0 = Instant::now();

    // build the reqwest request with the parsed method
    let method = reqwest::Method::from_bytes(req.method.as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, &req.url);

    // apply all headers from the parsed curl command
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }

    // attach request body if present
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }

    let resp = builder.send().await.context("send replay request")?;
    let elapsed_ms = t0.elapsed().as_millis() as u64;

    let replay_status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    let body_len = body.len();
    let body_hash = sha256_hex(&body);

    // determine verdict using the baseline if provided
    let (verdict, notes) = compute_verdict(
        replay_status,
        body_len,
        &body_hash,
        elapsed_ms,
        baseline,
    );

    Ok(ReplayResult {
        url: req.url.clone(),
        method: req.method.clone(),
        original_status: baseline.map(|b| b.status),
        replay_status,
        body_len,
        body_hash,
        elapsed_ms,
        verdict,
        notes,
    })
}

// Determine verdict from response metrics and baseline comparison
fn compute_verdict(
    status: u16,
    body_len: usize,
    body_hash: &str,
    elapsed_ms: u64,
    baseline: Option<&OriginalBaseline>,
) -> (Verdict, Vec<String>) {
    let mut notes = Vec::new();

    // no baseline means we can only check current response for obvious failure signals
    let Some(base) = baseline else {
        if status >= 400 {
            notes.push(format!("No baseline; response is {status} — may be fixed"));
            return (Verdict::Indeterminate, notes);
        }
        notes.push("No baseline available for comparison — verdict is indeterminate".into());
        return (Verdict::Indeterminate, notes);
    };

    let status_changed = status != base.status;

    // a move to 4xx/5xx from a 2xx/3xx suggests the issue is fixed
    let is_error_response = status >= 400;
    let was_success = base.status < 400;

    if status_changed {
        notes.push(format!("Status changed: {} → {}", base.status, status));
        if was_success && is_error_response {
            return (Verdict::AppearsFixed, notes);
        }
    }

    // check body similarity: exact hash match is the strongest signal
    if let Some(orig_hash) = &base.body_hash {
        if body_hash == orig_hash {
            notes.push("Response body hash matches original — likely still vulnerable".into());
            return (Verdict::StillVulnerable, notes);
        }
        notes.push("Response body hash differs from original".into());
    }

    // fall back to length comparison
    if let Some(orig_len) = base.body_len {
        let delta = (body_len as i64 - orig_len as i64).unsigned_abs();
        if delta < 100 {
            notes.push(format!("Body length similar ({body_len} vs {orig_len}) — likely still vulnerable"));
            return (Verdict::StillVulnerable, notes);
        }
        notes.push(format!("Body length changed significantly ({body_len} vs {orig_len})"));
        return (Verdict::AppearsFixed, notes);
    }

    // timing anomaly check: if response is very fast it may be short-circuited (fixed)
    if elapsed_ms < 50 {
        notes.push(format!("Response was very fast ({elapsed_ms}ms) — may be cached error page"));
    }

    notes.push("Insufficient data for confident verdict".into());
    (Verdict::Indeterminate, notes)
}

// SHA-256 hex digest of a string
fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

// Build a reqwest client with the given settings
pub fn build_client(timeout_ms: u64, insecure: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .user_agent("mg-replay/0.1 (security research)")
        .danger_accept_invalid_certs(insecure)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("build HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Baseline: original response was 200 OK
    fn base_200(hash: Option<&str>, len: Option<usize>) -> OriginalBaseline {
        OriginalBaseline { status: 200, body_hash: hash.map(String::from), body_len: len }
    }

    #[test]
    fn still_vulnerable_on_hash_match() {
        let (v, notes) = compute_verdict(200, 100, "abc123", 200, Some(&base_200(Some("abc123"), Some(100))));
        assert_eq!(v, Verdict::StillVulnerable);
        assert!(notes.iter().any(|n| n.contains("hash matches")));
    }

    #[test]
    fn appears_fixed_when_200_becomes_403() {
        let (v, _) = compute_verdict(403, 50, "xyz", 100, Some(&base_200(None, None)));
        assert_eq!(v, Verdict::AppearsFixed);
    }

    #[test]
    fn still_vulnerable_when_length_similar() {
        let (v, _) = compute_verdict(200, 1010, "different_hash", 100, Some(&base_200(Some("orig_hash"), Some(1000))));
        assert_eq!(v, Verdict::StillVulnerable);
    }

    #[test]
    fn appears_fixed_when_length_very_different() {
        let (v, _) = compute_verdict(200, 5000, "diff", 100, Some(&base_200(Some("orig"), Some(200))));
        assert_eq!(v, Verdict::AppearsFixed);
    }

    #[test]
    fn no_baseline_returns_indeterminate() {
        let (v, _) = compute_verdict(200, 100, "hash", 100, None);
        assert_eq!(v, Verdict::Indeterminate);
    }
}
