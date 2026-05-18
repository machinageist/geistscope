/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-authz — IDOR/BOLA multi-role authorization tester.
 *                  Replays recorded requests under two sessions and flags
 *                  broken object-level authorization when session-B reaches
 *                  ownership-scoped resources that should be session-A only.
 * Notes:           Session headers loaded via session::load_session_config
 *                  for named engagements; env-var JSON fallback for ad-hoc use.
 *                  Concurrency bounded with tokio::JoinSet drain pattern.
 *******************************************************************/

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;
use url::Url;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "authz";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-authz";

// URL path segments that suggest ownership-scoped resources
const OWNERSHIP_SEGMENTS: &[&str] = &[
    "/users/", "/accounts/", "/orders/", "/items/",
    "/files/", "/documents/",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-authz",
    about = "IDOR/BOLA authorization tester — replay requests under alternate sessions"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Primary session name (attacker role)
    #[arg(long)]
    session_a: String,

    /// Victim session name (lower/different role)
    #[arg(long)]
    session_b: String,

    /// JSON file of requests to replay (default: read from engagement findings)
    #[arg(long)]
    requests: Option<String>,

    /// Maximum concurrent replays
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One request record from the input file or finding
#[derive(Debug, Clone, Deserialize)]
struct RequestRecord {
    method: String,
    url: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    body: Option<String>,
}

// Result of replaying one request under both sessions
#[derive(Debug, Serialize)]
struct AuthzResult {
    method: String,
    url: String,
    status_a: u16,
    status_b: u16,
    body_hash_a: String,
    body_hash_b: String,
    verdict: Verdict,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
enum Verdict {
    /// Session-B reached a resource it should not have
    Idor,
    /// Session-B status differs from session-A; worth manual review
    Different,
    /// No authorization difference detected
    Ok,
}

// Top-level output written to disk
#[derive(Serialize)]
struct AuthzResults {
    engagement: String,
    session_a: String,
    session_b: String,
    timestamp: String,
    total_requests: usize,
    idor_count: usize,
    results: Vec<AuthzResult>,
}

// ── Session loading ───────────────────────────────────────────────────────────

// Load headers for a named session: try the session engagement, then env var fallback
fn load_session_headers(
    engagements_dir: &Path,
    session_name: &str,
    env_var: &str,
) -> Result<HeaderMap> {
    // Try loading session.json from an engagement named after the session
    let session_eng_path = engagements_dir.join(session_name);
    if session_eng_path.join("engagement.json").exists()
        && let Ok(eng) = Engagement::load(&session_eng_path)
        && let Ok(headers) = session::get_auth_headers_sync(&eng)
        && !headers.is_empty()
    {
        return Ok(headers);
    }

    // Fall back to env var JSON object
    let raw = std::env::var(env_var)
        .with_context(|| format!("session {session_name:?} not found and {env_var} is not set"))?;
    let map: HashMap<String, String> =
        serde_json::from_str(&raw).with_context(|| format!("parse {env_var} as JSON object"))?;
    let mut headers = HeaderMap::new();
    for (k, v) in map {
        let name = HeaderName::from_bytes(k.as_bytes())
            .with_context(|| format!("invalid header name {k:?} in {env_var}"))?;
        let value = HeaderValue::from_str(&v)
            .with_context(|| format!("invalid header value for {k:?} in {env_var}"))?;
        headers.insert(name, value);
    }
    Ok(headers)
}

// ── Request collection ────────────────────────────────────────────────────────

// Load requests from a JSON file path
fn load_requests_from_file(path: &str) -> Result<Vec<RequestRecord>> {
    let raw = fs::read_to_string(path).with_context(|| format!("read requests file: {path}"))?;
    serde_json::from_str(&raw).context("parse requests JSON array")
}

// Extract URLs from engagement findings JSON files and build GET request records
fn load_requests_from_findings(findings_dir: &Path) -> Result<Vec<RequestRecord>> {
    let mut records = Vec::new();
    let Ok(entries) = fs::read_dir(findings_dir) else {
        return Ok(records);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(&raw) else {
            continue;
        };
        // Extract any "url" string fields from the finding object or its sub-objects
        collect_urls_from_value(&val, &mut records);
    }
    Ok(records)
}

// Recursively collect "url" string fields from a JSON value
fn collect_urls_from_value(val: &serde_json::Value, records: &mut Vec<RequestRecord>) {
    match val {
        serde_json::Value::Object(map) => {
            if let Some(url_val) = map.get("url")
                && let Some(url_str) = url_val.as_str()
                && (url_str.starts_with("http://") || url_str.starts_with("https://"))
            {
                records.push(RequestRecord {
                    method: "GET".to_string(),
                    url: url_str.to_string(),
                    headers: HashMap::new(),
                    body: None,
                });
            }
            for v in map.values() {
                collect_urls_from_value(v, records);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_urls_from_value(v, records);
            }
        }
        _ => {}
    }
}

// ── Authorization check ───────────────────────────────────────────────────────

// Determine whether a URL looks like an ownership-scoped resource
fn is_ownership_scoped(url_str: &str) -> bool {
    // Check named segments
    let lower = url_str.to_lowercase();
    if OWNERSHIP_SEGMENTS.iter().any(|seg| lower.contains(seg)) {
        return true;
    }
    // Check for numeric ID segments in the path
    if let Ok(parsed) = Url::parse(url_str) {
        return parsed.path_segments().map(|mut segs| {
            segs.any(|seg| seg.chars().all(|c| c.is_ascii_digit()) && !seg.is_empty())
        }).unwrap_or(false);
    }
    false
}

// Compute a short hex hash of a response body for comparison
fn body_hash(body: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    body.hash(&mut h);
    format!("{:016x}", h.finish())
}

// Replay one request with session headers; return (status, body_hash)
async fn replay(
    client: &reqwest::Client,
    req: &RequestRecord,
    session_headers: &HeaderMap,
) -> (u16, String) {
    let method = reqwest::Method::from_bytes(req.method.as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(method, &req.url);
    // Apply request-level headers from the record
    for (k, v) in &req.headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    // Apply session headers (overrides request headers for auth fields)
    for (k, v) in session_headers {
        builder = builder.header(k, v);
    }
    if let Some(body) = &req.body {
        builder = builder.body(body.clone());
    }
    match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            (status, body_hash(&text))
        }
        Err(_) => (0, String::new()),
    }
}

// Classify the authorization verdict from two replay results
fn classify(
    req: &RequestRecord,
    status_a: u16,
    body_hash_a: &str,
    status_b: u16,
    body_hash_b: &str,
) -> Verdict {
    // If session-B gets 200 (or same status as A) on an ownership-scoped URL → IDOR
    if is_ownership_scoped(&req.url)
        && status_b == 200
        && (status_a == 200 || body_hash_a == body_hash_b)
    {
        return Verdict::Idor;
    }
    if status_a != status_b {
        return Verdict::Different;
    }
    Verdict::Ok
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let engagements_dir = Path::new(&args.engagements_dir);

    let eng = Engagement::load_named(engagements_dir, &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Load session headers for both roles
    let headers_a = load_session_headers(engagements_dir, &args.session_a, "MG_SESSION_A_HEADERS")
        .with_context(|| format!("load session-A headers ({})", args.session_a))?;
    let headers_b = load_session_headers(engagements_dir, &args.session_b, "MG_SESSION_B_HEADERS")
        .with_context(|| format!("load session-B headers ({})", args.session_b))?;

    // Collect request list
    let requests: Vec<RequestRecord> = if let Some(path) = &args.requests {
        load_requests_from_file(path)?
    } else {
        load_requests_from_findings(&eng.findings_dir())?
    };

    if requests.is_empty() {
        bail!("no requests to replay — provide --requests or populate engagement findings");
    }
    eprintln!(
        "mg-authz: {} requests, session-A={}, session-B={}",
        requests.len(),
        args.session_a,
        args.session_b
    );

    // Build the HTTP client
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Replay each request under both sessions with bounded concurrency
    // Each task returns (index, status_a, hash_a, status_b, hash_b)
    type TaskResult = (usize, u16, String, u16, String);
    let mut join_set: JoinSet<TaskResult> = JoinSet::new();
    let mut raw_results: Vec<TaskResult> = Vec::new();

    for (idx, req) in requests.iter().enumerate() {
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            raw_results.push(r);
        }
        let client_a = client.clone();
        let client_b = client.clone();
        let req_a = req.clone();
        let req_b = req.clone();
        let ha = headers_a.clone();
        let hb = headers_b.clone();
        join_set.spawn(async move {
            let (sa, ha_hash) = replay(&client_a, &req_a, &ha).await;
            let (sb, hb_hash) = replay(&client_b, &req_b, &hb).await;
            (idx, sa, ha_hash, sb, hb_hash)
        });
    }
    while let Some(Ok(r)) = join_set.join_next().await {
        raw_results.push(r);
    }

    // Sort by original request index to keep deterministic output order
    raw_results.sort_by_key(|r| r.0);

    // Build classified results
    let mut results: Vec<AuthzResult> = raw_results
        .iter()
        .map(|(idx, sa, ha_hash, sb, hb_hash)| {
            let req = &requests[*idx];
            let verdict = classify(req, *sa, ha_hash, *sb, hb_hash);
            AuthzResult {
                method: req.method.clone(),
                url: req.url.clone(),
                status_a: *sa,
                status_b: *sb,
                body_hash_a: ha_hash.clone(),
                body_hash_b: hb_hash.clone(),
                verdict,
            }
        })
        .collect();

    // Print table
    println!("{:<6} {:<50} {:>8} {:>8} VERDICT", "METHOD", "URL", "SES-A", "SES-B");
    println!("{}", "-".repeat(90));
    for r in &results {
        let url_display: String = r.url.chars().take(50).collect();
        println!(
            "{:<6} {:<50} {:>8} {:>8} {:?}",
            r.method, url_display, r.status_a, r.status_b, r.verdict
        );
    }

    let idor_count = results.iter().filter(|r| r.verdict == Verdict::Idor).count();
    println!("\nIDOR findings: {idor_count}");

    // Write results to disk
    let authz_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&authz_dir).context("create authz output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = authz_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    // Move results into the output struct (avoids cloning)
    let output = AuthzResults {
        engagement: args.engagement.clone(),
        session_a: args.session_a.clone(),
        session_b: args.session_b.clone(),
        timestamp: ts,
        total_requests: results.len(),
        idor_count,
        results: {
            // drain results into output (swap with empty to avoid clone)
            let mut tmp = Vec::new();
            std::mem::swap(&mut tmp, &mut results);
            tmp
        },
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!(
        "requests={} idor={} session_a={} session_b={}",
        output.total_requests,
        idor_count,
        args.session_a,
        args.session_b
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_ownership_scoped_detects_named_segments() {
        assert!(is_ownership_scoped("https://api.example.com/users/123"));
        assert!(is_ownership_scoped("https://api.example.com/orders/456/detail"));
        assert!(is_ownership_scoped("https://api.example.com/files/abc.pdf"));
        assert!(!is_ownership_scoped("https://api.example.com/health"));
        assert!(!is_ownership_scoped("https://api.example.com/login"));
    }

    #[test]
    fn is_ownership_scoped_detects_numeric_id_segments() {
        assert!(is_ownership_scoped("https://api.example.com/api/123/profile"));
        assert!(!is_ownership_scoped("https://api.example.com/api/profile"));
    }

    #[test]
    fn classify_flags_idor_when_session_b_reaches_200_ownership_resource() {
        let req = RequestRecord {
            method: "GET".into(),
            url: "https://api.example.com/users/999".into(),
            headers: HashMap::new(),
            body: None,
        };
        let verdict = classify(&req, 200, "aabbccdd", 200, "aabbccdd");
        assert_eq!(verdict, Verdict::Idor);
    }

    #[test]
    fn classify_flags_different_on_status_mismatch() {
        let req = RequestRecord {
            method: "GET".into(),
            url: "https://api.example.com/health".into(),
            headers: HashMap::new(),
            body: None,
        };
        let verdict = classify(&req, 200, "aabb", 403, "ccdd");
        assert_eq!(verdict, Verdict::Different);
    }

    #[test]
    fn classify_ok_when_statuses_match_non_ownership() {
        let req = RequestRecord {
            method: "GET".into(),
            url: "https://api.example.com/health".into(),
            headers: HashMap::new(),
            body: None,
        };
        let verdict = classify(&req, 200, "aabb", 200, "ccdd");
        assert_eq!(verdict, Verdict::Ok);
    }

    #[test]
    fn collect_urls_from_value_extracts_http_urls() {
        let val = serde_json::json!({
            "url": "https://api.example.com/users/1",
            "nested": {"url": "https://api.example.com/orders/2"}
        });
        let mut records = Vec::new();
        collect_urls_from_value(&val, &mut records);
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|r| r.url.contains("users")));
        assert!(records.iter().any(|r| r.url.contains("orders")));
    }

    #[test]
    fn load_requests_from_file_parses_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reqs.json");
        let content = serde_json::json!([
            {"method": "GET", "url": "https://example.com/api/users/1"}
        ]);
        fs::write(&path, serde_json::to_string(&content).unwrap()).unwrap();
        let records = load_requests_from_file(path.to_str().unwrap()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].method, "GET");
    }

    #[test]
    fn body_hash_is_deterministic() {
        assert_eq!(body_hash("hello world"), body_hash("hello world"));
        assert_ne!(body_hash("hello"), body_hash("world"));
    }
}
