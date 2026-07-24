/*******************************************************************
 * Filename:        sqli.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-sqli — SQL injection detection (error-based and time-based blind)
 *                  Injects payloads into URL parameters and POST body fields
 *                  found in crawl corpus, checks for DB error strings and
 *                  measures response-time deltas for blind detection.
 * Notes:           Error-based probes run concurrently via JoinSet.
 *                  Time-based probes run per injectable point sequentially
 *                  (baseline first, then timed payloads) to avoid false
 *                  positives from concurrent load skewing measurements.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;
use tokio::time::Instant;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "sqli";
const AUDIT_TOOL: &str = "mg-sqli";

// Number of baseline requests used to establish expected response time
const BASELINE_SAMPLE_COUNT: u32 = 3;

// Error-based SQL injection payloads
const ERROR_PAYLOADS: &[&str] = &[
    "'",
    "''",
    "\"",
    "1' OR '1'='1",
    "1\" OR \"1\"=\"1",
    "1 AND 1=1--",
    "1 AND 1=2--",
    "'; SELECT SLEEP(0); --",
];

// Time-based blind SQL injection payloads (MySQL, MSSQL, PostgreSQL, SQLite)
const TIME_PAYLOADS: &[&str] = &[
    "'; SELECT SLEEP(5); --",
    "'; WAITFOR DELAY '0:0:5'; --",
    "'; SELECT pg_sleep(5); --",
    "'; SELECT CASE WHEN (1=1) THEN RANDOMBLOB(100000000) ELSE 0 END; --",
];

// ── Regex catalog ─────────────────────────────────────────────────────────────

struct ErrorPatterns {
    patterns: Vec<(&'static str, Regex)>,
}

static ERROR_CATALOG: OnceLock<ErrorPatterns> = OnceLock::new();

// Initialize DB error patterns once; panics only on regex syntax error at startup
fn error_catalog() -> &'static ErrorPatterns {
    ERROR_CATALOG.get_or_init(|| ErrorPatterns {
        patterns: vec![
            (
                "MySQL",
                Regex::new(
                    r"You have an error in your SQL syntax|mysql_fetch_array|MySQLSyntaxError",
                )
                .unwrap(),
            ),
            (
                "MSSQL",
                Regex::new(r"Unclosed quotation mark|Microsoft SQL Server|OLE DB").unwrap(),
            ),
            (
                "PostgreSQL",
                Regex::new(r"PostgreSQL.*ERROR|pg_query\(\)|PSQLException").unwrap(),
            ),
            ("Oracle", Regex::new(r"ORA-[0-9]+|Oracle.*Driver").unwrap()),
            (
                "SQLite",
                Regex::new(r"SQLite.*error|sqlite3\.OperationalError").unwrap(),
            ),
            (
                "Generic",
                Regex::new(r"SQLSTATE|jdbc\.SQLException").unwrap(),
            ),
        ],
    })
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    /// Engagement name (must have crawl output)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent error-based probes
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 20)]
    timeout: u64,

    /// Minimum milliseconds above baseline to flag as time-based SQLi
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

// Classification of an error-based probe
#[derive(Debug, Serialize, PartialEq, Eq)]
enum ErrorVerdict {
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
    db_type: Option<String>,
    verdict: ErrorVerdict,
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

#[derive(Debug, Serialize, PartialEq, Eq)]
enum TimeVerdict {
    Confirmed,
    Miss,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SqliResults {
    engagement: String,
    timestamp: String,
    error_probes: usize,
    time_probes: usize,
    error_confirmed: usize,
    time_confirmed: usize,
    error_results: Vec<ErrorResult>,
    time_results: Vec<TimeResult>,
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
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
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

// Check response body for known DB error signatures; return the DB type if found
fn detect_db_error(body: &str) -> Option<&'static str> {
    let catalog = error_catalog();
    for (db_name, pattern) in &catalog.patterns {
        if pattern.is_match(body) {
            return Some(db_name);
        }
    }
    None
}

// Minimal percent-encoding for payload values in query strings
fn urlencoding_simple(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            ' ' => vec!['%', '2', '0'],
            '&' => vec!['%', '2', '6'],
            '#' => vec!['%', '2', '3'],
            _ => vec![c],
        })
        .collect()
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

// Probe one point with one error-based payload; return ErrorResult
async fn probe_error(
    client: reqwest::Client,
    point: InjectablePoint,
    payload: String,
) -> ErrorResult {
    let (body, _) = send_injected(&client, &point, &payload).await;
    let snippet: String = body.chars().take(512).collect();
    let db_type = detect_db_error(&body).map(|s| s.to_string());
    let verdict = if db_type.is_some() {
        ErrorVerdict::Confirmed
    } else {
        ErrorVerdict::Miss
    };
    ErrorResult {
        url: point.base_url,
        param: point.param,
        method: point.method,
        payload,
        db_type,
        verdict,
        body_snippet: snippet,
    }
}

// Baseline an endpoint: return average response time over BASELINE_SAMPLE_COUNT requests
async fn baseline_ms(client: &reqwest::Client, point: &InjectablePoint) -> u64 {
    let mut total = 0u64;
    let benign = "1";
    for _ in 0..BASELINE_SAMPLE_COUNT {
        let (_, ms) = send_injected(client, point, benign).await;
        total += ms;
    }
    total / u64::from(BASELINE_SAMPLE_COUNT)
}

// Probe one point with time-based payloads; return one TimeResult per payload
async fn probe_time_series(
    client: reqwest::Client,
    point: InjectablePoint,
    threshold_ms: u64,
) -> Vec<TimeResult> {
    let base_ms = baseline_ms(&client, &point).await;
    let mut results = Vec::new();

    for payload in TIME_PAYLOADS {
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

// ── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
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
        "mg-sqli: {} injectable points, concurrency={}",
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

    // ── Error-based probes (concurrent) ──────────────────────────────────────
    let mut join_set: JoinSet<ErrorResult> = JoinSet::new();
    let mut error_results: Vec<ErrorResult> = Vec::new();

    for point in &points {
        for payload in ERROR_PAYLOADS {
            // Drain when at concurrency ceiling
            if join_set.len() >= args.concurrency
                && let Some(Ok(r)) = join_set.join_next().await
            {
                error_results.push(r);
            }
            let c = client.clone();
            let pt = point.clone();
            let pld = payload.to_string();
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

    // Print confirmed findings
    for r in &error_results {
        if r.verdict == ErrorVerdict::Confirmed {
            eprintln!(
                "  [error-sqli] {} param={} db={} payload={}",
                r.url,
                r.param,
                r.db_type.as_deref().unwrap_or("unknown"),
                r.payload
            );
        }
    }
    for r in &time_results {
        if r.verdict == TimeVerdict::Confirmed {
            eprintln!(
                "  [time-sqli] {} param={} baseline={}ms response={}ms payload={}",
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

    let output = SqliResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        error_probes: error_results.len(),
        time_probes: time_results.len(),
        error_confirmed,
        time_confirmed,
        error_results,
        time_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create sqli output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write SQLi results JSON")?;

    eprintln!(
        "mg-sqli: error_confirmed={} time_confirmed={} — {}",
        output.error_confirmed,
        output.time_confirmed,
        results_path.display()
    );

    // Write findings for confirmed error-based SQLi
    for r in output
        .error_results
        .iter()
        .filter(|r| r.verdict == ErrorVerdict::Confirmed)
    {
        let tf = ToolFinding::new("mg-sqli", "SQL Injection (Error-Based)", FindingSeverity::High)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("db={} payload={}", r.db_type.as_deref().unwrap_or("unknown"), r.payload))
            .recommendation("Use parameterized queries / prepared statements; never interpolate user input into SQL");
        let _ = write_finding(&eng, &tf);
    }
    // Write findings for confirmed time-based SQLi
    for r in output
        .time_results
        .iter()
        .filter(|r| r.verdict == TimeVerdict::Confirmed)
    {
        let tf = ToolFinding::new("mg-sqli", "SQL Injection (Time-Based Blind)", FindingSeverity::High)
            .url(r.url.clone())
            .parameter(r.param.clone())
            .evidence(format!("payload={} baseline={}ms response={}ms", r.payload, r.baseline_ms, r.response_ms))
            .recommendation("Use parameterized queries / prepared statements; never interpolate user input into SQL");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "error_confirmed={} time_confirmed={} ts={ts}",
            output.error_confirmed, output.time_confirmed
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_mysql_error_in_body() {
        let body = "Warning: You have an error in your SQL syntax near...";
        let db = detect_db_error(body);
        assert_eq!(db, Some("MySQL"));
    }

    #[test]
    fn detect_mssql_error_in_body() {
        let body = "Unclosed quotation mark after the character string.";
        let db = detect_db_error(body);
        assert_eq!(db, Some("MSSQL"));
    }

    #[test]
    fn detect_postgresql_error_in_body() {
        let body = "PostgreSQL ERROR: unterminated quoted string at or near \"'\"";
        let db = detect_db_error(body);
        assert_eq!(db, Some("PostgreSQL"));
    }

    #[test]
    fn detect_oracle_error_in_body() {
        let body = "ORA-00907: missing right parenthesis";
        let db = detect_db_error(body);
        assert_eq!(db, Some("Oracle"));
    }

    #[test]
    fn detect_sqlite_error_in_body() {
        let body = "sqlite3.OperationalError: unrecognized token";
        let db = detect_db_error(body);
        assert_eq!(db, Some("SQLite"));
    }

    #[test]
    fn detect_generic_sqlstate_error() {
        let body = "SQLSTATE[42000]: Syntax error or access violation";
        let db = detect_db_error(body);
        assert_eq!(db, Some("Generic"));
    }

    #[test]
    fn clean_body_returns_none() {
        let body = "<html><body>Welcome!</body></html>";
        let db = detect_db_error(body);
        assert!(db.is_none());
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-17T12:00:00Z"),
            "2026-05-17T12_00_00Z"
        );
    }
}
