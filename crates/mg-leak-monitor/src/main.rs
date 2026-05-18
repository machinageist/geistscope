/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-leak-monitor — continuous GitHub leak monitoring
 * Notes:           Polls GitHub Search API for new commits from a target org
 *                  or mentioning a target domain that contain secrets.
 *                  State is persisted across restarts to avoid re-alerting.
 *******************************************************************/

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const GITHUB_SEARCH_URL: &str = "https://api.github.com/search/code";
const GITHUB_TOKEN_ENV: &str = "MG_GITHUB_TOKEN";

// Search terms appended to the org or domain qualifier
const SECRET_TERMS: &[&str] = &["password", "secret", "api_key", "AWS_SECRET"];

const DEFAULT_INTERVAL_SECS: u64 = 300;
const STATE_FILENAME: &str = "state.json";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-leak-monitor",
    about = "Continuous GitHub leak monitoring for an org or domain"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// GitHub organization to monitor
    #[arg(long)]
    org: String,

    /// Additional domain to search for
    #[arg(long)]
    domain: Option<String>,

    /// GitHub API token (or set MG_GITHUB_TOKEN)
    #[arg(long)]
    token: Option<String>,

    /// Polling interval in seconds
    #[arg(long, default_value_t = DEFAULT_INTERVAL_SECS)]
    interval_secs: u64,

    /// Maximum number of poll cycles (0 = run forever)
    #[arg(long, default_value_t = 0)]
    max_runs: u64,
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Default)]
struct MonitorState {
    // Track the last-seen indexed_at per query term to avoid re-alerting
    last_seen: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SearchResponse {
    items: Vec<SearchItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SearchItem {
    name: String,
    path: String,
    html_url: String,
    repository: RepoInfo,
    #[serde(default)]
    last_modified: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RepoInfo {
    full_name: String,
    html_url: String,
    #[serde(default)]
    private: bool,
}

#[derive(Debug, Serialize)]
struct LeakFinding {
    discovered_at: String,
    query: String,
    file_name: String,
    file_path: String,
    repo: String,
    url: String,
    repo_private: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Resolve GitHub token from --token or environment
    let token = args
        .token
        .clone()
        .or_else(|| std::env::var(GITHUB_TOKEN_ENV).ok())
        .context("GitHub token required — pass --token or set MG_GITHUB_TOKEN")?;

    // Load the engagement for state directory and audit log
    let eng = Engagement::load_named(
        std::path::Path::new(&args.engagements_dir),
        &args.engagement,
    )
    .with_context(|| format!("load engagement {}", args.engagement))?;

    // Prepare the leak-monitor state directory under the engagement
    let monitor_dir = eng.root.join("leak-monitor");
    fs::create_dir_all(&monitor_dir).context("create leak-monitor dir")?;

    let state_path = monitor_dir.join(STATE_FILENAME);
    let mut state = load_state(&state_path);

    // Build the reqwest client with auth and user-agent headers
    let client = build_client(&token).context("build GitHub HTTP client")?;

    // Assemble queries for this engagement
    let queries = build_queries(&args.org, args.domain.as_deref());

    // Set up Ctrl-C handler to save state and exit cleanly
    let running = Arc::new(AtomicBool::new(true));
    let running_ctrlc = Arc::clone(&running);
    ctrlc_setup(running_ctrlc);

    eprintln!(
        "mg-leak-monitor: org={} queries={} interval={}s",
        args.org,
        queries.len(),
        args.interval_secs
    );

    let _ = eng.audit(
        "mg-leak-monitor",
        &args.org,
        Some(&format!("queries={} started", queries.len())),
    );

    let mut run_count: u64 = 0;

    // Poll loop — runs until Ctrl-C or max_runs reached
    while running.load(Ordering::SeqCst) {
        run_count += 1;
        eprintln!("  poll cycle #{run_count}");

        for query in &queries {
            if !running.load(Ordering::SeqCst) {
                break;
            }

            let new_items =
                poll_query(&client, query, &mut state, &monitor_dir).await;

            match new_items {
                Ok(count) => {
                    if count > 0 {
                        eprintln!("  [{query}] {count} new finding(s)");
                    }
                }
                Err(e) => {
                    eprintln!("  [{query}] error: {e:#}");
                }
            }
        }

        // Persist state after each poll cycle
        save_state(&state_path, &state);

        if args.max_runs > 0 && run_count >= args.max_runs {
            eprintln!("  reached max_runs={} — stopping", args.max_runs);
            break;
        }

        if running.load(Ordering::SeqCst) {
            tokio::time::sleep(tokio::time::Duration::from_secs(args.interval_secs)).await;
        }
    }

    // Final state save on exit
    save_state(&state_path, &state);
    eprintln!("mg-leak-monitor: state saved to {}", state_path.display());

    Ok(())
}

// ── Poll logic ────────────────────────────────────────────────────────────────

// Poll one query term, report new items, update state; returns count of new findings
async fn poll_query(
    client: &reqwest::Client,
    query: &str,
    state: &mut MonitorState,
    monitor_dir: &Path,
) -> Result<usize> {
    let resp = client
        .get(GITHUB_SEARCH_URL)
        .query(&[("q", query), ("sort", "indexed"), ("order", "desc"), ("per_page", "30")])
        .send()
        .await
        .with_context(|| format!("GET search for {query}"))?;

    // Handle rate limiting — if near the limit, log and return
    let rate_remaining = resp
        .headers()
        .get("X-RateLimit-Remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(99);

    let rate_reset = resp
        .headers()
        .get("X-RateLimit-Reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    if rate_remaining == 0 {
        let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
        let wait = rate_reset.saturating_sub(now);
        eprintln!("  rate limit exhausted — reset in {wait}s");
        return Ok(0);
    }

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub API {status} for query {query}: {body}");
    }

    let search: SearchResponse = resp.json().await.context("parse search response")?;

    let last_seen_key = query.to_string();
    let prev_last = state.last_seen.get(&last_seen_key).cloned().unwrap_or_default();

    let mut new_count = 0;
    let mut newest_ts: Option<String> = None;
    let now_ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default();

    let ts_prefix = format_findings_ts_prefix();
    let findings_path = monitor_dir.join(format!("findings-{ts_prefix}.json"));

    for item in &search.items {
        // Use html_url as a stable item identifier since indexed_at is not in the response
        let item_key = item.html_url.clone();

        if !prev_last.is_empty() && item_key == prev_last {
            break;
        }

        if newest_ts.is_none() {
            newest_ts = Some(item_key.clone());
        }

        let finding = LeakFinding {
            discovered_at: now_ts.clone(),
            query: query.to_string(),
            file_name: item.name.clone(),
            file_path: item.path.clone(),
            repo: item.repository.full_name.clone(),
            url: item.html_url.clone(),
            repo_private: item.repository.private,
        };

        // Print to stdout
        println!(
            "[LEAK] {} — {} — {}",
            finding.repo, finding.file_path, finding.url
        );

        // Append to findings JSONL file
        append_finding(&findings_path, &finding);
        new_count += 1;
    }

    // Update the last-seen marker to the newest item this cycle
    if let Some(key) = newest_ts {
        state.last_seen.insert(last_seen_key, key);
    }

    Ok(new_count)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Build a set of GitHub search queries for the given org and optional domain
pub fn build_queries(org: &str, domain: Option<&str>) -> Vec<String> {
    let mut queries = Vec::new();

    for term in SECRET_TERMS {
        queries.push(format!("org:{org} {term}"));
    }

    if let Some(d) = domain {
        for term in SECRET_TERMS {
            queries.push(format!("\"{d}\" {term}"));
        }
    }

    queries
}

// Build the reqwest client with GitHub auth and user-agent headers
fn build_client(token: &str) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    let auth_value = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("build Authorization header")?;
    headers.insert(AUTHORIZATION, auth_value);
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("mg-leak-monitor/0.1"),
    );
    // Request modern GitHub API response format
    headers.insert(
        "Accept",
        HeaderValue::from_static("application/vnd.github.v3+json"),
    );

    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .context("build reqwest client")
}

// Load persisted monitor state from disk, returning default if missing or corrupt
fn load_state(path: &std::path::Path) -> MonitorState {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

// Persist monitor state to disk as pretty JSON
fn save_state(path: &std::path::Path, state: &MonitorState) {
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = fs::write(path, json);
    }
}

// Append a single finding as a JSON object line to a JSONL file
fn append_finding(path: &std::path::Path, finding: &LeakFinding) {
    if let Ok(line) = serde_json::to_string(finding)
        && let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(f, "{line}");
    }
}

// Return a filesystem-safe timestamp prefix for findings filenames
fn format_findings_ts_prefix() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())[..19]
        .replace(':', "-")
}

// Install a Ctrl-C handler that sets the running flag to false
fn ctrlc_setup(running: Arc<AtomicBool>) {
    // Best-effort; if ctrlc setup fails, the poll loop will still exit on max_runs
    // Drop the handle explicitly — the task runs for the process lifetime
    drop(tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\nmg-leak-monitor: Ctrl-C received — saving state and exiting");
            running.store(false, Ordering::SeqCst);
        }
    }));
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_queries_org_only() {
        let queries = build_queries("acmecorp", None);
        // Should have one query per SECRET_TERMS entry
        assert_eq!(queries.len(), SECRET_TERMS.len());
        assert!(queries.iter().all(|q| q.starts_with("org:acmecorp ")));
        assert!(queries.iter().any(|q| q.contains("password")));
        assert!(queries.iter().any(|q| q.contains("AWS_SECRET")));
    }

    #[test]
    fn build_queries_with_domain_doubles_count() {
        let queries = build_queries("acmecorp", Some("acme.com"));
        assert_eq!(queries.len(), SECRET_TERMS.len() * 2);
        assert!(queries.iter().any(|q| q.contains("\"acme.com\"")));
    }

    #[test]
    fn state_round_trips_through_json() {
        let mut state = MonitorState::default();
        state
            .last_seen
            .insert("org:acme password".into(), "https://github.com/x".into());
        let json = serde_json::to_string(&state).unwrap();
        let state2: MonitorState = serde_json::from_str(&json).unwrap();
        assert_eq!(
            state2.last_seen.get("org:acme password"),
            Some(&"https://github.com/x".to_string())
        );
    }

    #[test]
    fn findings_ts_prefix_is_safe_filename() {
        let prefix = format_findings_ts_prefix();
        // Must not contain colons (reserved on some filesystems)
        assert!(!prefix.contains(':'));
        // Must be non-empty
        assert!(!prefix.is_empty());
    }

    #[test]
    fn append_finding_writes_valid_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("findings.json");

        let finding = LeakFinding {
            discovered_at: "2026-05-18T00:00:00Z".into(),
            query: "org:acme password".into(),
            file_name: "config.yml".into(),
            file_path: "deploy/config.yml".into(),
            repo: "acme/infra".into(),
            url: "https://github.com/acme/infra/blob/main/deploy/config.yml".into(),
            repo_private: false,
        };

        append_finding(&path, &finding);
        append_finding(&path, &finding);

        let content = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line must be valid JSON
        for line in &lines {
            serde_json::from_str::<serde_json::Value>(line).unwrap();
        }
    }
}
