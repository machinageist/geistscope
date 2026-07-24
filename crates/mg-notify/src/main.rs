/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-notify — engagement finding webhook notifier.
 *                  Watches findings/ for new .json files and pushes
 *                  messages to Slack, Discord, and/or ntfy.sh.
 * Notes:           Seen-file state is persisted to notify/state.json so
 *                  the process can restart without re-sending old findings.
 *                  Exits cleanly on SIGINT / Ctrl-C.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const NOTIFY_SUBDIR: &str = "notify";
const STATE_FILENAME: &str = "state.json";
const NTFY_BASE_URL: &str = "https://ntfy.sh";
const DEFAULT_POLL_SECS: u64 = 10;
const AUDIT_TOOL: &str = "mg-notify";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-notify",
    about = "Engagement finding webhook notifier — Slack, Discord, ntfy.sh"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Slack incoming webhook URL
    #[arg(long, env = "MG_SLACK_WEBHOOK")]
    slack_url: Option<String>,

    /// Discord incoming webhook URL
    #[arg(long, env = "MG_DISCORD_WEBHOOK")]
    discord_url: Option<String>,

    /// ntfy.sh topic name
    #[arg(long, env = "MG_NTFY_TOPIC")]
    ntfy_topic: Option<String>,

    /// Seconds between finding directory polls
    #[arg(long, default_value_t = DEFAULT_POLL_SECS)]
    poll_secs: u64,

    /// Maximum poll iterations; 0 = run forever
    #[arg(long, default_value_t = 0)]
    max_runs: u64,
}

// ── Finding schema (best-effort) ─────────────────────────────────────────────

// Best-effort parse of a finding file — missing fields default to None
#[derive(Debug, Deserialize, Default)]
struct FindingFile {
    title: Option<String>,
    severity: Option<String>,
    url: Option<String>,
}

// ── State ────────────────────────────────────────────────────────────────────

// Tracks which finding filenames we have already notified about
#[derive(Debug, Serialize, Deserialize, Default)]
struct NotifyState {
    seen: HashSet<String>,
}

// Load state from disk, returning an empty state if the file is missing
fn load_state(path: &Path) -> NotifyState {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

// Persist state to disk
fn save_state(path: &Path, state: &NotifyState) -> Result<()> {
    let json = serde_json::to_string_pretty(state).context("serialize state")?;
    fs::write(path, json).context("write state")?;
    Ok(())
}

// ── Finding scan ─────────────────────────────────────────────────────────────

// Return filenames of .json files in findings_dir not already in state.seen
fn new_finding_filenames(findings_dir: &Path, state: &NotifyState) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(findings_dir).context("read findings dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        if !state.seen.contains(&name) {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

// ── Message formatting ────────────────────────────────────────────────────────

// Format a plain-text notification message from a finding
fn format_message(finding: &FindingFile, filename: &str, engagement_name: &str) -> String {
    let severity = finding
        .severity
        .as_deref()
        .unwrap_or("UNKNOWN")
        .to_uppercase();
    let title = finding.title.as_deref().unwrap_or(filename);
    let url = finding.url.as_deref().unwrap_or("(no url)");
    format!("[{severity}] {title}\nURL: {url}\nEngagement: {engagement_name}")
}

// Map severity string to an ntfy.sh priority header value
fn ntfy_priority(severity: Option<&str>) -> &'static str {
    match severity.unwrap_or("").to_lowercase().as_str() {
        "critical" => "urgent",
        "high" => "high",
        "medium" => "default",
        "low" => "low",
        "info" => "min",
        _ => "default",
    }
}

// ── Webhook delivery ─────────────────────────────────────────────────────────

// POST a message to a Slack incoming webhook
async fn post_slack(client: &reqwest::Client, url: &str, message: &str) -> Result<()> {
    let body = serde_json::json!({"text": message});
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .context("slack post")?
        .error_for_status()
        .context("slack response")?;
    Ok(())
}

// POST a message to a Discord incoming webhook
async fn post_discord(client: &reqwest::Client, url: &str, message: &str) -> Result<()> {
    let body = serde_json::json!({"content": message});
    client
        .post(url)
        .json(&body)
        .send()
        .await
        .context("discord post")?
        .error_for_status()
        .context("discord response")?;
    Ok(())
}

// POST a message to ntfy.sh with severity-derived priority and title headers
async fn post_ntfy(
    client: &reqwest::Client,
    topic: &str,
    message: &str,
    finding: &FindingFile,
) -> Result<()> {
    let url = format!("{NTFY_BASE_URL}/{topic}");
    let title = finding.title.as_deref().unwrap_or("New Finding");
    let priority = ntfy_priority(finding.severity.as_deref());
    client
        .post(&url)
        .header("Title", title)
        .header("Priority", priority)
        .body(message.to_string())
        .send()
        .await
        .context("ntfy post")?
        .error_for_status()
        .context("ntfy response")?;
    Ok(())
}

// ── Poll loop ─────────────────────────────────────────────────────────────────

// Run one poll iteration: scan for new findings and dispatch webhooks
async fn poll_once(
    client: &reqwest::Client,
    findings_dir: &Path,
    state: &mut NotifyState,
    state_path: &Path,
    args: &Args,
    engagement_name: &str,
) -> Result<()> {
    let new_names = new_finding_filenames(findings_dir, state)?;

    for name in new_names {
        let path = findings_dir.join(&name);
        let finding: FindingFile = fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();

        let message = format_message(&finding, &name, engagement_name);
        eprintln!("mg-notify: new finding {name}");
        println!("{message}");

        // Deliver to all configured endpoints; log errors but don't abort
        if let Some(url) = &args.slack_url
            && let Err(e) = post_slack(client, url, &message).await
        {
            eprintln!("  slack error: {e:#}");
        }
        if let Some(url) = &args.discord_url
            && let Err(e) = post_discord(client, url, &message).await
        {
            eprintln!("  discord error: {e:#}");
        }
        if let Some(topic) = &args.ntfy_topic
            && let Err(e) = post_ntfy(client, topic, &message, &finding).await
        {
            eprintln!("  ntfy error: {e:#}");
        }

        state.seen.insert(name);
    }

    save_state(state_path, state)?;
    Ok(())
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let findings_dir = eng.findings_dir();
    if !findings_dir.exists() {
        fs::create_dir_all(&findings_dir).context("create findings dir")?;
    }

    let notify_dir = eng.root.join(NOTIFY_SUBDIR);
    fs::create_dir_all(&notify_dir).context("create notify dir")?;
    let state_path = notify_dir.join(STATE_FILENAME);

    let mut state = load_state(&state_path);

    // Seed seen set with files already present so we don't re-notify on start
    for entry in fs::read_dir(&findings_dir).context("read findings dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            state.seen.insert(name);
        }
    }
    save_state(&state_path, &state)?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("build HTTP client")?;

    let poll_interval = Duration::from_secs(args.poll_secs);
    let mut runs: u64 = 0;

    eprintln!(
        "mg-notify: watching findings/ for {} (poll={}s, max_runs={})",
        args.engagement, args.poll_secs, args.max_runs
    );

    // Install Ctrl-C handler; on signal the loop exits cleanly
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(());
    });

    loop {
        poll_once(
            &client,
            &findings_dir,
            &mut state,
            &state_path,
            &args,
            &args.engagement,
        )
        .await?;

        runs += 1;
        if args.max_runs > 0 && runs >= args.max_runs {
            break;
        }

        // Wait for poll interval or shutdown signal
        tokio::select! {
            _ = tokio::time::sleep(poll_interval) => {},
            _ = &mut shutdown_rx => {
                eprintln!("mg-notify: shutting down");
                break;
            }
        }
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!("runs={runs} seen={}", state.seen.len())),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> PathBuf {
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-notify-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn format_message_uses_defaults_for_missing_fields() {
        let f = FindingFile::default();
        let msg = format_message(&f, "finding-001.json", "acme");
        assert!(msg.contains("[UNKNOWN]"));
        assert!(msg.contains("Engagement: acme"));
    }

    #[test]
    fn format_message_uses_finding_fields() {
        let f = FindingFile {
            title: Some("XSS in search".into()),
            severity: Some("high".into()),
            url: Some("https://example.com/search?q=<script>".into()),
        };
        let msg = format_message(&f, "f.json", "acme");
        assert!(msg.starts_with("[HIGH] XSS in search"));
        assert!(msg.contains("https://example.com"));
    }

    #[test]
    fn ntfy_priority_maps_correctly() {
        assert_eq!(ntfy_priority(Some("critical")), "urgent");
        assert_eq!(ntfy_priority(Some("high")), "high");
        assert_eq!(ntfy_priority(Some("MEDIUM")), "default");
        assert_eq!(ntfy_priority(Some("low")), "low");
        assert_eq!(ntfy_priority(Some("info")), "min");
        assert_eq!(ntfy_priority(None), "default");
    }

    #[test]
    fn new_finding_filenames_excludes_seen() {
        let t = tmp();
        let findings = t.join("findings");
        fs::create_dir_all(&findings).unwrap();
        fs::write(findings.join("old.json"), b"{}").unwrap();
        fs::write(findings.join("new.json"), b"{}").unwrap();
        fs::write(findings.join("not-json.txt"), b"x").unwrap();

        let mut state = NotifyState::default();
        state.seen.insert("old.json".into());

        let names = new_finding_filenames(&findings, &state).unwrap();
        assert_eq!(names, vec!["new.json"]);
    }

    #[test]
    fn state_round_trip() {
        let t = tmp();
        let path = t.join(STATE_FILENAME);
        let mut state = NotifyState::default();
        state.seen.insert("a.json".into());
        save_state(&path, &state).unwrap();

        let loaded = load_state(&path);
        assert!(loaded.seen.contains("a.json"));
    }

    #[test]
    fn load_state_returns_empty_for_missing_file() {
        let t = tmp();
        let state = load_state(&t.join("does-not-exist.json"));
        assert!(state.seen.is_empty());
    }
}
