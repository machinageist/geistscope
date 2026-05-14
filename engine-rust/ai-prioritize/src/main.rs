/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     ai-prioritize — cross-reference recon summary with bug-hunting
 *                  skills and produce a ranked priorities.md + priorities.json
 * Notes:           Anthropic is the primary backend (ANTHROPIC_API_KEY env var).
 *                  Falls back to Ollama if the key is absent.
 *                  Each run appends a timestamped section to priorities.md.
 *                  Skips the LLM call if the output is still fresh and recon
 *                  data has not changed since the last run.
 *******************************************************************/
mod parse;
mod prompt;
mod skills;

use std::io::Write as IoWrite;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use fingerprint::Fingerprint;
use llm_client::LlmClient;

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "ai-prioritize",
    about = "Rank attack surface using recon data and bug-hunting skills"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory (overrides MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to bug-hunting skills directory
    #[arg(
        long,
        env = "MG_SKILLS_DIR",
        default_value = "~/.claude/bug-hunting-skills"
    )]
    skills_dir: String,

    /// Claude model ID to use (Anthropic backend)
    #[arg(long, default_value = "claude-sonnet-4-6")]
    model: String,

    /// Ollama model to use when ANTHROPIC_API_KEY is not set
    #[arg(long, default_value = "llama3.2")]
    ollama_model: String,

    /// Hours before a valid priorities.md is considered stale (time-based expiry)
    #[arg(long, default_value_t = 24)]
    stale_hours: u64,

    /// Re-run even if priorities are still fresh
    #[arg(long)]
    force: bool,
}

// ── Recon types (mirrors orchestrator output shape for JSON deserialization) ─

#[derive(Deserialize)]
struct ReconSummary {
    engagement: String,
    target: String,
    generated_at: String,
    host_count: usize,
    hosts: Vec<HostRecord>,
}

#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    ips: Vec<String>,
    source: String,
    http_accessible: bool,
    fingerprint: Option<Fingerprint>,
    open_ports: Vec<u16>,
    services: Vec<String>,
}

// ── Priorities JSON output ───────────────────────────────────────────────────

#[derive(Serialize)]
struct PrioritiesFile {
    engagement: String,
    generated_at: String,
    recon_at: String,
    priorities: Vec<parse::Priority>,
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // resolve ~ in skills_dir path
    let skills_dir = expand_tilde(&args.skills_dir);
    let eng =
        engagement::Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
            .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    if !summary_path.exists() {
        anyhow::bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let priorities_path = eng.recon_dir().join("priorities.md");
    let priorities_json_path = eng.recon_dir().join("priorities.json");

    // check freshness before paying for a model call
    if !args.force && is_fresh(&priorities_path, &summary_path, args.stale_hours) {
        eprintln!(
            "priorities are up to date (use --force to regenerate, --stale-hours to tune threshold)"
        );
        return Ok(());
    }

    // load recon summary
    let summary_raw = std::fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&summary_raw).context("parse summary.json")?;

    eprintln!(
        "ai-prioritize: {} hosts, {} skills",
        summary.host_count,
        count_skills(&skills_dir)
    );

    // load and trim skill files
    let skill_list = skills::load_skills(Path::new(&skills_dir)).context("load skills")?;
    if skill_list.is_empty() {
        anyhow::bail!("no skills found at {} — check MG_SKILLS_DIR", skills_dir);
    }
    eprintln!("  loaded {} skill files", skill_list.len());

    // select LLM backend: Anthropic if API key present, else Ollama
    let client = build_client(&args)?;

    eprintln!("  calling LLM...");
    let system = prompt::system_prompt();
    let user = prompt::user_prompt(&summary, &skill_list);

    let llm_response = client
        .complete(system, &user)
        .await
        .context("LLM call failed")?;

    // parse structured priorities from the LLM markdown
    let parsed = parse::parse_llm_output(&llm_response, Path::new(&skills_dir));
    eprintln!("  parsed {} priority entries", parsed.priorities.len());

    // timestamps for the run record
    let run_ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format run timestamp")?;
    let recon_ts = summary.generated_at.clone();

    // append timestamped section to priorities.md
    append_to_priorities_md(
        &priorities_path,
        &args.engagement,
        &run_ts,
        &recon_ts,
        &parsed.raw_markdown,
    )?;

    // always overwrite priorities.json with the latest ranked list
    let pf = PrioritiesFile {
        engagement: summary.engagement.clone(),
        generated_at: run_ts.clone(),
        recon_at: recon_ts,
        priorities: parsed.priorities,
    };
    let json = serde_json::to_string_pretty(&pf).context("serialize priorities")?;
    std::fs::write(&priorities_json_path, json).context("write priorities.json")?;

    let _ = eng.audit(
        "ai-prioritize",
        &summary.target,
        Some(&format!("run={run_ts}")),
    );

    eprintln!("  written: {}", priorities_path.display());
    eprintln!("  written: {}", priorities_json_path.display());
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Decide whether the existing priorities.md is still valid
fn is_fresh(priorities_path: &Path, summary_path: &Path, stale_hours: u64) -> bool {
    if !priorities_path.exists() {
        return false;
    }

    // parse the most recent run timestamp from the HTML comment markers we write
    let last_run = parse_last_run_time(priorities_path);
    let now = SystemTime::now();

    // stale if the recon summary is newer than when we last ran
    if let (Ok(summary_mtime), Some(lr)) =
        (summary_path.metadata().and_then(|m| m.modified()), last_run)
        && summary_mtime > lr
    {
        return false;
    }

    // stale if more than stale_hours have elapsed since the last run, or no run recorded
    match last_run {
        Some(lr) => {
            let age = now.duration_since(lr).unwrap_or(Duration::MAX);
            if age > Duration::from_secs(stale_hours * 3600) {
                return false;
            }
        }
        None => return false,
    }

    true
}

// Find the most recent <!-- run: ISO8601 --> marker in priorities.md and return its time
fn parse_last_run_time(path: &Path) -> Option<SystemTime> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut last: Option<SystemTime> = None;

    // scan for lines like: <!-- run: 2026-05-08T15:30:00Z recon: ... -->
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("<!-- run: ") {
            // extract the timestamp token before the next space
            if let Some(ts_str) = rest.split_whitespace().next() {
                // parse as RFC3339 then convert to SystemTime via unix epoch
                if let Ok(odt) = OffsetDateTime::parse(ts_str, &Rfc3339) {
                    let unix = odt.unix_timestamp();
                    if unix >= 0 {
                        let st = SystemTime::UNIX_EPOCH + Duration::from_secs(unix as u64);
                        // keep the most recent timestamp in the file
                        last = Some(match last {
                            Some(prev) if st > prev => st,
                            Some(prev) => prev,
                            None => st,
                        });
                    }
                }
            }
        }
    }

    last
}

// Append one timestamped run section to priorities.md; create the file with a header if new
fn append_to_priorities_md(
    path: &Path,
    engagement: &str,
    run_ts: &str,
    recon_ts: &str,
    markdown: &str,
) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .context("open priorities.md")?;

    // write file header only on first creation (file was just created, size is 0)
    if f.metadata()?.len() == 0 {
        writeln!(f, "# GeistScope Priorities — {engagement}\n")?;
    }

    // parseable run marker used by is_fresh()
    writeln!(f, "<!-- run: {run_ts} recon: {recon_ts} -->\n")?;
    // human-readable section heading
    writeln!(f, "## Run {run_ts}\n")?;
    // the LLM's table and observations verbatim
    writeln!(f, "{markdown}\n")?;
    // visual separator between runs
    writeln!(f, "---\n")?;

    Ok(())
}

// Build the LLM client; prefer Anthropic, fall back to Ollama
fn build_client(args: &Args) -> Result<LlmClient> {
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        eprintln!("  backend: Anthropic ({})", args.model);
        LlmClient::anthropic(key, &args.model).context("build Anthropic client")
    } else {
        eprintln!(
            "  backend: Ollama ({}) — set ANTHROPIC_API_KEY for better results",
            args.ollama_model
        );
        LlmClient::ollama(&args.ollama_model).context("build Ollama client")
    }
}

// Count skill directories without loading their content (for the status line)
fn count_skills(skills_dir: &str) -> usize {
    std::fs::read_dir(skills_dir)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).count())
        .unwrap_or(0)
}

// Expand a leading ~ to the home directory
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_string()
}
