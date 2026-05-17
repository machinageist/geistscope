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

// Chain-analysis JSON output
#[derive(Serialize)]
struct ChainAnalysisFile {
    engagement: String,
    generated_at: String,
    recon_at: String,
    source_files: Vec<String>,
    analysis_markdown: String,
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
    let chain_md_path = eng.recon_dir().join("chain-analysis.md");
    let chain_json_path = eng.recon_dir().join("chain-analysis.json");

    // check freshness before paying for model calls
    let priorities_fresh = is_fresh(&priorities_path, &summary_path, args.stale_hours);
    let chain_fresh = is_fresh(&chain_md_path, &summary_path, args.stale_hours)
        && is_fresh(&chain_json_path, &summary_path, args.stale_hours);
    if !args.force && priorities_fresh && chain_fresh {
        eprintln!(
            "priorities and chain analysis are up to date (use --force to regenerate, --stale-hours to tune threshold)"
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
    let priority_markdown = parsed.raw_markdown.clone();
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

    eprintln!("  calling LLM for chain analysis...");
    let chain_markdown =
        run_chain_analysis(&client, &summary_raw, &priority_markdown, &eng).await?;
    write_chain_analysis(
        &chain_md_path,
        &chain_json_path,
        &summary.engagement,
        &run_ts,
        &summary.generated_at,
        chain_markdown,
    )?;

    let _ = eng.audit(
        "ai-prioritize",
        &summary.target,
        Some(&format!("run={run_ts} chain_analysis=true")),
    );

    eprintln!("  written: {}", priorities_path.display());
    eprintln!("  written: {}", priorities_json_path.display());
    eprintln!("  written: {}", chain_md_path.display());
    eprintln!("  written: {}", chain_json_path.display());
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

// Run the chain-analysis LLM pass with bounded local evidence
async fn run_chain_analysis(
    client: &LlmClient,
    summary_raw: &str,
    priorities_markdown: &str,
    eng: &engagement::Engagement,
) -> Result<String> {
    let probe_path = eng.recon_dir().join("probe-report.json");
    let probe_report = read_bounded_optional(&probe_path, 128 * 1024)?;
    let summary_bounded = bounded_text(summary_raw, 256 * 1024);
    let priorities_bounded = bounded_text(priorities_markdown, 96 * 1024);
    let system = prompt::chain_system_prompt();
    let user = prompt::chain_user_prompt(
        &summary_bounded,
        &priorities_bounded,
        probe_report.as_deref(),
    );
    client
        .complete(system, &user)
        .await
        .context("chain-analysis LLM call failed")
}

// Write chain analysis markdown and JSON files
fn write_chain_analysis(
    md_path: &Path,
    json_path: &Path,
    engagement: &str,
    run_ts: &str,
    recon_ts: &str,
    analysis_markdown: String,
) -> Result<()> {
    let md = format!(
        "# GeistScope Chain Analysis — {engagement}\n\n\
         <!-- run: {run_ts} recon: {recon_ts} -->\n\n\
         {analysis_markdown}\n"
    );
    std::fs::write(md_path, md).context("write chain-analysis.md")?;
    let file = ChainAnalysisFile {
        engagement: engagement.to_string(),
        generated_at: run_ts.to_string(),
        recon_at: recon_ts.to_string(),
        source_files: vec![
            "recon/summary.json".into(),
            "recon/priorities.md".into(),
            "recon/probe-report.json".into(),
        ],
        analysis_markdown,
    };
    let json = serde_json::to_string_pretty(&file).context("serialize chain-analysis.json")?;
    std::fs::write(json_path, json).context("write chain-analysis.json")?;
    Ok(())
}

// Truncate UTF-8 text to a byte cap and preserve boundary validity
fn bounded_text(raw: &str, max_bytes: usize) -> String {
    if raw.len() <= max_bytes {
        return raw.to_string();
    }
    let mut end = max_bytes;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n\n<!-- truncated: {} bytes hidden -->",
        &raw[..end],
        raw.len().saturating_sub(end)
    )
}

// Read an optional local evidence file with a model-visible byte cap
fn read_bounded_optional(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(Some(bounded_text(&raw, max_bytes)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "ai-prioritize-chain-test-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn bounded_optional_file_truncates_at_char_boundary() {
        let dir = tmp_dir();
        let path = dir.join("probe-report.json");
        std::fs::write(&path, format!("{}é", "a".repeat(8))).unwrap();

        let value = read_bounded_optional(&path, 9).unwrap().unwrap();

        assert!(value.contains("truncated"));
        assert!(value.is_char_boundary(value.len()));
    }

    #[test]
    fn chain_analysis_writer_outputs_markdown_and_json() {
        let dir = tmp_dir();
        let md = dir.join("chain-analysis.md");
        let json = dir.join("chain-analysis.json");

        write_chain_analysis(
            &md,
            &json,
            "acme",
            "2026-05-15T00:00:00Z",
            "2026-05-14T00:00:00Z",
            "## Chains\n\nNone yet.".into(),
        )
        .unwrap();

        assert!(
            std::fs::read_to_string(&md)
                .unwrap()
                .contains("GeistScope Chain Analysis")
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json).unwrap()).unwrap();
        assert_eq!(parsed["engagement"], "acme");
    }
}
