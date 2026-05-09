/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     mg-replay — Burp Repeater equivalent for finding verification
 *                  Reads a finding markdown file, extracts curl commands from the
 *                  "## Evidence" section, replays each request, and outputs a
 *                  verdict: still_vulnerable / appears_fixed / indeterminate
 * Notes:           The finding file is identified by its ID or by path.
 *                  If the finding includes original response metadata (status,
 *                  body hash) in frontmatter, those are used as the comparison
 *                  baseline; otherwise the verdict is heuristic.
 *                  Replay results are written to findings/<id>-replay-<ts>.json.
 *******************************************************************/

mod parse;
mod replay;

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

use crate::replay::{OriginalBaseline, Verdict};

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "mg-replay", about = "Replay finding curl evidence and verify exploitability")]
struct Args {
    /// Engagement name
    engagement: String,

    /// Finding ID prefix (e.g. "20260509-probe-001") or path to a finding .md file
    finding: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// HTTP timeout in milliseconds
    #[arg(long, default_value_t = 15_000)]
    timeout_ms: u64,

    /// Accept self-signed TLS certificates
    #[arg(long)]
    insecure: bool,
}

// ── Finding frontmatter ───────────────────────────────────────────────────────

// Subset of the finding frontmatter we need for replay
#[derive(Deserialize, Default)]
struct FindingMeta {
    #[allow(dead_code)]
    title: Option<String>,
    #[allow(dead_code)]
    severity: Option<String>,
    // optional baseline response info — may be hand-filled after initial discovery
    original_status: Option<u16>,
    original_body_hash: Option<String>,
    original_body_len: Option<usize>,
}

// Full replay run output written to disk
#[derive(Serialize)]
struct ReplayReport {
    engagement: String,
    finding: String,
    replayed_at: String,
    total_commands: usize,
    results: Vec<replay::ReplayResult>,
    overall_verdict: String,
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng_root = Path::new(&args.engagements_dir).join(&args.engagement);
    let eng = Engagement::load(&eng_root)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // resolve the finding file: by direct path or by searching findings/ for matching ID prefix
    let finding_path = resolve_finding_path(&eng.findings_dir(), &args.finding)?;
    eprintln!("mg-replay: {}", finding_path.display());

    let markdown = std::fs::read_to_string(&finding_path)
        .with_context(|| format!("read {}", finding_path.display()))?;

    // parse optional baseline metadata from the frontmatter block
    let meta = parse_frontmatter(&markdown);
    let baseline = meta.original_status.map(|status| OriginalBaseline {
        status,
        body_hash: meta.original_body_hash.clone(),
        body_len: meta.original_body_len,
    });

    if let Some(b) = &baseline {
        eprintln!("  baseline: status={}", b.status);
    } else {
        eprintln!("  no baseline in frontmatter — verdict will be heuristic");
    }

    // extract curl commands from the Evidence section
    let curl_commands = parse::extract_curl_commands(&markdown);
    if curl_commands.is_empty() {
        anyhow::bail!("no curl commands found in ## Evidence section of {}", finding_path.display());
    }
    eprintln!("  {} curl command(s) to replay", curl_commands.len());

    // build the HTTP client; honor the --insecure flag from the finding if set
    let client = replay::build_client(args.timeout_ms, args.insecure).context("build client")?;

    let mut results = Vec::new();

    // replay each curl command and collect results
    for cmd in &curl_commands {
        let req = match parse::parse_curl(cmd) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [parse err] {e}");
                continue;
            }
        };

        eprintln!("  → {} {}", req.method, req.url);
        let use_insecure = args.insecure || req.insecure;

        // rebuild client with the request-level insecure flag if needed
        let client_for_req = if use_insecure != args.insecure {
            replay::build_client(args.timeout_ms, use_insecure)?
        } else {
            client.clone()
        };

        let result = replay::replay(&client_for_req, &req, baseline.as_ref()).await
            .unwrap_or_else(|e| {
                eprintln!("  [replay err] {e}");
                replay::ReplayResult {
                    url: req.url.clone(),
                    method: req.method.clone(),
                    original_status: baseline.as_ref().map(|b| b.status),
                    replay_status: 0,
                    body_len: 0,
                    body_hash: String::new(),
                    elapsed_ms: 0,
                    verdict: Verdict::Indeterminate,
                    notes: vec![format!("request error: {e}")],
                }
            });

        // print per-request summary
        eprintln!("    {} → {:?}", result.replay_status, result.verdict);
        for note in &result.notes {
            eprintln!("    note: {note}");
        }

        results.push(result);
    }

    // compute overall verdict: worst-case across all replays
    let overall = if results.iter().any(|r| r.verdict == Verdict::StillVulnerable) {
        "still_vulnerable"
    } else if results.iter().all(|r| r.verdict == Verdict::AppearsFixed) {
        "appears_fixed"
    } else {
        "indeterminate"
    };

    eprintln!("  overall verdict: {overall}");

    // write the replay report to findings/
    let ts = OffsetDateTime::now_utc().format(&Rfc3339).context("format timestamp")?;
    let finding_stem = finding_path.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("finding");
    let report_name = format!("{finding_stem}-replay-{}.json", &ts[..10]);
    let report_path = eng.findings_dir().join(&report_name);

    let report = ReplayReport {
        engagement: args.engagement.clone(),
        finding: finding_stem.to_string(),
        replayed_at: ts,
        total_commands: curl_commands.len(),
        results,
        overall_verdict: overall.to_string(),
    };
    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    std::fs::write(&report_path, json).context("write report")?;

    // audit log entry
    let _ = eng.audit(
        "mg-replay",
        finding_stem,
        Some(&format!("verdict={overall} cmds={}", curl_commands.len())),
    );

    eprintln!("  written: {}", report_path.display());
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Resolve the finding path: direct file path or search findings/ by ID prefix
fn resolve_finding_path(findings_dir: &Path, id_or_path: &str) -> Result<std::path::PathBuf> {
    let direct = Path::new(id_or_path);
    if direct.exists() { return Ok(direct.to_path_buf()); }

    // search findings/ for a file whose name starts with the given prefix
    let entries = std::fs::read_dir(findings_dir)
        .with_context(|| format!("read {}", findings_dir.display()))?;

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with(id_or_path) && name_str.ends_with(".md") {
            return Ok(entry.path());
        }
    }

    anyhow::bail!("finding '{}' not found in {} or as a direct path", id_or_path, findings_dir.display())
}

// Extract YAML-ish frontmatter between --- delimiters and parse known fields
fn parse_frontmatter(markdown: &str) -> FindingMeta {
    let mut lines = markdown.lines();
    if lines.next().map(str::trim) != Some("---") {
        return FindingMeta::default();
    }

    let mut meta = FindingMeta::default();
    for line in lines {
        if line.trim() == "---" { break; }
        // parse simple "key: value" pairs
        if let Some(colon) = line.find(':') {
            let key = line[..colon].trim();
            let val = line[colon + 1..].trim().to_string();
            match key {
                "title"              => meta.title = Some(val),
                "severity"           => meta.severity = Some(val),
                "original_status"    => meta.original_status = val.parse().ok(),
                "original_body_hash" => meta.original_body_hash = Some(val),
                "original_body_len"  => meta.original_body_len = val.parse().ok(),
                _ => {}
            }
        }
    }
    meta
}
