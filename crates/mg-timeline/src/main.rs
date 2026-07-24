/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-timeline — chronological activity timeline for an engagement.
 *                  Walks the engagement workspace, reads JSON file timestamps
 *                  and content, and produces a sorted timeline of tool runs
 *                  and findings.
 * Notes:           Uses file mtime as the primary timestamp; falls back to a
 *                  "timestamp" field inside the JSON if present.
 *                  Output written to engagements/<name>/timeline/timeline-<ts>.<ext>.
 *******************************************************************/

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use walkdir::WalkDir;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const TIMELINE_SUBDIR: &str = "timeline";
const TIMELINE_FILE_PREFIX: &str = "timeline-";
const AUDIT_TOOL: &str = "mg-timeline";

// Directory names and the tool names we map them to
const DIR_TOOL_MAP: &[(&str, &str)] = &[
    ("recon", "mg-recon"),
    ("crawl", "mg-crawl"),
    ("findings", "finding"),
    ("xss", "mg-xss"),
    ("sqli", "mg-sqli"),
    ("ssrf", "mg-ssrf"),
    ("ssti", "mg-ssti"),
    ("takeover", "mg-takeover"),
    ("tls-scan", "mg-tls-scan"),
    ("dns-enum", "mg-dns-enum"),
    ("vhost", "mg-vhost"),
    ("openapi", "mg-openapi"),
    ("graphql", "mg-graphql"),
    ("jwt", "mg-jwt"),
    ("cors-exploit", "mg-cors-exploit"),
    ("redirect", "mg-redirect"),
    ("csrf", "mg-csrf"),
    ("smuggle", "mg-smuggle"),
    ("xxe", "mg-xxe"),
    ("traversal", "mg-traversal"),
    ("oauth", "mg-oauth"),
    ("authz", "mg-authz"),
    ("cmdinject", "mg-cmdinject"),
    ("aws", "mg-aws"),
    ("cloud-enum", "mg-cloud-enum"),
    ("github", "mg-github"),
    ("shodan", "mg-shodan"),
    ("nuclei", "mg-nuclei-bridge"),
    ("diff", "mg-diff"),
    ("traffic", "mg-replay"),
    ("notify", "mg-notify"),
    ("timeline", "mg-timeline"),
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-timeline",
    about = "Engagement activity timeline — chronological view of all tool runs and findings"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Output format
    #[arg(long, default_value = "markdown")]
    output_format: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Markdown,
    Text,
    Json,
}

// ── Event types ───────────────────────────────────────────────────────────────

// One timeline event derived from a single file in the engagement workspace
#[derive(Debug, Serialize)]
struct TimelineEvent {
    // Unix timestamp seconds for sorting; stored as i64 for serde
    #[serde(skip)]
    unix_secs: i64,
    timestamp: String,
    tool: String,
    summary: String,
    path: String,
}

// Best-effort schema for extracting metadata from any engagement JSON file
#[derive(Debug, Deserialize, Default)]
struct AnyJson {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    // Array length hints — treat either field as item count source
    #[serde(default)]
    hosts: Option<serde_json::Value>,
    #[serde(default)]
    results: Option<serde_json::Value>,
    #[serde(default)]
    findings: Option<serde_json::Value>,
    #[serde(default)]
    endpoints: Option<serde_json::Value>,
}

// ── Tool name resolution ─────────────────────────────────────────────────────

// Derive a tool name from the parent directory of a file
fn tool_from_parent(path: &Path, engagement_root: &Path) -> String {
    // Walk up to find the first component after the engagement root
    let rel = path.strip_prefix(engagement_root).unwrap_or(path);
    let first_component = rel
        .components()
        .next()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".into());

    for (dir, tool) in DIR_TOOL_MAP {
        if first_component == *dir {
            return tool.to_string();
        }
    }
    first_component
}

// ── Summary extraction ────────────────────────────────────────────────────────

// Build a human-readable summary string from a parsed JSON file and its tool
fn extract_summary(parsed: &AnyJson, tool: &str, raw: &str) -> String {
    // Finding files have title + severity
    if let (Some(title), Some(severity)) = (&parsed.title, &parsed.severity) {
        return format!("[{severity}] {title}");
    }
    if let Some(title) = &parsed.title {
        return title.clone();
    }

    // Count items for scan output files
    let count = count_json_items(parsed, raw);
    if count > 0 {
        return format!("{tool} — {count} items");
    }

    tool.to_string()
}

// Extract item count from known array fields or the raw JSON if it is a bare array
fn count_json_items(parsed: &AnyJson, raw: &str) -> usize {
    if let Some(v) = &parsed.hosts
        && let Some(arr) = v.as_array()
    {
        return arr.len();
    }
    if let Some(v) = &parsed.results
        && let Some(arr) = v.as_array()
    {
        return arr.len();
    }
    if let Some(v) = &parsed.findings
        && let Some(arr) = v.as_array()
    {
        return arr.len();
    }
    if let Some(v) = &parsed.endpoints
        && let Some(arr) = v.as_array()
    {
        return arr.len();
    }
    // Try bare array
    if let Ok(arr) = serde_json::from_str::<serde_json::Value>(raw)
        && let Some(arr) = arr.as_array()
    {
        return arr.len();
    }
    0
}

// ── Timestamp parsing ─────────────────────────────────────────────────────────

// Parse an RFC 3339 timestamp string to unix seconds
fn parse_rfc3339_unix(s: &str) -> Option<i64> {
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

// Read file mtime as unix seconds
fn mtime_unix(path: &Path) -> Option<i64> {
    fs::metadata(path).ok().and_then(|m| {
        m.modified().ok().and_then(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        })
    })
}

// Format unix seconds as "YYYY-MM-DD HH:MM" UTC
fn format_unix_utc(unix_secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_secs)
        .ok()
        .and_then(|dt| {
            let fmt =
                time::format_description::parse("[year]-[month]-[day] [hour]:[minute]").ok()?;
            dt.format(&fmt).ok()
        })
        .unwrap_or_else(|| unix_secs.to_string())
}

// ── Walker ────────────────────────────────────────────────────────────────────

// Walk the engagement root and build timeline events from all JSON files
fn collect_events(eng: &Engagement) -> Result<Vec<TimelineEvent>> {
    let mut events = Vec::new();

    for entry in WalkDir::new(&eng.root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        // Skip engagement.json and scope.json — not tool output
        let fname = path.file_name().unwrap_or_default().to_string_lossy();
        if fname == "engagement.json" || fname == "scope.json" || fname == "state.json" {
            continue;
        }

        let raw = match fs::read_to_string(path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let parsed: AnyJson = serde_json::from_str(&raw).unwrap_or_default();

        // Prefer embedded timestamp, fall back to mtime
        let unix_secs = parsed
            .timestamp
            .as_deref()
            .and_then(parse_rfc3339_unix)
            .or_else(|| mtime_unix(path))
            .unwrap_or(0);

        let timestamp = format_unix_utc(unix_secs);
        let tool = tool_from_parent(path, &eng.root);
        let summary = extract_summary(&parsed, &tool, &raw);

        events.push(TimelineEvent {
            unix_secs,
            timestamp,
            tool,
            summary,
            path: path.display().to_string(),
        });
    }

    events.sort_by_key(|e| e.unix_secs);
    Ok(events)
}

// ── Output rendering ──────────────────────────────────────────────────────────

// Render events as a Markdown timeline string
fn render_markdown(events: &[TimelineEvent]) -> String {
    let mut out = String::from("# Engagement Timeline\n\n");
    for e in events {
        out.push_str(&format!(
            "## {}\n**{}** — {}\n\n",
            e.timestamp, e.tool, e.summary
        ));
    }
    out
}

// Render events as plain text
fn render_text(events: &[TimelineEvent]) -> String {
    events
        .iter()
        .map(|e| format!("[{}] {} — {}", e.timestamp, e.tool, e.summary))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let events = collect_events(&eng).context("collect events")?;

    // Determine output content and file extension
    let (content, ext) = match args.output_format {
        OutputFormat::Markdown => (render_markdown(&events), "md"),
        OutputFormat::Text => (render_text(&events), "txt"),
        OutputFormat::Json => (
            serde_json::to_string_pretty(&events).context("serialize events")?,
            "json",
        ),
    };

    // Print to stdout
    println!("{content}");

    // Write to timeline/ subdir
    let timeline_dir = eng.root.join(TIMELINE_SUBDIR);
    fs::create_dir_all(&timeline_dir).context("create timeline dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_safe = ts.replace(':', "-");
    let out_path = timeline_dir.join(format!("{TIMELINE_FILE_PREFIX}{ts_safe}.{ext}"));
    fs::write(&out_path, &content).context("write timeline file")?;

    eprintln!(
        "mg-timeline: {} events written to {}",
        events.len(),
        out_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!("events={}", events.len())),
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
        let p = std::env::temp_dir().join(format!("mg-timeline-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn tool_from_parent_maps_known_dirs() {
        let root = PathBuf::from("/eng/acme");
        let path = root.join("recon").join("summary.json");
        assert_eq!(tool_from_parent(&path, &root), "mg-recon");

        let path2 = root.join("findings").join("xss-001.json");
        assert_eq!(tool_from_parent(&path2, &root), "finding");
    }

    #[test]
    fn tool_from_parent_returns_dir_name_for_unknown() {
        let root = PathBuf::from("/eng/acme");
        let path = root.join("custom-tool").join("out.json");
        assert_eq!(tool_from_parent(&path, &root), "custom-tool");
    }

    #[test]
    fn extract_summary_uses_title_and_severity_for_findings() {
        let parsed = AnyJson {
            title: Some("Reflected XSS".into()),
            severity: Some("high".into()),
            ..Default::default()
        };
        let summary = extract_summary(&parsed, "finding", "{}");
        assert_eq!(summary, "[high] Reflected XSS");
    }

    #[test]
    fn extract_summary_counts_bare_array() {
        let raw = serde_json::json!([{"hostname":"a"},{"hostname":"b"}]).to_string();
        let parsed = AnyJson::default();
        let summary = extract_summary(&parsed, "mg-recon", &raw);
        assert!(summary.contains("2 items"), "got: {summary}");
    }

    #[test]
    fn format_unix_utc_produces_readable_date() {
        // 2026-01-01T00:00:00Z = 1767225600 (UTC calendar epoch)
        let s = format_unix_utc(1_767_225_600);
        assert_eq!(s, "2026-01-01 00:00");
    }

    #[test]
    fn collect_events_finds_json_files() {
        let t = tmp();
        let eng_dir = t.join("acme");
        fs::create_dir_all(eng_dir.join("findings")).unwrap();
        // Write minimal engagement.json so Engagement::load works
        let meta = serde_json::json!({
            "name": "acme",
            "target": "acme.test",
            "created_at": "2026-01-01T00:00:00Z"
        });
        fs::write(
            eng_dir.join("engagement.json"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
        fs::write(
            eng_dir.join("scope.json"),
            serde_json::json!({"allow":["acme.test"],"deny":[]}).to_string(),
        )
        .unwrap();

        // Write a finding file
        let finding = serde_json::json!({"title":"Test XSS","severity":"high","url":"https://acme.test/search"});
        fs::write(
            eng_dir.join("findings").join("xss-001.json"),
            serde_json::to_string(&finding).unwrap(),
        )
        .unwrap();

        let eng = Engagement::load(&eng_dir).unwrap();
        let events = collect_events(&eng).unwrap();
        assert!(!events.is_empty());
        assert!(events.iter().any(|e| e.tool == "finding"));
    }
}
