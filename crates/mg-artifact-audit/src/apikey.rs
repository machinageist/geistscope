/*******************************************************************
 * Filename:        apikey.rs
 * Author:          Jeff
 * Date:            2026-05-22
 * Description:     API key extraction from crawl corpus
 * Notes:           Ported from mg-apikey; logic unchanged.
 *                  Regex catalog compiled once via OnceLock.
 *                  Findings de-duplicated by (pattern_type, masked_value).
 *                  No active HTTP — purely filesystem analysis.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "apikey";
const AUDIT_TOOL: &str = "mg-apikey";
const MASK_KEEP_CHARS: usize = 8;
const LEAK_HEADERS: &[&str] = &["x-api-key", "authorization", "api-key", "x-auth-token"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
pub struct Args {
    pub engagement: String,
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    pub engagements_dir: String,
    #[arg(long, default_value_t = 5)]
    pub concurrency: usize,
    #[arg(long, default_value_t = 15)]
    pub timeout: u64,
}

// ── Regex catalog ────────────────────────────────────────────────────────────

struct KeyPattern {
    name: &'static str,
    re: Regex,
    group: usize,
}

static CATALOG: OnceLock<Vec<KeyPattern>> = OnceLock::new();

fn catalog() -> &'static Vec<KeyPattern> {
    CATALOG.get_or_init(|| {
        vec![
            KeyPattern { name: "AWS Access Key", re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), group: 0 },
            KeyPattern { name: "Google API Key", re: Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap(), group: 0 },
            KeyPattern { name: "GitHub Token", re: Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap(), group: 0 },
            KeyPattern { name: "Stripe Key", re: Regex::new(r"sk_(live|test)_[A-Za-z0-9]{24,}").unwrap(), group: 0 },
            KeyPattern { name: "Slack Token", re: Regex::new(r"xox[baprs]-[0-9A-Za-z\-]{10,48}").unwrap(), group: 0 },
            KeyPattern { name: "Twilio Key", re: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(), group: 0 },
            KeyPattern { name: "SendGrid Key", re: Regex::new(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}").unwrap(), group: 0 },
            KeyPattern { name: "Mailgun Key", re: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(), group: 0 },
            KeyPattern { name: "PagerDuty Key", re: Regex::new(r"[ru][0-9a-zA-Z_\-]{18}").unwrap(), group: 0 },
            KeyPattern { name: "Bearer Token", re: Regex::new(r"[Bb]earer\s+([A-Za-z0-9\-_\.]{20,})").unwrap(), group: 1 },
            KeyPattern {
                name: "Generic Secret",
                re: Regex::new(
                    r#"(?i)(?:secret|api_key|apikey|access_key|auth_token|private_key)\s*[=:]\s*['"]([A-Za-z0-9\-_\.]{16,})['"]"#,
                ).unwrap(),
                group: 1,
            },
        ]
    })
}

// ── Data types ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, PartialEq, Eq, Hash)]
struct RawFinding {
    key_type: String,
    masked: String,
}

#[derive(Debug, Serialize)]
struct KeyFinding {
    key_type: String,
    masked_value: String,
    source_file: String,
}

#[derive(Serialize)]
struct ApiKeyResults {
    engagement: String,
    timestamp: String,
    files_scanned: usize,
    findings_count: usize,
    findings: Vec<KeyFinding>,
}

#[derive(Deserialize)]
struct CrawlEntry {
    #[serde(default)]
    headers: serde_json::Value,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| "unknown".into())
}

fn ts_for_filename(ts: &str) -> String {
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
}

fn mask_key(value: &str) -> String {
    let prefix: String = value.chars().take(MASK_KEEP_CHARS).collect();
    format!("{prefix}...")
}

fn scan_text(text: &str) -> Vec<(&'static str, String)> {
    let mut hits = Vec::new();
    for pattern in catalog() {
        for caps in pattern.re.captures_iter(text) {
            let value = if pattern.group == 0 {
                caps.get(0).map(|m| m.as_str().to_string())
            } else {
                caps.get(pattern.group).map(|m| m.as_str().to_string())
            };
            if let Some(v) = value
                && v.len() >= 16
            {
                hits.push((pattern.name, v));
            }
        }
    }
    hits
}

fn scan_headers(headers: &serde_json::Value, source: &str) -> Vec<KeyFinding> {
    let mut findings = Vec::new();
    let obj = match headers.as_object() {
        Some(o) => o,
        None => return findings,
    };
    for (key, val) in obj {
        let key_lower = key.to_lowercase();
        if LEAK_HEADERS.iter().any(|h| key_lower == *h)
            && let Some(val_str) = val.as_str()
            && val_str.len() >= 8
        {
            findings.push(KeyFinding {
                key_type: format!("Header:{key}"),
                masked_value: mask_key(val_str),
                source_file: source.into(),
            });
        }
    }
    findings
}

fn collect_files(dir: &Path, exts: &[&str]) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return files;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_files(&path, exts));
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && exts.contains(&ext)
        {
            files.push(path);
        }
    }
    files
}

fn dedup_hits(
    hits: Vec<(&'static str, String)>,
    source: &str,
    seen: &mut HashSet<RawFinding>,
    findings: &mut Vec<KeyFinding>,
) {
    for (key_type, value) in hits {
        let masked = mask_key(&value);
        let raw = RawFinding {
            key_type: key_type.to_string(),
            masked: masked.clone(),
        };
        if seen.insert(raw) {
            findings.push(KeyFinding {
                key_type: key_type.to_string(),
                masked_value: masked,
                source_file: source.to_string(),
            });
        }
    }
}

fn scan_index_headers(crawl_dir: &Path, findings: &mut Vec<KeyFinding>) {
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return;
    };
    for entry in hosts.flatten() {
        let index_path = entry.path().join("index.json");
        if !index_path.exists() {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(entries): Result<Vec<CrawlEntry>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        let source = index_path.display().to_string();
        for entry in entries {
            let mut hdr_findings = scan_headers(&entry.headers, &source);
            findings.append(&mut hdr_findings);
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub async fn run(args: Args) -> Result<()> {
    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let crawl_dir = eng.crawl_dir();
    if !crawl_dir.exists() {
        anyhow::bail!("crawl directory not found — run `mg-crawl {}` first", args.engagement);
    }

    let scan_files = collect_files(&crawl_dir, &["html", "js", "json"]);
    eprintln!("mg-apikey: {} files to scan", scan_files.len());

    let _ = catalog();

    let mut all_findings: Vec<KeyFinding> = Vec::new();
    let mut seen: HashSet<RawFinding> = HashSet::new();
    let mut files_scanned: usize = 0;

    struct ScanResult {
        source: String,
        hits: Vec<(&'static str, String)>,
    }

    let mut join_set: JoinSet<ScanResult> = JoinSet::new();

    for file_path in scan_files {
        while join_set.len() >= args.concurrency {
            if let Some(Ok(r)) = join_set.join_next().await {
                dedup_hits(r.hits, &r.source, &mut seen, &mut all_findings);
            }
        }
        join_set.spawn(async move {
            let source = file_path.display().to_string();
            let text = fs::read_to_string(&file_path).unwrap_or_default();
            let hits = scan_text(&text);
            ScanResult { source, hits }
        });
        files_scanned += 1;
    }

    while let Some(Ok(r)) = join_set.join_next().await {
        dedup_hits(r.hits, &r.source, &mut seen, &mut all_findings);
    }

    let mut index_findings: Vec<KeyFinding> = Vec::new();
    scan_index_headers(&crawl_dir, &mut index_findings);
    all_findings.extend(index_findings);

    eprintln!("mg-apikey: {} files scanned, {} findings", files_scanned, all_findings.len());
    for f in &all_findings {
        eprintln!("  [{}] {} — {}", f.key_type, f.masked_value, f.source_file);
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = ApiKeyResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        files_scanned,
        findings_count: all_findings.len(),
        findings: all_findings,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create apikey output dir")?;
    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(&results_path, serde_json::to_string_pretty(&output).unwrap_or_default())
        .context("write apikey results")?;

    eprintln!("mg-apikey: findings={} — {}", output.findings_count, results_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!("files={} findings={} ts={ts}", output.files_scanned, output.findings_count)),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_key_keeps_first_eight_chars() {
        assert_eq!(mask_key("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSF...");
    }

    #[test]
    fn mask_key_short_value_keeps_all() {
        assert_eq!(mask_key("SHORT"), "SHORT...");
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T09:15:00Z"), "2026-05-18T09_15_00Z");
    }

    #[test]
    fn scan_text_finds_aws_key() {
        let text = "config.key = 'AKIAIOSFODNN7EXAMPLE123456';";
        let hits = scan_text(text);
        assert!(hits.iter().any(|(t, _)| *t == "AWS Access Key"));
    }

    #[test]
    fn scan_text_finds_google_api_key() {
        let text = "apiKey: 'AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE'";
        let hits = scan_text(text);
        assert!(hits.iter().any(|(t, _)| *t == "Google API Key"));
    }

    #[test]
    fn scan_text_finds_generic_secret() {
        let text = r#"api_key = 'supersecretvalue12345'"#;
        let hits = scan_text(text);
        assert!(hits.iter().any(|(t, _)| *t == "Generic Secret"));
    }

    #[test]
    fn scan_text_finds_bearer_token() {
        let text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abc";
        let hits = scan_text(text);
        assert!(hits.iter().any(|(t, _)| *t == "Bearer Token"));
    }

    #[test]
    fn scan_text_returns_empty_on_clean_content() {
        let text = "<html><body>Hello World</body></html>";
        let hits = scan_text(text);
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_headers_flags_authorization_header() {
        let headers = serde_json::json!({"Authorization": "Bearer sometoken12345"});
        let findings = scan_headers(&headers, "test/index.json");
        assert!(!findings.is_empty());
        assert!(findings[0].key_type.contains("Authorization"));
    }

    #[test]
    fn scan_headers_ignores_short_values() {
        let headers = serde_json::json!({"x-api-key": "short"});
        let findings = scan_headers(&headers, "test/index.json");
        assert!(findings.is_empty());
    }

    #[test]
    fn dedup_hits_prevents_duplicate_findings() {
        let mut seen = HashSet::new();
        let mut findings = Vec::new();
        let hits = vec![("AWS Access Key", "AKIAIOSFODNN7EXAMPLE123456".to_string())];
        let hits2 = vec![("AWS Access Key", "AKIAIOSFODNN7EXAMPLE123456".to_string())];
        dedup_hits(hits, "file1.js", &mut seen, &mut findings);
        dedup_hits(hits2, "file2.js", &mut seen, &mut findings);
        assert_eq!(findings.len(), 1);
    }
}
