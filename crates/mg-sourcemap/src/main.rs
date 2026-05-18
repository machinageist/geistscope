/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-sourcemap — source map downloader and analyzer
 *                  Finds .js.map URLs from js-analyze findings, crawl HTML,
 *                  and .map suffix probes; downloads, extracts source paths
 *                  and embedded source content; scans for secrets and
 *                  internal paths.
 * Notes:           sourcesContent[] may be absent in maps — handled gracefully.
 *                  Source files are written to sourcemap/sources/<sanitized>.
 *                  Secret values are masked to first 8 chars before writing.
 *******************************************************************/

use std::collections::HashSet;
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

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "sourcemap";
const SOURCES_SUBDIR: &str = "sources";
const AUDIT_TOOL: &str = "mg-sourcemap";
const SECRET_MASK_LEN: usize = 8;

// Path substrings that flag an internal-looking source path
const INTERNAL_PATH_KEYWORDS: &[&str] = &[
    "internal", "private", "secret", "config", "admin", "auth", "password",
];

// ── Regex patterns (compiled once) ───────────────────────────────────────────

// Compile and return the AWS access key pattern
fn re_aws_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"AKIA[0-9A-Z]{16}").unwrap())
}

// Compile and return the generic API key pattern
fn re_api_key() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"[Aa][Pp][Ii][_\-]?[Kk]ey['":\s=]+['"]([A-Za-z0-9\-_]{20,})['"]"#).unwrap()
    })
}

// Compile and return the hardcoded password pattern
fn re_password() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"[Pp]assword['":\s=]+['"]([^'"]{6,})['"]"#).unwrap()
    })
}

// Compile and return the JWT token pattern
fn re_jwt() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]*").unwrap()
    })
}

// Compile and return the sourceMappingURL comment pattern
fn re_source_map_comment() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"//[#@]\s*sourceMappingURL=(\S+)").unwrap()
    })
}

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-sourcemap",
    about = "Source map analyzer — extracts source files and scans for secrets"
)]
struct Args {
    /// Engagement name (must have engagement.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent downloads
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// A finding from js-analyze that references a source map
#[derive(Deserialize)]
struct JsAnalyzeFinding {
    #[serde(rename = "type")]
    finding_type: String,
    value: String,
}

// js-analyze results file shape
#[derive(Deserialize)]
struct JsAnalyzeResults {
    #[serde(default)]
    findings: Vec<JsAnalyzeFinding>,
}

// A parsed source map JSON file
#[derive(Deserialize)]
struct SourceMap {
    #[serde(default)]
    sources: Vec<String>,
    #[serde(rename = "sourcesContent", default)]
    sources_content: Vec<Option<String>>,
}

// One secret found in source content
#[derive(Debug, Serialize)]
struct SecretFinding {
    source_path: String,
    kind: String,
    value_preview: String,
}

// One internal path flagged
#[derive(Debug, Serialize)]
struct InternalPathFinding {
    source_path: String,
    matched_keyword: String,
}

// Result for one downloaded source map
#[derive(Debug, Serialize)]
struct MapResult {
    map_url: String,
    sources_count: usize,
    sources_content_count: usize,
    internal_paths: Vec<InternalPathFinding>,
    secrets: Vec<SecretFinding>,
    sources_written: Vec<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SourcemapResults {
    engagement: String,
    timestamp: String,
    maps_downloaded: usize,
    total_secrets: usize,
    total_internal_paths: usize,
    results: Vec<MapResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Sanitize a source path for use as a filesystem component
// Replaces path separators and special characters that are unsafe on disk
fn sanitize_source_path(path: &str) -> String {
    path.chars()
        .map(|c| match c {
            '/' | '\\' => '_',
            ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c => c,
        })
        .collect()
}

// Mask a secret value to first SECRET_MASK_LEN chars + "..."
fn mask_secret(value: &str) -> String {
    if value.len() <= SECRET_MASK_LEN {
        return "*".repeat(value.len());
    }
    format!("{}...", &value[..SECRET_MASK_LEN])
}

// Check a source path string for internal-looking keywords
fn flag_internal_paths(source_path: &str) -> Vec<InternalPathFinding> {
    let lower = source_path.to_lowercase();
    INTERNAL_PATH_KEYWORDS
        .iter()
        .filter(|&&kw| lower.contains(kw))
        .map(|&kw| InternalPathFinding {
            source_path: source_path.to_string(),
            matched_keyword: kw.to_string(),
        })
        .collect()
}

// Scan source content for secrets using compiled regexes
fn scan_for_secrets(source_path: &str, content: &str) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    for m in re_aws_key().find_iter(content) {
        findings.push(SecretFinding {
            source_path: source_path.to_string(),
            kind: "aws-key".into(),
            value_preview: mask_secret(m.as_str()),
        });
    }

    for cap in re_api_key().captures_iter(content) {
        if let Some(val) = cap.get(1) {
            findings.push(SecretFinding {
                source_path: source_path.to_string(),
                kind: "api-key".into(),
                value_preview: mask_secret(val.as_str()),
            });
        }
    }

    for cap in re_password().captures_iter(content) {
        if let Some(val) = cap.get(1) {
            findings.push(SecretFinding {
                source_path: source_path.to_string(),
                kind: "password".into(),
                value_preview: mask_secret(val.as_str()),
            });
        }
    }

    for m in re_jwt().find_iter(content) {
        findings.push(SecretFinding {
            source_path: source_path.to_string(),
            kind: "jwt".into(),
            value_preview: mask_secret(m.as_str()),
        });
    }

    findings
}

// Collect source map URLs from js-analyze results files
fn collect_from_js_analyze(js_analyze_dir: &Path) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok(entries) = fs::read_dir(js_analyze_dir) else {
        return urls;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !name.starts_with("results-") || !name.ends_with(".json") {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(results): Result<JsAnalyzeResults, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for f in results.findings {
            if f.finding_type == "source_map" && f.value.starts_with("http") {
                urls.push(f.value);
            }
        }
    }
    urls
}

// Collect source map URLs referenced in crawl HTML/JS via sourceMappingURL comments
fn collect_from_crawl(crawl_dir: &Path) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return urls;
    };
    for host_entry in hosts.flatten() {
        if !host_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let js_dir = host_entry.path().join("js");
        let html_dir = host_entry.path().join("html");
        for dir in [&js_dir, &html_dir] {
            let Ok(files) = fs::read_dir(dir) else {
                continue;
            };
            for file in files.flatten() {
                let Ok(content) = fs::read_to_string(file.path()) else {
                    continue;
                };
                for cap in re_source_map_comment().captures_iter(&content) {
                    if let Some(url) = cap.get(1) {
                        let u = url.as_str();
                        if u.starts_with("http") {
                            urls.push(u.to_string());
                        }
                    }
                }
            }
        }
    }
    urls
}

// Collect source map URL candidates by appending .map to JS URLs from crawl corpus
fn collect_map_probes(crawl_dir: &Path) -> Vec<String> {
    let mut candidates = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return candidates;
    };
    for host_entry in hosts.flatten() {
        if !host_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        let index_path = host_entry.path().join("index.json");
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(entries): Result<Vec<serde_json::Value>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        for entry in entries {
            if let Some(url) = entry.get("url").and_then(|u| u.as_str())
                && url.ends_with(".js")
            {
                candidates.push(format!("{url}.map"));
            }
        }
    }
    candidates
}

// Download and analyze one source map URL
async fn process_map(
    client: reqwest::Client,
    map_url: String,
    sources_dir: std::path::PathBuf,
) -> MapResult {
    let mut result = MapResult {
        map_url: map_url.clone(),
        sources_count: 0,
        sources_content_count: 0,
        internal_paths: Vec::new(),
        secrets: Vec::new(),
        sources_written: Vec::new(),
    };

    let Ok(resp) = client.get(&map_url).send().await else {
        return result;
    };

    if !resp.status().is_success() {
        return result;
    }

    let Ok(body) = resp.text().await else {
        return result;
    };

    let Ok(map): Result<SourceMap, _> = serde_json::from_str(&body) else {
        return result;
    };

    result.sources_count = map.sources.len();
    result.sources_content_count = map.sources_content.iter().filter(|c| c.is_some()).count();

    // Flag internal-looking source paths
    for src_path in &map.sources {
        result.internal_paths.extend(flag_internal_paths(src_path));
    }

    // Scan sourcesContent for secrets and write to disk
    for (i, content_opt) in map.sources_content.iter().enumerate() {
        let Some(content) = content_opt else { continue };
        let src_path = map.sources.get(i).map(|s| s.as_str()).unwrap_or("unknown");

        // Scan for secrets
        result.secrets.extend(scan_for_secrets(src_path, content));

        // Write source file to disk
        let safe_name = sanitize_source_path(src_path);
        let dest = sources_dir.join(&safe_name);
        if let Ok(()) = fs::write(&dest, content) {
            result.sources_written.push(safe_name);
        }
    }

    result
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .default_headers(auth_headers)
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Collect map URLs from all three sources
    let mut map_urls: Vec<String> = Vec::new();
    map_urls.extend(collect_from_js_analyze(&eng.root.join("js-analyze")));
    map_urls.extend(collect_from_crawl(&eng.crawl_dir()));
    map_urls.extend(collect_map_probes(&eng.crawl_dir()));

    // Deduplicate
    let mut seen: HashSet<String> = HashSet::new();
    map_urls.retain(|u| seen.insert(u.clone()));

    if map_urls.is_empty() {
        eprintln!("mg-sourcemap: no source map URLs found — run mg-crawl / mg-js-analyze first");
        return Ok(());
    }

    eprintln!(
        "mg-sourcemap: {} map URLs, concurrency={}",
        map_urls.len(),
        args.concurrency
    );

    // Prepare output directories
    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    let sources_dir = output_dir.join(SOURCES_SUBDIR);
    fs::create_dir_all(&sources_dir).context("create sourcemap/sources dir")?;

    let mut join_set: JoinSet<MapResult> = JoinSet::new();
    let mut all_results: Vec<MapResult> = Vec::new();

    for url in map_urls {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            all_results.push(r);
        }
        let c = client.clone();
        let sd = sources_dir.clone();
        join_set.spawn(process_map(c, url, sd));
    }

    // Drain remaining
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let total_secrets: usize = all_results.iter().map(|r| r.secrets.len()).sum();
    let total_internal_paths: usize = all_results.iter().map(|r| r.internal_paths.len()).sum();

    for r in &all_results {
        if !r.secrets.is_empty() || !r.internal_paths.is_empty() {
            eprintln!("  [{}] secrets={} internal={}", r.map_url, r.secrets.len(), r.internal_paths.len());
        }
    }

    let output = SourcemapResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        maps_downloaded: all_results.len(),
        total_secrets,
        total_internal_paths,
        results: all_results,
    };

    let out_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write results JSON")?;

    eprintln!(
        "mg-sourcemap: {} maps, {} secrets, {} internal paths — {}",
        output.maps_downloaded,
        output.total_secrets,
        output.total_internal_paths,
        out_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "maps={} secrets={} internal={} ts={ts}",
            output.maps_downloaded, output.total_secrets, output.total_internal_paths
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T10:00:00Z"), "2026-05-18T10_00_00Z");
    }

    #[test]
    fn sanitize_source_path_replaces_separators() {
        assert_eq!(
            sanitize_source_path("src/internal/config.ts"),
            "src_internal_config.ts"
        );
        assert_eq!(
            sanitize_source_path("C:\\Users\\secret\\file.ts"),
            "C__Users_secret_file.ts"
        );
    }

    #[test]
    fn mask_secret_truncates_long_values() {
        assert_eq!(mask_secret("AKIAIOSFODNN7EXAMPLE"), "AKIAIOSF...");
        assert_eq!(mask_secret("short"), "*****");
    }

    #[test]
    fn flag_internal_paths_matches_keywords() {
        let findings = flag_internal_paths("src/internal/auth/config.ts");
        let keywords: Vec<_> = findings.iter().map(|f| f.matched_keyword.as_str()).collect();
        assert!(keywords.contains(&"internal"));
        assert!(keywords.contains(&"auth"));
        assert!(keywords.contains(&"config"));
    }

    #[test]
    fn scan_for_secrets_finds_aws_key() {
        let content = "const key = 'AKIAIOSFODNN7EXAMPLE';";
        let findings = scan_for_secrets("test.ts", content);
        assert!(findings.iter().any(|f| f.kind == "aws-key"));
    }

    #[test]
    fn scan_for_secrets_finds_jwt() {
        let content = "token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abcdefghij'";
        let findings = scan_for_secrets("test.ts", content);
        assert!(findings.iter().any(|f| f.kind == "jwt"));
    }

    #[test]
    fn collect_from_crawl_missing_dir_returns_empty() {
        let result = collect_from_crawl(Path::new("/tmp/mg_sm_no_such_dir_xyz"));
        assert!(result.is_empty());
    }
}
