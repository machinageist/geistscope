/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-metadata — document metadata extractor from crawl corpus.
 * Notes:           Downloads docs linked in crawl corpus (PDF, Office, JPEG).
 *                  Extracts author names, internal paths, and software versions
 *                  via raw byte scanning — no external metadata libraries.
 *                  DOCX/XLSX/PPTX are ZIP containers; we read docProps/core.xml.
 *                  JPEG EXIF is located by magic bytes `Exif\x00\x00`.
 *******************************************************************/

use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "metadata";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-metadata";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_CONCURRENCY: usize = 3;

// Document extensions we care about
const DOC_EXTENSIONS: &[&str] = &[
    ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".jpg", ".jpeg", ".png",
];

// Internal path patterns that suggest exposed filesystem layout
const INTERNAL_PATH_PATTERNS: &[&str] = &["C:\\", "/home/", "/Users/"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-metadata",
    about = "Extract metadata from documents found in the crawl corpus"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent downloads
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Flags extracted from a single document
#[derive(Debug, Serialize)]
struct DocFlags {
    authors: Vec<String>,
    internal_paths: Vec<String>,
    software_versions: Vec<String>,
}

// Result for one processed document
#[derive(Debug, Serialize)]
struct DocMetadata {
    url: String,
    doc_type: String,
    flags: DocFlags,
}

// Crawl index endpoint entry — minimal fields
#[derive(Debug, Deserialize)]
struct CrawlEndpoint {
    url: String,
}

// Crawl index file shape — url list may be under "endpoints" or "urls"
#[derive(Debug, Deserialize)]
struct CrawlIndex {
    #[serde(default)]
    endpoints: Vec<CrawlEndpoint>,
    #[serde(default)]
    urls: Vec<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct MetadataResults {
    engagement: String,
    timestamp: String,
    documents_checked: usize,
    documents_with_flags: usize,
    results: Vec<DocMetadata>,
}

// ── Crawl corpus helpers ──────────────────────────────────────────────────────

// Collect all document URLs from crawl directory JSON files
fn collect_doc_urls(crawl_dir: &Path) -> Vec<String> {
    let mut urls = Vec::new();
    if !crawl_dir.exists() {
        return urls;
    }

    // Walk host subdirs and read index.json files
    let Ok(entries) = fs::read_dir(crawl_dir) else {
        return urls;
    };

    for entry in entries.flatten() {
        let index_path = entry.path().join("index.json");
        if !index_path.exists() {
            continue;
        }
        let Ok(raw) = fs::read_to_string(&index_path) else {
            continue;
        };
        let Ok(index) = serde_json::from_str::<CrawlIndex>(&raw) else {
            continue;
        };

        // Collect from endpoints array
        for ep in &index.endpoints {
            if is_doc_url(&ep.url) {
                urls.push(ep.url.clone());
            }
        }
        // Collect from urls array (alternate schema)
        for u in &index.urls {
            if is_doc_url(u) {
                urls.push(u.clone());
            }
        }
    }

    urls.sort();
    urls.dedup();
    urls
}

// Return true if the URL path ends with a tracked extension
fn is_doc_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    DOC_EXTENSIONS.iter().any(|ext| lower.contains(ext))
}

// ── Metadata extraction ───────────────────────────────────────────────────────

// Extract metadata flags from raw document bytes
fn extract_flags(bytes: &[u8], doc_type: &str) -> DocFlags {
    match doc_type {
        "pdf" => extract_pdf_flags(bytes),
        "docx" | "xlsx" | "pptx" => extract_office_flags(bytes),
        "jpg" | "jpeg" => extract_jpeg_flags(bytes),
        _ => DocFlags {
            authors: Vec::new(),
            internal_paths: Vec::new(),
            software_versions: Vec::new(),
        },
    }
}

// Scan PDF bytes for metadata fields using simple pattern matching
fn extract_pdf_flags(bytes: &[u8]) -> DocFlags {
    let text = String::from_utf8_lossy(bytes);
    let mut authors = Vec::new();
    let mut internal_paths = Vec::new();
    let mut software_versions = Vec::new();

    // Extract value between '(' and ')' after each PDF metadata key
    for key in &["/Author (", "/Creator (", "/Producer (", "/Title ("] {
        if let Some(val) = extract_pdf_value(&text, key) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                match *key {
                    "/Author (" => authors.push(trimmed.clone()),
                    "/Creator (" | "/Producer (" => software_versions.push(trimmed.clone()),
                    _ => {}
                }
                // Check if value contains an internal path
                for pat in INTERNAL_PATH_PATTERNS {
                    if trimmed.contains(pat) {
                        internal_paths.push(trimmed.clone());
                        break;
                    }
                }
            }
        }
    }

    DocFlags {
        authors,
        internal_paths,
        software_versions,
    }
}

// Extract string between '(' and ')' after a PDF metadata key
fn extract_pdf_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let start = text.find(key)? + key.len();
    let rest = &text[start..];
    let end = rest.find(')')?;
    Some(&rest[..end])
}

// Open ZIP container and scan docProps/core.xml for Office metadata
fn extract_office_flags(bytes: &[u8]) -> DocFlags {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = match zip::ZipArchive::new(cursor) {
        Ok(a) => a,
        Err(_) => {
            return DocFlags {
                authors: Vec::new(),
                internal_paths: Vec::new(),
                software_versions: Vec::new(),
            };
        }
    };

    let xml = match archive.by_name("docProps/core.xml") {
        Ok(mut f) => {
            let mut buf = String::new();
            let _ = f.read_to_string(&mut buf);
            buf
        }
        Err(_) => String::new(),
    };

    let mut authors = Vec::new();
    let mut internal_paths = Vec::new();

    for (open_tag, close_tag) in &[
        ("<dc:creator>", "</dc:creator>"),
        ("<cp:lastModifiedBy>", "</cp:lastModifiedBy>"),
        ("<dc:title>", "</dc:title>"),
    ] {
        if let Some(val) = extract_xml_value(&xml, open_tag, close_tag) {
            let trimmed = val.trim().to_string();
            if !trimmed.is_empty() {
                authors.push(trimmed.clone());
                for pat in INTERNAL_PATH_PATTERNS {
                    if trimmed.contains(pat) {
                        internal_paths.push(trimmed.clone());
                        break;
                    }
                }
            }
        }
    }

    DocFlags {
        authors,
        internal_paths,
        software_versions: Vec::new(),
    }
}

// Extract text content between XML open and close tags
fn extract_xml_value<'a>(xml: &'a str, open: &str, close: &str) -> Option<&'a str> {
    let start = xml.find(open)? + open.len();
    let rest = &xml[start..];
    let end = rest.find(close)?;
    Some(&rest[..end])
}

// Scan JPEG bytes for EXIF magic and extract Make/Model strings
fn extract_jpeg_flags(bytes: &[u8]) -> DocFlags {
    const EXIF_MAGIC: &[u8] = b"Exif\x00\x00";
    let mut software_versions = Vec::new();

    // Find EXIF block
    if let Some(exif_start) = find_subsequence(bytes, EXIF_MAGIC) {
        let exif_block = &bytes[exif_start..];
        // Scan for printable ASCII strings of at least 4 chars (crude Make/Model heuristic)
        let mut current = Vec::new();
        for &b in exif_block.iter().take(4096) {
            if b.is_ascii_graphic() || b == b' ' {
                current.push(b);
            } else {
                if current.len() >= 4 {
                    let s = String::from_utf8_lossy(&current).trim().to_string();
                    if !s.is_empty() && s != "Exif" {
                        software_versions.push(s);
                    }
                }
                current.clear();
            }
        }
    }

    // Deduplicate
    software_versions.sort();
    software_versions.dedup();

    DocFlags {
        authors: Vec::new(),
        internal_paths: Vec::new(),
        software_versions,
    }
}

// Find byte subsequence within a slice; return starting index or None
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// Detect doc type from URL extension
fn doc_type_from_url(url: &str) -> &'static str {
    let lower = url.to_lowercase();
    if lower.contains(".pdf") {
        "pdf"
    } else if lower.contains(".docx") {
        "docx"
    } else if lower.contains(".xlsx") {
        "xlsx"
    } else if lower.contains(".pptx") {
        "pptx"
    } else if lower.contains(".doc") {
        "doc"
    } else if lower.contains(".xls") {
        "xls"
    } else if lower.contains(".jpeg") || lower.contains(".jpg") {
        "jpg"
    } else if lower.contains(".png") {
        "png"
    } else {
        "unknown"
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-metadata: collecting document URLs from crawl corpus");

    let doc_urls = collect_doc_urls(&eng.crawl_dir());
    eprintln!("  {} document URLs found", doc_urls.len());

    let auth_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-metadata/0.1")
        .default_headers(auth_headers)
        .build()
        .context("build HTTP client")?;

    // Download and extract metadata with bounded concurrency
    let mut join_set: JoinSet<Option<DocMetadata>> = JoinSet::new();
    let mut results: Vec<DocMetadata> = Vec::new();

    for url in doc_urls {
        // Drain when at concurrency ceiling
        while join_set.len() >= args.concurrency {
            if let Some(Ok(Some(meta))) = join_set.join_next().await {
                results.push(meta);
            }
        }

        let client = client.clone();
        let url_clone = url.clone();
        join_set.spawn(async move {
            let doc_type = doc_type_from_url(&url_clone);
            eprintln!("  downloading {} ({})", url_clone, doc_type);

            let bytes = match client.get(&url_clone).send().await {
                Ok(resp) if resp.status().is_success() => {
                    match resp.bytes().await {
                        Ok(b) => b.to_vec(),
                        Err(_) => return None,
                    }
                }
                _ => return None,
            };

            let flags = extract_flags(&bytes, doc_type);
            let has_flags = !flags.authors.is_empty()
                || !flags.internal_paths.is_empty()
                || !flags.software_versions.is_empty();

            if has_flags {
                Some(DocMetadata {
                    url: url_clone,
                    doc_type: doc_type.to_string(),
                    flags,
                })
            } else {
                None
            }
        });
    }

    // Drain remaining tasks
    while let Some(Ok(Some(meta))) = join_set.join_next().await {
        results.push(meta);
    }

    let total_checked = results.len();
    let with_flags = results.iter().filter(|r| {
        !r.flags.authors.is_empty()
            || !r.flags.internal_paths.is_empty()
            || !r.flags.software_versions.is_empty()
    }).count();

    eprintln!("  {} documents with flags", with_flags);

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create metadata output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = MetadataResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        documents_checked: total_checked,
        documents_with_flags: with_flags,
        results,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Emit findings for documents with secrets or internal path exposure
    for doc in &output.results {
        // HIGH if software_versions contains credential-like strings (AWS key pattern)
        // In practice the extractor puts software names in software_versions; still flag as HIGH
        // since any secret embedded in document content is a HIGH finding
        if !doc.flags.software_versions.is_empty()
            && doc.flags.software_versions.iter().any(|s| s.contains("AKIA") || s.contains("secret"))
        {
            let tf = ToolFinding::new("mg-metadata", "Secret Found in Document Metadata", FindingSeverity::High)
                .url(doc.url.clone())
                .evidence(format!(
                    "doc_type={} secrets={:?}",
                    doc.doc_type, doc.flags.software_versions
                ))
                .recommendation(
                    "Remove sensitive data from document metadata before publishing; \
                     rotate any exposed credentials; audit document publishing pipeline"
                );
            let _ = write_finding(&eng, &tf);
        }

        // MEDIUM if internal filesystem paths are exposed
        if !doc.flags.internal_paths.is_empty() {
            let tf = ToolFinding::new("mg-metadata", "Internal Filesystem Path in Document Metadata", FindingSeverity::Medium)
                .url(doc.url.clone())
                .evidence(format!(
                    "doc_type={} internal_paths={:?}",
                    doc.doc_type, doc.flags.internal_paths
                ))
                .recommendation(
                    "Strip document metadata before publishing; use PDF/Office metadata scrubbers; \
                     check document conversion pipeline for path leakage"
                );
            let _ = write_finding(&eng, &tf);
        }
    }

    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_doc_url_matches_extensions() {
        assert!(is_doc_url("https://example.com/report.pdf"));
        assert!(is_doc_url("https://example.com/data.xlsx"));
        assert!(is_doc_url("https://example.com/photo.JPEG"));
        assert!(!is_doc_url("https://example.com/index.html"));
        assert!(!is_doc_url("https://example.com/style.css"));
    }

    #[test]
    fn doc_type_from_url_returns_correct_type() {
        assert_eq!(doc_type_from_url("https://x.com/file.pdf"), "pdf");
        assert_eq!(doc_type_from_url("https://x.com/file.docx"), "docx");
        assert_eq!(doc_type_from_url("https://x.com/file.jpg"), "jpg");
        assert_eq!(doc_type_from_url("https://x.com/file.JPEG"), "jpg");
        assert_eq!(doc_type_from_url("https://x.com/file.pptx"), "pptx");
    }

    #[test]
    fn extract_pdf_value_extracts_between_parens() {
        let text = "/Author (Jane Doe) /Title (Report)";
        assert_eq!(extract_pdf_value(text, "/Author ("), Some("Jane Doe"));
        assert_eq!(extract_pdf_value(text, "/Title ("), Some("Report"));
    }

    #[test]
    fn extract_xml_value_finds_tag_content() {
        let xml = "<dc:creator>John</dc:creator><dc:title>Doc</dc:title>";
        assert_eq!(
            extract_xml_value(xml, "<dc:creator>", "</dc:creator>"),
            Some("John")
        );
    }

    #[test]
    fn find_subsequence_locates_needle() {
        let haystack = b"hello world exif test";
        assert_eq!(find_subsequence(haystack, b"exif"), Some(12));
        assert!(find_subsequence(haystack, b"missing").is_none());
    }

    #[test]
    fn extract_pdf_flags_finds_internal_path() {
        let text = "/Creator (C:\\Users\\alice\\doc.docx)\n";
        let flags = extract_pdf_flags(text.as_bytes());
        assert!(
            flags.internal_paths.iter().any(|p| p.contains("C:\\"))
        );
    }
}
