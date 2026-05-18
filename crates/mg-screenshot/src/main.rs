/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-screenshot — headless bulk screenshotter
 *                  Reads HTTP/HTTPS hosts from recon/summary.json, opens
 *                  each URL with a headless Chromium tab, captures a PNG,
 *                  and writes an HTML index for visual review.
 * Notes:           chromiumoxide 0.7 requires a spawned handler task.
 *                  Chromium binary must be on PATH (chrome, chromium,
 *                  or chromium-browser).
 *******************************************************************/

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chromiumoxide::browser::{Browser, BrowserConfig};
use clap::Parser;
use futures::StreamExt;
use serde::Deserialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "screenshots";
const INDEX_FILENAME: &str = "index.html";
const AUDIT_TOOL: &str = "mg-screenshot";
const DEFAULT_CONCURRENCY: usize = 3;
const DEFAULT_TIMEOUT_SECS: u64 = 20;
const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 800;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-screenshot",
    about = "Headless bulk screenshotter — captures PNG per host from recon"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent browser tabs
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// Navigation timeout in seconds per URL
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// Viewport width in pixels
    #[arg(long, default_value_t = DEFAULT_WIDTH)]
    width: u32,

    /// Viewport height in pixels
    #[arg(long, default_value_t = DEFAULT_HEIGHT)]
    height: u32,
}

// ── Recon types ──────────────────────────────────────────────────────────────

// Mirrors the HostRecord shape written by mg-recon
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Mirrors the ReconSummary shape written by mg-recon
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Build a base URL preferring HTTPS when port 443 is open
fn base_url_for_host(rec: &HostRecord) -> String {
    if rec.open_ports.contains(&443) {
        return format!("https://{}", rec.hostname);
    }
    if rec.open_ports.contains(&80) {
        return format!("http://{}", rec.hostname);
    }
    format!("https://{}", rec.hostname)
}

// Sanitize a URL string to a safe filesystem filename (no slashes or special chars)
fn url_to_filename(url: &str) -> String {
    url.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' => c,
            _ => '_',
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

// Return current UTC time as RFC 3339 string
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Collect unique base URLs from recon summary
fn collect_urls(summary: &ReconSummary) -> Vec<String> {
    let mut urls = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for host in &summary.hosts {
        if !host.http_accessible {
            continue;
        }
        // Always attempt both HTTP and HTTPS when both ports are present
        for url in candidate_urls(host) {
            if seen.insert(url.clone()) {
                urls.push(url);
            }
        }
    }
    urls
}

// Generate HTTP and HTTPS candidate URLs for a host based on open ports
fn candidate_urls(rec: &HostRecord) -> Vec<String> {
    let mut urls = Vec::new();
    if rec.open_ports.contains(&443) {
        urls.push(format!("https://{}", rec.hostname));
    }
    if rec.open_ports.contains(&80) {
        urls.push(format!("http://{}", rec.hostname));
    }
    if urls.is_empty() {
        // Fall back to the best-guess URL when no standard ports recorded
        urls.push(base_url_for_host(rec));
    }
    urls
}

// Screenshot one URL: navigate, capture PNG, save to output_dir
async fn screenshot_url(
    browser: &Browser,
    url: &str,
    output_dir: &Path,
    timeout_secs: u64,
    width: u32,
    height: u32,
) -> Result<PathBuf> {
    use chromiumoxide::cdp::browser_protocol::page::{
        CaptureScreenshotFormat, Viewport,
    };
    use chromiumoxide::page::ScreenshotParams;

    let page = browser
        .new_page(url)
        .await
        .with_context(|| format!("open page {url}"))?;

    // Wait up to timeout for navigation; ignore timeout errors (page may still be usable)
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        page.wait_for_navigation(),
    )
    .await;

    let clip = Viewport {
        x: 0.0,
        y: 0.0,
        width: width as f64,
        height: height as f64,
        scale: 1.0,
    };

    let params = ScreenshotParams::builder()
        .format(CaptureScreenshotFormat::Png)
        .clip(clip)
        .build();

    let png_bytes = page
        .screenshot(params)
        .await
        .with_context(|| format!("screenshot {url}"))?;

    let filename = format!("{}.png", url_to_filename(url));
    let out_path = output_dir.join(&filename);
    fs::write(&out_path, &png_bytes)
        .with_context(|| format!("write {}", out_path.display()))?;

    // Close the tab to free resources
    page.close().await.ok();

    Ok(out_path)
}

// Write an HTML index page with a grid of screenshots and URL labels
fn write_html_index(
    output_dir: &Path,
    results: &[(String, Option<PathBuf>)],
) -> Result<()> {
    let mut rows = String::new();
    for (url, path_opt) in results {
        let img_tag = match path_opt {
            Some(p) => {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                format!(
                    r#"<figure><img src="{name}" alt="{url}" loading="lazy"><figcaption><a href="{url}">{url}</a></figcaption></figure>"#
                )
            }
            None => format!(
                r#"<figure class="err"><p class="label">{url}</p><p class="err-msg">screenshot failed</p></figure>"#
            ),
        };
        rows.push_str("    ");
        rows.push_str(&img_tag);
        rows.push('\n');
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>mg-screenshot index</title>
<style>
  body {{ font-family: sans-serif; background: #111; color: #eee; margin: 1rem; }}
  .grid {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
  figure {{ margin: 0; background: #222; padding: 0.5rem; border-radius: 4px; max-width: {width}px; }}
  img {{ max-width: 100%; border: 1px solid #444; }}
  figcaption {{ font-size: 0.75rem; word-break: break-all; margin-top: 0.25rem; }}
  a {{ color: #7af; }}
  .err {{ border: 2px solid #f55; }}
  .err-msg {{ color: #f88; font-size: 0.75rem; }}
  .label {{ font-size: 0.75rem; word-break: break-all; }}
</style>
</head>
<body>
<h1>mg-screenshot results</h1>
<div class="grid">
{rows}</div>
</body>
</html>
"#,
        width = DEFAULT_WIDTH
    );

    let index_path = output_dir.join(INDEX_FILENAME);
    fs::write(&index_path, html)
        .with_context(|| format!("write {}", index_path.display()))?;
    Ok(())
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    if !summary_path.exists() {
        anyhow::bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let urls = collect_urls(&summary);
    if urls.is_empty() {
        anyhow::bail!("no HTTP-accessible hosts found in recon/summary.json");
    }

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create screenshots dir")?;

    eprintln!(
        "mg-screenshot: {} URLs, concurrency={}, timeout={}s",
        urls.len(),
        args.concurrency,
        args.timeout
    );

    // Launch headless Chromium; handler must be driven on its own task
    let browser_config = BrowserConfig::builder()
        .window_size(args.width, args.height)
        .build()
        .map_err(|e| anyhow::anyhow!("chromium config error: {e}"))?;

    let (browser, mut handler) = Browser::launch(browser_config).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("No Chrome") || msg.contains("not found") || msg.contains("executable") {
            anyhow::anyhow!(
                "chromium not found in PATH — install chromium or google-chrome\n  (original error: {msg})"
            )
        } else {
            anyhow::anyhow!("browser launch failed: {msg}")
        }
    })?;

    // Drive the browser event loop on a background task
    let _handler_task = tokio::spawn(async move {
        loop {
            if handler.next().await.is_none() {
                break;
            }
        }
    });

    // Take screenshots with bounded concurrency using futures::stream
    let timeout = args.timeout;
    let width = args.width;
    let height = args.height;
    let output_dir_ref = output_dir.clone();

    let results: Vec<(String, Option<PathBuf>)> = futures::stream::iter(urls.iter().cloned())
        .map(|url| {
            let browser = &browser;
            let out = output_dir_ref.clone();
            async move {
                eprintln!("  → {url}");
                match screenshot_url(browser, &url, &out, timeout, width, height).await {
                    Ok(path) => {
                        eprintln!("    saved: {}", path.display());
                        (url, Some(path))
                    }
                    Err(e) => {
                        eprintln!("    error: {e}");
                        (url, None)
                    }
                }
            }
        })
        .buffered(args.concurrency)
        .collect()
        .await;

    let success_count = results.iter().filter(|(_, p)| p.is_some()).count();

    // Write HTML index
    write_html_index(&output_dir, &results).context("write HTML index")?;

    let index_path = output_dir.join(INDEX_FILENAME);
    eprintln!(
        "mg-screenshot: {}/{} succeeded — index: {}",
        success_count,
        results.len(),
        index_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "urls={} success={} ts={}",
            results.len(),
            success_count,
            now_rfc3339()
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_to_filename_strips_scheme_and_special_chars() {
        assert_eq!(url_to_filename("https://example.com"), "https___example.com");
        assert_eq!(
            url_to_filename("http://api.example.com/v1?foo=bar"),
            "http___api.example.com_v1_foo_bar"
        );
    }

    #[test]
    fn collect_urls_deduplicates_and_skips_inaccessible() {
        let summary = ReconSummary {
            hosts: vec![
                HostRecord {
                    hostname: "example.com".into(),
                    http_accessible: true,
                    open_ports: vec![80, 443],
                },
                HostRecord {
                    hostname: "other.com".into(),
                    http_accessible: false,
                    open_ports: vec![80],
                },
                HostRecord {
                    hostname: "example.com".into(),
                    http_accessible: true,
                    open_ports: vec![80, 443],
                },
            ],
        };
        let urls = collect_urls(&summary);
        // example.com gives https + http, other.com skipped, duplicate collapsed
        assert_eq!(urls.len(), 2);
        assert!(urls.contains(&"https://example.com".to_string()));
        assert!(urls.contains(&"http://example.com".to_string()));
    }

    #[test]
    fn base_url_prefers_https() {
        let rec = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![80, 443],
        };
        assert_eq!(base_url_for_host(&rec), "https://example.com");
    }
}
