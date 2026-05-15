/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     mg-crawl — BFS web crawler with JS secret extraction
 *                  Writes HTML pages, JS assets, endpoints.json, and
 *                  secrets.json under engagements/<name>/crawl/<host>/
 * Notes:           Rate-limited to 1 req/sec by default; use --rate-ms 0
 *                  to disable throttling (not recommended).
 *                  robots.txt is honored by default; use --ignore-robots
 *                  to disable. Out-of-scope URLs are silently skipped.
 *******************************************************************/

mod analyze;
mod crawl;
mod extract;

use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;

use engagement::Engagement;
use http_client::{Client, ClientConfig};

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "mg-crawl", about = "BFS crawler with JS secret extraction")]
struct Args {
    /// Engagement name (must have engagement.json)
    engagement: String,

    /// One or more starting URLs to crawl
    #[arg(required = true, num_args = 1..)]
    urls: Vec<String>,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum crawl depth from each start URL (default: 2)
    #[arg(long, default_value_t = 2)]
    depth: u32,

    /// Minimum milliseconds between requests — 0 disables throttling
    #[arg(long, default_value_t = 1000)]
    rate_ms: u64,

    /// HTTP request timeout in milliseconds
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,

    /// Do not honor robots.txt Disallow directives
    #[arg(long)]
    ignore_robots: bool,

    /// Re-crawl even if crawl output already exists for this host
    #[arg(long)]
    force: bool,
}

// ── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // build scope checker closure from the engagement's scope.json
    let scope = eng.scope().context("load scope")?;

    // scope_fn needs to be Send + Sync for the crawl config; clone the rules
    let scope_fn = Box::new(move |hostname: &str| scope.is_in_scope(hostname));

    // check for existing crawl output and skip unless --force
    let crawl_dir = eng.crawl_dir();
    if !args.force && has_prior_crawl(&crawl_dir, &args.urls) {
        eprintln!("crawl output already exists — use --force to re-crawl");
        return Ok(());
    }

    // build the shared HTTP client with configured rate limit
    let rate_ms = if args.rate_ms > 0 {
        Some(args.rate_ms)
    } else {
        None
    };
    let default_headers = session::get_auth_headers(&eng)
        .await
        .context("load session auth headers")?;
    let auth_header_count = default_headers.len();
    let client = Client::new(ClientConfig {
        timeout_ms: args.timeout_ms,
        rate_limit_ms: rate_ms,
        default_headers,
        ..Default::default()
    })
    .context("build HTTP client")?;

    eprintln!(
        "mg-crawl: {} start URL(s), depth={}, rate={}ms, ignore-robots={}, auth_headers={}",
        args.urls.len(),
        args.depth,
        args.rate_ms,
        args.ignore_robots,
        auth_header_count
    );

    let cfg = crawl::CrawlConfig {
        engagement: args.engagement.clone(),
        start_urls: args.urls.clone(),
        max_depth: args.depth,
        ignore_robots: args.ignore_robots,
        crawl_dir: crawl_dir.clone(),
        scope_fn,
    };

    crawl::crawl(cfg, &client).await?;

    // record the run in the engagement audit log
    let target_summary = args.urls.join(", ");
    let _ = eng.audit(
        "mg-crawl",
        &target_summary,
        Some(&format!(
            "depth={} urls={} auth_headers={}",
            args.depth,
            args.urls.len(),
            auth_header_count
        )),
    );

    Ok(())
}

// Return true if a host-level crawl directory with index.json already exists
// for at least one of the provided start URLs (indicating a prior run)
fn has_prior_crawl(crawl_dir: &Path, urls: &[String]) -> bool {
    urls.iter().any(|u| {
        if let Ok(parsed) = url::Url::parse(u) {
            let host = parsed.host_str().unwrap_or("unknown");
            crawl_dir.join(host).join("index.json").exists()
        } else {
            false
        }
    })
}
