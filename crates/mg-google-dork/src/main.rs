/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-google-dork — generates and optionally executes Google dork queries.
 * Notes:           All 14 dork queries are always printed to stdout.
 *                  API execution requires both --api-key (Google CSE key) and --cx (search engine ID).
 *                  Results use Google Custom Search JSON API v1.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::form_urlencoded;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const GOOGLE_CSE_BASE: &str = "https://www.googleapis.com/customsearch/v1";
const CSE_RESULTS_PER_QUERY: u32 = 10;
const OUTPUT_SUBDIR: &str = "google-dork";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-google-dork";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// Rate limit between CSE calls — free tier has 100 queries/day limit
const CSE_RATE_MS: u64 = 1_000;

// 14 dork query templates — {domain} is replaced with the target domain
const DORK_TEMPLATES: &[&str] = &[
    "site:{domain} filetype:pdf",
    "site:{domain} filetype:sql",
    "site:{domain} filetype:env",
    "site:{domain} inurl:admin",
    "site:{domain} inurl:login",
    "site:{domain} inurl:phpinfo",
    "site:{domain} \"index of /\"",
    "site:{domain} \"SQL syntax\"",
    "site:{domain} intitle:\"Apache Tomcat\"",
    "\"{domain}\" password filetype:txt",
    "\"{domain}\" inurl:backup",
    "\"{domain}\" ext:bak OR ext:old",
    "site:{domain} inurl:wp-admin",
    "site:{domain} filetype:xls",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-google-dork",
    about = "Generate and optionally execute Google dork queries for a domain"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Target domain
    #[arg(long)]
    domain: String,

    /// Google Custom Search API key
    #[arg(long)]
    api_key: Option<String>,

    /// Google Custom Search Engine ID (cx)
    #[arg(long)]
    cx: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Google CSE API item in results
#[derive(Debug, Deserialize)]
struct CseItem {
    link: Option<String>,
    title: Option<String>,
}

// Google CSE API response
#[derive(Debug, Deserialize)]
struct CseResponse {
    #[serde(default)]
    items: Vec<CseItem>,
}

// One dork result
#[derive(Debug, Serialize)]
struct DorkResult {
    query: String,
    hits: Vec<DorkHit>,
}

// One search result hit
#[derive(Debug, Serialize)]
struct DorkHit {
    url: String,
    title: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct DorkResults {
    engagement: String,
    timestamp: String,
    domain: String,
    executed: bool,
    queries: Vec<String>,
    results: Vec<DorkResult>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Build all 14 dork queries for a domain by substituting the {domain} placeholder
fn build_queries(domain: &str) -> Vec<String> {
    DORK_TEMPLATES
        .iter()
        .map(|t| t.replace("{domain}", domain))
        .collect()
}

// Execute one query against the Google Custom Search API
async fn execute_dork(
    client: &reqwest::Client,
    query: &str,
    api_key: &str,
    cx: &str,
) -> Result<Vec<DorkHit>> {
    let encoded_query: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("q", query)
        .append_pair("key", api_key)
        .append_pair("cx", cx)
        .append_pair("num", &CSE_RESULTS_PER_QUERY.to_string())
        .finish();
    let url = format!("{GOOGLE_CSE_BASE}?{encoded_query}");

    let resp = client
        .get(&url)
        .send()
        .await
        .context("Google CSE request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Google CSE returned {status}: {body}");
    }

    let parsed: CseResponse = resp.json().await.context("parse CSE JSON")?;
    let hits = parsed
        .items
        .into_iter()
        .map(|item| DorkHit {
            url: item.link.unwrap_or_default(),
            title: item.title.unwrap_or_default(),
        })
        .collect();
    Ok(hits)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-google-dork: domain={}", args.domain);

    let queries = build_queries(&args.domain);

    // Always print all queries
    println!("\n=== Google Dork Queries for {} ===", args.domain);
    for (i, q) in queries.iter().enumerate() {
        println!("  {:2}. {q}", i + 1);
    }

    let execute = args.api_key.is_some() && args.cx.is_some();
    let mut dork_results: Vec<DorkResult> = Vec::new();

    if execute {
        let api_key = args.api_key.as_deref().unwrap();
        let cx = args.cx.as_deref().unwrap();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(args.timeout))
            .user_agent("mg-google-dork/0.1")
            .build()
            .context("build HTTP client")?;

        let rate = Duration::from_millis(CSE_RATE_MS);

        println!("\n=== Executing Queries ===");
        for query in &queries {
            eprintln!("  querying: {query}");
            tokio::time::sleep(rate).await;

            let hits = execute_dork(&client, query, api_key, cx)
                .await
                .unwrap_or_default();

            if !hits.is_empty() {
                println!("  [{} hits] {query}", hits.len());
                for hit in &hits {
                    println!("    {}", hit.url);
                }
            }

            dork_results.push(DorkResult {
                query: query.clone(),
                hits,
            });
        }

        let _ = eng.audit(AUDIT_TOOL, &args.domain, Some("executed=true"));
    } else {
        eprintln!("  no --api-key + --cx provided; skipping API execution");
        // Still write query list with empty hits
        for query in &queries {
            dork_results.push(DorkResult {
                query: query.clone(),
                hits: Vec::new(),
            });
        }
        let _ = eng.audit(AUDIT_TOOL, &args.domain, Some("executed=false"));
    }

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create google-dork output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = DorkResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        domain: args.domain.clone(),
        executed: execute,
        queries: queries.clone(),
        results: dork_results,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_queries_generates_fourteen() {
        let queries = build_queries("example.com");
        assert_eq!(queries.len(), 14);
    }

    #[test]
    fn build_queries_substitutes_domain() {
        let queries = build_queries("target.io");
        assert!(queries[0].contains("target.io"));
        assert!(!queries[0].contains("{domain}"));
    }

    #[test]
    fn build_queries_all_contain_domain() {
        let queries = build_queries("acme.org");
        for q in &queries {
            assert!(q.contains("acme.org"), "query missing domain: {q}");
        }
    }

    #[test]
    fn build_queries_includes_password_dork() {
        let queries = build_queries("example.com");
        assert!(queries.iter().any(|q| q.contains("password")));
    }
}
