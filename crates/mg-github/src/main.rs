/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-github — GitHub OSINT code search for secrets,
 *                  internal domains, and config files exposed in repos
 *                  belonging to a target org or mentioning a target domain.
 * Notes:           Uses GitHub code search API. Respects X-RateLimit-*
 *                  headers and sleeps until reset when quota is exhausted.
 *                  Unauthenticated requests are rate-limited to 10/min;
 *                  a token raises this to 30/min.
 *******************************************************************/

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const GITHUB_SEARCH_URL: &str = "https://api.github.com/search/code";
const OUTPUT_SUBDIR: &str = "github";
const AUDIT_TOOL: &str = "mg-github";
const USER_AGENT: &str = "mg-github/0.1 (geistscope security scanner)";
// Pause between search queries to avoid secondary rate limits
const INTER_QUERY_DELAY_MS: u64 = 2000;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-github",
    about = "GitHub OSINT — search for secrets and config files in org repos"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// GitHub org name to search
    #[arg(long)]
    org: String,

    /// Also dork by domain name
    #[arg(long)]
    domain: Option<String>,

    /// GitHub personal access token (or env MG_GITHUB_TOKEN)
    #[arg(long, env = "MG_GITHUB_TOKEN")]
    token: Option<String>,

    /// Request timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One code search result item from the GitHub API
#[derive(Deserialize)]
struct SearchItem {
    repository: SearchRepo,
    path: String,
    html_url: String,
    score: f64,
}

// Repository field within a search item
#[derive(Deserialize)]
struct SearchRepo {
    full_name: String,
}

// GitHub code search API response envelope
#[derive(Deserialize)]
struct SearchResponse {
    items: Vec<SearchItem>,
    #[allow(dead_code)]
    total_count: u64,
}

// Rate-limit headers parsed from a GitHub API response
struct RateLimit {
    remaining: u64,
    reset_unix: u64,
}

// One de-duplicated finding written to disk
#[derive(Serialize)]
struct GithubFinding {
    repo: String,
    path: String,
    html_url: String,
    score: f64,
    query: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct GithubResults {
    engagement: String,
    org: String,
    domain: Option<String>,
    timestamp: String,
    total_queries: usize,
    total_findings: usize,
    findings: Vec<GithubFinding>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize a timestamp string for use in a filename (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Parse rate-limit headers from a reqwest response
fn parse_rate_limit(resp: &reqwest::Response) -> Option<RateLimit> {
    let remaining = resp
        .headers()
        .get("x-ratelimit-remaining")?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;
    let reset_unix = resp
        .headers()
        .get("x-ratelimit-reset")?
        .to_str()
        .ok()?
        .parse::<u64>()
        .ok()?;
    Some(RateLimit { remaining, reset_unix })
}

// Wait until the GitHub rate-limit reset timestamp if quota is zero
async fn wait_for_rate_limit_reset(reset_unix: u64) {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if reset_unix > now_unix {
        let wait_secs = reset_unix - now_unix + 2;
        eprintln!("  rate limit exhausted — waiting {}s for reset", wait_secs);
        tokio::time::sleep(Duration::from_secs(wait_secs)).await;
    }
}

// Run one GitHub code search query; return de-duplicated findings
async fn run_query(
    client: &reqwest::Client,
    query: &str,
    seen_urls: &mut HashSet<String>,
) -> Result<Vec<GithubFinding>> {
    let url = format!("{}?q={}&per_page=100", GITHUB_SEARCH_URL, urlencoding_simple(query));
    let resp = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let rate = parse_rate_limit(&resp);

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        eprintln!("  query failed status={} body={}", status, &body[..body.len().min(200)]);
        return Ok(Vec::new());
    }

    let search: SearchResponse = resp.json().await.context("parse search response")?;

    // Check rate limit after consuming the response
    if let Some(rl) = rate
        && rl.remaining == 0
    {
        wait_for_rate_limit_reset(rl.reset_unix).await;
    }

    let mut findings = Vec::new();
    for item in search.items {
        if seen_urls.contains(&item.html_url) {
            continue;
        }
        seen_urls.insert(item.html_url.clone());
        findings.push(GithubFinding {
            repo: item.repository.full_name,
            path: item.path,
            html_url: item.html_url,
            score: item.score,
            query: query.to_string(),
        });
    }

    Ok(findings)
}

// Minimal percent-encoding for GitHub search query strings
fn urlencoding_simple(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => out.push_str("%20"),
            '"' => out.push_str("%22"),
            '#' => out.push_str("%23"),
            '&' => out.push_str("%26"),
            '+' => out.push_str("%2B"),
            _ => out.push(c),
        }
    }
    out
}

// Build the list of search queries for an org (and optional domain)
fn build_queries(org: &str, domain: Option<&str>) -> Vec<String> {
    let mut queries = vec![
        format!("org:{org} filename:.env"),
        format!("org:{org} filename:config.yml password"),
        format!("org:{org} AWS_SECRET_ACCESS_KEY"),
        format!("org:{org} \"-----BEGIN RSA PRIVATE KEY-----\""),
        format!("org:{org} \"-----BEGIN OPENSSH PRIVATE KEY-----\""),
        format!("org:{org} database_url"),
        format!("org:{org} STRIPE_SECRET"),
    ];
    if let Some(d) = domain {
        queries.push(format!("\"{d}\" password"));
        queries.push(format!("\"{d}\" secret_key"));
    }
    queries
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // warn when no token is present; unauthenticated requests hit a lower rate limit
    if args.token.is_none() {
        eprintln!("mg-github: no token — running unauthenticated (10 req/min limit)");
        eprintln!("  set --token or MG_GITHUB_TOKEN for higher limits");
    }

    let mut request_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent(USER_AGENT);

    // GitHub requires Accept header for v3 API
    let mut default_headers = reqwest::header::HeaderMap::new();
    default_headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("application/vnd.github.v3+json"),
    );
    if let Some(ref token) = args.token {
        let bearer = format!("Bearer {token}");
        default_headers.insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(&bearer).context("build auth header")?,
        );
    }
    request_builder = request_builder.default_headers(default_headers);

    let client = request_builder.build().context("build HTTP client")?;

    let queries = build_queries(&args.org, args.domain.as_deref());
    eprintln!(
        "mg-github: org={} queries={} domain={}",
        args.org,
        queries.len(),
        args.domain.as_deref().unwrap_or("none")
    );

    let mut seen_urls: HashSet<String> = HashSet::new();
    let mut all_findings: Vec<GithubFinding> = Vec::new();
    let mut query_count = 0usize;

    for query in &queries {
        eprintln!("  query: {query}");
        match run_query(&client, query, &mut seen_urls).await {
            Ok(mut findings) => {
                for f in &findings {
                    eprintln!("    [hit] {} {}", f.repo, f.path);
                }
                all_findings.append(&mut findings);
            }
            Err(e) => eprintln!("  query error: {e}"),
        }
        query_count += 1;
        // Pause between queries to avoid secondary rate limits
        if query_count < queries.len() {
            tokio::time::sleep(Duration::from_millis(INTER_QUERY_DELAY_MS)).await;
        }
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = GithubResults {
        engagement: args.engagement.clone(),
        org: args.org.clone(),
        domain: args.domain.clone(),
        timestamp: ts.clone(),
        total_queries: queries.len(),
        total_findings: all_findings.len(),
        findings: all_findings,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create github output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).context("serialize output")?,
    )
    .context("write github results JSON")?;

    eprintln!(
        "mg-github: {} findings across {} queries — {}",
        output.total_findings,
        output.total_queries,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "org={} queries={} findings={} ts={ts}",
            args.org,
            output.total_queries,
            output.total_findings
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_queries_returns_org_queries_without_domain() {
        let queries = build_queries("acme", None);
        assert_eq!(queries.len(), 7);
        assert!(queries.iter().all(|q| q.contains("org:acme")));
    }

    #[test]
    fn build_queries_appends_domain_queries() {
        let queries = build_queries("acme", Some("acme.com"));
        assert_eq!(queries.len(), 9);
        let domain_queries: Vec<_> = queries.iter().filter(|q| q.contains("acme.com")).collect();
        assert_eq!(domain_queries.len(), 2);
    }

    #[test]
    fn urlencoding_simple_encodes_space_and_quotes() {
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("\"hello\""), "%22hello%22");
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-17T12:00:00Z"), "2026-05-17T12_00_00Z");
    }
}
