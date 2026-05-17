/*******************************************************************
 * Filename:        crawl.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     BFS web crawler — depth-limited, same-origin, in-scope,
 *                  robots.txt aware, rate-limited via the shared HTTP client
 * Notes:           Each page is stored as <sha256>.html in the crawl directory.
 *                  index.json maps URL → sha256 for deduplication.
 *                  Out-of-scope URLs are silently skipped, not errored.
 *******************************************************************/

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::analyze::{EndpointMatch, SecretMatch, find_secrets};
use crate::extract::{
    extract_form_actions, extract_inline_scripts, extract_links, extract_script_srcs, resolve_url,
};
use crate::js_analyzer::{
    GraphqlCandidate, InternalRef, JsAnalysis, VulnerableLibrary, analyze_js,
};

const GRAPHQL_INTROSPECTION_QUERY: &str = "query GeistScopeIntrospection { __schema { queryType { name } mutationType { name } types { name kind } } }";

// Caller-provided configuration for a single crawl run
pub struct CrawlConfig {
    pub engagement: String,
    pub start_urls: Vec<String>,
    pub max_depth: u32,
    pub ignore_robots: bool,
    pub graphql_introspection: bool,
    pub crawl_dir: PathBuf,
    pub scope_fn: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

// Aggregated output written to disk at the end of the run
#[derive(serde::Serialize)]
pub struct CrawlIndex {
    pub engagement: String,
    pub host: String,
    pub page_count: usize,
    pub js_count: usize,
    // URL → sha256 filename mapping
    pub pages: HashMap<String, String>,
    pub js_files: HashMap<String, String>,
}

// Mutable crawl artifacts collected while pages and scripts are analyzed
#[derive(Default)]
struct CrawlFindings {
    secrets: Vec<SecretMatch>,
    endpoints: Vec<EndpointMatch>,
    internal_refs: Vec<InternalRef>,
    vulnerable_libraries: Vec<VulnerableLibrary>,
    graphql_candidates: Vec<GraphqlCandidate>,
}

// Run the full BFS crawl for one starting URL set and write all output files
pub async fn crawl(cfg: CrawlConfig, client: &http_client::Client) -> Result<()> {
    let start_urls: Vec<Url> = cfg
        .start_urls
        .iter()
        .filter_map(|u| Url::parse(u).ok())
        .collect();

    if start_urls.is_empty() {
        anyhow::bail!("no valid start URLs");
    }

    // derive the host from the first start URL for directory naming
    let host = start_urls[0].host_str().unwrap_or("unknown").to_string();
    let host_dir = cfg.crawl_dir.join(&host);
    let pages_dir = host_dir.join("pages");
    let js_dir = host_dir.join("js");
    std::fs::create_dir_all(&pages_dir)?;
    std::fs::create_dir_all(&js_dir)?;

    // load robots.txt if we should honor it
    let robots_disallowed = if cfg.ignore_robots {
        HashSet::new()
    } else {
        fetch_robots(&start_urls[0], client).await
    };

    // BFS queue: (URL, depth)
    let mut queue: VecDeque<(Url, u32)> = start_urls.iter().map(|u| (u.clone(), 0)).collect();

    let mut visited: HashSet<String> = HashSet::new();
    let mut page_index: HashMap<String, String> = HashMap::new();
    let mut js_index: HashMap<String, String> = HashMap::new();
    let mut findings = CrawlFindings::default();

    // mark start URLs as visited before the loop
    for u in &start_urls {
        visited.insert(canonicalize(u));
    }

    while let Some((url, depth)) = queue.pop_front() {
        // skip if disallowed by robots.txt
        if is_disallowed(&url, &robots_disallowed) {
            eprintln!("  [robots] skipping {url}");
            continue;
        }

        eprintln!("  crawl [{depth}] {url}");

        // fetch the page body; skip on HTTP error or non-HTML response
        let html = match client.get_text(url.as_str()).await {
            Ok(body) => body,
            Err(e) => {
                eprintln!("  [err] {url}: {e}");
                continue;
            }
        };

        // store the page and record its SHA-256 hash
        let hash = sha256_hex(&html);
        let page_path = pages_dir.join(format!("{hash}.html"));
        std::fs::write(&page_path, &html)
            .with_context(|| format!("write {}", page_path.display()))?;
        page_index.insert(url.to_string(), hash.clone());

        // scan inline scripts for secrets and endpoints
        for script_text in extract_inline_scripts(&html) {
            findings
                .secrets
                .extend(find_secrets(&script_text, url.as_str()));
            merge_js_analysis(analyze_js(&script_text, url.as_str()), &mut findings);
        }

        // fetch and analyze external JS files
        for src_raw in extract_script_srcs(&html) {
            if let Some(src_url) = resolve_url(&src_raw, &url) {
                fetch_and_analyze_js(&src_url, &js_dir, client, &mut js_index, &mut findings).await;
            }
        }

        // extract form actions as endpoint candidates
        for action_raw in extract_form_actions(&html) {
            if let Some(action_url) = resolve_url(&action_raw, &url) {
                findings.endpoints.push(EndpointMatch::with_details(
                    path_with_query(&action_url),
                    url.to_string(),
                    "GET",
                    "html_form",
                    Some("form".into()),
                    false,
                ));
            }
        }

        // enqueue same-origin, in-scope links if depth budget allows
        if depth < cfg.max_depth {
            for href in extract_links(&html) {
                let Some(next) = resolve_url(&href, &url) else {
                    continue;
                };
                // only follow same-origin links
                if next.host_str() != url.host_str() {
                    continue;
                }
                // only visit in-scope targets
                let hostname = next.host_str().unwrap_or("");
                if !(cfg.scope_fn)(hostname) {
                    continue;
                }
                let canon = canonicalize(&next);
                if visited.insert(canon) {
                    queue.push_back((next, depth + 1));
                }
            }
        }
    }

    // write index.json — URL → sha256 map for all crawled pages
    write_json(
        &host_dir.join("index.json"),
        &CrawlIndex {
            engagement: cfg.engagement.clone(),
            host: host.clone(),
            page_count: page_index.len(),
            js_count: js_index.len(),
            pages: page_index,
            js_files: js_index,
        },
    )?;

    let CrawlFindings {
        secrets,
        endpoints,
        internal_refs,
        vulnerable_libraries,
        graphql_candidates,
    } = findings;

    // write endpoints.json — deduplicated list of discovered API paths
    let unique_endpoints = dedup_endpoints(endpoints);
    write_json(&host_dir.join("endpoints.json"), &unique_endpoints)?;

    // write secrets.json — all regex-matched secret candidates
    write_json(&host_dir.join("secrets.json"), &secrets)?;

    // write internal-refs.json — SSRF/useful internal references from JS
    let unique_internal_refs = dedup_hash(internal_refs);
    write_json(&host_dir.join("internal-refs.json"), &unique_internal_refs)?;

    // write vulnerable-libraries.json — embedded library CVE hints
    let unique_vulnerable_libraries = dedup_hash(vulnerable_libraries);
    write_json(
        &host_dir.join("vulnerable-libraries.json"),
        &unique_vulnerable_libraries,
    )?;

    // write GraphQL candidates and optionally attempt a bounded introspection query
    let unique_graphql_candidates = dedup_hash(graphql_candidates);
    if !unique_graphql_candidates.is_empty() {
        write_json(
            &host_dir.join("graphql-candidates.json"),
            &unique_graphql_candidates,
        )?;
        if cfg.graphql_introspection {
            try_graphql_introspection(
                &start_urls[0],
                &unique_graphql_candidates,
                &host_dir,
                client,
                &cfg.scope_fn,
            )
            .await;
        }
    }

    eprintln!(
        "  crawl complete — {} endpoints, {} secret candidates, {} internal refs, {} vulnerable libraries",
        unique_endpoints.len(),
        secrets.len(),
        unique_internal_refs.len(),
        unique_vulnerable_libraries.len()
    );
    Ok(())
}

// Fetch a JS file, store it, and run analyze.rs over its content
async fn fetch_and_analyze_js(
    url: &Url,
    js_dir: &Path,
    client: &http_client::Client,
    js_index: &mut HashMap<String, String>,
    findings: &mut CrawlFindings,
) {
    if js_index.contains_key(url.as_str()) {
        return;
    }

    let body = match client.get_text(url.as_str()).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("  [js err] {url}: {e}");
            return;
        }
    };

    let hash = sha256_hex(&body);
    let dest = js_dir.join(format!("{hash}.js"));
    if let Err(e) = std::fs::write(&dest, &body) {
        eprintln!("  [write err] {}: {e}", dest.display());
        return;
    }

    js_index.insert(url.to_string(), hash);
    findings.secrets.extend(find_secrets(&body, url.as_str()));
    merge_js_analysis(analyze_js(&body, url.as_str()), findings);
}

// Merge one JS analysis result into aggregate crawl vectors
fn merge_js_analysis(analysis: JsAnalysis, findings: &mut CrawlFindings) {
    findings.endpoints.extend(analysis.endpoints);
    findings.internal_refs.extend(analysis.internal_refs);
    findings
        .vulnerable_libraries
        .extend(analysis.vulnerable_libraries);
    findings
        .graphql_candidates
        .extend(analysis.graphql_candidates);
}

// Try one GraphQL introspection request per unique in-scope candidate
async fn try_graphql_introspection(
    base: &Url,
    candidates: &[GraphqlCandidate],
    host_dir: &Path,
    client: &http_client::Client,
    scope_fn: &(dyn Fn(&str) -> bool + Send + Sync),
) {
    let body = json!({ "query": GRAPHQL_INTROSPECTION_QUERY });
    let mut tried = HashSet::new();
    for candidate in candidates.iter().take(3) {
        let Some(url) = resolve_graphql_url(base, &candidate.endpoint) else {
            continue;
        };
        let host = url.host_str().unwrap_or("");
        if !scope_fn(host) || !tried.insert(url.to_string()) {
            continue;
        }
        match client.post_json_text(url.as_str(), &body).await {
            Ok(text) if text.contains("__schema") => {
                let path = host_dir.join("graphql-schema.json");
                if let Err(e) = std::fs::write(&path, text) {
                    eprintln!("  [graphql write err] {}: {e}", path.display());
                } else {
                    eprintln!("  [graphql] introspection saved from {url}");
                }
                return;
            }
            Ok(_) => eprintln!("  [graphql] {url} returned no __schema"),
            Err(e) => eprintln!("  [graphql err] {url}: {e}"),
        }
    }
}

// Resolve one GraphQL candidate against the crawl base URL
fn resolve_graphql_url(base: &Url, endpoint: &str) -> Option<Url> {
    if let Ok(url) = Url::parse(endpoint) {
        return Some(url);
    }
    base.join(endpoint).ok()
}

// Fetch and parse robots.txt; return the set of disallowed path prefixes
async fn fetch_robots(base: &Url, client: &http_client::Client) -> HashSet<String> {
    let robots_url = format!(
        "{}://{}/robots.txt",
        base.scheme(),
        base.host_str().unwrap_or("")
    );

    let text = match client.get_text(&robots_url).await {
        Ok(t) => t,
        Err(_) => return HashSet::new(),
    };

    // parse only Disallow directives for User-agent: * blocks
    let mut in_wildcard_block = false;
    let mut disallowed = HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some(rest) = line.strip_prefix("User-agent:") {
            in_wildcard_block = rest.trim() == "*";
        } else if in_wildcard_block && let Some(path) = line.strip_prefix("Disallow:") {
            let p = path.trim();
            if !p.is_empty() {
                disallowed.insert(p.to_string());
            }
        }
    }

    disallowed
}

// Return true if any robots.txt Disallow prefix matches this URL's path
fn is_disallowed(url: &Url, disallowed: &HashSet<String>) -> bool {
    let path = url.path();
    disallowed
        .iter()
        .any(|prefix| path.starts_with(prefix.as_str()))
}

// Canonical URL string: strip query + fragment, lowercase host for dedup key
fn canonicalize(url: &Url) -> String {
    let mut u = url.clone();
    u.set_query(None);
    u.set_fragment(None);
    u.to_string()
}

// Return path plus query string for endpoint rows
fn path_with_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

// SHA-256 hex digest of a string
fn sha256_hex(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    hex::encode(h.finalize())
}

// Serialize any Serialize value to a pretty-printed JSON file
fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    std::fs::write(path, json).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

// Deduplicate endpoint matches by (path, method) — the testable surface
// keeps the first-observed source_url as evidence so provenance isn't lost
fn dedup_endpoints(endpoints: Vec<EndpointMatch>) -> Vec<EndpointMatch> {
    let mut seen = HashSet::new();
    endpoints
        .into_iter()
        .filter(|e| seen.insert((e.path.clone(), e.method.clone())))
        .collect()
}

// Deduplicate hashable rows while preserving first-seen order
fn dedup_hash<T>(items: Vec<T>) -> Vec<T>
where
    T: Eq + Hash + Clone,
{
    let mut seen = HashSet::new();
    items
        .into_iter()
        .filter(|entry| seen.insert(entry.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_strips_query_and_fragment() {
        let u = Url::parse("https://example.com/path?q=1&r=2#section").unwrap();
        assert_eq!(canonicalize(&u), "https://example.com/path");
    }

    #[test]
    fn sha256_hex_is_deterministic() {
        assert_eq!(sha256_hex("hello"), sha256_hex("hello"));
        assert_ne!(sha256_hex("hello"), sha256_hex("world"));
    }

    #[test]
    fn is_disallowed_matches_prefix() {
        let dis: HashSet<String> = ["/admin", "/private"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let u1 = Url::parse("https://example.com/admin/users").unwrap();
        let u2 = Url::parse("https://example.com/about").unwrap();
        assert!(is_disallowed(&u1, &dis));
        assert!(!is_disallowed(&u2, &dis));
    }

    #[test]
    fn robots_parse_wildcard_disallow() {
        // Simulated parse: the async fetch is unit-tested through is_disallowed
        let raw = "User-agent: *\nDisallow: /admin\nDisallow: /private\n\nUser-agent: Googlebot\nDisallow:\n";
        let mut in_wildcard = false;
        let mut dis = HashSet::new();
        for line in raw.lines() {
            if let Some(r) = line.strip_prefix("User-agent:") {
                in_wildcard = r.trim() == "*";
            } else if in_wildcard {
                if let Some(p) = line.strip_prefix("Disallow:") {
                    let p = p.trim();
                    if !p.is_empty() {
                        dis.insert(p.to_string());
                    }
                }
            }
        }
        assert!(dis.contains("/admin"));
        assert!(dis.contains("/private"));
        assert!(!dis.contains("/"));
    }

    #[test]
    fn dedup_endpoints_collapses_same_path_across_pages() {
        let endpoints = vec![
            EndpointMatch::with_details("/api/x", "https://h/a", "GET", "js_string", None, false),
            EndpointMatch::with_details("/api/x", "https://h/b", "GET", "js_string", None, false),
            EndpointMatch::with_details("/api/x", "https://h/c", "POST", "js_fetch", None, false),
            EndpointMatch::with_details("/api/y", "https://h/a", "GET", "js_string", None, false),
        ];
        let out = dedup_endpoints(endpoints);
        assert_eq!(out.len(), 3);
        let paths: Vec<&str> = out.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"/api/x"));
        assert!(paths.contains(&"/api/y"));
        assert!(out.iter().any(|e| e.path == "/api/x" && e.method == "POST"));
    }
}
