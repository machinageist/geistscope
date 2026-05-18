/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-oauth — OAuth 2.0 flow analyzer; tests state CSRF,
 *                  redirect_uri bypass, PKCE downgrade, implicit flow.
 * Notes:           Uses redirect::Policy::none() so we can inspect
 *                  Location headers directly without following redirects.
 *                  Reads crawl corpus for candidate OAuth URLs; also
 *                  accepts --auth-url for direct single-URL testing.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "oauth";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-oauth";

// URL path/query fragments that indicate an OAuth authorization endpoint
const OAUTH_INDICATORS: &[&str] = &[
    "/oauth",
    "/authorize",
    "/auth",
    "/connect",
    "response_type=",
    "client_id=",
];

// Attacker-controlled redirect_uri values to test
const REDIRECT_BYPASS_URIS: &[&str] = &[
    "https://attacker.com",
    "//attacker.com",
];

// Keyword fragments to detect in bypass redirect targets
const ATTACKER_DOMAIN: &str = "attacker.com";

// Severity strings
const SEVERITY_HIGH: &str = "HIGH";
const SEVERITY_MEDIUM: &str = "MEDIUM";
const SEVERITY_LOW: &str = "LOW";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-oauth",
    about = "OAuth 2.0 flow analyzer — state CSRF, redirect bypass, PKCE, implicit flow"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Test a specific authorization URL directly (in addition to crawl corpus)
    #[arg(long)]
    auth_url: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// One OAuth finding
#[derive(Debug, Serialize)]
struct OAuthFinding {
    url: String,
    check: String,
    severity: String,
    detail: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct OAuthResults {
    engagement: String,
    timestamp: String,
    total_urls_tested: usize,
    findings: Vec<OAuthFinding>,
}

// Minimal crawl entry shape for scanning URLs
#[derive(Deserialize)]
struct CrawlEntry {
    #[serde(default)]
    url: String,
    #[serde(default)]
    links: Vec<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Collect OAuth candidate URLs from the crawl directory
fn collect_from_crawl(crawl_dir: &Path) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return urls;
    };
    for entry in hosts.flatten() {
        if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            continue;
        }
        // Read pages.json or index.json for discovered URLs
        for filename in &["pages.json", "index.json"] {
            let path = entry.path().join(filename);
            let Ok(raw) = fs::read_to_string(&path) else {
                continue;
            };
            let Ok(entries): Result<Vec<CrawlEntry>, _> = serde_json::from_str(&raw) else {
                continue;
            };
            for ce in entries {
                if is_oauth_candidate(&ce.url) {
                    urls.push(ce.url.clone());
                }
                for link in ce.links {
                    if is_oauth_candidate(&link) {
                        urls.push(link);
                    }
                }
            }
        }
    }
    // Deduplicate
    urls.sort();
    urls.dedup();
    urls
}

// Return true if a URL looks like an OAuth authorization endpoint
fn is_oauth_candidate(url: &str) -> bool {
    if url.is_empty() {
        return false;
    }
    let lower = url.to_lowercase();
    OAUTH_INDICATORS.iter().any(|ind| lower.contains(ind))
}

// Extract the redirect_uri parameter value from a URL
fn extract_redirect_uri(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    parsed
        .query_pairs()
        .find(|(k, _)| k == "redirect_uri")
        .map(|(_, v)| v.into_owned())
}

// Extract the "legitimate" domain from a redirect_uri value
fn legit_domain_from_redirect_uri(redirect_uri: &str) -> Option<String> {
    let parsed = Url::parse(redirect_uri).ok()?;
    parsed.host_str().map(|h| h.to_string())
}

// Get the Location header value from a response (redirect destination)
fn location_header(resp: &reqwest::Response) -> Option<String> {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// ── Checks ────────────────────────────────────────────────────────────────────

// Test missing state parameter — CSRF risk
async fn check_state_csrf(
    client: &reqwest::Client,
    auth_url: &str,
) -> Option<OAuthFinding> {
    // Strip the state param from the URL and send without it
    let mut parsed = Url::parse(auth_url).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "state")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.set_query(None);
    {
        let mut qs = parsed.query_pairs_mut();
        for (k, v) in &pairs {
            qs.append_pair(k, v);
        }
    }
    let resp = client.get(parsed.as_str()).send().await.ok()?;
    let status = resp.status().as_u16();
    let loc = location_header(&resp).unwrap_or_default();
    // Missing state is a problem when server still redirects to redirect_uri
    if status == 302 || status == 200 {
        let original_redir = extract_redirect_uri(auth_url).unwrap_or_default();
        if !original_redir.is_empty() && (loc.starts_with(&original_redir) || status == 200) {
            return Some(OAuthFinding {
                url: auth_url.to_string(),
                check: "missing_state".to_string(),
                severity: SEVERITY_MEDIUM.to_string(),
                detail: format!(
                    "Authorization endpoint accepts requests without state parameter (status={status})"
                ),
            });
        }
        // Even with no redirect_uri known, flag if server returns 200 on stateless request
        if status == 200 && original_redir.is_empty() {
            return Some(OAuthFinding {
                url: auth_url.to_string(),
                check: "missing_state".to_string(),
                severity: SEVERITY_MEDIUM.to_string(),
                detail: format!(
                    "Authorization endpoint accepts stateless request with status={status}"
                ),
            });
        }
    }
    None
}

// Test redirect_uri bypass with attacker-controlled values
async fn check_redirect_bypass(
    client: &reqwest::Client,
    auth_url: &str,
) -> Vec<OAuthFinding> {
    let mut findings = Vec::new();
    let original_redir = extract_redirect_uri(auth_url);
    let legit_domain = original_redir
        .as_deref()
        .and_then(legit_domain_from_redirect_uri);

    // Build the full list of payloads including domain-prefixed variant
    let mut payloads: Vec<String> = REDIRECT_BYPASS_URIS
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Some(ref domain) = legit_domain {
        payloads.push(format!("https://{domain}.attacker.com"));
        payloads.push("https://legit.com.attacker.com".to_string());
    } else {
        payloads.push("https://legit.com.attacker.com".to_string());
    }

    for payload in &payloads {
        let Some(mut parsed) = Url::parse(auth_url).ok() else {
            continue;
        };
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .filter(|(k, _)| k != "redirect_uri")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        parsed.set_query(None);
        {
            let mut qs = parsed.query_pairs_mut();
            for (k, v) in &pairs {
                qs.append_pair(k, v);
            }
            qs.append_pair("redirect_uri", payload);
        }
        let Ok(resp) = client.get(parsed.as_str()).send().await else {
            continue;
        };
        let status = resp.status().as_u16();
        let loc = location_header(&resp).unwrap_or_default();
        if status == 302 && loc.contains(ATTACKER_DOMAIN) {
            findings.push(OAuthFinding {
                url: auth_url.to_string(),
                check: "redirect_bypass".to_string(),
                severity: SEVERITY_HIGH.to_string(),
                detail: format!(
                    "redirect_uri bypass: server redirected to {loc} (payload={payload})"
                ),
            });
        }
    }
    findings
}

// Test PKCE downgrade — send without code_challenge when it was present
async fn check_pkce_downgrade(
    client: &reqwest::Client,
    auth_url: &str,
) -> Option<OAuthFinding> {
    // Only relevant when original URL has code_challenge
    if !auth_url.contains("code_challenge") {
        return None;
    }
    let mut parsed = Url::parse(auth_url).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "code_challenge" && k != "code_challenge_method")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.set_query(None);
    {
        let mut qs = parsed.query_pairs_mut();
        for (k, v) in &pairs {
            qs.append_pair(k, v);
        }
    }
    let resp = client.get(parsed.as_str()).send().await.ok()?;
    let status = resp.status().as_u16();
    let loc = location_header(&resp).unwrap_or_default();
    // If the server proceeds (302 with code in Location or 200), PKCE is not enforced
    if (status == 302 && loc.contains("code=")) || status == 200 {
        return Some(OAuthFinding {
            url: auth_url.to_string(),
            check: "pkce_not_enforced".to_string(),
            severity: SEVERITY_MEDIUM.to_string(),
            detail: format!(
                "Server accepted authorization request without code_challenge (status={status})"
            ),
        });
    }
    None
}

// Test implicit flow by sending response_type=token
async fn check_implicit_flow(
    client: &reqwest::Client,
    auth_url: &str,
) -> Option<OAuthFinding> {
    let mut parsed = Url::parse(auth_url).ok()?;
    let pairs: Vec<(String, String)> = parsed
        .query_pairs()
        .filter(|(k, _)| k != "response_type")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    parsed.set_query(None);
    {
        let mut qs = parsed.query_pairs_mut();
        for (k, v) in &pairs {
            qs.append_pair(k, v);
        }
        qs.append_pair("response_type", "token");
    }
    let resp = client.get(parsed.as_str()).send().await.ok()?;
    let status = resp.status().as_u16();
    let loc = location_header(&resp).unwrap_or_default();
    // Implicit flow enabled when server redirects with access_token in fragment
    if status == 302 && loc.contains("access_token=") {
        return Some(OAuthFinding {
            url: auth_url.to_string(),
            check: "implicit_flow".to_string(),
            severity: SEVERITY_LOW.to_string(),
            detail: "Server supports implicit flow (response_type=token); access_token present in redirect fragment".to_string(),
        });
    }
    None
}

// Run all checks for one OAuth URL, return all findings
async fn analyze_url(client: &reqwest::Client, auth_url: &str) -> Vec<OAuthFinding> {
    let mut findings = Vec::new();
    if let Some(f) = check_state_csrf(client, auth_url).await {
        findings.push(f);
    }
    findings.extend(check_redirect_bypass(client, auth_url).await);
    if let Some(f) = check_pkce_downgrade(client, auth_url).await {
        findings.push(f);
    }
    if let Some(f) = check_implicit_flow(client, auth_url).await {
        findings.push(f);
    }
    findings
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Build no-redirect client for direct Location inspection
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Collect candidate OAuth URLs from crawl corpus
    let mut oauth_urls = collect_from_crawl(&eng.crawl_dir());
    if let Some(ref direct_url) = args.auth_url
        && !oauth_urls.contains(direct_url)
    {
        oauth_urls.push(direct_url.clone());
    }

    if oauth_urls.is_empty() {
        eprintln!(
            "mg-oauth: no OAuth endpoints found in crawl/ — pass --auth-url to test directly"
        );
    }

    eprintln!("mg-oauth: testing {} OAuth endpoint(s)", oauth_urls.len());

    let mut all_findings: Vec<OAuthFinding> = Vec::new();
    for url in &oauth_urls {
        eprintln!("  analyzing {url}");
        let findings = analyze_url(&client, url).await;
        for f in &findings {
            println!("[{}] {} — {}", f.severity, f.check, f.url);
        }
        all_findings.extend(findings);
    }

    println!(
        "\n=== OAuth Analysis Complete: {} finding(s) ===",
        all_findings.len()
    );

    // Write findings for each confirmed OAuth issue
    for f in &all_findings {
        let severity = match f.severity.as_str() {
            SEVERITY_HIGH => FindingSeverity::High,
            SEVERITY_MEDIUM => FindingSeverity::Medium,
            _ => continue,
        };
        let tf = ToolFinding::new(AUDIT_TOOL, format!("OAuth: {}", f.check), severity)
            .url(f.url.clone())
            .evidence(f.detail.clone())
            .recommendation(match f.check.as_str() {
                "redirect_bypass" => "Validate redirect_uri against an explicit allowlist; never accept arbitrary domains",
                "missing_state" => "Require a cryptographically random state parameter on every authorization request",
                "pkce_not_enforced" => "Reject authorization requests that lack a code_challenge when PKCE is advertised",
                _ => "Review OAuth 2.0 security best practices (RFC 9700)",
            });
        let _ = write_finding(&eng, &tf);
    }

    // Write results JSON
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create oauth output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = OAuthResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        total_urls_tested: oauth_urls.len(),
        findings: all_findings,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!("urls_tested={} findings={}", results.total_urls_tested, results.findings.len());
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_oauth_candidate_matches_known_patterns() {
        assert!(is_oauth_candidate("https://example.com/oauth/authorize?client_id=abc"));
        assert!(is_oauth_candidate("https://example.com/auth?response_type=code"));
        assert!(is_oauth_candidate("https://example.com/connect/token"));
        assert!(!is_oauth_candidate("https://example.com/api/users"));
        assert!(!is_oauth_candidate(""));
    }

    #[test]
    fn extract_redirect_uri_parses_param() {
        let url = "https://example.com/oauth/authorize?client_id=abc&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&response_type=code";
        let redir = extract_redirect_uri(url).unwrap();
        assert_eq!(redir, "https://app.example.com/callback");
    }

    #[test]
    fn extract_redirect_uri_returns_none_when_absent() {
        let url = "https://example.com/oauth/authorize?client_id=abc";
        assert!(extract_redirect_uri(url).is_none());
    }

    #[test]
    fn legit_domain_extracts_host() {
        let domain = legit_domain_from_redirect_uri("https://app.example.com/callback").unwrap();
        assert_eq!(domain, "app.example.com");
    }

    #[test]
    fn collect_from_crawl_returns_empty_for_missing_dir() {
        let results = collect_from_crawl(Path::new("/nonexistent/crawl"));
        assert!(results.is_empty());
    }

    #[test]
    fn collect_from_crawl_finds_oauth_urls() {
        let tmp = tempfile::tempdir().unwrap();
        let host_dir = tmp.path().join("example.com");
        fs::create_dir_all(&host_dir).unwrap();
        let entries = serde_json::json!([
            {
                "url": "https://example.com/oauth/authorize?client_id=x&response_type=code",
                "links": ["https://example.com/about"]
            }
        ]);
        fs::write(
            host_dir.join("pages.json"),
            serde_json::to_string(&entries).unwrap(),
        )
        .unwrap();
        let urls = collect_from_crawl(tmp.path());
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("/oauth/authorize"));
    }
}
