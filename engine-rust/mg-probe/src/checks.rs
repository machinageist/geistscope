/*******************************************************************
 * Filename:        checks.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     All passive and semi-active probe checks — security headers,
 *                  CORS, cookies, exposed debug assets, HTML content analysis
 * Notes:           Each check function takes a host + reqwest client and returns
 *                  a list of ProbeIssues. Severity follows CVSS rough equivalents:
 *                  Info < Low < Medium < High < Critical.
 *                  Semi-active checks (probing debug paths) make real HTTP requests;
 *                  they are skipped for out-of-scope hosts.
 *******************************************************************/

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;

use engagement::Severity;

// One identified security issue from any check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeIssue {
    pub check: String,
    pub host: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub evidence: String,
}

// Endpoint row loaded from mg-crawl endpoints.json
#[derive(Debug, Clone, Deserialize)]
struct CrawlEndpoint {
    path: String,
    source_url: String,
}

impl ProbeIssue {
    // Map our issue severity to the engagement Severity enum
    pub fn severity_enum(&self) -> Severity {
        match self.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
}

// ── Security header check ────────────────────────────────────────────────────

// Required headers and their significance
const REQUIRED_HEADERS: &[(&str, &str, &str)] = &[
    (
        "content-security-policy",
        "info",
        "Content-Security-Policy header missing",
    ),
    (
        "x-frame-options",
        "info",
        "X-Frame-Options header missing — clickjacking risk",
    ),
    (
        "x-content-type-options",
        "info",
        "X-Content-Type-Options header missing — MIME sniffing risk",
    ),
    ("referrer-policy", "info", "Referrer-Policy header missing"),
    (
        "permissions-policy",
        "info",
        "Permissions-Policy header missing",
    ),
];

const HSTS_HEADER: &str = "strict-transport-security";

// Fetch the host root and report each missing security response header
pub async fn check_security_headers(
    client: &Client,
    base_url: &str,
    host: &str,
) -> Vec<ProbeIssue> {
    let resp = match client.get(base_url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [probe/headers] {host}: {e}");
            return vec![];
        }
    };

    let headers = resp.headers().clone();
    let is_https = base_url.starts_with("https://");
    let mut issues = Vec::new();

    // check each required header
    for (name, severity, title) in REQUIRED_HEADERS {
        let present = headers.contains_key(*name)
            || (*name == "content-security-policy"
                && headers.contains_key("x-content-security-policy"));
        if !present {
            issues.push(ProbeIssue {
                check: "security-headers".into(),
                host: host.into(),
                severity: severity.to_string(),
                title: title.to_string(),
                detail: format!("Response from {base_url} does not include {name}"),
                evidence: format!("GET {base_url} → {}", resp.status().as_u16()),
            });
        }
    }

    // HSTS only meaningful over HTTPS
    if is_https && !headers.contains_key(HSTS_HEADER) {
        issues.push(ProbeIssue {
            check: "security-headers".into(),
            host: host.into(),
            severity: "low".into(),
            title: "Strict-Transport-Security header missing".into(),
            detail: format!("{base_url} is served over HTTPS but lacks HSTS"),
            evidence: format!("GET {base_url} → {}", resp.status().as_u16()),
        });
    }

    // server version disclosure check — flag if version number visible
    if let Some(srv) = headers.get("server").and_then(|v| v.to_str().ok())
        && srv.chars().any(|c| c.is_ascii_digit())
    {
        issues.push(ProbeIssue {
            check: "version-disclosure".into(),
            host: host.into(),
            severity: "info".into(),
            title: "Server version disclosed in response header".into(),
            detail: "Server header reveals version information".into(),
            evidence: format!("Server: {srv}"),
        });
    }

    issues
}

// ── CORS check ───────────────────────────────────────────────────────────────

const CORS_PROBE_ORIGIN: &str = "https://evil-origin-probe.com";

// Send a request with a foreign Origin header and check if it is reflected
pub async fn check_cors(client: &Client, base_url: &str, host: &str) -> Vec<ProbeIssue> {
    let resp = match client
        .get(base_url)
        .header("Origin", CORS_PROBE_ORIGIN)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [probe/cors] {host}: {e}");
            return vec![];
        }
    };

    let headers = resp.headers();
    let acao = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let acac = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("false");

    let mut issues = Vec::new();

    // wildcard with credentials is impossible per spec but misconfigured proxies sometimes do it
    if acao == "*" {
        issues.push(ProbeIssue {
            check: "cors".into(),
            host: host.into(),
            severity: "medium".into(),
            title: "CORS: wildcard Access-Control-Allow-Origin".into(),
            detail: "Any origin may read cross-origin responses from this endpoint".into(),
            evidence: format!("Access-Control-Allow-Origin: {acao}"),
        });
    }

    // reflected origin + credentials = credentialed cross-origin reads (High)
    if acao == CORS_PROBE_ORIGIN && acac.eq_ignore_ascii_case("true") {
        issues.push(ProbeIssue {
            check: "cors".into(),
            host: host.into(),
            severity: "high".into(),
            title: "CORS: arbitrary origin reflected with credentials".into(),
            detail: "Attacker-controlled origin is reflected and credentials are allowed — \
                       credentialed cross-origin reads are possible"
                .into(),
            evidence: format!(
                "Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"
            ),
        });
    } else if acao == CORS_PROBE_ORIGIN {
        // reflected without credentials — lower severity
        issues.push(ProbeIssue {
            check: "cors".into(),
            host: host.into(),
            severity: "low".into(),
            title: "CORS: arbitrary origin reflected (no credentials)".into(),
            detail: "Attacker-controlled origin is reflected without allow-credentials".into(),
            evidence: format!("Access-Control-Allow-Origin: {acao}"),
        });
    }

    issues
}

// ── Cookie check ─────────────────────────────────────────────────────────────

// Inspect Set-Cookie headers on the root response for missing security flags
pub async fn check_cookies(client: &Client, base_url: &str, host: &str) -> Vec<ProbeIssue> {
    let resp = match client.get(base_url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  [probe/cookies] {host}: {e}");
            return vec![];
        }
    };

    let is_https = base_url.starts_with("https://");
    let mut issues = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    for val in resp.headers().get_all("set-cookie") {
        let Ok(cookie_str) = val.to_str() else {
            continue;
        };
        let lower = cookie_str.to_lowercase();
        let redacted_cookie = redact_set_cookie(cookie_str);

        // extract cookie name (before first = or ;)
        let name = cookie_str
            .split('=')
            .next()
            .unwrap_or("?")
            .trim()
            .to_string();
        if seen_names.contains(&name) {
            continue;
        }
        seen_names.insert(name.clone());

        // Secure flag required over HTTPS
        if is_https && !lower.contains("; secure") && !lower.contains(";secure") {
            issues.push(ProbeIssue {
                check: "cookies".into(),
                host: host.into(),
                severity: "medium".into(),
                title: format!("Cookie '{name}' missing Secure flag"),
                detail: "Cookie transmitted over HTTPS lacks the Secure attribute; \
                           may be transmitted over HTTP if the browser is redirected"
                    .into(),
                evidence: format!("Set-Cookie: {redacted_cookie}"),
            });
        }

        // HttpOnly flag prevents JS access to the cookie value
        if !lower.contains("; httponly") && !lower.contains(";httponly") {
            issues.push(ProbeIssue {
                check: "cookies".into(),
                host: host.into(),
                severity: "medium".into(),
                title: format!("Cookie '{name}' missing HttpOnly flag"),
                detail: "Cookie lacks the HttpOnly attribute; JavaScript running on the page \
                           can read its value (XSS amplification)"
                    .into(),
                evidence: format!("Set-Cookie: {redacted_cookie}"),
            });
        }

        // SameSite prevents CSRF cookie sending
        if !lower.contains("samesite=") {
            issues.push(ProbeIssue {
                check: "cookies".into(),
                host: host.into(),
                severity: "low".into(),
                title: format!("Cookie '{name}' missing SameSite attribute"),
                detail: "Cookie lacks SameSite; defaults to 'Lax' in modern browsers but \
                           explicit declaration is preferred and required for older browsers"
                    .into(),
                evidence: format!("Set-Cookie: {redacted_cookie}"),
            });
        }
    }

    issues
}

// Preserve cookie name and attributes while removing the secret cookie value from reports
fn redact_set_cookie(cookie: &str) -> String {
    let Some((name, rest)) = cookie.split_once('=') else {
        return "<redacted>".into();
    };
    let attrs = rest.find(';').map(|idx| &rest[idx..]).unwrap_or("");
    format!("{}=<redacted>{attrs}", name.trim())
}

// ── Exposed path check ───────────────────────────────────────────────────────

// Paths that commonly expose debug interfaces, API docs, or config
const DEBUG_PATHS: &[(&str, &str, &str)] = &[
    ("/swagger-ui.html", "low", "Swagger UI exposed"),
    ("/swagger-ui", "low", "Swagger UI exposed"),
    ("/swagger", "low", "Swagger endpoint exposed"),
    ("/api-docs", "low", "API documentation exposed"),
    ("/openapi.json", "low", "OpenAPI spec exposed"),
    ("/api/swagger.json", "low", "Swagger JSON spec exposed"),
    ("/v2/api-docs", "low", "Swagger v2 API docs exposed"),
    ("/actuator", "medium", "Spring Actuator root exposed"),
    (
        "/actuator/env",
        "high",
        "Spring Actuator /env exposes environment variables",
    ),
    (
        "/actuator/beans",
        "medium",
        "Spring Actuator /beans exposed",
    ),
    (
        "/actuator/heapdump",
        "high",
        "Spring Actuator /heapdump exposes JVM heap",
    ),
    ("/metrics", "low", "Metrics endpoint exposed"),
    ("/__debug", "medium", "Debug interface exposed"),
    ("/debug", "medium", "Debug interface exposed"),
    ("/console", "high", "Console interface exposed"),
    ("/_ah/admin", "high", "App Engine admin console exposed"),
    ("/.env", "high", ".env file exposed — may contain secrets"),
    ("/config.json", "medium", "config.json exposed"),
    ("/server-status", "low", "Apache server-status exposed"),
    ("/phpinfo.php", "medium", "phpinfo() output exposed"),
    ("/info.php", "medium", "phpinfo() output exposed"),
    (
        "/wp-json/wp/v2/users",
        "low",
        "WordPress user enumeration via REST API",
    ),
];

const MAX_ACTIVE_ENDPOINTS: usize = 80;
const MAX_ACTIVE_REQUESTS: usize = 240;
const XSS_MARKER: &str = "geist-xss-probe";
const SQLI_MARKER: &str = "'";
const OPEN_REDIRECT_TARGET: &str = "https://example.com/geistscope-open-redirect";
const REDIRECT_PARAMS: &[&str] = &[
    "url",
    "uri",
    "next",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_to",
    "continue",
    "target",
    "dest",
    "destination",
];
const DB_ERROR_PATTERNS: &[&str] = &[
    "SQLSTATE[",
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "pg_query():",
    "PostgreSQL query failed",
    "unterminated quoted string",
    "Microsoft OLE DB Provider for SQL Server",
    "SQLite/JDBCDriver",
    "sqlite3.OperationalError",
    "ORA-",
];

// Probe each known debug/exposure path; record any that return 200 or 403
pub async fn check_exposed_paths(client: &Client, base_url: &str, host: &str) -> Vec<ProbeIssue> {
    let base = base_url.trim_end_matches('/');
    let mut issues = Vec::new();

    for (path, severity, title) in DEBUG_PATHS {
        let url = format!("{base}{path}");
        let status = match client.get(&url).send().await {
            Ok(r) => r.status().as_u16(),
            Err(_) => continue,
        };
        // 200 = definitively exposed; 403 = exists but access controlled (worth noting)
        if status == 200 || status == 403 {
            issues.push(ProbeIssue {
                check: "exposed-paths".into(),
                host: host.into(),
                severity: if status == 403 { "info" } else { severity }.to_string(),
                title: title.to_string(),
                detail: format!("Path {path} returned HTTP {status}"),
                evidence: format!("GET {url} → {status}"),
            });
        }
    }

    issues
}

// Run low-volume active probes against crawled endpoint query parameters
pub async fn check_active_endpoint_params(
    client: &Client,
    base_url: &str,
    host: &str,
    crawl_host_dir: &Path,
    rate: Duration,
) -> Vec<ProbeIssue> {
    let endpoints = load_crawl_endpoints(crawl_host_dir);
    let mut issues = Vec::new();
    let mut requests = 0usize;
    let base = match Url::parse(base_url) {
        Ok(base) => base,
        Err(_) => return issues,
    };

    for endpoint in endpoints.iter().take(MAX_ACTIVE_ENDPOINTS) {
        let Some(url) = endpoint_url(&base, &endpoint.path) else {
            continue;
        };
        let params = query_param_names(&url);
        for param in params {
            if requests >= MAX_ACTIVE_REQUESTS {
                return issues;
            }

            if let Some(issue) =
                probe_reflected_marker(client, host, &url, &param, &endpoint.source_url).await
            {
                issues.push(issue);
            }
            requests += 1;
            tokio::time::sleep(rate).await;

            if requests >= MAX_ACTIVE_REQUESTS {
                return issues;
            }
            if let Some(issue) =
                probe_sql_error(client, host, &url, &param, &endpoint.source_url).await
            {
                issues.push(issue);
            }
            requests += 1;
            tokio::time::sleep(rate).await;
        }

        for param in redirect_params_for(&url) {
            if requests >= MAX_ACTIVE_REQUESTS {
                return issues;
            }
            if let Some(issue) =
                probe_open_redirect(client, &base, host, &url, param, &endpoint.source_url).await
            {
                issues.push(issue);
            }
            requests += 1;
            tokio::time::sleep(rate).await;
        }
    }

    issues
}

// Load crawler endpoint rows from endpoints.json
fn load_crawl_endpoints(crawl_host_dir: &Path) -> Vec<CrawlEndpoint> {
    let path = crawl_host_dir.join("endpoints.json");
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

// Resolve one crawler endpoint path against a base URL
fn endpoint_url(base: &Url, path: &str) -> Option<Url> {
    if let Ok(url) = Url::parse(path) {
        return Some(url);
    }
    base.join(path).ok()
}

// Return unique query parameter names
fn query_param_names(url: &Url) -> Vec<String> {
    let mut seen = HashSet::new();
    url.query_pairs()
        .filter_map(|(key, _)| {
            let key = key.to_string();
            seen.insert(key.clone()).then_some(key)
        })
        .collect()
}

// Return redirect parameter candidates for a URL
fn redirect_params_for(url: &Url) -> Vec<&'static str> {
    let existing = query_param_names(url);
    let existing_redirects: Vec<&'static str> = REDIRECT_PARAMS
        .iter()
        .copied()
        .filter(|param| existing.iter().any(|key| key.eq_ignore_ascii_case(param)))
        .collect();
    if !existing_redirects.is_empty() {
        return existing_redirects;
    }

    let path = url.path().to_lowercase();
    if path.contains("redirect")
        || path.contains("login")
        || path.contains("oauth")
        || path.contains("callback")
    {
        return vec!["next", "redirect_uri", "return_to"];
    }
    Vec::new()
}

// Return a mutated copy of a URL with one query value replaced
fn mutated_param_url(url: &Url, param: &str, value: &str) -> Url {
    let mut mutated = url.clone();
    let mut pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(key, val)| {
            if key == param {
                (key.to_string(), value.to_string())
            } else {
                (key.to_string(), val.to_string())
            }
        })
        .collect();
    if !pairs.iter().any(|(key, _)| key == param) {
        pairs.push((param.to_string(), value.to_string()));
    }
    mutated.query_pairs_mut().clear().extend_pairs(pairs);
    mutated
}

// Probe one parameter with a harmless marker and report reflection
async fn probe_reflected_marker(
    client: &Client,
    host: &str,
    url: &Url,
    param: &str,
    source_url: &str,
) -> Option<ProbeIssue> {
    let mutated = mutated_param_url(url, param, XSS_MARKER);
    let body = fetch_body(client, mutated.as_str()).await?;
    if !body.contains(XSS_MARKER) {
        return None;
    }
    Some(ProbeIssue {
        check: "active-reflection".into(),
        host: host.into(),
        severity: "medium".into(),
        title: format!("Reflected input marker in parameter '{param}'"),
        detail: "A harmless marker was reflected in the response. This is not an execution proof, but it is a candidate reflected XSS or HTML injection sink.".into(),
        evidence: format!("GET {mutated}\nsource: {source_url}\nmarker: {XSS_MARKER}"),
    })
}

// Probe one parameter with a single quote and report database errors
async fn probe_sql_error(
    client: &Client,
    host: &str,
    url: &Url,
    param: &str,
    source_url: &str,
) -> Option<ProbeIssue> {
    let mutated = mutated_param_url(url, param, SQLI_MARKER);
    let body = fetch_body(client, mutated.as_str()).await?;
    let pattern = db_error_match(&body)?;
    Some(ProbeIssue {
        check: "active-sqli-error".into(),
        host: host.into(),
        severity: "high".into(),
        title: format!("Database error after single-quote probe in '{param}'"),
        detail: "A single-quote probe caused a database error string in the response. No UNION, stacked-query, or destructive payloads were sent.".into(),
        evidence: format!("GET {mutated}\nsource: {source_url}\nmatched: {pattern}"),
    })
}

// Probe one redirect parameter without following the redirect
async fn probe_open_redirect(
    client: &Client,
    base: &Url,
    host: &str,
    url: &Url,
    param: &str,
    source_url: &str,
) -> Option<ProbeIssue> {
    let mutated = mutated_param_url(url, param, OPEN_REDIRECT_TARGET);
    let resp = client.get(mutated.as_str()).send().await.ok()?;
    if !resp.status().is_redirection() {
        return None;
    }
    let location = resp.headers().get("location")?.to_str().ok()?;
    let destination = url.join(location).ok()?;
    if !is_off_origin(base, &destination) {
        return None;
    }
    Some(ProbeIssue {
        check: "active-open-redirect".into(),
        host: host.into(),
        severity: "medium".into(),
        title: format!("Open redirect candidate in parameter '{param}'"),
        detail: "A redirect parameter accepted an off-origin URL. The active client did not follow the redirect.".into(),
        evidence: format!(
            "GET {mutated}\nsource: {source_url}\nLocation: {location}"
        ),
    })
}

// Fetch response body text for active probes
async fn fetch_body(client: &Client, url: &str) -> Option<String> {
    let resp = client.get(url).send().await.ok()?;
    resp.text().await.ok()
}

// Return matched database error marker
fn db_error_match(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    DB_ERROR_PATTERNS
        .iter()
        .copied()
        .find(|pattern| lower.contains(&pattern.to_lowercase()))
}

// Return true when a redirect destination leaves the original origin
fn is_off_origin(base: &Url, destination: &Url) -> bool {
    matches!(destination.scheme(), "http" | "https") && destination.host_str() != base.host_str()
}

// ── HTML content analysis ────────────────────────────────────────────────────

// Regex patterns that suggest stack traces or sensitive disclosures in HTML
const STACK_TRACE_PATTERNS: &[(&str, &str)] = &[
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at java\.[a-z]", "Java stack trace"),
    (r"NullPointerException", "Java NPE in response"),
    (r"RuntimeException", "Java RuntimeException in response"),
    (r"ActiveRecord::[A-Z]", "Rails/ActiveRecord exception"),
    (r"ActionController::[A-Z]", "Rails controller exception"),
    (r"Django Version:", "Django debug page exposed"),
    (r"Error in file .+ on line \d+", "PHP error in response"),
    (r"SQLSTATE\[", "SQL error message in response"),
    (r"Warning: mysql_", "PHP MySQL warning in response"),
    (r"ORA-\d{5}", "Oracle DB error in response"),
    (r"pg_query\(\):", "PostgreSQL error in response"),
];

// Scan stored crawl HTML files for stack traces and sensitive disclosures
pub fn check_html_files(
    crawl_host_dir: &std::path::Path,
    host: &str,
    index: &serde_json::Value,
) -> Vec<ProbeIssue> {
    use regex::Regex;

    let patterns: Vec<(&str, Regex)> = STACK_TRACE_PATTERNS
        .iter()
        .filter_map(|(pat, label)| Regex::new(pat).ok().map(|r| (*label, r)))
        .collect();

    let pages_dir = crawl_host_dir.join("pages");
    if !pages_dir.exists() {
        return vec![];
    }

    let mut issues = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // iterate each URL→hash pair in the index
    let Some(pages) = index.get("pages").and_then(|p| p.as_object()) else {
        return vec![];
    };

    for (url, hash_val) in pages {
        let hash = hash_val.as_str().unwrap_or("");
        if !is_sha256_hex(hash) {
            continue;
        }
        let page_path = pages_dir.join(format!("{hash}.html"));
        let Ok(html) = std::fs::read_to_string(&page_path) else {
            continue;
        };

        for (label, re) in &patterns {
            if re.is_match(&html) && seen.insert(label.to_string()) {
                // find the matching line for evidence
                let evidence_line = html
                    .lines()
                    .find(|l| re.is_match(l))
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>();

                issues.push(ProbeIssue {
                    check: "html-analysis".into(),
                    host: host.into(),
                    severity: "low".into(),
                    title: format!("{label} found in crawl output"),
                    detail: format!("Matched in page: {url}"),
                    evidence: evidence_line,
                });
            }
        }
    }

    issues
}

// Crawl page filenames are SHA-256 hex digests; reject tampered index paths
fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a crawl index JSON with one page entry
    fn make_index(url: &str, hash: &str) -> serde_json::Value {
        serde_json::json!({ "pages": { url: hash } })
    }

    #[test]
    fn html_check_finds_stack_trace() {
        let dir = tempfile::tempdir().unwrap();
        let pages = dir.path().join("pages");
        std::fs::create_dir_all(&pages).unwrap();
        let hash = "a".repeat(64);
        std::fs::write(
            pages.join(format!("{hash}.html")),
            "Traceback (most recent call last):\n  File x.py",
        )
        .unwrap();
        let index = make_index("https://example.com/crash", &hash);
        let issues = check_html_files(dir.path(), "example.com", &index);
        assert!(issues.iter().any(|i| i.check == "html-analysis"));
    }

    #[test]
    fn html_check_clean_page_no_issues() {
        let dir = tempfile::tempdir().unwrap();
        let pages = dir.path().join("pages");
        std::fs::create_dir_all(&pages).unwrap();
        let hash = "d".repeat(64);
        std::fs::write(
            pages.join(format!("{hash}.html")),
            "<html><body>Hello</body></html>",
        )
        .unwrap();
        let index = make_index("https://example.com/", &hash);
        let issues = check_html_files(dir.path(), "example.com", &index);
        assert!(issues.is_empty());
    }

    #[test]
    fn html_check_ignores_tampered_index_paths() {
        let dir = tempfile::tempdir().unwrap();
        let pages = dir.path().join("pages");
        std::fs::create_dir_all(&pages).unwrap();
        let index = make_index("https://example.com/crash", "../outside");
        let issues = check_html_files(dir.path(), "example.com", &index);
        assert!(issues.is_empty());
    }

    #[test]
    fn redacts_set_cookie_value_but_keeps_attributes() {
        let redacted = redact_set_cookie("session=secret-value; Path=/; HttpOnly");
        assert_eq!(redacted, "session=<redacted>; Path=/; HttpOnly");
        assert!(!redacted.contains("secret-value"));
    }

    #[test]
    fn active_mutation_replaces_existing_query_param() {
        let url = Url::parse("https://example.com/search?q=test&page=1").unwrap();
        let mutated = mutated_param_url(&url, "q", "probe");
        assert_eq!(
            mutated.as_str(),
            "https://example.com/search?q=probe&page=1"
        );
    }

    #[test]
    fn active_mutation_adds_missing_query_param() {
        let url = Url::parse("https://example.com/login").unwrap();
        let mutated = mutated_param_url(&url, "next", OPEN_REDIRECT_TARGET);
        assert_eq!(
            mutated.as_str(),
            "https://example.com/login?next=https%3A%2F%2Fexample.com%2Fgeistscope-open-redirect"
        );
    }

    #[test]
    fn db_error_patterns_match_case_insensitively() {
        assert_eq!(
            db_error_match("fatal: unterminated quoted string at or near"),
            Some("unterminated quoted string")
        );
    }

    #[test]
    fn off_origin_detects_external_redirects() {
        let base = Url::parse("https://example.com").unwrap();
        let same = Url::parse("https://example.com/path").unwrap();
        let external = Url::parse("https://attacker.test/path").unwrap();
        assert!(!is_off_origin(&base, &same));
        assert!(is_off_origin(&base, &external));
    }
}
