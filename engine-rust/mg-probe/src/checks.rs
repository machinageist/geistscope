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

use reqwest::Client;
use serde::{Deserialize, Serialize};

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

impl ProbeIssue {
    // Map our issue severity to the engagement Severity enum
    pub fn severity_enum(&self) -> Severity {
        match self.severity.as_str() {
            "critical" => Severity::Critical,
            "high"     => Severity::High,
            "medium"   => Severity::Medium,
            "low"      => Severity::Low,
            _          => Severity::Info,
        }
    }
}

// ── Security header check ────────────────────────────────────────────────────

// Required headers and their significance
const REQUIRED_HEADERS: &[(&str, &str, &str)] = &[
    ("content-security-policy",   "info",   "Content-Security-Policy header missing"),
    ("x-frame-options",           "info",   "X-Frame-Options header missing — clickjacking risk"),
    ("x-content-type-options",    "info",   "X-Content-Type-Options header missing — MIME sniffing risk"),
    ("referrer-policy",           "info",   "Referrer-Policy header missing"),
    ("permissions-policy",        "info",   "Permissions-Policy header missing"),
];

const HSTS_HEADER: &str = "strict-transport-security";

// Fetch the host root and report each missing security response header
pub async fn check_security_headers(client: &Client, base_url: &str, host: &str) -> Vec<ProbeIssue> {
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
            || (*name == "content-security-policy" && headers.contains_key("x-content-security-policy"));
        if !present {
            issues.push(ProbeIssue {
                check:    "security-headers".into(),
                host:     host.into(),
                severity: severity.to_string(),
                title:    title.to_string(),
                detail:   format!("Response from {base_url} does not include {name}"),
                evidence: format!("GET {base_url} → {}", resp.status().as_u16()),
            });
        }
    }

    // HSTS only meaningful over HTTPS
    if is_https && !headers.contains_key(HSTS_HEADER) {
        issues.push(ProbeIssue {
            check:    "security-headers".into(),
            host:     host.into(),
            severity: "low".into(),
            title:    "Strict-Transport-Security header missing".into(),
            detail:   format!("{base_url} is served over HTTPS but lacks HSTS"),
            evidence: format!("GET {base_url} → {}", resp.status().as_u16()),
        });
    }

    // server version disclosure check — flag if version number visible
    if let Some(srv) = headers.get("server").and_then(|v| v.to_str().ok())
        && srv.chars().any(|c| c.is_ascii_digit())
    {
        issues.push(ProbeIssue {
            check:    "version-disclosure".into(),
            host:     host.into(),
            severity: "info".into(),
            title:    "Server version disclosed in response header".into(),
            detail:   "Server header reveals version information".into(),
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
            check:    "cors".into(),
            host:     host.into(),
            severity: "medium".into(),
            title:    "CORS: wildcard Access-Control-Allow-Origin".into(),
            detail:   "Any origin may read cross-origin responses from this endpoint".into(),
            evidence: format!("Access-Control-Allow-Origin: {acao}"),
        });
    }

    // reflected origin + credentials = credentialed cross-origin reads (High)
    if acao == CORS_PROBE_ORIGIN && acac.eq_ignore_ascii_case("true") {
        issues.push(ProbeIssue {
            check:    "cors".into(),
            host:     host.into(),
            severity: "high".into(),
            title:    "CORS: arbitrary origin reflected with credentials".into(),
            detail:   "Attacker-controlled origin is reflected and credentials are allowed — \
                       credentialed cross-origin reads are possible".into(),
            evidence: format!(
                "Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}"
            ),
        });
    } else if acao == CORS_PROBE_ORIGIN {
        // reflected without credentials — lower severity
        issues.push(ProbeIssue {
            check:    "cors".into(),
            host:     host.into(),
            severity: "low".into(),
            title:    "CORS: arbitrary origin reflected (no credentials)".into(),
            detail:   "Attacker-controlled origin is reflected without allow-credentials".into(),
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
        let Ok(cookie_str) = val.to_str() else { continue };
        let lower = cookie_str.to_lowercase();

        // extract cookie name (before first = or ;)
        let name = cookie_str.split('=').next().unwrap_or("?").trim().to_string();
        if seen_names.contains(&name) { continue; }
        seen_names.insert(name.clone());

        // Secure flag required over HTTPS
        if is_https && !lower.contains("; secure") && !lower.contains(";secure") {
            issues.push(ProbeIssue {
                check:    "cookies".into(),
                host:     host.into(),
                severity: "medium".into(),
                title:    format!("Cookie '{name}' missing Secure flag"),
                detail:   "Cookie transmitted over HTTPS lacks the Secure attribute; \
                           may be transmitted over HTTP if the browser is redirected".into(),
                evidence: format!("Set-Cookie: {cookie_str}"),
            });
        }

        // HttpOnly flag prevents JS access to the cookie value
        if !lower.contains("; httponly") && !lower.contains(";httponly") {
            issues.push(ProbeIssue {
                check:    "cookies".into(),
                host:     host.into(),
                severity: "medium".into(),
                title:    format!("Cookie '{name}' missing HttpOnly flag"),
                detail:   "Cookie lacks the HttpOnly attribute; JavaScript running on the page \
                           can read its value (XSS amplification)".into(),
                evidence: format!("Set-Cookie: {cookie_str}"),
            });
        }

        // SameSite prevents CSRF cookie sending
        if !lower.contains("samesite=") {
            issues.push(ProbeIssue {
                check:    "cookies".into(),
                host:     host.into(),
                severity: "low".into(),
                title:    format!("Cookie '{name}' missing SameSite attribute"),
                detail:   "Cookie lacks SameSite; defaults to 'Lax' in modern browsers but \
                           explicit declaration is preferred and required for older browsers".into(),
                evidence: format!("Set-Cookie: {cookie_str}"),
            });
        }
    }

    issues
}

// ── Exposed path check ───────────────────────────────────────────────────────

// Paths that commonly expose debug interfaces, API docs, or config
const DEBUG_PATHS: &[(&str, &str, &str)] = &[
    ("/swagger-ui.html",       "low",    "Swagger UI exposed"),
    ("/swagger-ui",            "low",    "Swagger UI exposed"),
    ("/swagger",               "low",    "Swagger endpoint exposed"),
    ("/api-docs",              "low",    "API documentation exposed"),
    ("/openapi.json",          "low",    "OpenAPI spec exposed"),
    ("/api/swagger.json",      "low",    "Swagger JSON spec exposed"),
    ("/v2/api-docs",           "low",    "Swagger v2 API docs exposed"),
    ("/actuator",              "medium", "Spring Actuator root exposed"),
    ("/actuator/env",          "high",   "Spring Actuator /env exposes environment variables"),
    ("/actuator/beans",        "medium", "Spring Actuator /beans exposed"),
    ("/actuator/heapdump",     "high",   "Spring Actuator /heapdump exposes JVM heap"),
    ("/metrics",               "low",    "Metrics endpoint exposed"),
    ("/__debug",               "medium", "Debug interface exposed"),
    ("/debug",                 "medium", "Debug interface exposed"),
    ("/console",               "high",   "Console interface exposed"),
    ("/_ah/admin",             "high",   "App Engine admin console exposed"),
    ("/.env",                  "high",   ".env file exposed — may contain secrets"),
    ("/config.json",           "medium", "config.json exposed"),
    ("/server-status",         "low",    "Apache server-status exposed"),
    ("/phpinfo.php",           "medium", "phpinfo() output exposed"),
    ("/info.php",              "medium", "phpinfo() output exposed"),
    ("/wp-json/wp/v2/users",   "low",    "WordPress user enumeration via REST API"),
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
                check:    "exposed-paths".into(),
                host:     host.into(),
                severity: if status == 403 { "info" } else { severity }.to_string(),
                title:    title.to_string(),
                detail:   format!("Path {path} returned HTTP {status}"),
                evidence: format!("GET {url} → {status}"),
            });
        }
    }

    issues
}

// ── HTML content analysis ────────────────────────────────────────────────────

// Regex patterns that suggest stack traces or sensitive disclosures in HTML
const STACK_TRACE_PATTERNS: &[(&str, &str)] = &[
    (r"Traceback \(most recent call last\)",  "Python stack trace"),
    (r"at java\.[a-z]",                       "Java stack trace"),
    (r"NullPointerException",                  "Java NPE in response"),
    (r"RuntimeException",                      "Java RuntimeException in response"),
    (r"ActiveRecord::[A-Z]",                  "Rails/ActiveRecord exception"),
    (r"ActionController::[A-Z]",              "Rails controller exception"),
    (r"Django Version:",                       "Django debug page exposed"),
    (r"Error in file .+ on line \d+",         "PHP error in response"),
    (r"SQLSTATE\[",                            "SQL error message in response"),
    (r"Warning: mysql_",                       "PHP MySQL warning in response"),
    (r"ORA-\d{5}",                            "Oracle DB error in response"),
    (r"pg_query\(\):",                         "PostgreSQL error in response"),
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
    if !pages_dir.exists() { return vec![]; }

    let mut issues = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // iterate each URL→hash pair in the index
    let Some(pages) = index.get("pages").and_then(|p| p.as_object()) else {
        return vec![];
    };

    for (url, hash_val) in pages {
        let hash = hash_val.as_str().unwrap_or("");
        let page_path = pages_dir.join(format!("{hash}.html"));
        let Ok(html) = std::fs::read_to_string(&page_path) else { continue };

        for (label, re) in &patterns {
            if re.is_match(&html) && seen.insert(label.to_string()) {
                // find the matching line for evidence
                let evidence_line = html.lines()
                    .find(|l| re.is_match(l))
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(200)
                    .collect::<String>();

                issues.push(ProbeIssue {
                    check:    "html-analysis".into(),
                    host:     host.into(),
                    severity: "low".into(),
                    title:    format!("{label} found in crawl output"),
                    detail:   format!("Matched in page: {url}"),
                    evidence: evidence_line,
                });
            }
        }
    }

    issues
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
        let hash = "aabbcc";
        std::fs::write(pages.join(format!("{hash}.html")), "Traceback (most recent call last):\n  File x.py").unwrap();
        let index = make_index("https://example.com/crash", hash);
        let issues = check_html_files(dir.path(), "example.com", &index);
        assert!(issues.iter().any(|i| i.check == "html-analysis"));
    }

    #[test]
    fn html_check_clean_page_no_issues() {
        let dir = tempfile::tempdir().unwrap();
        let pages = dir.path().join("pages");
        std::fs::create_dir_all(&pages).unwrap();
        let hash = "ddeeff";
        std::fs::write(pages.join(format!("{hash}.html")), "<html><body>Hello</body></html>").unwrap();
        let index = make_index("https://example.com/", hash);
        let issues = check_html_files(dir.path(), "example.com", &index);
        assert!(issues.is_empty());
    }
}
