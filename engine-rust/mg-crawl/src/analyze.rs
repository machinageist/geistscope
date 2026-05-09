/*******************************************************************
 * Filename:        analyze.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Regex-based secret and endpoint extraction from JS content
 * Notes:           Regex-only approach; real AST parsing (oxc/swc) is v2.
 *                  Patterns tuned for high precision over recall — expect
 *                  false negatives on obfuscated code.
 *******************************************************************/

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// One matched secret candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMatch {
    pub pattern: String,
    pub value: String,
    pub source_url: String,
}

// One extracted API endpoint candidate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointMatch {
    pub path: String,
    pub source_url: String,
}

// Compiled regex catalog — initialized once, reused across all JS files
struct Catalog {
    secrets: Vec<(&'static str, Regex)>,
    endpoints: Vec<Regex>,
}

static CATALOG: OnceLock<Catalog> = OnceLock::new();

// Initialize the catalog exactly once; panics only at startup on regex syntax error
fn catalog() -> &'static Catalog {
    CATALOG.get_or_init(|| {
        let secrets = vec![
            // AWS access key ID
            ("aws-access-key",   Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
            // AWS secret access key (heuristic — 40 base64 chars after known prefixes)
            ("aws-secret-key",   Regex::new(r#"(?i)aws.{0,20}secret.{0,20}[=:]["']?\s*([A-Za-z0-9/+]{40})"#).unwrap()),
            // GitHub personal / fine-grained tokens
            ("github-token",     Regex::new(r"gh[pousr]_[A-Za-z0-9]{36,}").unwrap()),
            // JWT (three base64url segments)
            ("jwt",              Regex::new(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap()),
            // Slack bot / webhook tokens
            ("slack-token",      Regex::new(r"xox[baprs]-[0-9A-Za-z\-]{10,}").unwrap()),
            // Generic api_key / apikey assignment
            ("api-key",          Regex::new(r#"(?i)api[_-]?key\s*[=:]\s*["']([A-Za-z0-9_\-]{16,})"#).unwrap()),
            // Hardcoded password assignment
            ("password",         Regex::new(r#"(?i)password\s*[=:]\s*["']([^"']{8,})"#).unwrap()),
            // Private key header (PEM)
            ("private-key",      Regex::new(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----").unwrap()),
            // Google API key
            ("google-api-key",   Regex::new(r"AIza[0-9A-Za-z\-_]{35}").unwrap()),
            // Stripe secret key
            ("stripe-secret",    Regex::new(r"sk_(?:live|test)_[0-9A-Za-z]{24,}").unwrap()),
        ];

        // REST-style paths from fetch/axios/XHR calls
        let endpoints = vec![
            // fetch("/api/...) or fetch(`/api/...`)
            Regex::new(r#"fetch\s*\(\s*["'`](/[A-Za-z0-9_/\-\.?=&%]{2,})"#).unwrap(),
            // axios.get/post/put/delete("/api/...")
            Regex::new(r#"axios\.[a-z]+\s*\(\s*["'`](/[A-Za-z0-9_/\-\.?=&%]{2,})"#).unwrap(),
            // XMLHttpRequest .open("GET", "/api/...")
            Regex::new(r#"\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`](/[A-Za-z0-9_/\-\.?=&%]{2,})"#).unwrap(),
            // href="/api/..." in JS template strings
            Regex::new(r#"href\s*[:=]\s*["'`](/api/[A-Za-z0-9_/\-\.?=&%]{1,})"#).unwrap(),
        ];

        Catalog { secrets, endpoints }
    })
}

// Scan JS text for secret candidates; returns all matches deduplicated by value
pub fn find_secrets(js: &str, source_url: &str) -> Vec<SecretMatch> {
    let cat = catalog();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (name, re) in &cat.secrets {
        // use the first capture group if present, otherwise the full match
        for cap in re.captures_iter(js) {
            let value = cap.get(1)
                .or_else(|| cap.get(0))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if !value.is_empty() && seen.insert(value.clone()) {
                out.push(SecretMatch {
                    pattern: name.to_string(),
                    value,
                    source_url: source_url.to_string(),
                });
            }
        }
    }
    out
}

// Scan JS text for API endpoint paths; returns unique paths
pub fn find_endpoints(js: &str, source_url: &str) -> Vec<EndpointMatch> {
    let cat = catalog();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for re in &cat.endpoints {
        for cap in re.captures_iter(js) {
            // capture group 1 is the path
            if let Some(m) = cap.get(1) {
                let path = m.as_str().to_string();
                if seen.insert(path.clone()) {
                    out.push(EndpointMatch { path, source_url: source_url.to_string() });
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_aws_key() {
        let js = r#"const key = "AKIAIOSFODNN7EXAMPLE";"#;
        let hits = find_secrets(js, "https://example.com/app.js");
        assert!(hits.iter().any(|h| h.pattern == "aws-access-key"));
    }

    #[test]
    fn detects_github_token() {
        // 36 alphanumeric chars after ghp_ — minimum required by the pattern
        let js = r#"token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab""#;
        let hits = find_secrets(js, "https://example.com/app.js");
        assert!(hits.iter().any(|h| h.pattern == "github-token"));
    }

    #[test]
    fn detects_jwt() {
        let js = r#"auth = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c""#;
        let hits = find_secrets(js, "https://example.com/app.js");
        assert!(hits.iter().any(|h| h.pattern == "jwt"));
    }

    #[test]
    fn no_false_positive_on_clean_js() {
        let js = r#"function greet(name) { return "Hello " + name; }"#;
        let hits = find_secrets(js, "https://example.com/app.js");
        assert!(hits.is_empty());
    }

    #[test]
    fn detects_fetch_endpoint() {
        let js = r#"fetch("/api/v1/users")"#;
        let eps = find_endpoints(js, "https://example.com/app.js");
        assert!(eps.iter().any(|e| e.path == "/api/v1/users"));
    }

    #[test]
    fn detects_axios_endpoint() {
        let js = r#"axios.get("/api/orders?status=open")"#;
        let eps = find_endpoints(js, "https://example.com/app.js");
        assert!(eps.iter().any(|e| e.path.starts_with("/api/orders")));
    }

    #[test]
    fn deduplicates_repeated_matches() {
        let js = r#"fetch("/api/v1/users"); fetch("/api/v1/users");"#;
        let eps = find_endpoints(js, "https://example.com/app.js");
        assert_eq!(eps.iter().filter(|e| e.path == "/api/v1/users").count(), 1);
    }
}
