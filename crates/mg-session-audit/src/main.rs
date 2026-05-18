/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-session-audit — session management security auditor
 *                  Tests session fixation, cookie security flags, token entropy,
 *                  and session invalidation on logout.
 * Notes:           Cookie handling uses reqwest's built-in cookie store.
 *                  Set-Cookie headers are also parsed manually for flag inspection
 *                  since reqwest's cookie jar hides the original attributes.
 *                  Entropy check is approximate: token length and sequential detection.
 *******************************************************************/

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "session-audit";
const AUDIT_TOOL: &str = "mg-session-audit";
const USER_AGENT: &str = "mg-session-audit/0.1 (security scanner)";

// Known session cookie names to look for in Set-Cookie headers
const SESSION_COOKIE_NAMES: &[&str] = &[
    "session",
    "sessionid",
    "sid",
    "connect.sid",
    "phpsessid",
    "jsessionid",
    "asp.net_sessionid",
    "auth",
    "token",
];

// Value pre-planted before login to test fixation
const FIXATION_VALUE: &str = "FIXEDVALUE_MGTEST_12345";

// Minimum acceptable session token length in characters
const MIN_TOKEN_LENGTH: usize = 16;

// Number of sessions to collect for entropy analysis
const ENTROPY_SAMPLE_COUNT: usize = 10;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-session-audit",
    about = "Session management auditor — fixation, flags, entropy, invalidation"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Login endpoint URL
    #[arg(long)]
    login_url: String,

    /// Logout endpoint URL
    #[arg(long)]
    logout_url: String,

    /// Form field name for username
    #[arg(long, default_value = "username")]
    field_user: String,

    /// Form field name for password
    #[arg(long, default_value = "password")]
    field_pass: String,

    /// Username for login
    #[arg(long, default_value = "")]
    username: String,

    /// Password for login
    #[arg(long, default_value = "")]
    password: String,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Severity level of a session audit finding
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
enum Severity {
    High,
    Medium,
    Low,
    Info,
}

// One session audit finding
#[derive(Debug, Serialize)]
struct AuditFinding {
    check: String,
    severity: Severity,
    detail: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SessionAuditResults {
    engagement: String,
    timestamp: String,
    login_url: String,
    logout_url: String,
    high_count: usize,
    medium_count: usize,
    low_count: usize,
    findings: Vec<AuditFinding>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize a timestamp string for use in a filename (colons -> underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Build a new reqwest client with a fresh cookie store
fn build_client(timeout: u64) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .build()
        .context("build HTTP client")
}

// Parse Set-Cookie header values from a response, returning a map of name -> raw header value
fn parse_set_cookies(resp: &reqwest::Response) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for val in resp.headers().get_all("set-cookie") {
        if let Ok(s) = val.to_str() {
            // Cookie name is the part before the first '='
            if let Some(eq_pos) = s.find('=') {
                let name = s[..eq_pos].trim().to_lowercase();
                cookies.insert(name, s.to_string());
            }
        }
    }
    cookies
}

// Extract cookie value (the part between '=' and the first ';') from a raw Set-Cookie string
fn cookie_value_from_raw(raw: &str) -> &str {
    let after_eq = match raw.find('=') {
        Some(pos) => &raw[pos + 1..],
        None => return "",
    };
    match after_eq.find(';') {
        Some(pos) => after_eq[..pos].trim(),
        None => after_eq.trim(),
    }
}

// Check if a raw Set-Cookie string has the HttpOnly flag
fn has_httponly(raw: &str) -> bool {
    raw.to_lowercase().contains("httponly")
}

// Check if a raw Set-Cookie string has the Secure flag
fn has_secure(raw: &str) -> bool {
    raw.to_lowercase().contains("; secure")
        || raw.to_lowercase().ends_with("secure")
}

// Check if a raw Set-Cookie string has a SameSite attribute
fn has_samesite(raw: &str) -> bool {
    raw.to_lowercase().contains("samesite")
}

// Detect if a session cookie name is a known session identifier
fn is_session_cookie(name: &str) -> bool {
    let lower = name.to_lowercase();
    SESSION_COOKIE_NAMES.iter().any(|n| lower == *n || lower.contains(n))
}

// Send form POST credentials and return the response
async fn post_login(
    client: &reqwest::Client,
    url: &str,
    field_user: &str,
    field_pass: &str,
    username: &str,
    password: &str,
) -> Result<reqwest::Response> {
    let mut params = HashMap::new();
    params.insert(field_user, username);
    params.insert(field_pass, password);

    client
        .post(url)
        .form(&params)
        .send()
        .await
        .context("POST login")
}

// ── Check implementations ────────────────────────────────────────────────────

// Check session fixation: plant a cookie before login, verify it changes post-login
async fn check_fixation(
    login_url: &str,
    field_user: &str,
    field_pass: &str,
    username: &str,
    password: &str,
    timeout: u64,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // Build a client; plant the fixation cookie in the initial request
    let client = match build_client(timeout) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    // GET the login page first to establish a baseline session, then override
    let _ = client.get(login_url).send().await;

    // Now POST with a manually-set Cookie header to plant our fixed value
    // We use a separate raw client for this (cookie_store would override our planted value)
    let raw_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let mut params = HashMap::new();
    params.insert(field_user, username);
    params.insert(field_pass, password);

    let resp = raw_client
        .post(login_url)
        .header("Cookie", format!("session={FIXATION_VALUE}"))
        .form(&params)
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let set_cookies = parse_set_cookies(&resp);
    let mut fixated = false;

    for (name, raw) in &set_cookies {
        if !is_session_cookie(name) {
            continue;
        }
        let new_value = cookie_value_from_raw(raw);
        if new_value == FIXATION_VALUE {
            fixated = true;
        }
    }

    // Only flag if we got a Set-Cookie in the response (login appeared to succeed)
    if !set_cookies.is_empty() && fixated {
        findings.push(AuditFinding {
            check: "session_fixation".into(),
            severity: Severity::High,
            detail: format!(
                "session cookie value did not rotate after login at {login_url}; \
                 pre-login value was preserved"
            ),
        });
    } else if set_cookies.is_empty() {
        findings.push(AuditFinding {
            check: "session_fixation".into(),
            severity: Severity::Info,
            detail: format!(
                "no Set-Cookie in login response at {login_url}; \
                 fixation check inconclusive (credentials may be incorrect)"
            ),
        });
    }

    findings
}

// Check cookie security flags in Set-Cookie headers returned by the login endpoint
async fn check_cookie_flags(
    login_url: &str,
    field_user: &str,
    field_pass: &str,
    username: &str,
    password: &str,
    timeout: u64,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let client = match build_client(timeout) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let resp = match post_login(&client, login_url, field_user, field_pass, username, password).await
    {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let is_https = login_url.starts_with("https://");
    let set_cookies = parse_set_cookies(&resp);

    for (name, raw) in &set_cookies {
        if !is_session_cookie(name) {
            continue;
        }

        if !has_httponly(raw) {
            findings.push(AuditFinding {
                check: "cookie_httponly".into(),
                severity: Severity::Medium,
                detail: format!("cookie '{name}' is missing the HttpOnly flag — accessible via JavaScript"),
            });
        }

        if is_https && !has_secure(raw) {
            findings.push(AuditFinding {
                check: "cookie_secure".into(),
                severity: Severity::Medium,
                detail: format!(
                    "cookie '{name}' is missing the Secure flag on an HTTPS endpoint — \
                     may be transmitted over HTTP"
                ),
            });
        }

        if !has_samesite(raw) {
            findings.push(AuditFinding {
                check: "cookie_samesite".into(),
                severity: Severity::Low,
                detail: format!("cookie '{name}' is missing the SameSite attribute — CSRF risk"),
            });
        }
    }

    findings
}

// Collect ENTROPY_SAMPLE_COUNT tokens by logging in repeatedly, return them
async fn collect_session_tokens(
    login_url: &str,
    field_user: &str,
    field_pass: &str,
    username: &str,
    password: &str,
    timeout: u64,
) -> Vec<String> {
    let mut tokens = Vec::new();
    for _ in 0..ENTROPY_SAMPLE_COUNT {
        let client = match build_client(timeout) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let resp = match post_login(&client, login_url, field_user, field_pass, username, password)
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };
        let set_cookies = parse_set_cookies(&resp);
        for (name, raw) in &set_cookies {
            if is_session_cookie(name) {
                let value = cookie_value_from_raw(raw).to_string();
                if !value.is_empty() {
                    tokens.push(value);
                    break;
                }
            }
        }
    }
    tokens
}

// Analyze collected tokens for entropy indicators
fn check_token_entropy(tokens: &[String]) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    if tokens.is_empty() {
        findings.push(AuditFinding {
            check: "token_entropy".into(),
            severity: Severity::Info,
            detail: "could not collect session tokens — entropy check skipped".into(),
        });
        return findings;
    }

    // Check minimum length
    for token in tokens {
        if token.len() < MIN_TOKEN_LENGTH {
            findings.push(AuditFinding {
                check: "token_entropy_length".into(),
                severity: Severity::High,
                detail: format!(
                    "session token length {} is below minimum {} — low entropy",
                    token.len(),
                    MIN_TOKEN_LENGTH
                ),
            });
            break; // One finding is enough — all tokens are likely short
        }
    }

    // Check for sequential tokens: sort and check if consecutive tokens differ by 1
    if tokens.len() >= 2 {
        let mut numeric_tokens: Vec<u64> = tokens
            .iter()
            .filter_map(|t| t.parse::<u64>().ok())
            .collect();
        if !numeric_tokens.is_empty() && numeric_tokens.len() == tokens.len() {
            numeric_tokens.sort();
            let sequential = numeric_tokens
                .windows(2)
                .all(|w| w[1].saturating_sub(w[0]) <= 10);
            if sequential {
                findings.push(AuditFinding {
                    check: "token_entropy_sequential".into(),
                    severity: Severity::High,
                    detail: format!(
                        "session tokens appear sequential (numeric, range: {}-{}) — predictable",
                        numeric_tokens.first().unwrap_or(&0),
                        numeric_tokens.last().unwrap_or(&0)
                    ),
                });
            }
        }
    }

    findings
}

// Check session invalidation: logout, then replay old session cookie
async fn check_invalidation(
    login_url: &str,
    logout_url: &str,
    field_user: &str,
    field_pass: &str,
    username: &str,
    password: &str,
    timeout: u64,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // Log in, capture session cookie
    let client = match build_client(timeout) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let login_resp =
        match post_login(&client, login_url, field_user, field_pass, username, password).await {
            Ok(r) => r,
            Err(_) => return findings,
        };

    let set_cookies = parse_set_cookies(&login_resp);
    let mut old_cookie_header = String::new();

    for (name, raw) in &set_cookies {
        if is_session_cookie(name) {
            let value = cookie_value_from_raw(raw);
            old_cookie_header = format!("{name}={value}");
            break;
        }
    }

    if old_cookie_header.is_empty() {
        findings.push(AuditFinding {
            check: "session_invalidation".into(),
            severity: Severity::Info,
            detail: "no session cookie captured at login — invalidation check skipped".into(),
        });
        return findings;
    }

    // Logout (use the same client so cookie jar is sent)
    let _ = client.get(logout_url).send().await;

    // Replay old session cookie to the login URL (or a protected page)
    let raw_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout))
        .user_agent(USER_AGENT)
        .danger_accept_invalid_certs(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let replay_resp = raw_client
        .get(login_url)
        .header("Cookie", &old_cookie_header)
        .send()
        .await;

    if let Ok(r) = replay_resp
        && r.status().as_u16() == 200
    {
        findings.push(AuditFinding {
            check: "session_invalidation".into(),
            severity: Severity::High,
            detail: format!(
                "old session cookie returned 200 after logout at {logout_url} — \
                 session not invalidated server-side"
            ),
        });
    }

    findings
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!(
        "mg-session-audit: login={} logout={}",
        args.login_url, args.logout_url
    );

    let mut all_findings: Vec<AuditFinding> = Vec::new();

    // Run checks sequentially — session state must not bleed between checks
    eprintln!("  checking session fixation...");
    let mut fixation = check_fixation(
        &args.login_url,
        &args.field_user,
        &args.field_pass,
        &args.username,
        &args.password,
        args.timeout,
    )
    .await;
    all_findings.append(&mut fixation);

    eprintln!("  checking cookie flags...");
    let mut flags = check_cookie_flags(
        &args.login_url,
        &args.field_user,
        &args.field_pass,
        &args.username,
        &args.password,
        args.timeout,
    )
    .await;
    all_findings.append(&mut flags);

    // Entropy check requires credentials to be set
    if !args.username.is_empty() && !args.password.is_empty() {
        eprintln!("  collecting {} tokens for entropy analysis...", ENTROPY_SAMPLE_COUNT);
        let tokens = collect_session_tokens(
            &args.login_url,
            &args.field_user,
            &args.field_pass,
            &args.username,
            &args.password,
            args.timeout,
        )
        .await;
        let mut entropy = check_token_entropy(&tokens);
        all_findings.append(&mut entropy);
    }

    eprintln!("  checking session invalidation on logout...");
    let mut invalidation = check_invalidation(
        &args.login_url,
        &args.logout_url,
        &args.field_user,
        &args.field_pass,
        &args.username,
        &args.password,
        args.timeout,
    )
    .await;
    all_findings.append(&mut invalidation);

    // Summarize by severity
    let high_count = all_findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = all_findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = all_findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();

    for f in &all_findings {
        eprintln!("  [{:?}] {} — {}", f.severity, f.check, f.detail);
    }

    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = SessionAuditResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        login_url: args.login_url.clone(),
        logout_url: args.logout_url.clone(),
        high_count,
        medium_count,
        low_count,
        findings: all_findings,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create session-audit output dir")?;

    let results_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write session-audit results")?;

    eprintln!(
        "mg-session-audit: HIGH={} MEDIUM={} LOW={} — {}",
        high_count,
        medium_count,
        low_count,
        results_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "high={high_count} medium={medium_count} low={low_count} ts={ts}"
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-18T08:00:00Z"),
            "2026-05-18T08_00_00Z"
        );
    }

    #[test]
    fn cookie_value_from_raw_extracts_value() {
        let raw = "session=abc123xyz; Path=/; HttpOnly; Secure";
        assert_eq!(cookie_value_from_raw(raw), "abc123xyz");
    }

    #[test]
    fn cookie_value_from_raw_no_semicolon() {
        let raw = "session=abc123xyz";
        assert_eq!(cookie_value_from_raw(raw), "abc123xyz");
    }

    #[test]
    fn has_httponly_detects_flag() {
        assert!(has_httponly("session=abc; HttpOnly; Secure"));
        assert!(!has_httponly("session=abc; Secure"));
    }

    #[test]
    fn has_secure_detects_flag() {
        assert!(has_secure("session=abc; Path=/; Secure"));
        assert!(!has_secure("session=abc; Path=/; HttpOnly"));
    }

    #[test]
    fn has_samesite_detects_attribute() {
        assert!(has_samesite("session=abc; SameSite=Strict"));
        assert!(!has_samesite("session=abc; HttpOnly"));
    }

    #[test]
    fn is_session_cookie_recognizes_common_names() {
        assert!(is_session_cookie("session"));
        assert!(is_session_cookie("PHPSESSID"));
        assert!(is_session_cookie("connect.sid"));
        assert!(!is_session_cookie("theme"));
        assert!(!is_session_cookie("lang"));
    }

    #[test]
    fn check_token_entropy_flags_short_tokens() {
        let tokens = vec!["abc".to_string(), "def".to_string()];
        let findings = check_token_entropy(&tokens);
        assert!(findings
            .iter()
            .any(|f| f.check == "token_entropy_length" && f.severity == Severity::High));
    }

    #[test]
    fn check_token_entropy_flags_sequential_numeric_tokens() {
        let tokens: Vec<String> = (1000u64..1010).map(|n| n.to_string()).collect();
        let findings = check_token_entropy(&tokens);
        assert!(findings
            .iter()
            .any(|f| f.check == "token_entropy_sequential"));
    }

    #[test]
    fn check_token_entropy_no_findings_on_good_tokens() {
        let tokens = vec![
            "f3a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5".to_string(),
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d".to_string(),
        ];
        // Tokens are 32 chars (OK length) and non-numeric (no sequential check applies)
        let findings = check_token_entropy(&tokens);
        assert!(!findings
            .iter()
            .any(|f| f.severity == Severity::High));
    }

    #[test]
    fn check_token_entropy_empty_returns_info() {
        let findings = check_token_entropy(&[]);
        assert!(findings.iter().any(|f| f.severity == Severity::Info));
    }
}
