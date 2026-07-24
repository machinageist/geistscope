/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-secret-validate — classify and live-validate leaked secrets
 *                  Reads secrets from --secret args and crawl secrets.json files,
 *                  classifies them by regex, and probes known APIs to confirm validity.
 * Notes:           Secrets are masked to first 8 chars in all output.
 *                  AWS validation uses STS GetCallerIdentity without signing —
 *                  AuthFailure means the key exists but lacks permission (VALID).
 *                  Unknown-classified secrets are classified but not live-validated.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "secrets";
const AUDIT_TOOL: &str = "mg-secret-validate";
const MASK_LEN: usize = 8;

// AWS STS validation endpoint
const AWS_STS_URL: &str = "https://sts.amazonaws.com/";
const AWS_STS_BODY: &str = "Action=GetCallerIdentity&Version=2011-06-15&AWSAccessKeyId=";
const AWS_AUTH_FAILURE: &str = "AuthFailure";
const AWS_INVALID_TOKEN: &str = "InvalidClientTokenId";

// GitHub validation endpoint
const GITHUB_USER_URL: &str = "https://api.github.com/user";

// Stripe validation endpoint
const STRIPE_BALANCE_URL: &str = "https://api.stripe.com/v1/balance";

// Slack validation endpoint
const SLACK_AUTH_URL: &str = "https://slack.com/api/auth.test";

// Minimum length to classify an unrecognized string as Unknown
const UNKNOWN_MIN_LEN: usize = 20;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-secret-validate",
    about = "Classify and live-validate leaked secrets from crawl output or CLI args"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Explicit secret value(s) to validate (repeatable)
    #[arg(long = "secret", name = "secret")]
    secrets: Vec<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Classification of a secret string
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum SecretKind {
    AwsKey,
    GitHubToken,
    StripeKey,
    SlackToken,
    Unknown,
}

// Validation outcome
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
enum Validity {
    Valid,
    Invalid,
    Skipped,
    Error,
}

// One secret classification and validation result
#[derive(Debug, Serialize)]
struct SecretResult {
    masked: String,
    kind: SecretKind,
    validity: Validity,
    detail: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct ValidationOutput {
    engagement: String,
    timestamp: String,
    total: usize,
    valid_count: usize,
    results: Vec<SecretResult>,
}

// ── Regex registry ───────────────────────────────────────────────────────────

// Compiled regex patterns indexed by SecretKind
struct Pattern {
    kind: SecretKind,
    re: Regex,
}

// Return the lazily-compiled pattern list; ordered most-specific first
fn patterns() -> &'static Vec<Pattern> {
    static CELL: OnceLock<Vec<Pattern>> = OnceLock::new();
    CELL.get_or_init(|| {
        vec![
            Pattern {
                kind: SecretKind::AwsKey,
                re: Regex::new(r"^AKIA[0-9A-Z]{16}$").unwrap(),
            },
            Pattern {
                kind: SecretKind::GitHubToken,
                re: Regex::new(r"^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{36,})$").unwrap(),
            },
            Pattern {
                kind: SecretKind::StripeKey,
                re: Regex::new(r"^sk_(live|test)_[A-Za-z0-9]{24,}$").unwrap(),
            },
            Pattern {
                kind: SecretKind::SlackToken,
                re: Regex::new(r"^xox[baprs]-[0-9A-Za-z-]+$").unwrap(),
            },
        ]
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for use in filename
fn ts_for_filename(ts: &str) -> String {
    ts.chars().map(|c| if c == ':' { '_' } else { c }).collect()
}

// Mask a secret to its first MASK_LEN chars followed by ...
fn mask(secret: &str) -> String {
    if secret.len() <= MASK_LEN {
        format!("{}...", secret)
    } else {
        format!("{}...", &secret[..MASK_LEN])
    }
}

// Classify a secret string against the known patterns
fn classify(secret: &str) -> SecretKind {
    for pat in patterns() {
        if pat.re.is_match(secret) {
            return pat.kind.clone();
        }
    }
    if secret.len() > UNKNOWN_MIN_LEN {
        SecretKind::Unknown
    } else {
        // Too short to be meaningful — still Unknown but callers can filter
        SecretKind::Unknown
    }
}

// Collect secrets from crawl secrets.json files
fn collect_crawl_secrets(crawl_dir: &Path) -> Vec<String> {
    let mut secrets = Vec::new();
    let Ok(hosts) = fs::read_dir(crawl_dir) else {
        return secrets;
    };
    for entry in hosts.flatten() {
        let secrets_path = entry.path().join("secrets.json");
        let Ok(raw) = fs::read_to_string(&secrets_path) else {
            continue;
        };
        let Ok(arr): Result<Vec<String>, _> = serde_json::from_str(&raw) else {
            continue;
        };
        secrets.extend(arr);
    }
    secrets
}

// Validate an AWS key via STS GetCallerIdentity (no request signing required)
async fn validate_aws(client: &reqwest::Client, key: &str) -> (Validity, String) {
    let body = format!("{AWS_STS_BODY}{key}");
    let resp = client
        .post(AWS_STS_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await;
    match resp {
        Ok(r) => {
            let text = r.text().await.unwrap_or_default();
            if text.contains(AWS_AUTH_FAILURE) {
                (
                    Validity::Valid,
                    "STS AuthFailure — key exists, insufficient perms".into(),
                )
            } else if text.contains(AWS_INVALID_TOKEN) {
                (Validity::Invalid, "STS InvalidClientTokenId".into())
            } else {
                (
                    Validity::Error,
                    format!("unexpected STS response: {}", &text[..text.len().min(80)]),
                )
            }
        }
        Err(e) => (Validity::Error, e.to_string()),
    }
}

// Validate a GitHub token via /user
async fn validate_github(client: &reqwest::Client, token: &str) -> (Validity, String) {
    let resp = client
        .get(GITHUB_USER_URL)
        .header("Authorization", format!("token {token}"))
        .header("User-Agent", "mg-secret-validate/0.1")
        .send()
        .await;
    match resp {
        Ok(r) => {
            if r.status().as_u16() == 200 {
                (Validity::Valid, "GET /user returned 200".into())
            } else {
                (Validity::Invalid, format!("status {}", r.status().as_u16()))
            }
        }
        Err(e) => (Validity::Error, e.to_string()),
    }
}

// Validate a Stripe key via /v1/balance
async fn validate_stripe(client: &reqwest::Client, key: &str) -> (Validity, String) {
    let resp = client
        .get(STRIPE_BALANCE_URL)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await;
    match resp {
        Ok(r) => {
            if r.status().as_u16() == 200 {
                (Validity::Valid, "GET /v1/balance returned 200".into())
            } else {
                (Validity::Invalid, format!("status {}", r.status().as_u16()))
            }
        }
        Err(e) => (Validity::Error, e.to_string()),
    }
}

// Validate a Slack token via auth.test
async fn validate_slack(client: &reqwest::Client, token: &str) -> (Validity, String) {
    let resp = client
        .post(SLACK_AUTH_URL)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await;
    match resp {
        Ok(r) => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            if json["ok"].as_bool().unwrap_or(false) {
                (Validity::Valid, "auth.test ok=true".into())
            } else {
                let err = json["error"].as_str().unwrap_or("unknown").to_string();
                (Validity::Invalid, format!("auth.test ok=false error={err}"))
            }
        }
        Err(e) => (Validity::Error, e.to_string()),
    }
}

// Dispatch live validation by secret kind
async fn validate(client: &reqwest::Client, kind: &SecretKind, secret: &str) -> (Validity, String) {
    match kind {
        SecretKind::AwsKey => validate_aws(client, secret).await,
        SecretKind::GitHubToken => validate_github(client, secret).await,
        SecretKind::StripeKey => validate_stripe(client, secret).await,
        SecretKind::SlackToken => validate_slack(client, secret).await,
        SecretKind::Unknown => (
            Validity::Skipped,
            "unknown kind — skipping live validation".into(),
        ),
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Gather secrets from CLI + crawl
    let mut all_secrets: Vec<String> = args.secrets.clone();
    let crawl_dir = eng.crawl_dir();
    if crawl_dir.exists() {
        all_secrets.extend(collect_crawl_secrets(&crawl_dir));
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    all_secrets.retain(|s| seen.insert(s.clone()));

    eprintln!(
        "mg-secret-validate: {} unique secrets to process",
        all_secrets.len()
    );

    if all_secrets.is_empty() {
        eprintln!("mg-secret-validate: no secrets found — pass --secret or run mg-crawl first");
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .build()
        .context("build HTTP client")?;

    let mut results: Vec<SecretResult> = Vec::new();

    for secret in &all_secrets {
        let kind = classify(secret);
        let (validity, detail) = validate(&client, &kind, secret).await;
        let masked = mask(secret);

        // Print VALID in uppercase to make it stand out; INVALID in lowercase
        match &validity {
            Validity::Valid => eprintln!("  VALID   [{kind:?}] {masked} — {detail}"),
            Validity::Invalid => eprintln!("  invalid [{kind:?}] {masked} — {detail}"),
            Validity::Skipped => eprintln!("  skipped [{kind:?}] {masked}"),
            Validity::Error => eprintln!("  error   [{kind:?}] {masked} — {detail}"),
        }

        results.push(SecretResult {
            masked,
            kind,
            validity,
            detail,
        });
    }

    let valid_count = results
        .iter()
        .filter(|r| r.validity == Validity::Valid)
        .count();
    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = ValidationOutput {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        total: results.len(),
        valid_count,
        results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create secrets output dir")?;

    let results_path = output_dir.join(format!("validation-{ts_file}.json"));
    fs::write(
        &results_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write validation results JSON")?;

    eprintln!(
        "mg-secret-validate: {} total, {} valid — {}",
        output.total,
        output.valid_count,
        results_path.display()
    );

    // Write finding for each valid (live) secret
    for r in output
        .results
        .iter()
        .filter(|r| r.validity == Validity::Valid)
    {
        let tf = ToolFinding::new(
            "mg-secret-validate",
            "Valid Leaked Secret Confirmed",
            FindingSeverity::High,
        )
        .evidence(format!(
            "kind={:?} masked={} detail={}",
            r.kind, r.masked, r.detail
        ))
        .recommendation("Revoke and rotate the secret immediately; audit where it was exposed");
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "total={} valid={} ts={ts}",
            output.total, output.valid_count
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_aws_key() {
        assert_eq!(classify("AKIAIOSFODNN7EXAMPLE"), SecretKind::AwsKey);
    }

    #[test]
    fn classify_github_token_ghp() {
        let token = "ghp_".to_string() + &"A".repeat(36);
        assert_eq!(classify(&token), SecretKind::GitHubToken);
    }

    #[test]
    fn classify_github_pat() {
        let token = "github_pat_".to_string() + &"A".repeat(40);
        assert_eq!(classify(&token), SecretKind::GitHubToken);
    }

    #[test]
    fn classify_stripe_live() {
        let key = "sk_live_".to_string() + &"A".repeat(24);
        assert_eq!(classify(&key), SecretKind::StripeKey);
    }

    #[test]
    fn classify_stripe_test() {
        let key = "sk_test_".to_string() + &"B".repeat(24);
        assert_eq!(classify(&key), SecretKind::StripeKey);
    }

    #[test]
    fn classify_slack_bot() {
        assert_eq!(classify("xoxb-12345-67890-abcdef"), SecretKind::SlackToken);
    }

    #[test]
    fn classify_unknown_for_long_unrecognized() {
        let secret = "z".repeat(30);
        assert_eq!(classify(&secret), SecretKind::Unknown);
    }

    #[test]
    fn mask_truncates_to_eight_chars() {
        let m = mask("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(&m[..MASK_LEN], "AKIAIOSF");
        assert!(m.ends_with("..."));
    }

    #[test]
    fn mask_short_secret_appends_dots() {
        let m = mask("short");
        assert!(m.ends_with("..."));
    }

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(
            ts_for_filename("2026-05-17T10:00:00Z"),
            "2026-05-17T10_00_00Z"
        );
    }

    #[test]
    fn collect_crawl_secrets_returns_empty_for_missing_dir() {
        let dir = Path::new("/tmp/mg-sv-no-such-dir-xyz");
        assert!(collect_crawl_secrets(dir).is_empty());
    }
}
