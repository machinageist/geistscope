/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-breach — HIBP v3 breach lookup for a domain.
 * Notes:           API key is mandatory; exits with instructions if missing.
 *                  Fetches breach detail for each breach name that contains
 *                  password data. Rate-limit: HIBP free tier allows ~1 req/1.5s.
 *******************************************************************/

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const HIBP_BASE: &str = "https://haveibeenpwned.com/api/v3";
const OUTPUT_SUBDIR: &str = "breach";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-breach";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// HIBP free tier: ~1 req per 1.5 seconds
const HIBP_RATE_MS: u64 = 1_600;
const DATA_CLASS_PASSWORDS: &str = "Passwords";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-breach",
    about = "HIBP v3 breach data lookup — requires an API key"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Domain to look up breaches for
    #[arg(long)]
    domain: String,

    /// HIBP API key (or set $MG_HIBP_KEY)
    #[arg(long, env = "MG_HIBP_KEY")]
    api_key: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// HIBP breach detail response
#[derive(Debug, Deserialize)]
struct BreachDetail {
    #[serde(rename = "DataClasses", default)]
    data_classes: Vec<String>,
}

// Per-breach entry in our output
#[derive(Debug, Serialize)]
struct BreachEntry {
    name: String,
    email_count: usize,
    has_passwords: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct BreachResults {
    engagement: String,
    timestamp: String,
    domain: String,
    total_accounts: usize,
    has_passwords: bool,
    breaches: Vec<BreachEntry>,
}

// ── HIBP helpers ──────────────────────────────────────────────────────────────

// Fetch breached accounts for a domain; returns map of email-prefix -> breach names
async fn fetch_breached_domain(
    client: &reqwest::Client,
    domain: &str,
    api_key: &str,
) -> Result<HashMap<String, Vec<String>>> {
    let url = format!("{HIBP_BASE}/breacheddomain/{domain}");
    let resp = client
        .get(&url)
        .header("hibp-api-key", api_key)
        .send()
        .await
        .context("HIBP breacheddomain request")?;

    let status = resp.status();
    // 404 means domain has no breaches
    if status.as_u16() == 404 {
        return Ok(HashMap::new());
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        bail!("HIBP returned {status}: {body}");
    }

    let map: HashMap<String, Vec<String>> = resp.json().await.context("parse HIBP domain JSON")?;
    Ok(map)
}

// Fetch breach detail and check if it contains password data
async fn breach_has_passwords(client: &reqwest::Client, breach_name: &str, api_key: &str) -> bool {
    let url = format!("{HIBP_BASE}/breach/{breach_name}");
    let resp = client
        .get(&url)
        .header("hibp-api-key", api_key)
        .send()
        .await;

    let Ok(resp) = resp else { return false };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(detail) = resp.json::<BreachDetail>().await else {
        return false;
    };
    detail
        .data_classes
        .iter()
        .any(|c| c == DATA_CLASS_PASSWORDS)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let api_key = match args.api_key {
        Some(k) => k,
        None => {
            bail!(
                "HIBP API key required.\n\
                 Set $MG_HIBP_KEY or pass --api-key.\n\
                 Get a key at https://haveibeenpwned.com/API/Key"
            );
        }
    };

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-breach: domain={}", args.domain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-breach/0.1")
        .build()
        .context("build HTTP client")?;

    // Fetch all breached accounts for the domain
    let breached_map = fetch_breached_domain(&client, &args.domain, &api_key).await?;

    let total_accounts = breached_map.len();
    eprintln!("  {} breached accounts found", total_accounts);

    // Collect unique breach names and per-breach email counts
    let mut breach_email_count: HashMap<String, usize> = HashMap::new();
    for breach_list in breached_map.values() {
        for breach_name in breach_list {
            *breach_email_count.entry(breach_name.clone()).or_insert(0) += 1;
        }
    }

    // Check each breach for password data
    let rate = Duration::from_millis(HIBP_RATE_MS);
    let mut breach_entries = Vec::new();
    let mut any_passwords = false;

    let mut breach_names: Vec<String> = breach_email_count.keys().cloned().collect();
    breach_names.sort();

    for breach_name in &breach_names {
        let count = breach_email_count[breach_name];
        eprintln!("  checking breach: {breach_name} ({count} accounts)");

        tokio::time::sleep(rate).await;
        let has_pw = breach_has_passwords(&client, breach_name, &api_key).await;
        if has_pw {
            any_passwords = true;
        }

        breach_entries.push(BreachEntry {
            name: breach_name.clone(),
            email_count: count,
            has_passwords: has_pw,
        });
    }

    // Print summary
    println!("\n=== Breach Summary: {} ===", args.domain);
    println!("Total breached accounts: {total_accounts}");
    println!("Has password data:       {any_passwords}");
    for entry in &breach_entries {
        let pw_marker = if entry.has_passwords {
            " [PASSWORDS]"
        } else {
            ""
        };
        println!(
            "  {} ({} accounts){}",
            entry.name, entry.email_count, pw_marker
        );
    }

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create breach output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = BreachResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        domain: args.domain.clone(),
        total_accounts,
        has_passwords: any_passwords,
        breaches: breach_entries,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // HIGH finding if any breach contains plaintext passwords
    if results.has_passwords {
        let breach_names: Vec<&str> = results
            .breaches
            .iter()
            .filter(|b| b.has_passwords)
            .map(|b| b.name.as_str())
            .collect();
        let tf = ToolFinding::new(
            "mg-breach",
            "Credentials Exposed in Data Breach",
            FindingSeverity::High,
        )
        .url(format!(
            "https://haveibeenpwned.com/DomainSearch/{}",
            args.domain
        ))
        .evidence(format!(
            "domain={} breaches_with_passwords=[{}] total_accounts={}",
            args.domain,
            breach_names.join(", "),
            total_accounts
        ))
        .recommendation(
            "Force a password reset for all affected accounts; \
                 implement MFA; monitor for credential stuffing attacks; \
                 notify impacted users per breach notification obligations",
        );
        let _ = write_finding(&eng, &tf);
    }

    // MEDIUM finding listing total accounts breached regardless of password data
    if total_accounts > 0 {
        let tf = ToolFinding::new(
            "mg-breach",
            "Corporate Email Addresses Found in Breach Data",
            FindingSeverity::Medium,
        )
        .url(format!(
            "https://haveibeenpwned.com/DomainSearch/{}",
            args.domain
        ))
        .evidence(format!(
            "domain={} total_accounts={} total_breaches={}",
            args.domain,
            total_accounts,
            results.breaches.len()
        ))
        .recommendation(
            "Review breach details; enforce MFA across all corporate accounts; \
                 monitor for credential reuse and unauthorized access",
        );
        let _ = write_finding(&eng, &tf);
    }

    let _ = eng.audit(AUDIT_TOOL, &args.domain, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breach_detail_detects_passwords_class() {
        let detail = BreachDetail {
            data_classes: vec!["Emails".to_string(), "Passwords".to_string()],
        };
        assert!(
            detail
                .data_classes
                .iter()
                .any(|c| c == DATA_CLASS_PASSWORDS)
        );
    }

    #[test]
    fn breach_detail_no_passwords_class() {
        let detail = BreachDetail {
            data_classes: vec!["Emails".to_string(), "Usernames".to_string()],
        };
        assert!(
            !detail
                .data_classes
                .iter()
                .any(|c| c == DATA_CLASS_PASSWORDS)
        );
    }

    #[test]
    fn breach_email_count_aggregates_correctly() {
        let mut map: HashMap<String, Vec<String>> = HashMap::new();
        map.insert(
            "user1".to_string(),
            vec!["Adobe".to_string(), "LinkedIn".to_string()],
        );
        map.insert("user2".to_string(), vec!["Adobe".to_string()]);

        let mut counts: HashMap<String, usize> = HashMap::new();
        for breach_list in map.values() {
            for b in breach_list {
                *counts.entry(b.clone()).or_insert(0) += 1;
            }
        }
        assert_eq!(counts["Adobe"], 2);
        assert_eq!(counts["LinkedIn"], 1);
    }
}
