/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-social — GitHub org member enumeration and email pattern generation.
 * Notes:           GitHub token is optional but strongly recommended (rate-limit without it
 *                  is 60 req/hr). Email patterns are generated from name + --domain if
 *                  both are available. LinkedIn dork URL is printed to stdout for manual use.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const GITHUB_API_BASE: &str = "https://api.github.com";
const GITHUB_PER_PAGE: u32 = 100;
const OUTPUT_SUBDIR: &str = "social";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-social";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// GitHub API rate: be conservative between calls
const GITHUB_RATE_MS: u64 = 500;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-social",
    about = "GitHub org member enumeration and email pattern generation"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// GitHub organization name
    #[arg(long)]
    org: String,

    /// Target domain for email pattern derivation
    #[arg(long)]
    domain: Option<String>,

    /// GitHub personal access token (or set $GITHUB_TOKEN)
    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── GitHub API types ──────────────────────────────────────────────────────────

// Entry in /orgs/<org>/members response
#[derive(Debug, Deserialize)]
struct GhMember {
    login: String,
}

// Entry in /users/<username> response
#[derive(Debug, Deserialize)]
struct GhUser {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    company: Option<String>,
}

// ── Output types ─────────────────────────────────────────────────────────────

// Enriched member record with derived email patterns
#[derive(Debug, Serialize)]
struct MemberRecord {
    login: String,
    name: Option<String>,
    public_email: Option<String>,
    company: Option<String>,
    derived_emails: Vec<String>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct SocialResults {
    engagement: String,
    timestamp: String,
    org: String,
    member_count: usize,
    linkedin_dork: String,
    members: Vec<MemberRecord>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Add Authorization header to a request builder if a token is present
fn maybe_auth(
    builder: reqwest::RequestBuilder,
    token: &Option<String>,
) -> reqwest::RequestBuilder {
    if let Some(t) = token {
        builder.header("Authorization", format!("token {t}"))
    } else {
        builder
    }
}

// Derive candidate email addresses from a full name and domain
fn derive_emails(name: &str, domain: &str) -> Vec<String> {
    let parts: Vec<&str> = name.split_whitespace().collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    let first = parts[0].to_lowercase();
    let last = parts[parts.len() - 1].to_lowercase();
    let first_initial = first.chars().next().unwrap_or('x');

    vec![
        format!("{first}.{last}@{domain}"),
        format!("{first_initial}{last}@{domain}"),
        format!("{first}@{domain}"),
        format!("{first_initial}.{last}@{domain}"),
    ]
}

// Build the Google dork URL for LinkedIn enumeration
fn linkedin_dork(org: &str) -> String {
    format!(
        "https://www.google.com/search?q=site:linkedin.com/in+\"{org}\"+(developer+OR+engineer+OR+security)",
        org = org
    )
}

// ── GitHub helpers ────────────────────────────────────────────────────────────

// Fetch org member list (first page of per_page=100)
async fn fetch_org_members(
    client: &reqwest::Client,
    org: &str,
    token: &Option<String>,
) -> Result<Vec<GhMember>> {
    let url = format!(
        "{GITHUB_API_BASE}/orgs/{org}/members?per_page={GITHUB_PER_PAGE}"
    );
    let resp = maybe_auth(client.get(&url), token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("GitHub org members request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub org members returned {status}: {body}");
    }

    let members: Vec<GhMember> = resp.json().await.context("parse GitHub members JSON")?;
    Ok(members)
}

// Fetch user profile for a single GitHub login
async fn fetch_user(
    client: &reqwest::Client,
    login: &str,
    token: &Option<String>,
) -> Result<GhUser> {
    let url = format!("{GITHUB_API_BASE}/users/{login}");
    let resp = maybe_auth(client.get(&url), token)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("GitHub user request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("GitHub user {login} returned {status}: {body}");
    }

    let user: GhUser = resp.json().await.context("parse GitHub user JSON")?;
    Ok(user)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-social: org={}", args.org);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-social/0.1")
        .build()
        .context("build HTTP client")?;

    // Enumerate org members
    eprintln!("  fetching org members...");
    let raw_members = fetch_org_members(&client, &args.org, &args.github_token).await?;
    eprintln!("  {} members found", raw_members.len());

    let rate = Duration::from_millis(GITHUB_RATE_MS);
    let mut members: Vec<MemberRecord> = Vec::new();

    for m in &raw_members {
        tokio::time::sleep(rate).await;
        let user = fetch_user(&client, &m.login, &args.github_token)
            .await
            .unwrap_or(GhUser {
                name: None,
                email: None,
                company: None,
            });

        let derived_emails = match (&user.name, &args.domain) {
            (Some(name), Some(domain)) => derive_emails(name, domain),
            _ => Vec::new(),
        };

        eprintln!(
            "  {} — name={:?} email={:?} derived={}",
            m.login,
            user.name,
            user.email,
            derived_emails.len()
        );

        members.push(MemberRecord {
            login: m.login.clone(),
            name: user.name,
            public_email: user.email,
            company: user.company,
            derived_emails,
        });
    }

    // Print LinkedIn dork
    let dork = linkedin_dork(&args.org);
    println!("\n=== LinkedIn Dork URL ===");
    println!("{dork}");

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create social output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = SocialResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        org: args.org.clone(),
        member_count: members.len(),
        linkedin_dork: dork,
        members,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    let _ = eng.audit(AUDIT_TOOL, &args.org, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_emails_generates_four_patterns() {
        let emails = derive_emails("John Smith", "example.com");
        assert_eq!(emails.len(), 4);
        assert!(emails.contains(&"john.smith@example.com".to_string()));
        assert!(emails.contains(&"jsmith@example.com".to_string()));
        assert!(emails.contains(&"john@example.com".to_string()));
        assert!(emails.contains(&"j.smith@example.com".to_string()));
    }

    #[test]
    fn derive_emails_single_name_returns_empty() {
        let emails = derive_emails("Mononymous", "example.com");
        assert!(emails.is_empty());
    }

    #[test]
    fn linkedin_dork_contains_org() {
        let dork = linkedin_dork("acme-corp");
        assert!(dork.contains("acme-corp"));
        assert!(dork.contains("linkedin.com/in"));
    }

    #[test]
    fn derive_emails_lowercases_parts() {
        let emails = derive_emails("ALICE WONDER", "test.io");
        assert!(emails.contains(&"alice.wonder@test.io".to_string()));
    }
}
