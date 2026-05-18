/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-docker — Docker daemon and Portainer exposure scanner.
 *                  Detects unauthenticated Docker API, lists containers and
 *                  images, and flags privileged host-mount as theoretical HIGH.
 * Notes:           Reads hosts from recon/summary.json.
 *                  The privileged-mount container CREATE payload is NEVER sent.
 *                  It is documented in findings for manual verification only.
 *                  Docker API probed on ports 2375, 2376, 4243.
 *                  Portainer probed on ports 9000 and 9443.
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

const DOCKER_API_PORTS: &[u16] = &[2375, 2376, 4243];
const PORTAINER_PORTS: &[u16] = &[9000, 9443];
const DOCKER_API_VERSION: &str = "v1.41";
const DOCKER_INFO_PATH: &str = "/info";
const DOCKER_VERSION_PATH: &str = "/version";
const DOCKER_CONTAINERS_PATH: &str = "/containers/json?all=1";
const DOCKER_IMAGES_PATH: &str = "/images/json";
const DOCKER_NETWORKS_PATH: &str = "/networks";
const PORTAINER_STATUS_PATH: &str = "/api/status";

// Privileged mount payload — documented only, never sent
const PRIVILEGED_MOUNT_PAYLOAD: &str =
    r#"{"Image":"alpine","HostConfig":{"Binds":["/:/host"]}}"#;

const OUTPUT_SUBDIR: &str = "docker";
const OUTPUT_FILE_PREFIX: &str = "results-";
const CONTAINERS_FILE_PREFIX: &str = "containers-";
const IMAGES_FILE_PREFIX: &str = "images-";
const AUDIT_TOOL: &str = "mg-docker";
const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 10;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-docker",
    about = "Docker daemon and Portainer exposure scanner"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    timeout: u64,
}

// ── Recon types ───────────────────────────────────────────────────────────────

// Mirrors HostRecord in recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    #[allow(dead_code)]
    http_accessible: bool,
    #[allow(dead_code)]
    open_ports: Vec<u16>,
}

// Mirrors the top-level recon/summary.json shape
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// ── Docker API types ──────────────────────────────────────────────────────────

// Relevant fields from /v1.41/info
#[derive(Debug, Deserialize, Serialize, Default)]
struct DockerInfo {
    #[serde(rename = "ServerVersion", default)]
    server_version: String,
    #[serde(rename = "Containers", default)]
    containers: u64,
    #[serde(rename = "Images", default)]
    images: u64,
    #[serde(rename = "MemTotal", default)]
    mem_total: u64,
    #[serde(rename = "NCPU", default)]
    ncpu: u64,
}

// Abbreviated container summary from /v1.41/containers/json
#[derive(Debug, Deserialize, Serialize)]
struct ContainerSummary {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "State", default)]
    state: String,
}

// Abbreviated image summary from /v1.41/images/json
#[derive(Debug, Deserialize, Serialize)]
struct ImageSummary {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Vec<String>,
    #[serde(rename = "Size", default)]
    size: u64,
}

// ── Finding types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    Critical,
    High,
    #[allow(dead_code)]
    Medium,
    #[allow(dead_code)]
    Info,
}

// One detected issue
#[derive(Debug, Clone, Serialize)]
struct DockerFinding {
    host: String,
    port: u16,
    component: String,
    severity: Severity,
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    manual_verification_payload: Option<String>,
}

// Per-host Docker API exposure details
#[derive(Debug, Serialize)]
struct DockerApiExposure {
    host: String,
    port: u16,
    info: Option<DockerInfo>,
    version_raw: Option<String>,
    container_count: usize,
    image_count: usize,
    network_count: usize,
}

// Top-level output
#[derive(Serialize)]
struct DockerResults {
    engagement: String,
    timestamp: String,
    hosts_scanned: usize,
    findings: Vec<DockerFinding>,
    exposed_apis: Vec<DockerApiExposure>,
    critical_count: usize,
    high_count: usize,
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

// Build a Docker API endpoint URL for a given host, port, and path suffix
fn docker_url(host: &str, port: u16, path_suffix: &str) -> String {
    format!("http://{host}:{port}/{DOCKER_API_VERSION}{path_suffix}")
}

// Send a GET to a Docker API endpoint, return (status, body)
async fn docker_get(
    client: &reqwest::Client,
    host: &str,
    port: u16,
    path_suffix: &str,
) -> (u16, String) {
    let url = docker_url(host, port, path_suffix);
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (status, body)
        }
        Err(_) => (0, String::new()),
    }
}

// Probe one Docker API port — check for unauthenticated access
async fn probe_docker_port(
    client: &reqwest::Client,
    host: &str,
    port: u16,
) -> (Vec<DockerFinding>, Option<DockerApiExposure>) {
    let mut findings = Vec::new();

    // Check /info first — confirms API is open and unauthenticated
    let (s_info, b_info) = docker_get(client, host, port, DOCKER_INFO_PATH).await;
    if s_info != 200 {
        return (findings, None);
    }

    let info: Option<DockerInfo> = serde_json::from_str(&b_info).ok();
    findings.push(DockerFinding {
        host: host.to_string(),
        port,
        component: "docker-api".to_string(),
        severity: Severity::Critical,
        detail: format!(
            "Unauthenticated Docker API on port {port} — full daemon control possible"
        ),
        manual_verification_payload: None,
    });

    // Get version string
    let (s_ver, b_ver) = docker_get(client, host, port, DOCKER_VERSION_PATH).await;
    let version_raw = if s_ver == 200 { Some(b_ver) } else { None };

    // List containers
    let (s_ctr, b_ctr) = docker_get(client, host, port, DOCKER_CONTAINERS_PATH).await;
    let containers: Vec<ContainerSummary> = if s_ctr == 200 {
        serde_json::from_str(&b_ctr).unwrap_or_default()
    } else {
        Vec::new()
    };
    let container_count = containers.len();

    // List images
    let (s_img, b_img) = docker_get(client, host, port, DOCKER_IMAGES_PATH).await;
    let images: Vec<ImageSummary> = if s_img == 200 {
        serde_json::from_str(&b_img).unwrap_or_default()
    } else {
        Vec::new()
    };
    let image_count = images.len();

    // List networks
    let (s_net, b_net) = docker_get(client, host, port, DOCKER_NETWORKS_PATH).await;
    let networks: Vec<serde_json::Value> = if s_net == 200 {
        serde_json::from_str(&b_net).unwrap_or_default()
    } else {
        Vec::new()
    };
    let network_count = networks.len();

    // Flag privileged host-mount as theoretical — DO NOT send the payload
    findings.push(DockerFinding {
        host: host.to_string(),
        port,
        component: "docker-api".to_string(),
        severity: Severity::High,
        detail: "Privileged container with host root mount possible — manual verification required".to_string(),
        manual_verification_payload: Some(PRIVILEGED_MOUNT_PAYLOAD.to_string()),
    });

    let exposure = DockerApiExposure {
        host: host.to_string(),
        port,
        info,
        version_raw,
        container_count,
        image_count,
        network_count,
    };

    (findings, Some(exposure))
}

// Probe Portainer on a single port
async fn probe_portainer(
    client: &reqwest::Client,
    host: &str,
    port: u16,
) -> Vec<DockerFinding> {
    let mut findings = Vec::new();
    let scheme = if port == 9443 { "https" } else { "http" };
    let url = format!("{scheme}://{host}:{port}{PORTAINER_STATUS_PATH}");
    let status = match client.get(&url).send().await {
        Ok(resp) => resp.status().as_u16(),
        Err(_) => 0,
    };
    if status == 200 {
        findings.push(DockerFinding {
            host: host.to_string(),
            port,
            component: "portainer".to_string(),
            severity: Severity::High,
            detail: format!("Portainer management UI accessible on port {port}"),
            manual_verification_payload: None,
        });
    }
    findings
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    if !summary_path.exists() {
        anyhow::bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let raw = fs::read_to_string(&summary_path).context("read summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;
    let hosts: Vec<String> = summary.hosts.into_iter().map(|h| h.hostname).collect();
    let host_count = hosts.len();

    eprintln!("mg-docker: scanning {} hosts", host_count);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-docker/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Drain JoinSet when at concurrency ceiling to bound memory usage
    let mut join_set: tokio::task::JoinSet<(Vec<DockerFinding>, Vec<DockerApiExposure>)> =
        tokio::task::JoinSet::new();
    let mut all_findings: Vec<DockerFinding> = Vec::new();
    let mut all_exposures: Vec<DockerApiExposure> = Vec::new();
    let mut all_containers: Vec<(String, u16, Vec<ContainerSummary>)> = Vec::new();
    let mut all_images: Vec<(String, u16, Vec<ImageSummary>)> = Vec::new();

    for host in hosts {
        // Drain when at ceiling before spawning another task
        while join_set.len() >= args.concurrency {
            if let Some(Ok((f, e))) = join_set.join_next().await {
                all_findings.extend(f);
                all_exposures.extend(e);
            }
        }

        let client_clone = client.clone();
        let host_clone = host.clone();
        join_set.spawn(async move {
            let mut findings = Vec::new();
            let mut exposures = Vec::new();
            eprintln!("  scanning {host_clone}");

            // Docker API ports
            for &port in DOCKER_API_PORTS {
                let (mut f, exposure) =
                    probe_docker_port(&client_clone, &host_clone, port).await;
                findings.append(&mut f);
                if let Some(e) = exposure {
                    exposures.push(e);
                }
            }

            // Portainer ports
            for &port in PORTAINER_PORTS {
                let mut f = probe_portainer(&client_clone, &host_clone, port).await;
                findings.append(&mut f);
            }

            (findings, exposures)
        });
    }

    // Drain remaining tasks
    while let Some(Ok((f, e))) = join_set.join_next().await {
        all_findings.extend(f);
        all_exposures.extend(e);
    }

    // For each confirmed Docker API exposure, fetch and save container/image lists
    for exposure in &all_exposures {
        let (s_ctr, b_ctr) =
            docker_get(&client, &exposure.host, exposure.port, DOCKER_CONTAINERS_PATH).await;
        if s_ctr == 200 {
            let containers: Vec<ContainerSummary> =
                serde_json::from_str(&b_ctr).unwrap_or_default();
            if !containers.is_empty() {
                all_containers.push((exposure.host.clone(), exposure.port, containers));
            }
        }
        let (s_img, b_img) =
            docker_get(&client, &exposure.host, exposure.port, DOCKER_IMAGES_PATH).await;
        if s_img == 200 {
            let images: Vec<ImageSummary> = serde_json::from_str(&b_img).unwrap_or_default();
            if !images.is_empty() {
                all_images.push((exposure.host.clone(), exposure.port, images));
            }
        }
    }

    let critical_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();

    eprintln!(
        "mg-docker: {} findings (CRITICAL={} HIGH={})",
        all_findings.len(),
        critical_count,
        high_count,
    );

    // Print critical and high findings to stdout
    for f in all_findings.iter().filter(|f| {
        matches!(f.severity, Severity::Critical | Severity::High)
    }) {
        println!("[{:?}] {}:{} — {}", f.severity, f.host, f.port, f.detail);
        if let Some(ref payload) = f.manual_verification_payload {
            println!("  Manual payload (DO NOT auto-send): {payload}");
        }
    }

    // Write JSON output files
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create docker output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");

    let results = DockerResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        hosts_scanned: host_count,
        findings: all_findings,
        exposed_apis: all_exposures,
        critical_count,
        high_count,
    };
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));
    fs::write(&out_path, serde_json::to_string_pretty(&results)?)
        .context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Write per-host container lists
    for (host, port, containers) in &all_containers {
        let safe_host = host.replace(['.', ':'], "_");
        let ctr_path =
            out_dir.join(format!("{CONTAINERS_FILE_PREFIX}{safe_host}_{port}_{ts_file}.json"));
        let _ = fs::write(&ctr_path, serde_json::to_string_pretty(containers)?);
        println!("[*] Containers written to {}", ctr_path.display());
    }

    // Write per-host image lists
    for (host, port, images) in &all_images {
        let safe_host = host.replace(['.', ':'], "_");
        let img_path =
            out_dir.join(format!("{IMAGES_FILE_PREFIX}{safe_host}_{port}_{ts_file}.json"));
        let _ = fs::write(&img_path, serde_json::to_string_pretty(images)?);
        println!("[*] Images written to {}", img_path.display());
    }

    // Audit log
    let detail = format!(
        "hosts={host_count} critical={critical_count} high={high_count} exposed_apis={}",
        results.exposed_apis.len()
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_api_ports_contains_standard_ports() {
        assert!(DOCKER_API_PORTS.contains(&2375));
        assert!(DOCKER_API_PORTS.contains(&2376));
        assert!(DOCKER_API_PORTS.contains(&4243));
    }

    #[test]
    fn portainer_ports_contains_standard_ports() {
        assert!(PORTAINER_PORTS.contains(&9000));
        assert!(PORTAINER_PORTS.contains(&9443));
    }

    #[test]
    fn docker_url_formats_correctly() {
        let url = docker_url("10.0.0.1", 2375, DOCKER_INFO_PATH);
        assert_eq!(url, "http://10.0.0.1:2375/v1.41/info");
    }

    #[test]
    fn privileged_mount_payload_is_documented_not_empty() {
        // Payload must remain non-empty so it appears in findings output
        assert!(!PRIVILEGED_MOUNT_PAYLOAD.is_empty());
        assert!(PRIVILEGED_MOUNT_PAYLOAD.contains("alpine"));
        assert!(PRIVILEGED_MOUNT_PAYLOAD.contains("/:/host"));
    }

    #[test]
    fn docker_finding_serializes_severity_uppercase() {
        let f = DockerFinding {
            host: "10.0.0.1".to_string(),
            port: 2375,
            component: "docker-api".to_string(),
            severity: Severity::Critical,
            detail: "unauthenticated".to_string(),
            manual_verification_payload: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"CRITICAL\""));
    }

    #[test]
    fn docker_finding_omits_payload_field_when_none() {
        let f = DockerFinding {
            host: "10.0.0.1".to_string(),
            port: 9000,
            component: "portainer".to_string(),
            severity: Severity::High,
            detail: "portainer exposed".to_string(),
            manual_verification_payload: None,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("manual_verification_payload"));
    }

    #[test]
    fn docker_finding_includes_payload_when_some() {
        let f = DockerFinding {
            host: "10.0.0.1".to_string(),
            port: 2375,
            component: "docker-api".to_string(),
            severity: Severity::High,
            detail: "priv mount".to_string(),
            manual_verification_payload: Some(PRIVILEGED_MOUNT_PAYLOAD.to_string()),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("manual_verification_payload"));
        assert!(json.contains("alpine"));
    }
}
