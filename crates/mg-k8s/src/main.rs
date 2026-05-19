/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-k8s — Kubernetes API server, etcd, kubelet, and
 *                  dashboard misconfiguration scanner.
 * Notes:           Reads hosts from recon/summary.json.
 *                  API server probed on ports 6443, 8443, 443, 8080.
 *                  Kubelet TLS verify is intentionally disabled — self-signed
 *                  certs are the norm in k8s clusters.
 *                  No exploit payloads are sent. Detection only.
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

const API_SERVER_PORTS: &[u16] = &[6443, 8443, 443, 8080];
const ETCD_PORT: u16 = 2379;
const KUBELET_SECURE_PORT: u16 = 10250;
const KUBELET_READONLY_PORT: u16 = 10255;
const DASHBOARD_PORTS: &[u16] = &[8001, 30000, 30001, 30002];

const API_NAMESPACES_PATH: &str = "/api/v1/namespaces";
const API_DEFAULT_SECRETS_PATH: &str = "/api/v1/namespaces/default/secrets";
const API_CLUSTERROLEBINDINGS_PATH: &str =
    "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings";
const ETCD_KEYS_PATH: &str = "/v2/keys";
const KUBELET_PODS_PATH: &str = "/pods";
const DASHBOARD_PROXY_PATH: &str =
    "/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/";

const OUTPUT_SUBDIR: &str = "k8s";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-k8s";
const DEFAULT_CONCURRENCY: usize = 10;
const DEFAULT_TIMEOUT_SECS: u64 = 10;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-k8s",
    about = "Kubernetes misconfiguration scanner — anonymous access, etcd, kubelet, dashboard"
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

// ── Finding types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    Critical,
    High,
    Medium,
    Info,
}

// One detected misconfiguration
#[derive(Debug, Clone, Serialize)]
struct K8sFinding {
    host: String,
    port: u16,
    component: String,
    path: String,
    status: u16,
    severity: Severity,
    detail: String,
}

// Top-level output written to disk
#[derive(Serialize)]
struct K8sResults {
    engagement: String,
    timestamp: String,
    hosts_scanned: usize,
    findings: Vec<K8sFinding>,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    info_count: usize,
}

// ── Probe helpers ─────────────────────────────────────────────────────────────

// Send a GET to host:port/path, return (status, body); errors map to status 0
async fn http_get(
    client: &reqwest::Client,
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
) -> (u16, String) {
    let url = format!("{scheme}://{host}:{port}{path}");
    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            (status, body)
        }
        Err(_) => (0, String::new()),
    }
}

// Probe one API server port — check anonymous access and auth status
async fn probe_api_server(
    client: &reqwest::Client,
    host: &str,
    port: u16,
) -> Vec<K8sFinding> {
    let scheme = if port == 8080 { "http" } else { "https" };
    let mut findings = Vec::new();

    let (status, _body) = http_get(client, scheme, host, port, API_NAMESPACES_PATH).await;

    match status {
        200 => {
            findings.push(K8sFinding {
                host: host.to_string(),
                port,
                component: "api-server".to_string(),
                path: API_NAMESPACES_PATH.to_string(),
                status,
                severity: Severity::High,
                detail: "API server allows unauthenticated namespace listing".to_string(),
            });
            // Since we have access, probe for secret listing and RBAC bindings
            let (s_sec, _) =
                http_get(client, scheme, host, port, API_DEFAULT_SECRETS_PATH).await;
            if s_sec == 200 {
                findings.push(K8sFinding {
                    host: host.to_string(),
                    port,
                    component: "api-server".to_string(),
                    path: API_DEFAULT_SECRETS_PATH.to_string(),
                    status: s_sec,
                    severity: Severity::Critical,
                    detail: "Unauthenticated access to default namespace secrets".to_string(),
                });
            }
            let (s_rbac, b_rbac) =
                http_get(client, scheme, host, port, API_CLUSTERROLEBINDINGS_PATH).await;
            if s_rbac == 200 && b_rbac.contains("system:anonymous") {
                findings.push(K8sFinding {
                    host: host.to_string(),
                    port,
                    component: "api-server-rbac".to_string(),
                    path: API_CLUSTERROLEBINDINGS_PATH.to_string(),
                    status: s_rbac,
                    severity: Severity::Critical,
                    detail: "ClusterRoleBinding grants system:anonymous cluster access".to_string(),
                });
            } else if s_rbac == 200 {
                findings.push(K8sFinding {
                    host: host.to_string(),
                    port,
                    component: "api-server-rbac".to_string(),
                    path: API_CLUSTERROLEBINDINGS_PATH.to_string(),
                    status: s_rbac,
                    severity: Severity::Info,
                    detail: "ClusterRoleBindings readable (no system:anonymous found)".to_string(),
                });
            }
        }
        401 | 403 => {
            findings.push(K8sFinding {
                host: host.to_string(),
                port,
                component: "api-server".to_string(),
                path: API_NAMESPACES_PATH.to_string(),
                status,
                severity: Severity::Info,
                detail: "API server exists but authentication is required".to_string(),
            });
            // Still probe secrets and RBAC even with auth — 200 would mean misconfigured RBAC
            let (s_sec, _) =
                http_get(client, scheme, host, port, API_DEFAULT_SECRETS_PATH).await;
            if s_sec == 200 {
                findings.push(K8sFinding {
                    host: host.to_string(),
                    port,
                    component: "api-server".to_string(),
                    path: API_DEFAULT_SECRETS_PATH.to_string(),
                    status: s_sec,
                    severity: Severity::Critical,
                    detail: "Authenticated endpoint returns secrets without credentials (RBAC misconfiguration)".to_string(),
                });
            }
            let (s_rbac, b_rbac) =
                http_get(client, scheme, host, port, API_CLUSTERROLEBINDINGS_PATH).await;
            if s_rbac == 200 && b_rbac.contains("system:anonymous") {
                findings.push(K8sFinding {
                    host: host.to_string(),
                    port,
                    component: "api-server-rbac".to_string(),
                    path: API_CLUSTERROLEBINDINGS_PATH.to_string(),
                    status: s_rbac,
                    severity: Severity::Critical,
                    detail: "ClusterRoleBinding grants system:anonymous despite auth required".to_string(),
                });
            }
        }
        // Port closed or not k8s
        _ => {}
    }

    findings
}

// Probe etcd on port 2379
async fn probe_etcd(client: &reqwest::Client, host: &str) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let (status, _) = http_get(client, "http", host, ETCD_PORT, ETCD_KEYS_PATH).await;
    if status == 200 {
        findings.push(K8sFinding {
            host: host.to_string(),
            port: ETCD_PORT,
            component: "etcd".to_string(),
            path: ETCD_KEYS_PATH.to_string(),
            status,
            severity: Severity::Critical,
            detail: "Unauthenticated etcd v2 API — full key-value store exposed".to_string(),
        });
    }
    findings
}

// Probe kubelet secure port 10250 (TLS, no cert verify)
async fn probe_kubelet_secure(client: &reqwest::Client, host: &str) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let (status, _) =
        http_get(client, "https", host, KUBELET_SECURE_PORT, KUBELET_PODS_PATH).await;
    if status == 200 {
        findings.push(K8sFinding {
            host: host.to_string(),
            port: KUBELET_SECURE_PORT,
            component: "kubelet".to_string(),
            path: KUBELET_PODS_PATH.to_string(),
            status,
            severity: Severity::High,
            detail: "Unauthenticated kubelet API — pod listing accessible".to_string(),
        });
    }
    findings
}

// Probe kubelet read-only port 10255 (plain HTTP)
async fn probe_kubelet_readonly(client: &reqwest::Client, host: &str) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    let (status, _) =
        http_get(client, "http", host, KUBELET_READONLY_PORT, KUBELET_PODS_PATH).await;
    if status == 200 {
        findings.push(K8sFinding {
            host: host.to_string(),
            port: KUBELET_READONLY_PORT,
            component: "kubelet-readonly".to_string(),
            path: KUBELET_PODS_PATH.to_string(),
            status,
            severity: Severity::Medium,
            detail: "Kubelet read-only port exposed — pod info accessible without auth".to_string(),
        });
    }
    findings
}

// Probe dashboard on well-known ports
async fn probe_dashboard(client: &reqwest::Client, host: &str) -> Vec<K8sFinding> {
    let mut findings = Vec::new();
    for &port in DASHBOARD_PORTS {
        let scheme = if port == 8001 { "http" } else { "https" };
        let (status, _) = http_get(client, scheme, host, port, DASHBOARD_PROXY_PATH).await;
        if status == 200 {
            findings.push(K8sFinding {
                host: host.to_string(),
                port,
                component: "dashboard".to_string(),
                path: DASHBOARD_PROXY_PATH.to_string(),
                status,
                severity: Severity::High,
                detail: format!("Kubernetes dashboard accessible on port {port}"),
            });
        }
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

    eprintln!("mg-k8s: scanning {} hosts", host_count);

    // Build one client with TLS verify disabled for kubelet self-signed certs
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .user_agent("mg-k8s/0.1")
        .danger_accept_invalid_certs(true)
        .build()
        .context("build HTTP client")?;

    // Drain JoinSet when at concurrency ceiling to bound memory usage
    let mut join_set: tokio::task::JoinSet<Vec<K8sFinding>> = tokio::task::JoinSet::new();
    let mut all_findings: Vec<K8sFinding> = Vec::new();

    for host in hosts {
        // Drain when at ceiling before spawning another task
        while join_set.len() >= args.concurrency {
            if let Some(result) = join_set.join_next().await {
                all_findings.extend(result.unwrap_or_default());
            }
        }

        let client_clone = client.clone();
        let host_clone = host.clone();
        join_set.spawn(async move {
            let mut findings = Vec::new();
            eprintln!("  scanning {host_clone}");

            // API server — probe all candidate ports
            for &port in API_SERVER_PORTS {
                let mut f = probe_api_server(&client_clone, &host_clone, port).await;
                findings.append(&mut f);
            }
            // etcd
            findings.append(&mut probe_etcd(&client_clone, &host_clone).await);
            // kubelet secure
            findings.append(&mut probe_kubelet_secure(&client_clone, &host_clone).await);
            // kubelet read-only
            findings.append(&mut probe_kubelet_readonly(&client_clone, &host_clone).await);
            // dashboard
            findings.append(&mut probe_dashboard(&client_clone, &host_clone).await);

            findings
        });
    }

    // Drain remaining tasks
    while let Some(result) = join_set.join_next().await {
        all_findings.extend(result.unwrap_or_default());
    }

    let critical_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical))
        .count();
    let high_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High))
        .count();
    let medium_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .count();
    let info_count = all_findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Info))
        .count();

    eprintln!(
        "mg-k8s: {} findings (CRITICAL={} HIGH={} MEDIUM={} INFO={})",
        all_findings.len(),
        critical_count,
        high_count,
        medium_count,
        info_count,
    );

    // Print any critical or high findings to stdout
    for f in all_findings.iter().filter(|f| {
        matches!(f.severity, Severity::Critical | Severity::High)
    }) {
        println!(
            "[{:?}] {}:{}{} — {}",
            f.severity, f.host, f.port, f.path, f.detail
        );
    }

    // Write JSON output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create k8s output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let results = K8sResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        hosts_scanned: host_count,
        findings: all_findings,
        critical_count,
        high_count,
        medium_count,
        info_count,
    };
    let json = serde_json::to_string_pretty(&results)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    // Audit log
    let detail = format!(
        "hosts={host_count} findings={} critical={critical_count} high={high_count}",
        critical_count + high_count + medium_count + info_count
    );
    let _ = eng.audit(AUDIT_TOOL, &eng.meta.target, Some(&detail));

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_server_ports_includes_standard_k8s_ports() {
        assert!(API_SERVER_PORTS.contains(&6443));
        assert!(API_SERVER_PORTS.contains(&8080));
    }

    #[test]
    fn dashboard_ports_includes_nodeport_range() {
        assert!(DASHBOARD_PORTS.contains(&30000));
        assert!(DASHBOARD_PORTS.contains(&8001));
    }

    #[test]
    fn k8s_finding_serializes_severity_uppercase() {
        let f = K8sFinding {
            host: "10.0.0.1".to_string(),
            port: 6443,
            component: "api-server".to_string(),
            path: "/api/v1/namespaces".to_string(),
            status: 200,
            severity: Severity::Critical,
            detail: "anon access".to_string(),
        };
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"CRITICAL\""));
    }

    #[test]
    fn k8s_results_counts_match_findings() {
        let findings = [
            K8sFinding {
                host: "h".into(),
                port: 6443,
                component: "api-server".into(),
                path: "/api/v1/namespaces".into(),
                status: 200,
                severity: Severity::Critical,
                detail: "anon".into(),
            },
            K8sFinding {
                host: "h".into(),
                port: 10250,
                component: "kubelet".into(),
                path: "/pods".into(),
                status: 200,
                severity: Severity::High,
                detail: "unauth kubelet".into(),
            },
        ];
        let crit = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        let high = findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count();
        assert_eq!(crit, 1);
        assert_eq!(high, 1);
    }
}
