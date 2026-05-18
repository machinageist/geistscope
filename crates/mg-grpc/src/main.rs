/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-grpc — gRPC service discovery via HTTP/2 reflection
 *                  Probes hosts for gRPC endpoints, enumerates services via
 *                  server reflection, and tests unauthenticated method calls.
 * Notes:           No gRPC library used — raw HTTP/2 via reqwest with
 *                  http2_prior_knowledge() for cleartext, normal HTTPS for TLS.
 *                  gRPC frame: 1-byte compression flag + 4-byte big-endian len
 *                  + protobuf body.  Reflection uses field 1 = list_services.
 *******************************************************************/

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::task::JoinSet;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "grpc";
const AUDIT_TOOL: &str = "mg-grpc";

// Ports to probe for gRPC on each host
const GRPC_PROBE_PORTS: &[u16] = &[443, 8443, 50051, 9090];

// gRPC reflection service path
const REFLECTION_PATH: &str =
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo";

// Content-Type header value that identifies a gRPC server
const GRPC_CONTENT_TYPE: &str = "application/grpc";

// Minimal gRPC frame: no compression + 2-byte protobuf (field 1 = list_services, empty)
// Protobuf: \x0a\x00 = field 1, type 2, length 0
// Frame:    \x00 (no compression) + \x00\x00\x00\x02 (len=2) + \x0a\x00
const GRPC_REFLECTION_FRAME: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00];

// gRPC status 0 = OK (unauthenticated access); 16 = UNAUTHENTICATED
const GRPC_STATUS_OK: &str = "0";
const GRPC_STATUS_UNAUTHENTICATED: &str = "16";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-grpc",
    about = "gRPC service discovery — reflection, enumeration, unauth probe"
)]
struct Args {
    /// Engagement name (must have recon/summary.json)
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Maximum concurrent probes
    #[arg(long, default_value_t = 5)]
    concurrency: usize,

    /// HTTP timeout in seconds
    #[arg(long, default_value_t = 10)]
    timeout: u64,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Mirrors the HostRecord shape from recon/summary.json
#[derive(Deserialize)]
struct HostRecord {
    hostname: String,
    http_accessible: bool,
    // present in JSON; mg-grpc probes fixed ports rather than relying on recon port list
    #[allow(dead_code)]
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Recon summary root
#[derive(Deserialize)]
struct ReconSummary {
    hosts: Vec<HostRecord>,
}

// One discovered gRPC service on a host:port
#[derive(Debug, Serialize)]
struct ServiceEntry {
    name: String,
    unauth_accessible: bool,
    grpc_status: Option<String>,
}

// Result for one host:port probe
#[derive(Debug, Serialize)]
struct ProbeResult {
    host: String,
    port: u16,
    endpoint: String,
    grpc_detected: bool,
    services: Vec<ServiceEntry>,
}

// Top-level output written to disk
#[derive(Serialize)]
struct GrpcResults {
    engagement: String,
    timestamp: String,
    hosts_probed: usize,
    grpc_endpoints_found: usize,
    results: Vec<ProbeResult>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// Return current UTC timestamp as RFC 3339
fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

// Sanitize timestamp for filename use (colons → underscores)
fn ts_for_filename(ts: &str) -> String {
    ts.chars()
        .map(|c| if c == ':' { '_' } else { c })
        .collect()
}

// Extract length-delimited strings from a protobuf byte slice (best-effort)
// Field 4 in reflection response = list_services_response; field 1 inside = service
// name.  We scan for printable ASCII strings preceded by a length byte as a
// pragmatic substitute for a full protobuf decoder.
fn extract_service_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        // Look for a length byte followed by that many printable ASCII bytes
        let len = bytes[i] as usize;
        if len == 0 || i + 1 + len > bytes.len() {
            i += 1;
            continue;
        }
        let slice = &bytes[i + 1..i + 1 + len];
        // Accept if the slice looks like a valid gRPC service name:
        // printable ASCII, contains at least one dot or slash (package separator)
        if slice.iter().all(|&b| b.is_ascii_graphic()) {
            let s = std::str::from_utf8(slice).unwrap_or("");
            if s.contains('.') || s.contains('/') {
                names.push(s.to_string());
            }
        }
        i += 1 + len;
    }
    names
}

// Build a minimal gRPC unauth probe frame for a service (empty body)
fn build_empty_grpc_frame() -> Vec<u8> {
    // Empty message: compression=0, length=0
    vec![0x00, 0x00, 0x00, 0x00, 0x00]
}

// Probe one host:port for gRPC and enumerate services
async fn probe_host_port(
    host: String,
    port: u16,
    timeout: Duration,
) -> ProbeResult {
    // Use HTTPS for ports 443/8443, plain HTTP/2 for 50051/9090
    let (scheme, use_tls) = match port {
        443 | 8443 => ("https", true),
        _ => ("http", false),
    };
    let endpoint = format!("{scheme}://{}:{}{}", host, port, REFLECTION_PATH);

    let mut result = ProbeResult {
        host: host.clone(),
        port,
        endpoint: endpoint.clone(),
        grpc_detected: false,
        services: Vec::new(),
    };

    // Build client — TLS for 443/8443, cleartext HTTP/2 for others
    let client_builder = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(true);

    let client = if use_tls {
        client_builder.build()
    } else {
        client_builder.http2_prior_knowledge().build()
    };

    let Ok(client) = client else {
        return result;
    };

    // Send reflection request
    let resp = client
        .post(&endpoint)
        .header("Content-Type", GRPC_CONTENT_TYPE)
        .header("Te", "trailers")
        .body(GRPC_REFLECTION_FRAME)
        .send()
        .await;

    let Ok(resp) = resp else {
        return result;
    };

    // Check Content-Type to confirm gRPC server
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !content_type.starts_with(GRPC_CONTENT_TYPE) {
        return result;
    }

    result.grpc_detected = true;

    let body = resp.bytes().await.unwrap_or_default();

    // Skip the 5-byte gRPC frame header before parsing protobuf
    let proto_bytes = if body.len() > 5 { &body[5..] } else { &body[..] };
    let service_names = extract_service_names(proto_bytes);

    // For each discovered service, probe with an empty body to test unauth access
    for name in service_names {
        let svc_url = format!("{scheme}://{}:{}/{}/", host, port, name);
        let unauth_resp = client
            .post(&svc_url)
            .header("Content-Type", GRPC_CONTENT_TYPE)
            .header("Te", "trailers")
            .body(build_empty_grpc_frame())
            .send()
            .await;

        let (unauth_accessible, grpc_status) = match unauth_resp {
            Ok(r) => {
                let status = r
                    .headers()
                    .get("grpc-status")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                let accessible = status.as_deref() == Some(GRPC_STATUS_OK);
                (accessible, status)
            }
            Err(_) => (false, None),
        };

        result.services.push(ServiceEntry {
            name,
            unauth_accessible,
            grpc_status,
        });
    }

    result
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join("summary.json");
    let raw = fs::read_to_string(&summary_path).context("read recon/summary.json")?;
    let summary: ReconSummary = serde_json::from_str(&raw).context("parse summary.json")?;

    let scope = eng.scope().context("load scope")?;

    // Collect (host, port) pairs to probe
    let mut targets: Vec<(String, u16)> = Vec::new();
    for host in &summary.hosts {
        if !host.http_accessible || !scope.is_in_scope(&host.hostname) {
            continue;
        }
        for &port in GRPC_PROBE_PORTS {
            targets.push((host.hostname.clone(), port));
        }
    }

    eprintln!(
        "mg-grpc: {} targets ({}×{} ports), concurrency={}",
        targets.len(),
        targets.len() / GRPC_PROBE_PORTS.len().max(1),
        GRPC_PROBE_PORTS.len(),
        args.concurrency
    );

    let timeout = Duration::from_secs(args.timeout);
    let mut join_set: JoinSet<ProbeResult> = JoinSet::new();
    let mut all_results: Vec<ProbeResult> = Vec::new();

    for (host, port) in targets {
        // Drain when at concurrency ceiling
        if join_set.len() >= args.concurrency
            && let Some(Ok(r)) = join_set.join_next().await
        {
            all_results.push(r);
        }
        join_set.spawn(probe_host_port(host, port, timeout));
    }

    // Drain remaining
    while let Some(Ok(r)) = join_set.join_next().await {
        all_results.push(r);
    }

    // Print summary for detected endpoints
    for r in &all_results {
        if r.grpc_detected {
            eprintln!("  [grpc] {}", r.endpoint);
            for svc in &r.services {
                let tag = if svc.unauth_accessible {
                    "[UNAUTH]"
                } else if svc.grpc_status.as_deref() == Some(GRPC_STATUS_UNAUTHENTICATED) {
                    "[auth-required]"
                } else {
                    "[unknown]"
                };
                eprintln!("    {tag} {}", svc.name);
            }
        }
    }

    let grpc_count = all_results.iter().filter(|r| r.grpc_detected).count();
    let ts = now_rfc3339();
    let ts_file = ts_for_filename(&ts);

    let output = GrpcResults {
        engagement: args.engagement.clone(),
        timestamp: ts.clone(),
        hosts_probed: all_results.len(),
        grpc_endpoints_found: grpc_count,
        results: all_results,
    };

    let output_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&output_dir).context("create grpc output dir")?;

    let out_path = output_dir.join(format!("results-{ts_file}.json"));
    fs::write(
        &out_path,
        serde_json::to_string_pretty(&output).unwrap_or_default(),
    )
    .context("write results JSON")?;

    eprintln!(
        "mg-grpc: {} gRPC endpoints found — {}",
        grpc_count,
        out_path.display()
    );

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "targets={} grpc_found={} ts={ts}",
            output.hosts_probed, output.grpc_endpoints_found
        )),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ts_for_filename_replaces_colons() {
        assert_eq!(ts_for_filename("2026-05-18T10:00:00Z"), "2026-05-18T10_00_00Z");
    }

    #[test]
    fn extract_service_names_finds_dotted_name() {
        // Craft bytes: length prefix + "grpc.health.v1.Health"
        let name = b"grpc.health.v1.Health";
        let mut bytes = vec![name.len() as u8];
        bytes.extend_from_slice(name);
        let names = extract_service_names(&bytes);
        assert!(names.contains(&"grpc.health.v1.Health".to_string()));
    }

    #[test]
    fn extract_service_names_skips_non_printable() {
        // Raw bytes with no valid length-prefixed printable string
        let bytes = vec![0x01, 0x80, 0x01, 0x00];
        let names = extract_service_names(&bytes);
        assert!(names.is_empty());
    }

    #[test]
    fn grpc_reflection_frame_length() {
        // Frame must be exactly 7 bytes: 1 compression + 4 length + 2 protobuf
        assert_eq!(GRPC_REFLECTION_FRAME.len(), 7);
        assert_eq!(GRPC_REFLECTION_FRAME[0], 0x00); // no compression
    }
}
