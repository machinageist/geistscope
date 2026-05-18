/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-nuclei-bridge — runs Nuclei against engagement scope
 *                  and imports findings into the engagement findings directory
 *                  as normalized structured JSON.
 * Notes:           Streams nuclei's JSONL stdout line by line so findings
 *                  appear in real-time. Each line is a nuclei finding object.
 *                  nuclei binary must be in PATH or specified via --nuclei-path.
 *******************************************************************/

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const SUMMARY_FILENAME: &str = "summary.json";
const DEFAULT_NUCLEI_BIN: &str = "nuclei";
const DEFAULT_TEMPLATES_DIR: &str = "~/.nuclei-templates";
const DEFAULT_SEVERITY: &str = "high,critical";
const DEFAULT_CONCURRENCY: u32 = 25;
const DEFAULT_TIMEOUT: u32 = 30;
const OUTPUT_FILENAME_PREFIX: &str = "nuclei-";
const AUDIT_TOOL: &str = "mg-nuclei-bridge";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-nuclei-bridge",
    about = "Run Nuclei against engagement scope and import findings as structured JSON"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to nuclei binary
    #[arg(long, default_value = DEFAULT_NUCLEI_BIN)]
    nuclei_path: String,

    /// Path to nuclei templates directory
    #[arg(long, default_value = DEFAULT_TEMPLATES_DIR)]
    templates: String,

    /// Severity filter (comma-separated)
    #[arg(long, default_value = DEFAULT_SEVERITY)]
    severity: String,

    /// Max concurrent probes
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY)]
    concurrency: u32,

    /// Per-request timeout in seconds
    #[arg(long, default_value_t = DEFAULT_TIMEOUT)]
    timeout: u32,
}

// ── Input types ──────────────────────────────────────────────────────────────

// Minimal fields read from summary.json host entries
#[derive(Debug, Deserialize)]
struct HostRecord {
    hostname: String,
    #[serde(default)]
    http_accessible: bool,
    #[serde(default)]
    open_ports: Vec<u16>,
}

// Accepts both {"hosts":[...]} envelope and a bare array
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SummaryFile {
    Envelope { hosts: Vec<HostRecord> },
    Bare(Vec<HostRecord>),
}

impl SummaryFile {
    // Extract host list regardless of envelope shape
    fn into_hosts(self) -> Vec<HostRecord> {
        match self {
            SummaryFile::Envelope { hosts } => hosts,
            SummaryFile::Bare(hosts) => hosts,
        }
    }
}

// ── Nuclei output types ───────────────────────────────────────────────────────

// Raw nuclei JSONL output line (best-effort; extra fields are ignored)
#[derive(Debug, Deserialize)]
struct NucleiRawFinding {
    #[serde(rename = "templateID", alias = "template-id", default)]
    template_id: String,
    #[serde(default)]
    info: NucleiInfo,
    #[serde(rename = "matched-at", alias = "matched", default)]
    matched_at: String,
    #[serde(default)]
    host: String,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiInfo {
    #[serde(default)]
    name: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    description: String,
}

// Normalized finding stored to disk
#[derive(Debug, Serialize)]
struct NormalizedFinding {
    title: String,
    severity: String,
    url: String,
    matched_at: String,
    template_id: String,
    description: String,
}

// ── URL resolution ────────────────────────────────────────────────────────────

// Build a base URL string from a HostRecord, preferring HTTPS
fn base_url_for_host(host: &HostRecord) -> String {
    if host.open_ports.contains(&443) {
        return format!("https://{}", host.hostname);
    }
    if host.open_ports.contains(&80) {
        return format!("http://{}", host.hostname);
    }
    if let Some(port) = host
        .open_ports
        .iter()
        .copied()
        .find(|p| *p == 8443 || *p == 9443)
    {
        return format!("https://{}:{port}", host.hostname);
    }
    if let Some(port) = host.open_ports.first() {
        return format!("http://{}:{port}", host.hostname);
    }
    format!("https://{}", host.hostname)
}

// ── Nuclei check ─────────────────────────────────────────────────────────────

// Verify that the nuclei binary exists and is executable, printing help if not
fn check_nuclei_binary(nuclei_path: &str) -> Result<()> {
    let status = std::process::Command::new(nuclei_path)
        .arg("-version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() || s.code().is_some() => Ok(()),
        _ => bail!(
            "nuclei binary not found at '{}'\n\
             Install it: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest\n\
             Or specify: --nuclei-path /path/to/nuclei",
            nuclei_path
        ),
    }
}

// ── Summary loading ───────────────────────────────────────────────────────────

// Load host records from a recon summary.json
fn load_hosts(summary_path: &Path) -> Result<Vec<HostRecord>> {
    let raw = fs::read_to_string(summary_path)
        .with_context(|| format!("read {}", summary_path.display()))?;
    let parsed: SummaryFile = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", summary_path.display()))?;
    Ok(parsed.into_hosts())
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Verify nuclei binary before doing any file I/O
    check_nuclei_binary(&args.nuclei_path)?;

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    let summary_path = eng.recon_dir().join(SUMMARY_FILENAME);
    if !summary_path.exists() {
        bail!(
            "recon/summary.json not found — run `mg-recon {}` first",
            args.engagement
        );
    }

    let hosts = load_hosts(&summary_path).context("load hosts")?;
    let http_hosts: Vec<&HostRecord> = hosts.iter().filter(|h| h.http_accessible).collect();

    if http_hosts.is_empty() {
        eprintln!("mg-nuclei-bridge: no HTTP-accessible hosts in summary.json");
        return Ok(());
    }

    let urls: Vec<String> = http_hosts.iter().map(|h| base_url_for_host(h)).collect();
    eprintln!(
        "mg-nuclei-bridge: running nuclei against {} URLs (severity={}, concurrency={}, timeout={}s)",
        urls.len(),
        args.severity,
        args.concurrency,
        args.timeout,
    );

    // Build nuclei command with -json flag for JSONL output
    let mut cmd = Command::new(&args.nuclei_path);
    for url in &urls {
        cmd.args(["-u", url]);
    }
    cmd.args([
        "-json",
        "-severity",
        &args.severity,
        "-t",
        &args.templates,
        "-c",
        &args.concurrency.to_string(),
        "-timeout",
        &args.timeout.to_string(),
    ]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit()); // let nuclei progress bars flow to terminal

    let mut child = cmd.spawn().context("spawn nuclei")?;
    let stdout = child.stdout.take().context("take nuclei stdout")?;
    let mut lines = BufReader::new(stdout).lines();

    // Prepare output file path
    let findings_dir = eng.findings_dir();
    fs::create_dir_all(&findings_dir).context("create findings dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_safe = ts.replace(':', "-");
    let out_filename = format!("{OUTPUT_FILENAME_PREFIX}{}-{ts_safe}.json", args.engagement);
    let out_path: PathBuf = findings_dir.join(&out_filename);

    // Collect normalized findings as we stream lines
    let mut normalized: Vec<NormalizedFinding> = Vec::new();

    while let Some(line) = lines.next_line().await.context("read nuclei output")? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let raw: NucleiRawFinding = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                // Not a finding line (e.g. nuclei progress output); skip
                continue;
            }
        };

        let finding = NormalizedFinding {
            title: raw.info.name.clone(),
            severity: raw.info.severity.clone(),
            url: raw.host.clone(),
            matched_at: raw.matched_at.clone(),
            template_id: raw.template_id.clone(),
            description: raw.info.description.clone(),
        };

        println!(
            "[{}] {} — {} ({})",
            finding.severity.to_uppercase(),
            finding.title,
            finding.url,
            finding.template_id,
        );

        normalized.push(finding);
    }

    // Wait for nuclei to exit; non-zero exit is not fatal (findings may still exist)
    let exit_status = child.wait().await.context("wait for nuclei")?;
    if !exit_status.success() {
        eprintln!(
            "mg-nuclei-bridge: nuclei exited with status {}",
            exit_status
        );
    }

    let count = normalized.len();

    // Write collected findings to output file
    let json = serde_json::to_string_pretty(&normalized).context("serialize findings")?;
    fs::write(&out_path, &json).context("write findings file")?;

    eprintln!("mg-nuclei-bridge: {count} findings written to {}", out_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "urls={} findings={} severity={}",
            urls.len(),
            count,
            args.severity,
        )),
    );

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp() -> PathBuf {
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir()
            .join(format!("mg-nuclei-bridge-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn base_url_prefers_https() {
        let h = HostRecord {
            hostname: "api.example.com".into(),
            http_accessible: true,
            open_ports: vec![80, 443],
        };
        assert_eq!(base_url_for_host(&h), "https://api.example.com");
    }

    #[test]
    fn base_url_falls_back_to_nonstandard_port() {
        let h = HostRecord {
            hostname: "dev.example.com".into(),
            http_accessible: true,
            open_ports: vec![8080],
        };
        assert_eq!(base_url_for_host(&h), "http://dev.example.com:8080");
    }

    #[test]
    fn base_url_defaults_to_https_with_no_ports() {
        let h = HostRecord {
            hostname: "example.com".into(),
            http_accessible: true,
            open_ports: vec![],
        };
        assert_eq!(base_url_for_host(&h), "https://example.com");
    }

    #[test]
    fn load_hosts_accepts_envelope_shape() {
        let t = tmp();
        let path = t.join(SUMMARY_FILENAME);
        let env = serde_json::json!({
            "hosts": [{"hostname":"x.example.com","http_accessible":true,"open_ports":[443]}]
        });
        fs::write(&path, serde_json::to_string(&env).unwrap()).unwrap();
        let hosts = load_hosts(&path).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "x.example.com");
    }

    #[test]
    fn load_hosts_accepts_bare_array() {
        let t = tmp();
        let path = t.join(SUMMARY_FILENAME);
        let arr = serde_json::json!([
            {"hostname":"a.example.com","http_accessible":true,"open_ports":[]},
            {"hostname":"b.example.com","http_accessible":false,"open_ports":[]}
        ]);
        fs::write(&path, serde_json::to_string(&arr).unwrap()).unwrap();
        let hosts = load_hosts(&path).unwrap();
        assert_eq!(hosts.len(), 2);
    }

    #[test]
    fn nuclei_jsonl_parse_round_trip() {
        let line = serde_json::json!({
            "templateID": "xss-reflected",
            "info": {
                "name": "Reflected XSS",
                "severity": "high",
                "description": "Reflected XSS in query param"
            },
            "matched-at": "https://example.com/search?q=<script>",
            "host": "https://example.com"
        });
        let raw: NucleiRawFinding = serde_json::from_str(&line.to_string()).unwrap();
        assert_eq!(raw.template_id, "xss-reflected");
        assert_eq!(raw.info.severity, "high");
        assert_eq!(raw.info.name, "Reflected XSS");
    }
}
