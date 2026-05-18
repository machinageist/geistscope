/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-diff — scan-over-scan diff for engagement snapshots.
 *                  Compares two recon summary.json files and optional crawl
 *                  endpoint lists to surface new/removed hosts, port changes,
 *                  tech changes, and HTTP status changes.
 * Notes:           --baseline / --current are optional; if omitted the two
 *                  most recent timestamped subdirs under recon/ are used.
 *                  Output is written to engagements/<name>/diff/diff-<ts>.json.
 *******************************************************************/

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const SUMMARY_FILENAME: &str = "summary.json";
const DIFF_SUBDIR: &str = "diff";
const DIFF_FILE_PREFIX: &str = "diff-";
const AUDIT_TOOL: &str = "mg-diff";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-diff",
    about = "Scan-over-scan diff — new hosts, port changes, tech changes since last recon"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to baseline snapshot directory (auto-detect if omitted)
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Path to current snapshot directory (auto-detect if omitted)
    #[arg(long)]
    current: Option<PathBuf>,

    /// Output format
    #[arg(long, default_value = "text")]
    output_format: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

// ── Input types ──────────────────────────────────────────────────────────────

// Represents one host entry in summary.json
#[derive(Debug, Deserialize, Clone)]
struct HostRecord {
    hostname: String,
    #[serde(default)]
    open_ports: Vec<u16>,
    #[serde(default)]
    technologies: Vec<String>,
    #[serde(default)]
    http_status: Option<u16>,
}

// Accepts both {"hosts":[...]} envelope and a bare array
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SummaryFile {
    Envelope { hosts: Vec<HostRecord> },
    Bare(Vec<HostRecord>),
}

impl SummaryFile {
    // Extract the host list regardless of envelope variant
    fn into_hosts(self) -> Vec<HostRecord> {
        match self {
            SummaryFile::Envelope { hosts } => hosts,
            SummaryFile::Bare(hosts) => hosts,
        }
    }
}

// One crawl endpoint entry
#[derive(Debug, Deserialize)]
struct CrawlEndpoint {
    url: String,
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct PortChange {
    hostname: String,
    added: Vec<u16>,
    removed: Vec<u16>,
}

#[derive(Debug, Serialize)]
struct TechChange {
    hostname: String,
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Debug, Serialize)]
struct StatusChange {
    hostname: String,
    baseline_status: Option<u16>,
    current_status: Option<u16>,
}

#[derive(Debug, Serialize)]
struct DiffReport {
    baseline_path: String,
    current_path: String,
    new_subdomains: Vec<String>,
    removed_subdomains: Vec<String>,
    port_changes: Vec<PortChange>,
    tech_changes: Vec<TechChange>,
    status_changes: Vec<StatusChange>,
    new_crawl_endpoints: Vec<String>,
    removed_crawl_endpoints: Vec<String>,
}

// ── Entry point ──────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    // Resolve baseline and current directories
    let (baseline_dir, current_dir) = resolve_snapshot_dirs(&eng, &args)?;

    // Load summary files from both snapshots
    let baseline_hosts = load_summary(&baseline_dir.join(SUMMARY_FILENAME))
        .with_context(|| format!("load baseline {}", baseline_dir.display()))?;
    let current_hosts = load_summary(&current_dir.join(SUMMARY_FILENAME))
        .with_context(|| format!("load current {}", current_dir.display()))?;

    // Index both host lists by hostname for fast lookup
    let baseline_map: HashMap<String, &HostRecord> =
        baseline_hosts.iter().map(|h| (h.hostname.clone(), h)).collect();
    let current_map: HashMap<String, &HostRecord> =
        current_hosts.iter().map(|h| (h.hostname.clone(), h)).collect();

    // Compute new and removed subdomains
    let new_subdomains: Vec<String> = current_hosts
        .iter()
        .filter(|h| !baseline_map.contains_key(&h.hostname))
        .map(|h| h.hostname.clone())
        .collect();
    let removed_subdomains: Vec<String> = baseline_hosts
        .iter()
        .filter(|h| !current_map.contains_key(&h.hostname))
        .map(|h| h.hostname.clone())
        .collect();

    // Compute per-host port diffs for hosts present in both snapshots
    let mut port_changes: Vec<PortChange> = Vec::new();
    let mut tech_changes: Vec<TechChange> = Vec::new();
    let mut status_changes: Vec<StatusChange> = Vec::new();

    for (hostname, current_rec) in &current_map {
        let Some(baseline_rec) = baseline_map.get(hostname) else {
            continue;
        };

        // Port diff
        let base_ports: HashSet<u16> = baseline_rec.open_ports.iter().copied().collect();
        let curr_ports: HashSet<u16> = current_rec.open_ports.iter().copied().collect();
        let added_ports: Vec<u16> = curr_ports.difference(&base_ports).copied().collect();
        let removed_ports: Vec<u16> = base_ports.difference(&curr_ports).copied().collect();
        if !added_ports.is_empty() || !removed_ports.is_empty() {
            let mut ap = added_ports;
            let mut rp = removed_ports;
            ap.sort_unstable();
            rp.sort_unstable();
            port_changes.push(PortChange {
                hostname: hostname.clone(),
                added: ap,
                removed: rp,
            });
        }

        // Tech diff
        let base_tech: HashSet<&str> = baseline_rec.technologies.iter().map(|s| s.as_str()).collect();
        let curr_tech: HashSet<&str> = current_rec.technologies.iter().map(|s| s.as_str()).collect();
        let added_tech: Vec<String> = curr_tech.difference(&base_tech).map(|s| s.to_string()).collect();
        let removed_tech: Vec<String> = base_tech.difference(&curr_tech).map(|s| s.to_string()).collect();
        if !added_tech.is_empty() || !removed_tech.is_empty() {
            tech_changes.push(TechChange {
                hostname: hostname.clone(),
                added: added_tech,
                removed: removed_tech,
            });
        }

        // HTTP status diff
        if baseline_rec.http_status != current_rec.http_status {
            status_changes.push(StatusChange {
                hostname: hostname.clone(),
                baseline_status: baseline_rec.http_status,
                current_status: current_rec.http_status,
            });
        }
    }

    // Diff crawl endpoint lists if both snapshot crawl/ dirs exist
    let baseline_crawl = baseline_dir.join("crawl");
    let current_crawl = current_dir.join("crawl");
    let (new_crawl_endpoints, removed_crawl_endpoints) =
        if baseline_crawl.exists() && current_crawl.exists() {
            diff_crawl_endpoints(&baseline_crawl, &current_crawl)?
        } else {
            (Vec::new(), Vec::new())
        };

    let report = DiffReport {
        baseline_path: baseline_dir.display().to_string(),
        current_path: current_dir.display().to_string(),
        new_subdomains,
        removed_subdomains,
        port_changes,
        tech_changes,
        status_changes,
        new_crawl_endpoints,
        removed_crawl_endpoints,
    };

    // Print to stdout in the requested format
    match args.output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&report)?),
        OutputFormat::Text => print_text_report(&report),
    }

    // Write diff file to engagements/<name>/diff/
    let diff_dir = eng.root.join(DIFF_SUBDIR);
    fs::create_dir_all(&diff_dir).context("create diff dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    // Replace colons so the filename is valid on all platforms
    let ts_safe = ts.replace(':', "-");
    let out_path = diff_dir.join(format!("{DIFF_FILE_PREFIX}{ts_safe}.json"));
    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    fs::write(&out_path, &json).context("write diff file")?;

    eprintln!("mg-diff: written {}", out_path.display());

    let _ = eng.audit(
        AUDIT_TOOL,
        &eng.meta.target,
        Some(&format!(
            "new={} removed={} port_changes={} status_changes={}",
            report.new_subdomains.len(),
            report.removed_subdomains.len(),
            report.port_changes.len(),
            report.status_changes.len(),
        )),
    );

    Ok(())
}

// ── Snapshot resolution ───────────────────────────────────────────────────────

// Resolve (baseline, current) snapshot dirs from CLI or auto-detect from recon/
fn resolve_snapshot_dirs(eng: &Engagement, args: &Args) -> Result<(PathBuf, PathBuf)> {
    match (&args.baseline, &args.current) {
        (Some(b), Some(c)) => Ok((b.clone(), c.clone())),
        (None, None) => auto_detect_snapshots(&eng.recon_dir()),
        _ => bail!("--baseline and --current must both be provided or both omitted"),
    }
}

// Auto-detect the two most recent timestamped subdirs under recon/
fn auto_detect_snapshots(recon_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    // Also treat the recon dir itself as a valid snapshot dir (contains summary.json)
    if recon_dir.join(SUMMARY_FILENAME).exists() {
        bail!(
            "recon dir contains summary.json directly — \
             provide --baseline and --current explicitly"
        );
    }

    let mut subdirs: Vec<PathBuf> = fs::read_dir(recon_dir)
        .context("read recon dir")?
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| e.path().join(SUMMARY_FILENAME).exists())
        .map(|e| e.path())
        .collect();

    subdirs.sort();

    if subdirs.len() < 2 {
        bail!(
            "need at least 2 timestamped snapshot dirs under {}; found {}",
            recon_dir.display(),
            subdirs.len()
        );
    }

    // Oldest = baseline, newest = current
    let baseline = subdirs[subdirs.len() - 2].clone();
    let current = subdirs[subdirs.len() - 1].clone();
    Ok((baseline, current))
}

// ── Data loading ──────────────────────────────────────────────────────────────

// Load and parse a summary.json, tolerating envelope or bare-array shape
fn load_summary(path: &Path) -> Result<Vec<HostRecord>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let parsed: SummaryFile = serde_json::from_str(&raw)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(parsed.into_hosts())
}

// Collect all URL strings from .json files in a crawl snapshot dir
fn collect_crawl_urls(dir: &Path) -> Result<HashSet<String>> {
    let mut urls = HashSet::new();
    for entry in fs::read_dir(dir).context("read crawl dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        // Try array of CrawlEndpoint first, then array of bare strings
        if let Ok(endpoints) = serde_json::from_str::<Vec<CrawlEndpoint>>(&raw) {
            urls.extend(endpoints.into_iter().map(|e| e.url));
        } else if let Ok(strings) = serde_json::from_str::<Vec<String>>(&raw) {
            urls.extend(strings);
        }
    }
    Ok(urls)
}

// Compute new and removed crawl endpoints between two snapshot crawl dirs
fn diff_crawl_endpoints(
    baseline_crawl: &Path,
    current_crawl: &Path,
) -> Result<(Vec<String>, Vec<String>)> {
    let base_urls = collect_crawl_urls(baseline_crawl)?;
    let curr_urls = collect_crawl_urls(current_crawl)?;

    let mut new_urls: Vec<String> = curr_urls.difference(&base_urls).cloned().collect();
    let mut removed_urls: Vec<String> = base_urls.difference(&curr_urls).cloned().collect();
    new_urls.sort();
    removed_urls.sort();
    Ok((new_urls, removed_urls))
}

// ── Text report ───────────────────────────────────────────────────────────────

// Print a human-readable diff summary to stdout
fn print_text_report(r: &DiffReport) {
    println!("=== mg-diff ===");
    println!("Baseline: {}", r.baseline_path);
    println!("Current:  {}", r.current_path);
    println!();

    println!("New subdomains ({}):", r.new_subdomains.len());
    for h in &r.new_subdomains {
        println!("  + {h}");
    }

    println!("Removed subdomains ({}):", r.removed_subdomains.len());
    for h in &r.removed_subdomains {
        println!("  - {h}");
    }

    println!("Port changes ({}):", r.port_changes.len());
    for pc in &r.port_changes {
        if !pc.added.is_empty() {
            let ports: Vec<String> = pc.added.iter().map(|p| p.to_string()).collect();
            println!("  {} + ports: {}", pc.hostname, ports.join(", "));
        }
        if !pc.removed.is_empty() {
            let ports: Vec<String> = pc.removed.iter().map(|p| p.to_string()).collect();
            println!("  {} - ports: {}", pc.hostname, ports.join(", "));
        }
    }

    println!("Tech changes ({}):", r.tech_changes.len());
    for tc in &r.tech_changes {
        if !tc.added.is_empty() {
            println!("  {} + tech: {}", tc.hostname, tc.added.join(", "));
        }
        if !tc.removed.is_empty() {
            println!("  {} - tech: {}", tc.hostname, tc.removed.join(", "));
        }
    }

    println!("HTTP status changes ({}):", r.status_changes.len());
    for sc in &r.status_changes {
        println!(
            "  {} {} -> {}",
            sc.hostname,
            sc.baseline_status.map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
            sc.current_status.map(|s| s.to_string()).unwrap_or_else(|| "none".into()),
        );
    }

    println!("New crawl endpoints ({}):", r.new_crawl_endpoints.len());
    for u in &r.new_crawl_endpoints {
        println!("  + {u}");
    }

    println!("Removed crawl endpoints ({}):", r.removed_crawl_endpoints.len());
    for u in &r.removed_crawl_endpoints {
        println!("  - {u}");
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Build a unique temp dir per test
    fn tmp() -> PathBuf {
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-diff-test-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn write_summary(dir: &Path, hosts: &[serde_json::Value]) {
        fs::create_dir_all(dir).unwrap();
        let arr = serde_json::Value::Array(hosts.to_vec());
        fs::write(dir.join(SUMMARY_FILENAME), serde_json::to_string(&arr).unwrap()).unwrap();
    }

    #[test]
    fn detects_new_and_removed_subdomains() {
        let t = tmp();
        let base = t.join("base");
        let curr = t.join("curr");

        write_summary(
            &base,
            &[serde_json::json!({"hostname":"old.example.com","open_ports":[]})],
        );
        write_summary(
            &curr,
            &[serde_json::json!({"hostname":"new.example.com","open_ports":[]})],
        );

        let base_hosts = load_summary(&base.join(SUMMARY_FILENAME)).unwrap();
        let curr_hosts = load_summary(&curr.join(SUMMARY_FILENAME)).unwrap();

        let base_map: HashMap<String, &HostRecord> =
            base_hosts.iter().map(|h| (h.hostname.clone(), h)).collect();
        let curr_map: HashMap<String, &HostRecord> =
            curr_hosts.iter().map(|h| (h.hostname.clone(), h)).collect();

        let new: Vec<_> = curr_hosts
            .iter()
            .filter(|h| !base_map.contains_key(&h.hostname))
            .map(|h| h.hostname.clone())
            .collect();
        let removed: Vec<_> = base_hosts
            .iter()
            .filter(|h| !curr_map.contains_key(&h.hostname))
            .map(|h| h.hostname.clone())
            .collect();

        assert_eq!(new, vec!["new.example.com"]);
        assert_eq!(removed, vec!["old.example.com"]);
    }

    #[test]
    fn detects_port_additions() {
        let t = tmp();
        let base = t.join("base");
        let curr = t.join("curr");

        write_summary(
            &base,
            &[serde_json::json!({"hostname":"api.example.com","open_ports":[80]})],
        );
        write_summary(
            &curr,
            &[serde_json::json!({"hostname":"api.example.com","open_ports":[80,443]})],
        );

        let base_hosts = load_summary(&base.join(SUMMARY_FILENAME)).unwrap();
        let curr_hosts = load_summary(&curr.join(SUMMARY_FILENAME)).unwrap();

        let base_map: HashMap<String, &HostRecord> =
            base_hosts.iter().map(|h| (h.hostname.clone(), h)).collect();

        let curr_rec = &curr_hosts[0];
        let base_rec = base_map[&curr_rec.hostname];

        let base_ports: HashSet<u16> = base_rec.open_ports.iter().copied().collect();
        let curr_ports: HashSet<u16> = curr_rec.open_ports.iter().copied().collect();
        let added: Vec<u16> = curr_ports.difference(&base_ports).copied().collect();

        assert_eq!(added, vec![443]);
    }

    #[test]
    fn load_summary_accepts_envelope_shape() {
        let t = tmp();
        let path = t.join(SUMMARY_FILENAME);
        let envelope = serde_json::json!({
            "hosts": [{"hostname":"x.example.com","open_ports":[]}]
        });
        fs::write(&path, serde_json::to_string(&envelope).unwrap()).unwrap();
        let hosts = load_summary(&path).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].hostname, "x.example.com");
    }

    #[test]
    fn auto_detect_picks_oldest_and_newest() {
        let t = tmp();
        let recon = t.join("recon");
        let a = recon.join("2026-01-01");
        let b = recon.join("2026-02-01");
        let c = recon.join("2026-03-01");
        write_summary(&a, &[serde_json::json!({"hostname":"a.example.com","open_ports":[]})]);
        write_summary(&b, &[serde_json::json!({"hostname":"b.example.com","open_ports":[]})]);
        write_summary(&c, &[serde_json::json!({"hostname":"c.example.com","open_ports":[]})]);

        let (baseline, current) = auto_detect_snapshots(&recon).unwrap();
        assert_eq!(baseline, b);
        assert_eq!(current, c);
    }
}
