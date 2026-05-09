/*******************************************************************
 * Filename:        loader.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Async poller that reads engagement JSON files into app data
 * Notes:           Polls on a 2-second interval; no inotify/FSEvents dependency
 *******************************************************************/

use anyhow::Result;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

// Engagement list entry shown in the overview tab
#[derive(Clone, Debug)]
pub struct EngagementEntry {
    pub name: String,
    pub target: String,
    pub platform: String,
    pub findings_count: usize,
    pub recon_done: bool,
}

// Host record built from summary.json
#[derive(Clone, Debug, Default)]
pub struct HostRecord {
    pub hostname: String,
    pub open_ports: Vec<u16>,
    pub tech_stack: Vec<String>,
    pub status_code: Option<u16>,
    pub server: Option<String>,
}

// Finding entry built from findings/*.md frontmatter
#[derive(Clone, Debug)]
pub struct FindingEntry {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub host: String,
}

// Fuzz result entry from fuzz-*.json reports
#[derive(Clone, Debug)]
pub struct FuzzEntry {
    pub label: String,
    pub status: u16,
    pub len_delta: i64,
    pub elapsed_ms: u64,
    #[allow(dead_code)]
    pub interesting: bool,
}

// Snapshot of all loaded data for one engagement
#[derive(Clone, Debug, Default)]
pub struct EngagementData {
    pub hosts: Vec<HostRecord>,
    pub findings: Vec<FindingEntry>,
    pub fuzz_results: Vec<FuzzEntry>,
    pub log_lines: Vec<String>,
}

// Serde helpers for summary.json
#[derive(Deserialize)]
struct SummaryHost {
    hostname: Option<String>,
    open_ports: Option<Vec<u16>>,
    tech_stack: Option<Vec<String>>,
    status_code: Option<u16>,
    server: Option<String>,
}

// Serde helpers for fuzz JSON
#[derive(Deserialize)]
struct FuzzReport {
    results: Option<Vec<FuzzResult>>,
}

#[derive(Deserialize)]
struct FuzzResult {
    label: Option<String>,
    status: Option<u16>,
    diff: Option<FuzzDiff>,
    elapsed_ms: Option<u64>,
}

#[derive(Deserialize)]
struct FuzzDiff {
    len_delta: Option<i64>,
    interesting: Option<bool>,
}

// Discover all engagement directories under the engagements root
pub fn list_engagements(engagements_dir: &Path) -> Result<Vec<EngagementEntry>> {
    let mut out = Vec::new();
    if !engagements_dir.exists() {
        return Ok(out);
    }
    for entry in fs::read_dir(engagements_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let dir = entry.path();
        let meta_path = dir.join("engagement.json");
        if !meta_path.exists() {
            continue;
        }
        if let Ok(e) = parse_engagement_entry(&dir) {
            out.push(e);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// Parse engagement.json and count findings
fn parse_engagement_entry(dir: &Path) -> Result<EngagementEntry> {
    let raw = fs::read_to_string(dir.join("engagement.json"))?;
    let v: serde_json::Value = serde_json::from_str(&raw)?;
    let name = v["name"].as_str().unwrap_or("unknown").to_string();
    let target = v["target"].as_str().unwrap_or("").to_string();
    let platform = v["platform"].as_str().unwrap_or("").to_string();
    let recon_done = dir.join("recon").join("summary.json").exists();
    let findings_count = count_findings(&dir.join("findings"));
    Ok(EngagementEntry { name, target, platform, findings_count, recon_done })
}

// Count .md files in the findings directory
fn count_findings(findings_dir: &Path) -> usize {
    fs::read_dir(findings_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().is_some_and(|x| x == "md"))
                .count()
        })
        .unwrap_or(0)
}

// Load all data for a named engagement
pub fn load_engagement_data(engagements_dir: &Path, name: &str) -> EngagementData {
    let dir = engagements_dir.join(name);
    EngagementData {
        hosts: load_hosts(&dir),
        findings: load_findings(&dir),
        fuzz_results: load_fuzz(&dir),
        log_lines: load_log(&dir),
    }
}

// Parse summary.json into HostRecord list
fn load_hosts(dir: &Path) -> Vec<HostRecord> {
    let path = dir.join("recon").join("summary.json");
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return vec![],
    };
    arr.iter()
        .filter_map(|item| {
            let h: SummaryHost = serde_json::from_value(item.clone()).ok()?;
            Some(HostRecord {
                hostname: h.hostname.unwrap_or_default(),
                open_ports: h.open_ports.unwrap_or_default(),
                tech_stack: h.tech_stack.unwrap_or_default(),
                status_code: h.status_code,
                server: h.server,
            })
        })
        .collect()
}

// Parse finding markdown frontmatter for id, title, severity, host
fn load_findings(dir: &Path) -> Vec<FindingEntry> {
    let findings_dir = dir.join("findings");
    let mut out = Vec::new();
    let rd = match fs::read_dir(&findings_dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.extension().is_none_or(|x| x != "md") {
            continue;
        }
        if let Some(f) = parse_finding_frontmatter(&path) {
            out.push(f);
        }
    }
    out.sort_by_key(|a| severity_order(&a.severity));
    out
}

// Extract YAML-ish frontmatter fields from finding markdown
fn parse_finding_frontmatter(path: &Path) -> Option<FindingEntry> {
    let raw = fs::read_to_string(path).ok()?;
    let stem = path.file_stem()?.to_string_lossy().to_string();
    let mut id = stem.clone();
    let mut title = stem;
    let mut severity = "info".to_string();
    let mut host = String::new();
    let mut in_front = false;
    for line in raw.lines() {
        if line == "---" {
            if in_front {
                break;
            }
            in_front = true;
            continue;
        }
        if !in_front {
            continue;
        }
        if let Some(v) = line.strip_prefix("id: ") {
            id = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("title: ") {
            title = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("severity: ") {
            severity = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("host: ") {
            host = v.trim().to_string();
        }
    }
    Some(FindingEntry { id, title, severity, host })
}

// Sort severity: critical < high < medium < low < info
fn severity_order(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

// Collect interesting fuzz results from all fuzz-*.json files
fn load_fuzz(dir: &Path) -> Vec<FuzzEntry> {
    let recon_dir = dir.join("recon");
    let mut out = Vec::new();
    let rd = match fs::read_dir(&recon_dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    let mut paths: Vec<PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("fuzz-") && n.ends_with(".json"))
        })
        .collect();
    paths.sort();
    for path in paths {
        let raw = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let report: FuzzReport = match serde_json::from_str(&raw) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let results = match report.results {
            Some(r) => r,
            None => continue,
        };
        for r in results {
            let diff = r.diff.unwrap_or(FuzzDiff { len_delta: None, interesting: None });
            if diff.interesting.unwrap_or(false) {
                out.push(FuzzEntry {
                    label: r.label.unwrap_or_default(),
                    status: r.status.unwrap_or(0),
                    len_delta: diff.len_delta.unwrap_or(0),
                    elapsed_ms: r.elapsed_ms.unwrap_or(0),
                    interesting: true,
                });
            }
        }
    }
    out
}

// Read last N lines of audit.log
fn load_log(dir: &Path) -> Vec<String> {
    let path = dir.join("audit.log");
    let raw = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    raw.lines().rev().take(200).map(str::to_string).collect::<Vec<_>>().into_iter().rev().collect()
}
