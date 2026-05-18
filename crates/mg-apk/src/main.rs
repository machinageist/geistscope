/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-apk — Android APK static analysis for security misconfigurations.
 * Notes:           APKs are ZIP containers. Scans AndroidManifest.xml for dangerous
 *                  flags, DEX + assets for hardcoded secrets and cleartext URLs.
 *                  network_security_config.xml checked for cleartext traffic permission.
 *                  No tokio — fully synchronous file I/O.
 *******************************************************************/

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use clap::Parser;
use regex::Regex;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::Engagement;

// ── Constants ────────────────────────────────────────────────────────────────

const OUTPUT_SUBDIR: &str = "apk";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-apk";

// AndroidManifest.xml scan patterns
const MANIFEST_DEBUGGABLE: &str = "android:debuggable=\"true\"";
const MANIFEST_ALLOW_BACKUP: &str = "android:allowBackup=\"true\"";
const MANIFEST_EXPORTED: &str = "android:exported=\"true\"";
const NETWORK_CONFIG_CLEARTEXT: &str = "cleartextTrafficPermitted";

// AWS access key pattern prefix — AKIA followed by 16 uppercase alphanumerics
const AWS_KEY_PATTERN: &str = r"AKIA[0-9A-Z]{16}";
// Cleartext HTTP URL pattern
const HTTP_URL_PATTERN: &str = r"http://[a-zA-Z0-9./_-]+";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-apk",
    about = "Android APK static security analysis"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to the APK file to analyze
    #[arg(long)]
    apk: String,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Severity of a finding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    High,
    Medium,
    Low,
}

// One security finding
#[derive(Debug, Serialize)]
struct ApkFinding {
    severity: Severity,
    category: String,
    detail: String,
    location: String,
}

// Top-level output
#[derive(Serialize)]
struct ApkResults {
    engagement: String,
    timestamp: String,
    apk_path: String,
    finding_count: usize,
    findings: Vec<ApkFinding>,
}

// ── APK analysis ──────────────────────────────────────────────────────────────

// Read a named file from a ZIP archive as raw bytes
fn read_zip_entry(archive: &mut zip::ZipArchive<std::io::Cursor<Vec<u8>>>, name: &str) -> Option<Vec<u8>> {
    let mut entry = archive.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    Some(buf)
}

// Scan AndroidManifest.xml bytes for dangerous attribute flags
fn scan_manifest(bytes: &[u8]) -> Vec<ApkFinding> {
    let text = String::from_utf8_lossy(bytes);
    let mut findings = Vec::new();

    if text.contains(MANIFEST_DEBUGGABLE) {
        findings.push(ApkFinding {
            severity: Severity::High,
            category: "debuggable".to_string(),
            detail: "android:debuggable=\"true\" — app is debuggable in production".to_string(),
            location: "AndroidManifest.xml".to_string(),
        });
    }

    if text.contains(MANIFEST_ALLOW_BACKUP) {
        findings.push(ApkFinding {
            severity: Severity::Medium,
            category: "allow_backup".to_string(),
            detail: "android:allowBackup=\"true\" — app data can be extracted via adb backup".to_string(),
            location: "AndroidManifest.xml".to_string(),
        });
    }

    // Flag exported components — look for android:exported="true" with no permission attribute nearby
    let mut search_start = 0;
    while let Some(pos) = text[search_start..].find(MANIFEST_EXPORTED) {
        let abs_pos = search_start + pos;
        // Check a window of 300 chars before the exported flag for permission attribute
        let window_start = abs_pos.saturating_sub(300);
        let window = &text[window_start..abs_pos];
        if !window.contains("android:permission") {
            // Find the component name in a window before the flag
            let component_name = extract_component_name(window);
            findings.push(ApkFinding {
                severity: Severity::High,
                category: "exported_component".to_string(),
                detail: format!(
                    "android:exported=\"true\" without permission check — component: {}",
                    component_name
                ),
                location: "AndroidManifest.xml".to_string(),
            });
        }
        search_start = abs_pos + MANIFEST_EXPORTED.len();
    }

    findings
}

// Extract a component name (activity/service/receiver) from a manifest text window
fn extract_component_name(window: &str) -> String {
    for tag in &["<activity", "<service", "<receiver"] {
        if let Some(tag_pos) = window.rfind(tag) {
            let after_tag = &window[tag_pos..];
            if let Some(name_pos) = after_tag.find("android:name=\"") {
                let name_start = name_pos + "android:name=\"".len();
                let rest = &after_tag[name_start..];
                if let Some(end) = rest.find('"') {
                    return rest[..end].to_string();
                }
            }
        }
    }
    "(unknown)".to_string()
}

// Scan binary content (DEX, assets) for hardcoded secrets and cleartext URLs
fn scan_binary_content(bytes: &[u8], location: &str, aws_re: &Regex, http_re: &Regex) -> Vec<ApkFinding> {
    let text = String::from_utf8_lossy(bytes);
    let mut findings = Vec::new();

    // AWS access keys
    for m in aws_re.find_iter(&text) {
        findings.push(ApkFinding {
            severity: Severity::High,
            category: "hardcoded_aws_key".to_string(),
            detail: format!("AWS access key found: {}", m.as_str()),
            location: location.to_string(),
        });
    }

    // Cleartext HTTP URLs (not https)
    for m in http_re.find_iter(&text) {
        findings.push(ApkFinding {
            severity: Severity::Low,
            category: "cleartext_url".to_string(),
            detail: format!("Cleartext HTTP URL: {}", m.as_str()),
            location: location.to_string(),
        });
    }

    findings
}

// Scan network_security_config.xml for cleartext traffic permission
fn scan_network_config(bytes: &[u8]) -> Vec<ApkFinding> {
    let text = String::from_utf8_lossy(bytes);
    let mut findings = Vec::new();
    if text.contains(NETWORK_CONFIG_CLEARTEXT) {
        findings.push(ApkFinding {
            severity: Severity::Medium,
            category: "cleartext_traffic".to_string(),
            detail: "cleartextTrafficPermitted found in network_security_config.xml".to_string(),
            location: "res/xml/network_security_config.xml".to_string(),
        });
    }
    findings
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-apk: analyzing {}", args.apk);

    let apk_bytes = fs::read(&args.apk)
        .with_context(|| format!("read APK file {}", args.apk))?;

    let cursor = std::io::Cursor::new(apk_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("open APK as ZIP")?;

    eprintln!("  {} entries in APK", archive.len());

    // Compile regexes once
    let aws_re = Regex::new(AWS_KEY_PATTERN).expect("AWS regex");
    let http_re = Regex::new(HTTP_URL_PATTERN).expect("HTTP URL regex");

    let mut findings: Vec<ApkFinding> = Vec::new();

    // Scan AndroidManifest.xml
    if let Some(manifest_bytes) = read_zip_entry(&mut archive, "AndroidManifest.xml") {
        eprintln!("  scanning AndroidManifest.xml");
        findings.extend(scan_manifest(&manifest_bytes));
    } else {
        eprintln!("  AndroidManifest.xml not found in APK");
    }

    // Scan network_security_config.xml
    if let Some(nsc_bytes) = read_zip_entry(&mut archive, "res/xml/network_security_config.xml") {
        eprintln!("  scanning network_security_config.xml");
        findings.extend(scan_network_config(&nsc_bytes));
    }

    // Collect names of DEX files and asset text files to scan
    let entry_names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    for name in &entry_names {
        let is_dex = name.ends_with(".dex");
        let is_asset_text = name.starts_with("assets/")
            && !name.ends_with(".png")
            && !name.ends_with(".jpg")
            && !name.ends_with(".so");

        if (is_dex || is_asset_text)
            && let Some(bytes) = read_zip_entry(&mut archive, name)
        {
            let new_findings = scan_binary_content(&bytes, name, &aws_re, &http_re);
            if !new_findings.is_empty() {
                eprintln!("  {} findings in {}", new_findings.len(), name);
            }
            findings.extend(new_findings);
        }
    }

    eprintln!("  {} total findings", findings.len());

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create apk output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = ApkResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        apk_path: args.apk.clone(),
        finding_count: findings.len(),
        findings,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    let _ = eng.audit(AUDIT_TOOL, &args.apk, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_manifest_detects_debuggable() {
        let xml = b"<application android:debuggable=\"true\" android:allowBackup=\"false\">";
        let findings = scan_manifest(xml);
        assert!(findings.iter().any(|f| f.category == "debuggable"));
        assert!(!findings.iter().any(|f| f.category == "allow_backup"));
    }

    #[test]
    fn scan_manifest_detects_allow_backup() {
        let xml = b"<application android:allowBackup=\"true\">";
        let findings = scan_manifest(xml);
        assert!(findings.iter().any(|f| f.category == "allow_backup"));
    }

    #[test]
    fn scan_manifest_detects_exported_without_permission() {
        let xml = b"<activity android:name=\".MainActivity\" android:exported=\"true\">";
        let findings = scan_manifest(xml);
        assert!(findings.iter().any(|f| f.category == "exported_component"));
    }

    #[test]
    fn scan_manifest_no_finding_for_exported_with_permission() {
        let xml = b"<activity android:name=\".SafeActivity\" android:permission=\"com.example.PERM\" android:exported=\"true\">";
        let findings = scan_manifest(xml);
        assert!(!findings.iter().any(|f| f.category == "exported_component"));
    }

    #[test]
    fn scan_binary_finds_aws_key() {
        let aws_re = Regex::new(AWS_KEY_PATTERN).unwrap();
        let http_re = Regex::new(HTTP_URL_PATTERN).unwrap();
        let content = b"key=AKIAIOSFODNN7EXAMPLE rest of config";
        let findings = scan_binary_content(content, "classes.dex", &aws_re, &http_re);
        assert!(findings.iter().any(|f| f.category == "hardcoded_aws_key"));
    }

    #[test]
    fn scan_binary_finds_http_url() {
        let aws_re = Regex::new(AWS_KEY_PATTERN).unwrap();
        let http_re = Regex::new(HTTP_URL_PATTERN).unwrap();
        let content = b"endpoint=http://api.example.com/v1 rest";
        let findings = scan_binary_content(content, "assets/config.txt", &aws_re, &http_re);
        assert!(findings.iter().any(|f| f.category == "cleartext_url"));
    }

    #[test]
    fn scan_network_config_detects_cleartext() {
        let xml = b"<network-security-config><base-config cleartextTrafficPermitted=\"true\"/></network-security-config>";
        let findings = scan_network_config(xml);
        assert!(!findings.is_empty());
        assert!(findings[0].category == "cleartext_traffic");
    }

    #[test]
    fn extract_component_name_finds_activity_name() {
        let window = "<activity android:name=\".LoginActivity\" ";
        let name = extract_component_name(window);
        assert_eq!(name, ".LoginActivity");
    }
}
