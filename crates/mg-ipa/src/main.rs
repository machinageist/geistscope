/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-ipa — iOS IPA static analysis for security misconfigurations.
 * Notes:           IPAs are ZIP containers with a Payload/AppName.app/ directory.
 *                  Info.plist is a binary/XML plist — we scan as raw bytes.
 *                  The Mach-O binary is the entry named Payload/AppName.app/AppName
 *                  (matching bundle name, no extension). Bytes are scanned as strings.
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

const OUTPUT_SUBDIR: &str = "ipa";
const OUTPUT_FILE_PREFIX: &str = "results-";
const AUDIT_TOOL: &str = "mg-ipa";

// Info.plist scan patterns
const PLIST_ARBITRARY_LOADS: &str = "NSAllowsArbitraryLoads";
const PLIST_GET_TASK_ALLOW: &str = "get-task-allow";
const PLIST_URL_SCHEMES: &str = "CFBundleURLSchemes";
const PLIST_TRUE: &str = "<true/>";

// Secret patterns in Mach-O binary
const AWS_KEY_PATTERN: &str = r"AKIA[0-9A-Z]{16}";
const GOOGLE_KEY_PATTERN: &str = r"AIza[0-9A-Za-z\-_]{35}";
const HTTP_URL_PATTERN: &str = r"http://[a-zA-Z0-9./_-]+";

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-ipa",
    about = "iOS IPA static security analysis"
)]
struct Args {
    /// Engagement name
    engagement: String,

    /// Engagements root directory
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Path to the IPA file to analyze
    #[arg(long)]
    ipa: String,
}

// ── Data types ───────────────────────────────────────────────────────────────

// Severity of a finding
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "UPPERCASE")]
enum Severity {
    High,
    Medium,
    Low,
    Info,
}

// One security finding
#[derive(Debug, Serialize)]
struct IpaFinding {
    severity: Severity,
    category: String,
    detail: String,
    location: String,
}

// Top-level output
#[derive(Serialize)]
struct IpaResults {
    engagement: String,
    timestamp: String,
    ipa_path: String,
    app_name: Option<String>,
    finding_count: usize,
    findings: Vec<IpaFinding>,
}

// ── IPA analysis ──────────────────────────────────────────────────────────────

// Find the Info.plist path and app name from IPA ZIP entries
fn find_plist_and_app_name(names: &[String]) -> (Option<String>, Option<String>) {
    // Look for Payload/<AppName>.app/Info.plist
    for name in names {
        if name.starts_with("Payload/") && name.ends_with("/Info.plist") {
            // Extract <AppName> from Payload/<AppName>.app/Info.plist
            let parts: Vec<&str> = name.splitn(4, '/').collect();
            if parts.len() >= 3 {
                let app_dir = parts[1]; // e.g. "MyApp.app"
                let app_name = app_dir.trim_end_matches(".app").to_string();
                return (Some(name.clone()), Some(app_name));
            }
        }
    }
    (None, None)
}

// Find the Mach-O binary entry name for a given app name
fn find_macho_entry(names: &[String], app_name: &str) -> Option<String> {
    let expected = format!("Payload/{app_name}.app/{app_name}");
    names.iter().find(|n| *n == &expected).cloned()
}

// Check if a byte position near a key pattern is close to a <true/> tag
fn near_true(text: &str, key_pos: usize) -> bool {
    let end = (key_pos + 200).min(text.len());
    text[key_pos..end].contains(PLIST_TRUE)
}

// Scan Info.plist bytes for security-relevant flags
fn scan_plist(bytes: &[u8]) -> Vec<IpaFinding> {
    let text = String::from_utf8_lossy(bytes);
    let mut findings = Vec::new();

    // NSAllowsArbitraryLoads near <true/>
    if let Some(pos) = text.find(PLIST_ARBITRARY_LOADS)
        && near_true(&text, pos)
    {
        findings.push(IpaFinding {
            severity: Severity::Medium,
            category: "arbitrary_loads".to_string(),
            detail: "NSAllowsArbitraryLoads is true — cleartext HTTP traffic allowed".to_string(),
            location: "Info.plist".to_string(),
        });
    }

    // get-task-allow near <true/> — allows debugger attachment (dev builds only)
    if let Some(pos) = text.find(PLIST_GET_TASK_ALLOW)
        && near_true(&text, pos)
    {
        findings.push(IpaFinding {
            severity: Severity::High,
            category: "get_task_allow".to_string(),
            detail: "get-task-allow is true — app allows debugger attachment".to_string(),
            location: "Info.plist".to_string(),
        });
    }

    // CFBundleURLSchemes — custom URL scheme registered
    if text.contains(PLIST_URL_SCHEMES) {
        findings.push(IpaFinding {
            severity: Severity::Info,
            category: "custom_url_scheme".to_string(),
            detail: "CFBundleURLSchemes defined — custom URL scheme registered".to_string(),
            location: "Info.plist".to_string(),
        });
    }

    findings
}

// Scan Mach-O binary bytes as strings for secrets and cleartext URLs
fn scan_macho(bytes: &[u8], location: &str, aws_re: &Regex, gcp_re: &Regex, http_re: &Regex) -> Vec<IpaFinding> {
    let text = String::from_utf8_lossy(bytes);
    let mut findings = Vec::new();

    // AWS access keys
    for m in aws_re.find_iter(&text) {
        findings.push(IpaFinding {
            severity: Severity::High,
            category: "hardcoded_aws_key".to_string(),
            detail: format!("AWS access key found: {}", m.as_str()),
            location: location.to_string(),
        });
    }

    // Google API keys
    for m in gcp_re.find_iter(&text) {
        findings.push(IpaFinding {
            severity: Severity::High,
            category: "hardcoded_google_key".to_string(),
            detail: format!("Google API key found: {}", m.as_str()),
            location: location.to_string(),
        });
    }

    // Cleartext HTTP URLs
    for m in http_re.find_iter(&text) {
        findings.push(IpaFinding {
            severity: Severity::Low,
            category: "cleartext_url".to_string(),
            detail: format!("Cleartext HTTP URL: {}", m.as_str()),
            location: location.to_string(),
        });
    }

    findings
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let eng = Engagement::load_named(Path::new(&args.engagements_dir), &args.engagement)
        .with_context(|| format!("load engagement {}", args.engagement))?;

    eprintln!("mg-ipa: analyzing {}", args.ipa);

    let ipa_bytes = fs::read(&args.ipa)
        .with_context(|| format!("read IPA file {}", args.ipa))?;

    let cursor = std::io::Cursor::new(ipa_bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("open IPA as ZIP")?;

    eprintln!("  {} entries in IPA", archive.len());

    // Collect all entry names
    let entry_names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    let (plist_name, app_name) = find_plist_and_app_name(&entry_names);
    eprintln!("  app_name={:?}", app_name);

    // Compile regexes once
    let aws_re = Regex::new(AWS_KEY_PATTERN).expect("AWS regex");
    let gcp_re = Regex::new(GOOGLE_KEY_PATTERN).expect("GCP regex");
    let http_re = Regex::new(HTTP_URL_PATTERN).expect("HTTP URL regex");

    let mut findings: Vec<IpaFinding> = Vec::new();

    // Scan Info.plist
    if let Some(ref plist_path) = plist_name
        && let Ok(mut entry) = archive.by_name(plist_path)
    {
        let mut buf = Vec::new();
        let _ = entry.read_to_end(&mut buf);
        drop(entry);
        eprintln!("  scanning Info.plist");
        findings.extend(scan_plist(&buf));
    }

    // Scan Mach-O binary
    if let Some(ref name) = app_name
        && let Some(macho_entry) = find_macho_entry(&entry_names, name)
        && let Ok(mut entry) = archive.by_name(&macho_entry)
    {
        let mut buf = Vec::new();
        let _ = entry.read_to_end(&mut buf);
        drop(entry);
        eprintln!("  scanning Mach-O binary: {macho_entry}");
        findings.extend(scan_macho(&buf, &macho_entry, &aws_re, &gcp_re, &http_re));
    }

    eprintln!("  {} total findings", findings.len());

    // Write output
    let out_dir = eng.root.join(OUTPUT_SUBDIR);
    fs::create_dir_all(&out_dir).context("create ipa output dir")?;
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let ts_file = ts.replace(':', "-").replace('+', "Z");
    let out_path = out_dir.join(format!("{OUTPUT_FILE_PREFIX}{ts_file}.json"));

    let output = IpaResults {
        engagement: args.engagement.clone(),
        timestamp: ts,
        ipa_path: args.ipa.clone(),
        app_name,
        finding_count: findings.len(),
        findings,
    };
    let json = serde_json::to_string_pretty(&output)?;
    fs::write(&out_path, &json).context("write results JSON")?;
    println!("[*] Results written to {}", out_path.display());

    let _ = eng.audit(AUDIT_TOOL, &args.ipa, None);

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_plist_detects_arbitrary_loads() {
        let xml = b"<key>NSAllowsArbitraryLoads</key><true/>";
        let findings = scan_plist(xml);
        assert!(findings.iter().any(|f| f.category == "arbitrary_loads"));
    }

    #[test]
    fn scan_plist_no_finding_when_false() {
        let xml = b"<key>NSAllowsArbitraryLoads</key><false/>";
        let findings = scan_plist(xml);
        assert!(!findings.iter().any(|f| f.category == "arbitrary_loads"));
    }

    #[test]
    fn scan_plist_detects_get_task_allow() {
        let xml = b"<key>get-task-allow</key><true/>";
        let findings = scan_plist(xml);
        assert!(findings.iter().any(|f| f.category == "get_task_allow"));
    }

    #[test]
    fn scan_plist_detects_url_scheme() {
        let xml = b"<key>CFBundleURLSchemes</key><array><string>myapp</string></array>";
        let findings = scan_plist(xml);
        assert!(findings.iter().any(|f| f.category == "custom_url_scheme"));
    }

    #[test]
    fn find_plist_and_app_name_parses_correctly() {
        let names = vec![
            "Payload/MyApp.app/Info.plist".to_string(),
            "Payload/MyApp.app/MyApp".to_string(),
        ];
        let (plist, app) = find_plist_and_app_name(&names);
        assert_eq!(plist.as_deref(), Some("Payload/MyApp.app/Info.plist"));
        assert_eq!(app.as_deref(), Some("MyApp"));
    }

    #[test]
    fn find_macho_entry_finds_correct_entry() {
        let names = vec![
            "Payload/MyApp.app/Info.plist".to_string(),
            "Payload/MyApp.app/MyApp".to_string(),
            "Payload/MyApp.app/Frameworks/Lib.dylib".to_string(),
        ];
        let entry = find_macho_entry(&names, "MyApp");
        assert_eq!(entry.as_deref(), Some("Payload/MyApp.app/MyApp"));
    }

    #[test]
    fn scan_macho_finds_aws_key() {
        let aws_re = Regex::new(AWS_KEY_PATTERN).unwrap();
        let gcp_re = Regex::new(GOOGLE_KEY_PATTERN).unwrap();
        let http_re = Regex::new(HTTP_URL_PATTERN).unwrap();
        let content = b"secret=AKIAIOSFODNN7EXAMPLE trailing";
        let findings = scan_macho(content, "Payload/App.app/App", &aws_re, &gcp_re, &http_re);
        assert!(findings.iter().any(|f| f.category == "hardcoded_aws_key"));
    }

    #[test]
    fn scan_macho_finds_google_key() {
        let aws_re = Regex::new(AWS_KEY_PATTERN).unwrap();
        let gcp_re = Regex::new(GOOGLE_KEY_PATTERN).unwrap();
        let http_re = Regex::new(HTTP_URL_PATTERN).unwrap();
        // 35 chars after AIza
        let content = b"key=AIzaSyD-9tSrke72I6e0a8lLkjBn3m6EXAMPLEabcdef trailing";
        let findings = scan_macho(content, "Payload/App.app/App", &aws_re, &gcp_re, &http_re);
        assert!(findings.iter().any(|f| f.category == "hardcoded_google_key"));
    }

    #[test]
    fn scan_macho_finds_cleartext_url() {
        let aws_re = Regex::new(AWS_KEY_PATTERN).unwrap();
        let gcp_re = Regex::new(GOOGLE_KEY_PATTERN).unwrap();
        let http_re = Regex::new(HTTP_URL_PATTERN).unwrap();
        let content = b"endpoint http://api.example.com/v1/data end";
        let findings = scan_macho(content, "Payload/App.app/App", &aws_re, &gcp_re, &http_re);
        assert!(findings.iter().any(|f| f.category == "cleartext_url"));
    }
}
