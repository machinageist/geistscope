/*******************************************************************
 * Filename:        tool_finding.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     Machine-written finding record emitted by mg-* tool crates
 * Notes:           Distinct from the human-authored Finding in finding.rs.
 *                  Files land in engagements/<name>/findings/<tool>-<id>.json.
 *                  write_finding is idempotent — skips if same id already on disk.
 *******************************************************************/

use anyhow::Context;
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::PathBuf;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::Engagement;

// Maximum evidence payload kept on disk (bytes)
const EVIDENCE_MAX_BYTES: usize = 2048;
// Suffix appended after truncation so downstream consumers can detect it
const EVIDENCE_TRUNCATION_SUFFIX: &str = "... [truncated]";

// ---- severity enum

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum FindingSeverity {
    High,
    Medium,
    Low,
    Info,
}

// Display uppercase string matching the enum variant name
impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

// ---- tool finding record

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ToolFinding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendation: Option<String>,
    pub timestamp: String,
    // Optional opt-in distinguisher for tools that emit multiple findings sharing
    // the same (tool, url, parameter, title) tuple — e.g. payload variants
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,
}

impl ToolFinding {
    // Construct a new finding; sets deterministic id and UTC timestamp
    pub fn new(tool: impl Into<String>, title: impl Into<String>, severity: FindingSeverity) -> Self {
        let tool = tool.into();
        let title = title.into();
        let id = derive_id(&tool, "", "", &title, "");
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        Self {
            id,
            title,
            severity,
            tool,
            url: None,
            parameter: None,
            evidence: None,
            recommendation: None,
            timestamp,
            discriminator: None,
        }
    }

    // Builder — set the target url
    pub fn url(mut self, url: impl Into<String>) -> Self {
        let u = url.into();
        self.url = Some(u);
        self.recompute_id();
        self
    }

    // Builder — set the vulnerable parameter name
    pub fn parameter(mut self, p: impl Into<String>) -> Self {
        self.parameter = Some(p.into());
        self.recompute_id();
        self
    }

    // Builder — opt-in distinguisher when emitting multiple findings sharing the
    // same (tool, url, parameter, title) — e.g. payload, dbms, or technique
    pub fn discriminator(mut self, d: impl Into<String>) -> Self {
        self.discriminator = Some(d.into());
        self.recompute_id();
        self
    }

    // Builder — set evidence, truncated to EVIDENCE_MAX_BYTES with a marker suffix
    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        let mut s = e.into();
        if s.len() > EVIDENCE_MAX_BYTES {
            let mut boundary = EVIDENCE_MAX_BYTES.saturating_sub(EVIDENCE_TRUNCATION_SUFFIX.len());
            while boundary > 0 && !s.is_char_boundary(boundary) {
                boundary -= 1;
            }
            s.truncate(boundary);
            s.push_str(EVIDENCE_TRUNCATION_SUFFIX);
        }
        self.evidence = Some(s);
        self
    }

    // Recompute deterministic id from current tool/url/parameter/title/discriminator
    fn recompute_id(&mut self) {
        self.id = derive_id(
            &self.tool,
            self.url.as_deref().unwrap_or(""),
            self.parameter.as_deref().unwrap_or(""),
            &self.title,
            self.discriminator.as_deref().unwrap_or(""),
        );
    }

    // Builder — set remediation recommendation
    pub fn recommendation(mut self, r: impl Into<String>) -> Self {
        self.recommendation = Some(r.into());
        self
    }
}

// ---- write helper

// Write finding JSON to engagements/<name>/findings/<tool>-<id>.json; idempotent on same id
pub fn write_finding(eng: &Engagement, finding: &ToolFinding) -> anyhow::Result<PathBuf> {
    let findings_dir = eng.findings_dir();
    std::fs::create_dir_all(&findings_dir)
        .with_context(|| format!("create findings dir {}", findings_dir.display()))?;

    let filename = format!("{}-{}.json", safe_component(&finding.tool), finding.id);
    let path = findings_dir.join(&filename);

    // Skip if identical id already on disk (idempotent)
    if path.exists() {
        return Ok(path);
    }

    let json = serde_json::to_string_pretty(finding)
        .context("serialize ToolFinding")?;
    std::fs::write(&path, json)
        .with_context(|| format!("write {}", path.display()))?;

    Ok(path)
}

// ---- internal helpers

// Derive a 16-hex-char id from sha256(tool|url|parameter|title|discriminator)
fn derive_id(tool: &str, url: &str, parameter: &str, title: &str, discriminator: &str) -> String {
    let mut hasher = Sha256::new();
    // Pipe separators prevent ambiguity if fields contain each other's content
    hasher.update(tool.as_bytes());
    hasher.update(b"|");
    hasher.update(url.as_bytes());
    hasher.update(b"|");
    hasher.update(parameter.as_bytes());
    hasher.update(b"|");
    hasher.update(title.as_bytes());
    hasher.update(b"|");
    hasher.update(discriminator.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..8])
}

// Replace characters that are unsafe in filenames with dashes
fn safe_component(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect()
}

// ---- tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Engagement, EngagementMeta};
    use std::fs;

    fn tmp_eng() -> (tempfile::TempDir, Engagement) {
        let dir = tempfile::tempdir().unwrap();
        let meta = EngagementMeta {
            name: "test-eng".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        let eng = Engagement::init(dir.path(), meta).unwrap();
        (dir, eng)
    }

    #[test]
    fn id_is_deterministic() {
        let f1 = ToolFinding::new("mg-xss", "Reflected XSS", FindingSeverity::High)
            .url("https://example.com/search");
        let f2 = ToolFinding::new("mg-xss", "Reflected XSS", FindingSeverity::High)
            .url("https://example.com/search");
        assert_eq!(f1.id, f2.id);
        assert_eq!(f1.id.len(), 16);
    }

    #[test]
    fn id_differs_by_url() {
        let f1 = ToolFinding::new("mg-xss", "XSS", FindingSeverity::High)
            .url("https://a.com");
        let f2 = ToolFinding::new("mg-xss", "XSS", FindingSeverity::High)
            .url("https://b.com");
        assert_ne!(f1.id, f2.id);
    }

    #[test]
    fn evidence_truncated_with_marker() {
        let long = "x".repeat(4096);
        let f = ToolFinding::new("mg-sqli", "SQLi", FindingSeverity::Medium)
            .evidence(long);
        let ev = f.evidence.unwrap();
        assert!(ev.ends_with(EVIDENCE_TRUNCATION_SUFFIX));
        assert!(ev.len() <= EVIDENCE_MAX_BYTES);
    }

    #[test]
    fn discriminator_changes_id() {
        let base = ToolFinding::new("mg-sqli", "SQLi", FindingSeverity::High)
            .url("https://example.com/api");
        let f1 = base.clone().discriminator("payload-a");
        let f2 = base.clone().discriminator("payload-b");
        assert_ne!(f1.id, f2.id);
        // Same discriminator yields same id (idempotency preserved)
        let f1b = base.discriminator("payload-a");
        assert_eq!(f1.id, f1b.id);
    }

    #[test]
    fn severity_display_is_uppercase() {
        assert_eq!(FindingSeverity::High.to_string(), "HIGH");
        assert_eq!(FindingSeverity::Info.to_string(), "INFO");
    }

    #[test]
    fn write_finding_creates_json_file() {
        let (_dir, eng) = tmp_eng();
        let finding = ToolFinding::new("mg-xss", "Reflected XSS", FindingSeverity::High)
            .url("https://example.com/search")
            .parameter("q");
        let path = write_finding(&eng, &finding).unwrap();
        assert!(path.exists());
        let raw = fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed["tool"], "mg-xss");
        assert_eq!(parsed["title"], "Reflected XSS");
    }

    #[test]
    fn write_finding_is_idempotent() {
        let (_dir, eng) = tmp_eng();
        let finding = ToolFinding::new("mg-xss", "Reflected XSS", FindingSeverity::High);
        let p1 = write_finding(&eng, &finding).unwrap();
        let p2 = write_finding(&eng, &finding).unwrap();
        assert_eq!(p1, p2);
        // Only one file in findings/
        let count = fs::read_dir(eng.findings_dir()).unwrap().count();
        assert_eq!(count, 1);
    }
}
