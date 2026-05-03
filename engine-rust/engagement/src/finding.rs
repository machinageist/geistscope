// Author: Jeff
// Date: 2026-05-02
// Description: Finding records — markdown body with simple frontmatter

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::EngagementError;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Draft,
    Confirmed,
    Reported,
    Triaged,
    Resolved,
    Duplicate,
    Wontfix,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Confirmed => "confirmed",
            Self::Reported => "reported",
            Self::Triaged => "triaged",
            Self::Resolved => "resolved",
            Self::Duplicate => "duplicate",
            Self::Wontfix => "wontfix",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub status: Status,
    pub target: String,
    pub created: String,
    pub body: String,
}

impl Finding {
    // Render to a markdown file with YAML-ish frontmatter
    pub fn to_markdown(&self) -> String {
        format!(
            "---\nid: {}\ntitle: {}\nseverity: {}\nstatus: {}\ntarget: {}\ncreated: {}\n---\n\n{}",
            self.id,
            self.title,
            self.severity.as_str(),
            self.status.as_str(),
            self.target,
            self.created,
            self.body,
        )
    }

    // Skeleton body with the standard sections we want for every finding
    pub fn skeleton_body() -> String {
        "## Summary\n\n_one paragraph describing the issue_\n\n\
         ## Steps to reproduce\n\n1. \n2. \n3. \n\n\
         ## Impact\n\n_what an attacker can do, scoped to business impact_\n\n\
         ## Evidence\n\n_curl reproductions, screenshots, response excerpts_\n\n\
         ## Remediation\n\n_recommendation_\n"
            .to_string()
    }

    // Write the finding to <findings_dir>/<id>-<slug>.md and return the path
    pub fn write_to(&self, findings_dir: &Path) -> Result<PathBuf, EngagementError> {
        let slug = slugify(&self.title);
        let filename = format!("{}-{slug}.md", self.id);
        let path = findings_dir.join(filename);
        fs::write(&path, self.to_markdown())?;
        Ok(path)
    }
}

// Lowercase, alnum + dashes only, collapsed; truncated to 60 chars
fn slugify(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.truncate(60);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_basic() {
        assert_eq!(slugify("IDOR on /api/orders/{id}"), "idor-on-api-orders-id");
        assert_eq!(slugify("Reflected XSS in search"), "reflected-xss-in-search");
        assert_eq!(slugify("  leading and trailing  "), "leading-and-trailing");
    }

    #[test]
    fn markdown_has_frontmatter() {
        let f = Finding {
            id: "2026-05-02-001".into(),
            title: "Test".into(),
            severity: Severity::High,
            status: Status::Draft,
            target: "api.example.com".into(),
            created: "2026-05-02T10:00:00Z".into(),
            body: "## Summary\n\nbody here\n".into(),
        };
        let md = f.to_markdown();
        assert!(md.starts_with("---\n"));
        assert!(md.contains("severity: high"));
        assert!(md.contains("status: draft"));
        assert!(md.contains("body here"));
    }
}
