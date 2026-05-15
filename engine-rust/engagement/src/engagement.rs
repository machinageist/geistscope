/*******************************************************************
 * Filename:        engagement.rs
 * Author:          Jeff
 * Date:            2026-05-02
 * Description:     Engagement directory — metadata, layout, audit log
 * Notes:           Each engagement is a directory with engagement.json,
 *                  scope.json, audit.log, notes.md, recon/, crawl/, findings/
 *******************************************************************/

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::EngagementError;
use crate::scope::Scope;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngagementMeta {
    pub name: String,
    pub target: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

pub struct Engagement {
    pub root: PathBuf,
    pub meta: EngagementMeta,
}

impl Engagement {
    // Create a fresh engagement directory under `parent`; fails if it already exists
    pub fn init(parent: &Path, mut meta: EngagementMeta) -> Result<Self, EngagementError> {
        let root = engagement_path(parent, &meta.name)?;
        if root.exists() {
            return Err(EngagementError::AlreadyExists(root.display().to_string()));
        }

        if meta.created_at.is_empty() {
            meta.created_at = now_rfc3339()?;
        }

        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join("recon"))?;
        fs::create_dir_all(root.join("crawl"))?;
        fs::create_dir_all(root.join("findings"))?;

        write_json(&root.join("engagement.json"), &meta)?;
        Scope::default_for(&meta.target).save(&root.join("scope.json"))?;

        fs::write(
            root.join("notes.md"),
            format!(
                "# {} — {}\n\nCreated {}.\n\n## Notes\n\n",
                meta.name, meta.target, meta.created_at
            ),
        )?;
        fs::File::create(root.join("audit.log"))?;

        Ok(Self { root, meta })
    }

    // Resolve a validated engagement name under a parent directory
    pub fn path_for_name(parent: &Path, name: &str) -> Result<PathBuf, EngagementError> {
        engagement_path(parent, name)
    }

    // Load an existing engagement by name from a parent directory
    pub fn load_named(parent: &Path, name: &str) -> Result<Self, EngagementError> {
        Self::load(&engagement_path(parent, name)?)
    }

    // Load an existing engagement from disk
    pub fn load(root: &Path) -> Result<Self, EngagementError> {
        let meta_path = root.join("engagement.json");
        if !meta_path.exists() {
            return Err(EngagementError::NotFound(root.display().to_string()));
        }
        let raw = fs::read_to_string(&meta_path)?;
        let meta: EngagementMeta = serde_json::from_str(&raw)?;
        Ok(Self {
            root: root.to_path_buf(),
            meta,
        })
    }

    // List all engagements under a parent directory
    pub fn list(parent: &Path) -> Result<Vec<Self>, EngagementError> {
        if !parent.exists() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path();
            if path.join("engagement.json").exists()
                && let Ok(e) = Self::load(&path)
            {
                out.push(e);
            }
        }
        out.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
        Ok(out)
    }

    // Load and return the scope rules for this engagement
    pub fn scope(&self) -> Result<Scope, EngagementError> {
        Scope::load(&self.root.join("scope.json"))
    }

    // Persist updated scope rules back to scope.json
    pub fn save_scope(&self, scope: &Scope) -> Result<(), EngagementError> {
        scope.save(&self.root.join("scope.json"))
    }

    // Append an entry to audit.log: ISO-8601 timestamp + tool + target + optional detail
    pub fn audit(
        &self,
        tool: &str,
        target: &str,
        detail: Option<&str>,
    ) -> Result<(), EngagementError> {
        let ts = now_rfc3339()?;
        let mut line = format!("{ts} {} {}", audit_field(tool), audit_field(target));
        if let Some(d) = detail {
            line.push(' ');
            line.push_str(&audit_field(d));
        }
        line.push('\n');
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("audit.log"))?;
        f.write_all(line.as_bytes())?;
        Ok(())
    }

    // Append a timestamped block to notes.md
    pub fn append_note(&self, text: &str) -> Result<(), EngagementError> {
        let ts = now_rfc3339()?;
        let block = format!("\n### {ts}\n\n{text}\n");
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join("notes.md"))?;
        f.write_all(block.as_bytes())?;
        Ok(())
    }

    // Return path to the recon output directory
    pub fn recon_dir(&self) -> PathBuf {
        self.root.join("recon")
    }
    // Return path to the crawl output directory
    pub fn crawl_dir(&self) -> PathBuf {
        self.root.join("crawl")
    }
    // Return path to the findings directory
    pub fn findings_dir(&self) -> PathBuf {
        self.root.join("findings")
    }
    // Return path to the reverse-engineering directory
    pub fn re_dir(&self) -> PathBuf {
        self.root.join("re")
    }
}

// Return the safe on-disk path for an engagement name under a parent directory
fn engagement_path(parent: &Path, name: &str) -> Result<PathBuf, EngagementError> {
    validate_engagement_name(name)?;
    Ok(parent.join(name))
}

// Reject names that could escape the engagements directory or create ambiguous paths
fn validate_engagement_name(name: &str) -> Result<(), EngagementError> {
    if name.is_empty() {
        return Err(EngagementError::Invalid(
            "engagement name cannot be empty".into(),
        ));
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => {}
        _ => {
            return Err(EngagementError::Invalid(
                "engagement name must be a single path component".into(),
            ));
        }
    }

    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(EngagementError::Invalid(
            "engagement name cannot contain path separators".into(),
        ));
    }

    if name.chars().any(char::is_control) {
        return Err(EngagementError::Invalid(
            "engagement name cannot contain control characters".into(),
        ));
    }

    Ok(())
}

// Collapse audit fields to one line so user-controlled values cannot forge log entries
fn audit_field(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// Return the current UTC time formatted as RFC 3339
fn now_rfc3339() -> Result<String, EngagementError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

// Serialize value to pretty-printed JSON and write it to path
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), EngagementError> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Per-test unique temp dir; uses pid + atomic counter so parallel tests
    // never collide (SystemTime nanos can collide on fast tests)
    fn tmp_parent() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let p = std::env::temp_dir().join(format!("engagement-test-{pid}-{n}"));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn meta(name: &str, target: &str) -> EngagementMeta {
        EngagementMeta {
            name: name.into(),
            target: target.into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        }
    }

    #[test]
    fn init_creates_full_layout() {
        let p = tmp_parent();
        let e = Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        assert!(e.root.join("engagement.json").exists());
        assert!(e.root.join("scope.json").exists());
        assert!(e.root.join("notes.md").exists());
        assert!(e.root.join("audit.log").exists());
        assert!(e.root.join("recon").is_dir());
        assert!(e.root.join("crawl").is_dir());
        assert!(e.root.join("findings").is_dir());
    }

    #[test]
    fn init_refuses_existing() {
        let p = tmp_parent();
        Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        let err = Engagement::init(&p, meta("acme", "acme.test"));
        assert!(matches!(err, Err(EngagementError::AlreadyExists(_))));
    }

    #[test]
    fn init_rejects_path_traversal_names() {
        let p = tmp_parent();
        assert!(matches!(
            Engagement::init(&p, meta("../escape", "acme.test")),
            Err(EngagementError::Invalid(_))
        ));
        assert!(matches!(
            Engagement::init(&p, meta("nested/acme", "acme.test")),
            Err(EngagementError::Invalid(_))
        ));
        assert!(matches!(
            Engagement::init(&p, meta("nested\\acme", "acme.test")),
            Err(EngagementError::Invalid(_))
        ));
    }

    #[test]
    fn load_round_trip() {
        let p = tmp_parent();
        let e1 = Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        let e2 = Engagement::load(&e1.root).unwrap();
        assert_eq!(e2.meta.name, "acme");
        assert_eq!(e2.meta.target, "acme.test");
    }

    #[test]
    fn audit_log_appends() {
        let p = tmp_parent();
        let e = Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        e.audit("mg-scan", "api.acme.test", Some("ports=80-443"))
            .unwrap();
        e.audit("subdomain-enum", "acme.test", None).unwrap();
        let log = fs::read_to_string(e.root.join("audit.log")).unwrap();
        assert!(log.contains("mg-scan api.acme.test ports=80-443"));
        assert!(log.contains("subdomain-enum acme.test"));
    }

    #[test]
    fn audit_log_sanitizes_control_characters() {
        let p = tmp_parent();
        let e = Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        e.audit(
            "mg-scan\nforged",
            "api.acme.test",
            Some("open=1\nforged line"),
        )
        .unwrap();
        let log = fs::read_to_string(e.root.join("audit.log")).unwrap();
        assert_eq!(log.lines().count(), 1);
        assert!(log.contains("mg-scan forged api.acme.test open=1 forged line"));
    }

    #[test]
    fn list_returns_initialized_engagements() {
        let p = tmp_parent();
        Engagement::init(&p, meta("a-engagement", "a.test")).unwrap();
        Engagement::init(&p, meta("b-engagement", "b.test")).unwrap();
        let all = Engagement::list(&p).unwrap();
        assert_eq!(all.len(), 2);
        // Sorted alphabetically
        assert_eq!(all[0].meta.name, "a-engagement");
        assert_eq!(all[1].meta.name, "b-engagement");
    }

    #[test]
    fn scope_round_trip() {
        let p = tmp_parent();
        let e = Engagement::init(&p, meta("acme", "acme.test")).unwrap();
        let s = e.scope().unwrap();
        assert!(s.is_in_scope("api.acme.test"));
        assert!(!s.is_in_scope("other.test"));
    }
}
