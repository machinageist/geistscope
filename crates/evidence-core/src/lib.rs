// Author: Jeff
// Date: 2026-05-29
// Description: Evidence bundle writer for autonomous hunting replay results
// Notes: Writes immutable local artifacts plus redacted summaries; never overwrites a run

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvidenceBundleWriter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceBundleRequest {
    pub engagement_root: PathBuf,
    pub candidate_id: String,
    pub run_id: String,
    pub plan_json: String,
    pub approvals_json: String,
    pub semantic_diff_json: String,
    pub summary: String,
    pub raw_artifacts: Vec<RawEvidenceArtifact>,
    pub browser_snapshots: Vec<BrowserSnapshotArtifact>,
    pub oob_hit_json: Option<String>,
    pub replay_io_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserSnapshotArtifact {
    pub id: String,
    pub url: String,
    pub dom_html: String,
    pub screenshot_png: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvidenceArtifact {
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub bundle_dir: PathBuf,
    pub candidate_id: String,
    pub run_id: String,
    pub artifacts: Vec<EvidenceArtifactManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceArtifactManifest {
    pub path: String,
    pub sha256: String,
    pub len: usize,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceBundleError {
    #[error("evidence run already exists")]
    RunAlreadyExists,
    #[error("evidence path component is unsafe")]
    UnsafePath,
    #[error("io error: {0}")]
    Io(String),
    #[error("json error: {0}")]
    Json(String),
}

impl EvidenceBundleRequest {
    // Create an evidence bundle request rooted under an engagement directory
    pub fn new(
        engagement_root: impl Into<PathBuf>,
        candidate_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            engagement_root: engagement_root.into(),
            candidate_id: candidate_id.into(),
            run_id: run_id.into(),
            plan_json: "{}".into(),
            approvals_json: "[]".into(),
            semantic_diff_json: "{}".into(),
            summary: String::new(),
            raw_artifacts: Vec::new(),
            browser_snapshots: Vec::new(),
            oob_hit_json: None,
            replay_io_json: None,
        }
    }

    // Attach replay plan JSON to the immutable bundle
    pub fn with_plan_json(mut self, plan_json: impl Into<String>) -> Self {
        self.plan_json = plan_json.into();
        self
    }

    // Attach approval metadata JSON to the immutable bundle
    pub fn with_approvals_json(mut self, approvals_json: impl Into<String>) -> Self {
        self.approvals_json = approvals_json.into();
        self
    }

    // Attach semantic diff JSON to the immutable bundle
    pub fn with_semantic_diff_json(mut self, semantic_diff_json: impl Into<String>) -> Self {
        self.semantic_diff_json = semantic_diff_json.into();
        self
    }

    // Attach model-visible summary text that will be redacted before writing
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    // Attach local raw artifact bytes for hashing and immutable storage
    pub fn with_raw_artifact(mut self, name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Self {
        self.raw_artifacts.push(RawEvidenceArtifact {
            name: name.into(),
            bytes: bytes.into(),
        });
        self
    }

    // Attach redacted browser DOM and screenshot evidence
    pub fn with_browser_snapshot(mut self, snapshot: BrowserSnapshotArtifact) -> Self {
        self.browser_snapshots.push(snapshot);
        self
    }

    // Attach the correlated out-of-band hit JSON that proves a blind SSRF
    pub fn with_oob_hit_json(mut self, oob_hit_json: impl Into<String>) -> Self {
        self.oob_hit_json = Some(oob_hit_json.into());
        self
    }

    // Attach the recorded replay request/response JSON for reproduction
    pub fn with_replay_io_json(mut self, replay_io_json: impl Into<String>) -> Self {
        self.replay_io_json = Some(replay_io_json.into());
        self
    }
}

impl BrowserSnapshotArtifact {
    // Create browser snapshot evidence from local DOM and screenshot bytes
    pub fn new(
        id: impl Into<String>,
        url: impl Into<String>,
        dom_html: impl Into<String>,
        screenshot_png: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            id: id.into(),
            url: url.into(),
            dom_html: dom_html.into(),
            screenshot_png: screenshot_png.into(),
        }
    }
}

impl EvidenceBundleWriter {
    // Write an immutable evidence bundle; fail if the run already exists
    pub fn write(
        &self,
        request: EvidenceBundleRequest,
    ) -> Result<EvidenceBundle, EvidenceBundleError> {
        validate_component(&request.candidate_id)?;
        validate_component(&request.run_id)?;
        let bundle_dir = request
            .engagement_root
            .join("evidence")
            .join(&request.candidate_id)
            .join(&request.run_id);
        if bundle_dir.exists() {
            return Err(EvidenceBundleError::RunAlreadyExists);
        }

        std::fs::create_dir_all(bundle_dir.join("raw")).map_err(io_error)?;
        write_text(bundle_dir.join("plan.json"), &request.plan_json)?;
        write_text(bundle_dir.join("approvals.json"), &request.approvals_json)?;
        write_text(
            bundle_dir.join("semantic_diff.json"),
            &request.semantic_diff_json,
        )?;
        write_text(
            bundle_dir.join("summary.redacted.md"),
            &redact_summary(&request.summary),
        )?;
        // OOB and replay I/O are optional; write them only for active tests that produced them
        if let Some(oob_hit_json) = &request.oob_hit_json {
            write_text(bundle_dir.join("oob_hit.json"), oob_hit_json)?;
        }
        if let Some(replay_io_json) = &request.replay_io_json {
            write_text(bundle_dir.join("replay_io.json"), replay_io_json)?;
        }

        let mut artifacts = Vec::new();
        for artifact in request.raw_artifacts {
            validate_component(&artifact.name)?;
            let rel_path = PathBuf::from("raw").join(&artifact.name);
            let abs_path = bundle_dir.join(&rel_path);
            std::fs::write(&abs_path, &artifact.bytes).map_err(io_error)?;
            artifacts.push(EvidenceArtifactManifest {
                path: rel_path.display().to_string(),
                sha256: sha256_hex(&artifact.bytes),
                len: artifact.bytes.len(),
            });
        }
        for snapshot in request.browser_snapshots {
            validate_component(&snapshot.id)?;
            let rel_dir = PathBuf::from("browser-snapshots").join(&snapshot.id);
            let abs_dir = bundle_dir.join(&rel_dir);
            std::fs::create_dir_all(&abs_dir).map_err(io_error)?;
            let metadata = serde_json::to_string_pretty(&serde_json::json!({
                "id": snapshot.id,
                "url": snapshot.url,
                "dom_artifact": "dom.redacted.html",
                "screenshot_artifact": "screenshot.png",
            }))
            .map_err(json_error)?;
            write_text(abs_dir.join("metadata.json"), &metadata)?;
            let redacted_dom = redact_dom_snapshot(&snapshot.dom_html);
            write_text(abs_dir.join("dom.redacted.html"), &redacted_dom)?;
            let screenshot_path = rel_dir.join("screenshot.png");
            std::fs::write(bundle_dir.join(&screenshot_path), &snapshot.screenshot_png)
                .map_err(io_error)?;
            artifacts.push(EvidenceArtifactManifest {
                path: screenshot_path.display().to_string(),
                sha256: sha256_hex(&snapshot.screenshot_png),
                len: snapshot.screenshot_png.len(),
            });
        }

        let bundle = EvidenceBundle {
            bundle_dir: bundle_dir.clone(),
            candidate_id: request.candidate_id,
            run_id: request.run_id,
            artifacts,
        };
        let manifest = serde_json::to_string_pretty(&bundle).map_err(json_error)?;
        write_text(bundle_dir.join("manifest.json"), &manifest)?;
        Ok(bundle)
    }
}

// Write a UTF-8 artifact file
fn write_text(path: PathBuf, text: &str) -> Result<(), EvidenceBundleError> {
    std::fs::write(path, text).map_err(io_error)
}

// Validate that user-controlled path components cannot escape the bundle tree
fn validate_component(value: &str) -> Result<(), EvidenceBundleError> {
    if value.trim().is_empty() {
        return Err(EvidenceBundleError::UnsafePath);
    }
    let path = Path::new(value);
    if path.is_absolute()
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(EvidenceBundleError::UnsafePath);
    }
    Ok(())
}

// Redact common cookie, bearer token, and email shapes from model-visible summaries
fn redact_summary(summary: &str) -> String {
    summary
        .lines()
        .map(redact_summary_line)
        .collect::<Vec<_>>()
        .join("\n")
}

// Redact one summary line while preserving evidence shape
fn redact_summary_line(line: &str) -> String {
    let lowered = line.to_ascii_lowercase();
    if lowered.starts_with("cookie:") || lowered.contains("cookie=") || lowered.contains("session=")
    {
        return "Cookie: [REDACTED_COOKIE]".into();
    }
    if lowered.starts_with("authorization:")
        || lowered.contains("bearer ")
        || lowered.contains("token")
    {
        return "Authorization: [REDACTED_TOKEN]".into();
    }
    line.split_whitespace()
        .map(|word| {
            if looks_like_email(word) {
                "[REDACTED_EMAIL]".into()
            } else {
                word.into()
            }
        })
        .collect::<Vec<String>>()
        .join(" ")
}

// Redact DOM snapshot text before writing model-visible browser artifacts
fn redact_dom_snapshot(dom: &str) -> String {
    let mut redacted = dom.to_string();
    for token in
        dom.split(|ch: char| ch.is_whitespace() || matches!(ch, '<' | '>' | '"' | '\'' | '='))
    {
        let lower = token.to_ascii_lowercase();
        if !token.is_empty()
            && (lower.contains("token")
                || lower.contains("secret")
                || lower.contains("cookie")
                || lower.contains("password"))
        {
            redacted = redacted.replace(token, "[REDACTED_TOKEN]");
        } else if looks_like_email(token) {
            redacted = redacted.replace(token, "[REDACTED_EMAIL]");
        }
    }
    redacted
}

// Detect simple email-like tokens without pulling in a regex dependency
fn looks_like_email(value: &str) -> bool {
    let trimmed = value.trim_matches(|ch: char| ch.is_ascii_punctuation());
    trimmed.contains('@') && trimmed.contains('.')
}

// Hash local artifact bytes for immutable manifest references
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

// Convert IO errors to cloneable public errors
fn io_error(error: std::io::Error) -> EvidenceBundleError {
    EvidenceBundleError::Io(error.to_string())
}

// Convert JSON errors to cloneable public errors
fn json_error(error: serde_json::Error) -> EvidenceBundleError {
    EvidenceBundleError::Json(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_run_path_includes_candidate_id_and_run_id() {
        let root = tempfile::tempdir().unwrap();
        let request = EvidenceBundleRequest::new(root.path(), "candidate-001", "run-abc")
            .with_plan_json("{\"plan_hash\":\"plan-1\"}")
            .with_semantic_diff_json("{\"classification\":\"secure_denied\"}")
            .with_summary("safe summary");

        let bundle = EvidenceBundleWriter.write(request).unwrap();

        assert_eq!(
            bundle.bundle_dir,
            root.path().join("evidence/candidate-001/run-abc")
        );
        assert!(bundle.bundle_dir.join("manifest.json").exists());
    }

    #[test]
    fn existing_evidence_run_cannot_be_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let request = EvidenceBundleRequest::new(root.path(), "candidate-001", "run-abc")
            .with_summary("first run");
        EvidenceBundleWriter.write(request).unwrap();

        let duplicate = EvidenceBundleRequest::new(root.path(), "candidate-001", "run-abc")
            .with_summary("second run");
        let error = EvidenceBundleWriter.write(duplicate).unwrap_err();

        assert_eq!(error, EvidenceBundleError::RunAlreadyExists);
    }

    #[test]
    fn summary_redacted_markdown_contains_no_synthetic_cookies_tokens_or_pii() {
        let root = tempfile::tempdir().unwrap();
        let request = EvidenceBundleRequest::new(root.path(), "candidate-001", "run-redact")
            .with_summary(
                "Cookie: session=abc123\nAuthorization: Bearer secret-token\nEmail: jeff@example.com",
            );

        let bundle = EvidenceBundleWriter.write(request).unwrap();
        let summary =
            std::fs::read_to_string(bundle.bundle_dir.join("summary.redacted.md")).unwrap();

        assert!(!summary.contains("abc123"));
        assert!(!summary.contains("secret-token"));
        assert!(!summary.contains("jeff@example.com"));
        assert!(summary.contains("[REDACTED_COOKIE]"));
        assert!(summary.contains("[REDACTED_TOKEN]"));
        assert!(summary.contains("[REDACTED_EMAIL]"));
    }

    #[test]
    fn oob_hit_and_replay_io_written_when_present() {
        let root = tempfile::tempdir().unwrap();
        let request = EvidenceBundleRequest::new(root.path(), "ssrf-candidate", "run-oob")
            .with_semantic_diff_json("{\"classification\":\"ssrf_oob_confirmed\"}")
            .with_oob_hit_json(
                "{\"token\":\"abc\",\"binding\":{\"candidate_id\":\"ssrf-candidate\"}}",
            )
            .with_replay_io_json("{\"status\":200,\"url\":\"http://target.local/api/fetch\"}")
            .with_summary("SSRF confirmed via out-of-band callback");

        let bundle = EvidenceBundleWriter.write(request).unwrap();
        let oob = std::fs::read_to_string(bundle.bundle_dir.join("oob_hit.json")).unwrap();
        let replay_io = std::fs::read_to_string(bundle.bundle_dir.join("replay_io.json")).unwrap();

        assert!(oob.contains("\"token\":\"abc\""));
        assert!(oob.contains("ssrf-candidate"));
        assert!(replay_io.contains("\"status\":200"));
    }

    #[test]
    fn bundle_without_oob_omits_the_oob_file() {
        let root = tempfile::tempdir().unwrap();
        let request =
            EvidenceBundleRequest::new(root.path(), "readonly", "run-1").with_summary("ok");

        let bundle = EvidenceBundleWriter.write(request).unwrap();

        assert!(!bundle.bundle_dir.join("oob_hit.json").exists());
        assert!(!bundle.bundle_dir.join("replay_io.json").exists());
    }

    #[test]
    fn browser_snapshot_artifacts_write_redacted_dom_and_hashed_screenshot() {
        let root = tempfile::tempdir().unwrap();
        let request = EvidenceBundleRequest::new(root.path(), "candidate-001", "run-browser")
            .with_browser_snapshot(BrowserSnapshotArtifact::new(
                "search-page",
                "https://app.example.test/search?q=x",
                "<html><body data-token=\"secret-token\">jeff@example.com</body></html>",
                vec![137, 80, 78, 71, b's', b'e', b'c', b'r', b'e', b't'],
            ));

        let bundle = EvidenceBundleWriter.write(request).unwrap();
        let dom = std::fs::read_to_string(
            bundle
                .bundle_dir
                .join("browser-snapshots/search-page/dom.redacted.html"),
        )
        .unwrap();
        let screenshot = bundle
            .artifacts
            .iter()
            .find(|artifact| artifact.path == "browser-snapshots/search-page/screenshot.png")
            .unwrap();

        assert!(dom.contains("[REDACTED_TOKEN]"));
        assert!(dom.contains("[REDACTED_EMAIL]"));
        assert!(!dom.contains("secret-token"));
        assert!(!dom.contains("jeff@example.com"));
        assert_eq!(screenshot.len, 10);
        assert_eq!(screenshot.sha256.len(), 64);
    }
}
