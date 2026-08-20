// Author: Jeff
// Date: 2026-05-29
// Description: Evidence bundle writer for autonomous hunting replay results
// Notes: Publishes no-overwrite local artifacts; content identity is manifest-addressed

use std::collections::HashSet;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvidenceBundleWriter;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EvidenceBundleReader;

pub const MAX_GENERIC_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_GENERIC_BUNDLE_BYTES: usize = 32 * 1024 * 1024;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericEvidenceBundleRequest {
    pub engagement_root: PathBuf,
    pub candidate_id: String,
    pub run_id: String,
    pub artifacts: Vec<GenericEvidenceArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericEvidenceArtifact {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub visibility: EvidenceVisibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceVisibility {
    ModelVisibleRedacted,
    PrivateLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericEvidenceManifest {
    pub candidate_id: String,
    pub run_id: String,
    pub artifacts: Vec<GenericEvidenceArtifactManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericEvidenceArtifactManifest {
    pub path: String,
    pub sha256: String,
    pub len: usize,
    pub content_type: String,
    pub visibility: EvidenceVisibility,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericEvidenceBundle {
    pub bundle_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub manifest_sha256: String,
    pub candidate_id: String,
    pub run_id: String,
    pub artifacts: Vec<GenericEvidenceArtifactManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGenericEvidenceBundle {
    pub manifest_sha256: String,
    pub manifest: GenericEvidenceManifest,
    pub artifacts: Vec<VerifiedGenericEvidenceArtifact>,
}

impl VerifiedGenericEvidenceBundle {
    pub fn artifact(&self, relative_path: &str) -> Option<&VerifiedGenericEvidenceArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.relative_path == relative_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedGenericEvidenceArtifact {
    pub relative_path: String,
    pub bytes: Vec<u8>,
    pub content_type: String,
    pub visibility: EvidenceVisibility,
}

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
    #[error("duplicate evidence artifact path: {0}")]
    DuplicateArtifactPath(String),
    #[error("model-visible artifact is not UTF-8: {0}")]
    InvalidModelVisibleUtf8(String),
    #[error("model-visible artifact contains unredacted secret material: {0}")]
    UnredactedModelVisibleArtifact(String),
    #[error("evidence artifact exceeds the size limit: {0}")]
    ArtifactTooLarge(String),
    #[error("evidence bundle exceeds the total size limit")]
    BundleTooLarge,

    #[error("io error: {0}")]
    Io(String),
    #[error("json error: {0}")]
    Json(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceVerificationError {
    #[error("expected manifest digest is invalid")]
    InvalidExpectedDigest,
    #[error("evidence locator is unsafe")]
    UnsafeLocator,
    #[error("manifest digest does not match expected content identity")]
    ManifestDigestMismatch,
    #[error("manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("manifest identity does not match the requested bundle")]
    ManifestIdentityMismatch,
    #[error("artifact length mismatch: {path}")]
    ArtifactLengthMismatch { path: String },
    #[error("artifact digest mismatch: {path}")]
    ArtifactDigestMismatch { path: String },
    #[error("evidence verification io error: {0}")]
    Io(String),
    #[error("content-addressed evidence verification is unsupported on this platform")]
    UnsupportedPlatform,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenericWriterTestPhase {
    StagingCreated,
    StagingComplete,
    Published,
}

type GenericWriterTestHook<'a> = Option<&'a mut dyn FnMut(GenericWriterTestPhase, &Path, &str)>;

struct TrackedArtifactDirectory {
    relative_path: PathBuf,
    handle: std::fs::File,
}

struct TrackedArtifactFile {
    relative_path: PathBuf,
    handle: std::fs::File,
    len: usize,
    sha256: String,
}

struct StagedGenericEvidence {
    artifacts: Vec<GenericEvidenceArtifactManifest>,
    directories: Vec<TrackedArtifactDirectory>,
    files: Vec<TrackedArtifactFile>,
    manifest_sha256: String,
}

impl GenericEvidenceBundleRequest {
    pub fn new(
        engagement_root: impl Into<PathBuf>,
        candidate_id: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Self {
        Self {
            engagement_root: engagement_root.into(),
            candidate_id: candidate_id.into(),
            run_id: run_id.into(),
            artifacts: Vec::new(),
        }
    }

    pub fn with_model_visible_artifact(
        mut self,
        path: impl Into<PathBuf>,
        bytes: impl Into<Vec<u8>>,
        content_type: impl Into<String>,
    ) -> Self {
        self.artifacts.push(GenericEvidenceArtifact {
            path: path.into(),
            bytes: bytes.into(),
            content_type: content_type.into(),
            visibility: EvidenceVisibility::ModelVisibleRedacted,
        });
        self
    }

    pub fn with_private_artifact(
        mut self,
        path: impl Into<PathBuf>,
        bytes: impl Into<Vec<u8>>,
        content_type: impl Into<String>,
    ) -> Self {
        self.artifacts.push(GenericEvidenceArtifact {
            path: path.into(),
            bytes: bytes.into(),
            content_type: content_type.into(),
            visibility: EvidenceVisibility::PrivateLocal,
        });
        self
    }
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

impl EvidenceBundleReader {
    pub fn read_generic(
        &self,
        engagement_root: impl AsRef<Path>,
        candidate_id: &str,
        run_id: &str,
        expected_manifest_sha256: &str,
    ) -> Result<VerifiedGenericEvidenceBundle, EvidenceVerificationError> {
        if !is_lowercase_sha256(expected_manifest_sha256) {
            return Err(EvidenceVerificationError::InvalidExpectedDigest);
        }
        validate_component(candidate_id)
            .and_then(|_| validate_component(run_id))
            .map_err(|_| EvidenceVerificationError::UnsafeLocator)?;

        let root_path = engagement_root.as_ref();
        let root_metadata = std::fs::symlink_metadata(root_path).map_err(verification_io)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.file_type().is_dir() {
            return Err(EvidenceVerificationError::UnsafeLocator);
        }
        let root = open_directory_nofollow(root_path).map_err(verification_io)?;
        let evidence = open_child_directory_nofollow(&root, std::ffi::OsStr::new("evidence"))
            .map_err(verification_io)?;
        let candidate =
            open_child_directory_nofollow(&evidence, std::ffi::OsStr::new(candidate_id))
                .map_err(verification_io)?;
        let bundle = open_child_directory_nofollow(&candidate, std::ffi::OsStr::new(run_id))
            .map_err(verification_io)?;

        let manifest_bytes = read_relative_bounded(
            &bundle,
            Path::new("manifest.json"),
            MAX_GENERIC_BUNDLE_BYTES,
        )?;
        if sha256_hex(&manifest_bytes) != expected_manifest_sha256 {
            return Err(EvidenceVerificationError::ManifestDigestMismatch);
        }
        let manifest: GenericEvidenceManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|error| EvidenceVerificationError::InvalidManifest(error.to_string()))?;
        if manifest.candidate_id != candidate_id || manifest.run_id != run_id {
            return Err(EvidenceVerificationError::ManifestIdentityMismatch);
        }

        let expected_prefix = format!("evidence/{candidate_id}/{run_id}/");
        let mut seen = HashSet::new();
        let mut total_bytes = manifest_bytes.len();
        let mut artifacts = Vec::with_capacity(manifest.artifacts.len());
        for entry in &manifest.artifacts {
            if !is_lowercase_sha256(&entry.sha256)
                || entry.len > MAX_GENERIC_ARTIFACT_BYTES
                || entry.content_type.is_empty()
                || entry.content_type.trim() != entry.content_type
            {
                return Err(EvidenceVerificationError::InvalidManifest(
                    entry.path.clone(),
                ));
            }
            let relative_text = entry
                .path
                .strip_prefix(&expected_prefix)
                .filter(|relative| !relative.is_empty())
                .ok_or_else(|| EvidenceVerificationError::InvalidManifest(entry.path.clone()))?;
            let relative = Path::new(relative_text);
            validate_relative_path(relative)
                .map_err(|_| EvidenceVerificationError::InvalidManifest(entry.path.clone()))?;
            let portable_relative = portable_relative_path(relative);
            if portable_relative != relative_text
                || portable_relative == "manifest.json"
                || !seen.insert(portable_relative.clone())
                || (portable_relative.starts_with("raw/")
                    && entry.visibility != EvidenceVisibility::PrivateLocal)
            {
                return Err(EvidenceVerificationError::InvalidManifest(
                    entry.path.clone(),
                ));
            }
            total_bytes = total_bytes
                .checked_add(entry.len)
                .ok_or_else(|| EvidenceVerificationError::InvalidManifest(entry.path.clone()))?;
            if total_bytes > MAX_GENERIC_BUNDLE_BYTES {
                return Err(EvidenceVerificationError::InvalidManifest(
                    entry.path.clone(),
                ));
            }

            let bytes = read_relative_bounded(&bundle, relative, MAX_GENERIC_ARTIFACT_BYTES)?;
            if bytes.len() != entry.len {
                return Err(EvidenceVerificationError::ArtifactLengthMismatch {
                    path: portable_relative,
                });
            }
            if sha256_hex(&bytes) != entry.sha256 {
                return Err(EvidenceVerificationError::ArtifactDigestMismatch {
                    path: portable_relative,
                });
            }
            if entry.visibility == EvidenceVisibility::ModelVisibleRedacted {
                let text = std::str::from_utf8(&bytes)
                    .map_err(|_| EvidenceVerificationError::InvalidManifest(entry.path.clone()))?;
                if contains_obvious_secret(text) {
                    return Err(EvidenceVerificationError::InvalidManifest(
                        entry.path.clone(),
                    ));
                }
            }
            artifacts.push(VerifiedGenericEvidenceArtifact {
                relative_path: portable_relative,
                bytes,
                content_type: entry.content_type.clone(),
                visibility: entry.visibility,
            });
        }

        Ok(VerifiedGenericEvidenceBundle {
            manifest_sha256: expected_manifest_sha256.to_owned(),
            manifest,
            artifacts,
        })
    }
}

impl EvidenceBundleWriter {
    pub fn write_generic(
        &self,
        request: GenericEvidenceBundleRequest,
    ) -> Result<GenericEvidenceBundle, EvidenceBundleError> {
        self.write_generic_inner(request, None, false, None)
    }

    fn write_generic_inner(
        &self,
        request: GenericEvidenceBundleRequest,
        fail_after_writes: Option<usize>,
        force_cleanup_failure: bool,
        mut test_hook: GenericWriterTestHook<'_>,
    ) -> Result<GenericEvidenceBundle, EvidenceBundleError> {
        validate_component(&request.candidate_id)?;
        validate_component(&request.run_id)?;
        validate_generic_artifacts(&request)?;

        let root_metadata =
            std::fs::symlink_metadata(&request.engagement_root).map_err(io_error)?;
        if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
            return Err(EvidenceBundleError::UnsafePath);
        }
        let engagement_handle =
            open_directory_nofollow(&request.engagement_root).map_err(io_error)?;
        let engagement_root = request.engagement_root.canonicalize().map_err(io_error)?;
        if !engagement_root.is_dir() {
            return Err(EvidenceBundleError::UnsafePath);
        }
        if !directory_handle_matches_path(&engagement_handle, &engagement_root) {
            return Err(EvidenceBundleError::UnsafePath);
        }
        let (evidence_dir, evidence_handle) =
            create_safe_child_dir_at(&engagement_handle, &engagement_root, "evidence")?;
        let (candidate_dir, candidate_handle) =
            create_safe_child_dir_at(&evidence_handle, &evidence_dir, &request.candidate_id)?;
        let final_dir = candidate_dir.join(&request.run_id);
        match std::fs::symlink_metadata(&final_dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(EvidenceBundleError::UnsafePath);
            }
            Ok(_) => return Err(EvidenceBundleError::RunAlreadyExists),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }

        let (staging_name, staging_dir, staging_handle) =
            create_staging_dir_at(&candidate_handle, &candidate_dir, &request.run_id)?;
        if let Some(hook) = test_hook.as_mut() {
            hook(
                GenericWriterTestPhase::StagingCreated,
                &candidate_dir,
                &staging_name,
            );
        }
        if !directory_handle_matches_path(&candidate_handle, &candidate_dir)
            || !directory_handle_matches_path(&staging_handle, &staging_dir)
        {
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                EvidenceBundleError::UnsafePath,
                force_cleanup_failure,
            ));
        }
        let StagedGenericEvidence {
            artifacts,
            directories: artifact_directories,
            files: mut artifact_files,
            manifest_sha256,
        } = match write_generic_staging_at(&staging_handle, &request, fail_after_writes) {
            Ok(staged) => staged,
            Err(error) => {
                return Err(quarantine_staging(
                    &candidate_handle,
                    &staging_name,
                    &request.run_id,
                    error,
                    force_cleanup_failure,
                ));
            }
        };
        if let Err(error) = staging_handle.sync_all() {
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                io_error(error),
                force_cleanup_failure,
            ));
        }
        if let Some(hook) = test_hook.as_mut() {
            hook(
                GenericWriterTestPhase::StagingComplete,
                &candidate_dir,
                &staging_name,
            );
        }

        if !tracked_artifact_tree_matches(&staging_dir, &artifact_directories, &mut artifact_files)
        {
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                EvidenceBundleError::UnsafePath,
                force_cleanup_failure,
            ));
        }

        if final_dir.exists() || std::fs::symlink_metadata(&final_dir).is_ok() {
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                EvidenceBundleError::RunAlreadyExists,
                force_cleanup_failure,
            ));
        }
        if !directory_handle_matches_path(&candidate_handle, &candidate_dir)
            || !directory_handle_matches_path(&staging_handle, &staging_dir)
        {
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                EvidenceBundleError::UnsafePath,
                force_cleanup_failure,
            ));
        }
        if let Err(error) = rename_exclusive_at(&candidate_handle, &staging_name, &request.run_id) {
            let operation = if final_dir.exists() || std::fs::symlink_metadata(&final_dir).is_ok() {
                EvidenceBundleError::RunAlreadyExists
            } else {
                io_error(error)
            };
            return Err(quarantine_staging(
                &candidate_handle,
                &staging_name,
                &request.run_id,
                operation,
                force_cleanup_failure,
            ));
        }
        if let Some(hook) = test_hook.as_mut() {
            hook(
                GenericWriterTestPhase::Published,
                &candidate_dir,
                &request.run_id,
            );
        }
        if !tracked_artifact_tree_matches(&final_dir, &artifact_directories, &mut artifact_files) {
            return Err(quarantine_staging(
                &candidate_handle,
                &request.run_id,
                &request.run_id,
                EvidenceBundleError::UnsafePath,
                force_cleanup_failure,
            ));
        }
        if let Err(error) = candidate_handle.sync_all() {
            return Err(quarantine_staging(
                &candidate_handle,
                &request.run_id,
                &request.run_id,
                io_error(error),
                force_cleanup_failure,
            ));
        }

        Ok(GenericEvidenceBundle {
            manifest_path: final_dir.join("manifest.json"),
            bundle_dir: final_dir,
            manifest_sha256,
            candidate_id: request.candidate_id,
            run_id: request.run_id,
            artifacts,
        })
    }

    #[cfg(test)]
    fn write_generic_with_failure(
        &self,
        request: GenericEvidenceBundleRequest,
        fail_after_writes: Option<usize>,
    ) -> Result<GenericEvidenceBundle, EvidenceBundleError> {
        self.write_generic_inner(request, fail_after_writes, false, None)
    }

    #[cfg(test)]
    fn write_generic_with_cleanup_failure(
        &self,
        request: GenericEvidenceBundleRequest,
        fail_after_writes: Option<usize>,
    ) -> Result<GenericEvidenceBundle, EvidenceBundleError> {
        self.write_generic_inner(request, fail_after_writes, true, None)
    }

    #[cfg(test)]
    fn write_generic_with_test_hook<F>(
        &self,
        request: GenericEvidenceBundleRequest,
        mut hook: F,
    ) -> Result<GenericEvidenceBundle, EvidenceBundleError>
    where
        F: FnMut(GenericWriterTestPhase, &Path, &str),
    {
        self.write_generic_inner(request, None, false, Some(&mut hook))
    }

    // Write an immutable evidence bundle; fail if the run already exists
    pub fn write(
        &self,
        request: EvidenceBundleRequest,
    ) -> Result<EvidenceBundle, EvidenceBundleError> {
        validate_relative_identifier_path(&request.candidate_id)?;
        validate_relative_identifier_path(&request.run_id)?;
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

fn validate_generic_artifacts(
    request: &GenericEvidenceBundleRequest,
) -> Result<(), EvidenceBundleError> {
    let mut paths = HashSet::new();
    let mut total_bytes = 0usize;
    let mut manifest_entries = Vec::with_capacity(request.artifacts.len());
    for artifact in &request.artifacts {
        validate_relative_path(&artifact.path)?;
        let path = portable_relative_path(&artifact.path);
        if path == "manifest.json" || !paths.insert(path.clone()) {
            return Err(EvidenceBundleError::DuplicateArtifactPath(path));
        }
        if artifact.bytes.len() > MAX_GENERIC_ARTIFACT_BYTES {
            return Err(EvidenceBundleError::ArtifactTooLarge(path));
        }
        total_bytes = total_bytes
            .checked_add(artifact.bytes.len())
            .ok_or(EvidenceBundleError::BundleTooLarge)?;
        if total_bytes > MAX_GENERIC_BUNDLE_BYTES {
            return Err(EvidenceBundleError::BundleTooLarge);
        }
        if artifact.content_type.is_empty() || artifact.content_type.trim() != artifact.content_type
        {
            return Err(EvidenceBundleError::UnsafePath);
        }
        if artifact.visibility == EvidenceVisibility::ModelVisibleRedacted
            && std::str::from_utf8(&artifact.bytes).is_err()
        {
            return Err(EvidenceBundleError::InvalidModelVisibleUtf8(path));
        }
        if artifact.visibility == EvidenceVisibility::ModelVisibleRedacted {
            let text = std::str::from_utf8(&artifact.bytes)
                .map_err(|_| EvidenceBundleError::InvalidModelVisibleUtf8(path.clone()))?;
            if contains_obvious_secret(text) {
                return Err(EvidenceBundleError::UnredactedModelVisibleArtifact(path));
            }
        }
        let final_path = Path::new("evidence")
            .join(&request.candidate_id)
            .join(&request.run_id)
            .join(&artifact.path);
        manifest_entries.push(GenericEvidenceArtifactManifest {
            path: portable_relative_path(&final_path),
            sha256: sha256_hex(&artifact.bytes),
            len: artifact.bytes.len(),
            content_type: artifact.content_type.clone(),
            visibility: artifact.visibility,
        });
    }
    let manifest = GenericEvidenceManifest {
        candidate_id: request.candidate_id.clone(),
        run_id: request.run_id.clone(),
        artifacts: manifest_entries,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(json_error)?;
    total_bytes = total_bytes
        .checked_add(manifest_bytes.len())
        .ok_or(EvidenceBundleError::BundleTooLarge)?;
    if total_bytes > MAX_GENERIC_BUNDLE_BYTES {
        return Err(EvidenceBundleError::BundleTooLarge);
    }
    Ok(())
}

fn contains_obvious_secret(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("bearer ")
        || lowered.contains("authorization:")
        || lowered.contains("\"authorization\"")
        || lowered.contains("cookie:")
        || lowered.contains("\"cookie\"")
        || lowered.contains("session=")
        || lowered.contains("callback_token")
        || lowered.contains("callbacktoken")
        || lowered.contains("password")
        || lowered.contains("api_key")
        || lowered.contains("api-key")
        || lowered.contains("apikey")
        || lowered.contains("access_token")
        || lowered.contains("accesstoken")
        || lowered.contains("refresh_token")
        || lowered.contains("refreshtoken")
        || lowered.contains("client_secret")
        || lowered.contains("clientsecret")
        || lowered.contains("private_key")
        || lowered.contains("private key")
}

fn validate_relative_path(path: &Path) -> Result<(), EvidenceBundleError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.to_str().is_none()
        || path.to_string_lossy().contains('\\')
        || !path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(EvidenceBundleError::UnsafePath);
    }
    Ok(())
}

fn portable_relative_path(path: &Path) -> String {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .expect("validated evidence paths are UTF-8")
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn create_safe_child_dir_at(
    parent: &std::fs::File,
    parent_path: &Path,
    child: &str,
) -> Result<(PathBuf, std::fs::File), EvidenceBundleError> {
    match create_directory_at(parent, std::ffi::OsStr::new(child)) {
        Ok(()) => parent.sync_all().map_err(io_error)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(error)),
    }
    let handle = open_child_directory_nofollow(parent, std::ffi::OsStr::new(child))
        .map_err(|_| EvidenceBundleError::UnsafePath)?;
    let path = parent_path.join(child);
    if !directory_handle_matches_path(&handle, &path) {
        return Err(EvidenceBundleError::UnsafePath);
    }
    Ok((path, handle))
}

fn create_staging_dir_at(
    candidate: &std::fs::File,
    candidate_dir: &Path,
    run_id: &str,
) -> Result<(String, PathBuf, std::fs::File), EvidenceBundleError> {
    for _ in 0..100 {
        let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(".staging-{run_id}-{}-{sequence}", std::process::id());
        let path = candidate_dir.join(name);
        match create_directory_at(candidate, path.file_name().unwrap()) {
            Ok(()) => {
                let handle = open_child_directory_nofollow(candidate, path.file_name().unwrap())
                    .map_err(io_error)?;
                return Ok((
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    path,
                    handle,
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    Err(EvidenceBundleError::Io(
        "could not allocate a unique staging directory".into(),
    ))
}

fn write_generic_staging_at(
    staging_dir: &std::fs::File,
    request: &GenericEvidenceBundleRequest,
    fail_after_writes: Option<usize>,
) -> Result<StagedGenericEvidence, EvidenceBundleError> {
    let mut manifest_entries = Vec::with_capacity(request.artifacts.len());
    let mut artifact_directories = Vec::new();
    let mut artifact_files = Vec::with_capacity(request.artifacts.len() + 1);
    for (index, artifact) in request.artifacts.iter().enumerate() {
        if fail_after_writes == Some(index) {
            return Err(EvidenceBundleError::Io("injected write failure".into()));
        }
        write_relative_create_new(
            staging_dir,
            &artifact.path,
            &artifact.bytes,
            &mut artifact_directories,
            &mut artifact_files,
        )?;
        let final_path = Path::new("evidence")
            .join(&request.candidate_id)
            .join(&request.run_id)
            .join(&artifact.path);
        manifest_entries.push(GenericEvidenceArtifactManifest {
            path: portable_relative_path(&final_path),
            sha256: sha256_hex(&artifact.bytes),
            len: artifact.bytes.len(),
            content_type: artifact.content_type.clone(),
            visibility: artifact.visibility,
        });
    }

    let manifest = GenericEvidenceManifest {
        candidate_id: request.candidate_id.clone(),
        run_id: request.run_id.clone(),
        artifacts: manifest_entries.clone(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(json_error)?;
    write_relative_create_new(
        staging_dir,
        Path::new("manifest.json"),
        &manifest_bytes,
        &mut artifact_directories,
        &mut artifact_files,
    )?;
    Ok(StagedGenericEvidence {
        artifacts: manifest_entries,
        directories: artifact_directories,
        files: artifact_files,
        manifest_sha256: sha256_hex(&manifest_bytes),
    })
}

fn quarantine_staging(
    candidate: &std::fs::File,
    staging_name: &str,
    run_id: &str,
    operation: EvidenceBundleError,
    force_failure: bool,
) -> EvidenceBundleError {
    quarantine_staging_with_sequence(
        candidate,
        staging_name,
        run_id,
        operation,
        force_failure,
        || STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed),
    )
}

fn quarantine_staging_with_sequence(
    candidate: &std::fs::File,
    staging_name: &str,
    run_id: &str,
    operation: EvidenceBundleError,
    force_failure: bool,
    mut next_sequence: impl FnMut() -> u64,
) -> EvidenceBundleError {
    let cleanup = if force_failure {
        Err(std::io::Error::other("injected cleanup failure"))
    } else {
        let mut result = Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate an exclusive quarantine name",
        ));
        for _ in 0..100 {
            let quarantine = format!(
                ".failed-{run_id}-{}-{}",
                std::process::id(),
                next_sequence()
            );
            match rename_exclusive_at(candidate, staging_name, &quarantine) {
                Ok(()) => {
                    result = candidate.sync_all();
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    result = Err(error);
                    break;
                }
            }
        }
        result
    };
    match cleanup {
        Ok(()) => operation,
        Err(cleanup) => EvidenceBundleError::Io(format!(
            "evidence staging cleanup failed after {operation}: {cleanup}"
        )),
    }
}

#[cfg(unix)]
fn path_cstring(path: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(path.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "macos")]
const O_DIRECTORY_FLAG: i32 = 0x0010_0000;
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
const O_DIRECTORY_FLAG: i32 = 0x0001_0000;
#[cfg(all(target_os = "linux", any(target_arch = "arm", target_arch = "aarch64")))]
const O_DIRECTORY_FLAG: i32 = 0x0000_4000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
const O_NOFOLLOW_FLAG: i32 = 0x0002_0000;
#[cfg(all(target_os = "linux", any(target_arch = "arm", target_arch = "aarch64")))]
const O_NOFOLLOW_FLAG: i32 = 0x0000_8000;
#[cfg(target_os = "macos")]
const O_NONBLOCK_FLAG: i32 = 0x0000_0004;
#[cfg(target_os = "linux")]
const O_NONBLOCK_FLAG: i32 = 0x0000_0800;

#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64"
    ))
))]
compile_error!("evidence publication Linux open flags require an architecture review");

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_directory_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY_FLAG | O_NOFOLLOW_FLAG)
        .open(path)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn open_directory_nofollow(_path: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink-safe evidence publication is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn open_child_directory_nofollow(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    }
    let name = path_cstring(name)?;
    let fd = unsafe {
        openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            O_DIRECTORY_FLAG | O_NOFOLLOW_FLAG,
            0,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn open_child_directory_nofollow(
    _parent: &std::fs::File,
    _name: &std::ffi::OsStr,
) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink-safe evidence publication is unsupported on this platform",
    ))
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verification_io(error: std::io::Error) -> EvidenceVerificationError {
    if error.kind() == std::io::ErrorKind::Unsupported {
        EvidenceVerificationError::UnsupportedPlatform
    } else {
        EvidenceVerificationError::Io(error.to_string())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_relative_bounded(
    root: &std::fs::File,
    path: &Path,
    limit: usize,
) -> Result<Vec<u8>, EvidenceVerificationError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    }
    const O_RDONLY: i32 = 0;

    validate_relative_path(path).map_err(|_| EvidenceVerificationError::UnsafeLocator)?;
    let components = path.components().collect::<Vec<_>>();
    let mut directory = root.try_clone().map_err(verification_io)?;
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            return Err(EvidenceVerificationError::UnsafeLocator);
        };
        directory = open_child_directory_nofollow(&directory, name).map_err(verification_io)?;
    }
    let Some(Component::Normal(file_name)) = components.last() else {
        return Err(EvidenceVerificationError::UnsafeLocator);
    };
    let file_name = path_cstring(file_name).map_err(verification_io)?;
    let fd = unsafe {
        openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            O_RDONLY | O_NOFOLLOW_FLAG | O_NONBLOCK_FLAG,
            0,
        )
    };
    if fd < 0 {
        return Err(verification_io(std::io::Error::last_os_error()));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(verification_io)?;
    // Reject zero-length artifacts: content-addressed evidence must have
    // non-empty owned bytes. The read below will validate exact length
    // and SHA-256 afterwards.
    if metadata.len() == 0 {
        return Err(EvidenceVerificationError::UnsafeLocator);
    }

    if !metadata.file_type().is_file() || metadata.len() > limit as u64 {
        return Err(EvidenceVerificationError::UnsafeLocator);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(verification_io)?;
    if bytes.len() > limit {
        return Err(EvidenceVerificationError::UnsafeLocator);
    }
    Ok(bytes)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn read_relative_bounded(
    _root: &std::fs::File,
    _path: &Path,
    _limit: usize,
) -> Result<Vec<u8>, EvidenceVerificationError> {
    Err(EvidenceVerificationError::UnsupportedPlatform)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn create_directory_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn mkdirat(dirfd: i32, path: *const std::os::raw::c_char, mode: u32) -> i32;
    }
    let name = path_cstring(name)?;
    if unsafe { mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn create_directory_at(_parent: &std::fs::File, _name: &std::ffi::OsStr) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlink-safe evidence publication is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_relative_create_new(
    staging: &std::fs::File,
    path: &Path,
    bytes: &[u8],
    tracked_directories: &mut Vec<TrackedArtifactDirectory>,
    tracked_files: &mut Vec<TrackedArtifactFile>,
) -> Result<(), EvidenceBundleError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    }
    const O_RDWR: i32 = 0x0002;
    #[cfg(target_os = "macos")]
    const O_CREAT: i32 = 0x0200;
    #[cfg(target_os = "macos")]
    const O_EXCL: i32 = 0x0800;
    #[cfg(target_os = "linux")]
    const O_CREAT: i32 = 0x0040;
    #[cfg(target_os = "linux")]
    const O_EXCL: i32 = 0x0080;

    let mut directory = staging.try_clone().map_err(io_error)?;
    let mut relative_directory = PathBuf::new();
    let components = path.components().collect::<Vec<_>>();
    for component in &components[..components.len() - 1] {
        let Component::Normal(name) = component else {
            return Err(EvidenceBundleError::UnsafePath);
        };
        match create_directory_at(&directory, name) {
            Ok(()) => directory.sync_all().map_err(io_error)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(io_error(error)),
        }
        directory = open_child_directory_nofollow(&directory, name).map_err(io_error)?;
        relative_directory.push(name);
        tracked_directories.push(TrackedArtifactDirectory {
            relative_path: relative_directory.clone(),
            handle: directory.try_clone().map_err(io_error)?,
        });
    }
    let Component::Normal(file_name) = components.last().unwrap() else {
        return Err(EvidenceBundleError::UnsafePath);
    };
    let file_name = path_cstring(file_name).map_err(io_error)?;
    let fd = unsafe {
        openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW_FLAG,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    tracked_files.push(TrackedArtifactFile {
        relative_path: path.to_path_buf(),
        handle: file,
        len: bytes.len(),
        sha256: sha256_hex(bytes),
    });
    directory.sync_all().map_err(io_error)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn write_relative_create_new(
    _staging: &std::fs::File,
    _path: &Path,
    _bytes: &[u8],
    _tracked_directories: &mut Vec<TrackedArtifactDirectory>,
    _tracked_files: &mut Vec<TrackedArtifactFile>,
) -> Result<(), EvidenceBundleError> {
    Err(EvidenceBundleError::Io(
        "symlink-safe evidence publication is unsupported on this platform".into(),
    ))
}

#[cfg(unix)]
fn directory_handle_matches_path(handle: &std::fs::File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(handle_metadata) = handle.metadata() else {
        return false;
    };
    let Ok(path_metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    path_metadata.file_type().is_dir()
        && !path_metadata.file_type().is_symlink()
        && handle_metadata.dev() == path_metadata.dev()
        && handle_metadata.ino() == path_metadata.ino()
}

#[cfg(unix)]
fn tracked_artifact_tree_matches(
    root: &Path,
    directories: &[TrackedArtifactDirectory],
    files: &mut [TrackedArtifactFile],
) -> bool {
    use std::os::unix::fs::MetadataExt;

    if directories.iter().any(|directory| {
        !directory_handle_matches_path(&directory.handle, &root.join(&directory.relative_path))
    }) {
        return false;
    }

    files.iter_mut().all(|file| {
        let expected_path = root.join(&file.relative_path);
        let Ok(handle_metadata) = file.handle.metadata() else {
            return false;
        };
        let Ok(path_metadata) = std::fs::symlink_metadata(expected_path) else {
            return false;
        };
        if !handle_metadata.file_type().is_file()
            || !path_metadata.file_type().is_file()
            || path_metadata.file_type().is_symlink()
            || handle_metadata.dev() != path_metadata.dev()
            || handle_metadata.ino() != path_metadata.ino()
            || handle_metadata.len() != file.len as u64
            || path_metadata.len() != file.len as u64
        {
            return false;
        }

        let Ok(mut reader) = file.handle.try_clone() else {
            return false;
        };
        if reader.rewind().is_err() {
            return false;
        }
        let mut bytes = Vec::with_capacity(file.len);
        reader.read_to_end(&mut bytes).is_ok()
            && bytes.len() == file.len
            && sha256_hex(&bytes) == file.sha256
    })
}

#[cfg(not(unix))]
fn tracked_artifact_tree_matches(
    _root: &Path,
    _directories: &[TrackedArtifactDirectory],
    _files: &mut [TrackedArtifactFile],
) -> bool {
    false
}

#[cfg(not(unix))]
fn directory_handle_matches_path(_handle: &std::fs::File, _path: &Path) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn rename_exclusive_at(parent: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    const RENAME_EXCL: u32 = 0x0000_0004;
    unsafe extern "C" {
        fn renameatx_np(
            fromfd: i32,
            from: *const std::os::raw::c_char,
            tofd: i32,
            to: *const std::os::raw::c_char,
            flags: u32,
        ) -> i32;
    }
    let from = std::ffi::CString::new(from)?;
    let to = std::ffi::CString::new(to)?;
    let result = unsafe {
        renameatx_np(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_exclusive_at(parent: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    const RENAME_NOREPLACE: u32 = 1;
    unsafe extern "C" {
        fn renameat2(
            olddirfd: i32,
            oldpath: *const std::os::raw::c_char,
            newdirfd: i32,
            newpath: *const std::os::raw::c_char,
            flags: u32,
        ) -> i32;
    }
    let from = std::ffi::CString::new(from)?;
    let to = std::ffi::CString::new(to)?;
    let result = unsafe {
        renameat2(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_exclusive_at(_parent: &std::fs::File, _from: &str, _to: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "exclusive evidence publication is unsupported on this platform",
    ))
}

// Write a UTF-8 artifact file
fn write_text(path: PathBuf, text: &str) -> Result<(), EvidenceBundleError> {
    std::fs::write(path, text).map_err(io_error)
}

// Validate that user-controlled path components cannot escape the bundle tree
fn validate_component(value: &str) -> Result<(), EvidenceBundleError> {
    if value.trim().is_empty() || value.contains('\\') {
        return Err(EvidenceBundleError::UnsafePath);
    }
    let path = Path::new(value);
    let mut components = path.components();
    if path.is_absolute()
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(EvidenceBundleError::UnsafePath);
    }
    Ok(())
}

// Preserve safe nested identifiers accepted by the legacy public writer
fn validate_relative_identifier_path(value: &str) -> Result<(), EvidenceBundleError> {
    let path = Path::new(value);
    if value.trim().is_empty()
        || value.contains('\\')
        || path.is_absolute()
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
    fn legacy_writer_preserves_safe_nested_candidate_and_run_ids() {
        let root = tempfile::tempdir().unwrap();
        let request =
            EvidenceBundleRequest::new(root.path(), "team/candidate-001", "batch/run-abc")
                .with_summary("safe summary");

        let bundle = EvidenceBundleWriter.write(request).unwrap();

        assert_eq!(
            bundle.bundle_dir,
            root.path()
                .join("evidence/team/candidate-001/batch/run-abc")
        );
        assert!(bundle.bundle_dir.join("manifest.json").exists());
    }

    #[test]
    fn legacy_writer_rejects_traversal_and_backslash_identifiers_before_writing() {
        for (candidate_id, run_id) in [
            ("../candidate", "run"),
            ("candidate", "../run"),
            ("team\\candidate", "run"),
            ("candidate", "batch\\run"),
        ] {
            let root = tempfile::tempdir().unwrap();
            let request = EvidenceBundleRequest::new(root.path(), candidate_id, run_id)
                .with_summary("safe summary");

            assert_eq!(
                EvidenceBundleWriter.write(request).unwrap_err(),
                EvidenceBundleError::UnsafePath
            );
            assert!(!root.path().join("evidence").exists());
        }
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

    fn generic_request(root: &Path, run_id: &str) -> GenericEvidenceBundleRequest {
        GenericEvidenceBundleRequest::new(root, "candidate-001", run_id)
            .with_model_visible_artifact(
                "policy/policy-decision.json",
                br#"{"decision":"allowed"}"#.to_vec(),
                "application/json",
            )
            .with_private_artifact(
                "raw/response.bin",
                vec![0, 1, 2, 3],
                "application/octet-stream",
            )
    }

    #[test]
    fn generic_bundle_atomically_commits_and_manifests_every_artifact() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = root.path().canonicalize().unwrap();

        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "run-generic"))
            .unwrap();

        assert_eq!(
            bundle.bundle_dir,
            canonical_root.join("evidence/candidate-001/run-generic")
        );
        assert_eq!(
            bundle.manifest_path,
            bundle.bundle_dir.join("manifest.json")
        );
        assert_eq!(bundle.artifacts.len(), 2);
        let policy = bundle
            .artifacts
            .iter()
            .find(|entry| entry.path.ends_with("policy/policy-decision.json"))
            .unwrap();
        assert_eq!(
            policy.path,
            "evidence/candidate-001/run-generic/policy/policy-decision.json"
        );
        assert_eq!(policy.len, 22);
        assert_eq!(policy.sha256, sha256_hex(br#"{"decision":"allowed"}"#));
        assert_eq!(policy.content_type, "application/json");
        assert_eq!(policy.visibility, EvidenceVisibility::ModelVisibleRedacted);
        assert_eq!(policy.sha256.len(), 64);
        let private = bundle
            .artifacts
            .iter()
            .find(|entry| entry.path.ends_with("raw/response.bin"))
            .unwrap();
        assert_eq!(private.visibility, EvidenceVisibility::PrivateLocal);
        assert_eq!(private.len, 4);

        let persisted: GenericEvidenceManifest =
            serde_json::from_slice(&std::fs::read(&bundle.manifest_path).unwrap()).unwrap();
        assert_eq!(persisted.candidate_id, "candidate-001");
        assert_eq!(persisted.run_id, "run-generic");
        assert_eq!(persisted.artifacts, bundle.artifacts);
        assert!(
            !bundle
                .bundle_dir
                .parent()
                .unwrap()
                .join(".staging-run-generic")
                .exists()
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn open_fifo_writer_until(fifo: &Path, deadline: std::time::Instant) -> Option<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::Duration;

        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(O_NONBLOCK_FLAG)
                .open(fifo)
            {
                Ok(file) => return Some(file),
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return None,
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn wait_until_thread_finished<T>(
        worker: &std::thread::JoinHandle<T>,
        deadline: std::time::Instant,
    ) -> bool {
        use std::time::Duration;

        while !worker.is_finished() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn assert_content_addressed_fifo_rejected_without_blocking(
        root: &Path,
        run_id: &str,
        manifest_sha256: String,
        fifo: &Path,
    ) {
        use std::process::Command;
        use std::sync::mpsc;
        use std::time::Duration;

        assert!(Command::new("mkfifo").arg(fifo).status().unwrap().success());
        let root = root.to_path_buf();
        let run_id = run_id.to_owned();
        let (started_sender, started_receiver) = mpsc::channel();
        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            started_sender.send(()).unwrap();
            let rejected = EvidenceBundleReader
                .read_generic(root, "candidate-001", &run_id, &manifest_sha256)
                .is_err();
            sender.send(rejected).unwrap();
        });

        started_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("reader worker did not start");
        let result = receiver.recv_timeout(Duration::from_secs(1));
        if result == Err(mpsc::RecvTimeoutError::Timeout) {
            let _writer =
                open_fifo_writer_until(fifo, std::time::Instant::now() + Duration::from_secs(1));
            let recovered = receiver.recv_timeout(Duration::from_secs(1));
            if wait_until_thread_finished(
                &worker,
                std::time::Instant::now() + Duration::from_secs(1),
            ) {
                worker.join().unwrap();
            } else {
                drop(worker);
                panic!("reader worker did not stop after bounded FIFO recovery");
            }
            assert_ne!(
                recovered,
                Err(mpsc::RecvTimeoutError::Timeout),
                "reader worker did not stop after bounded FIFO recovery"
            );
            panic!("content-addressed FIFO read blocked past its deadline");
        }
        if wait_until_thread_finished(&worker, std::time::Instant::now() + Duration::from_secs(1)) {
            worker.join().unwrap();
        } else {
            drop(worker);
            panic!("reader worker sent a result but did not terminate");
        }
        assert_eq!(result, Ok(true));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn content_addressed_fifo_recovery_writer_is_bounded_without_reader() {
        use std::process::Command;
        use std::time::{Duration, Instant};

        let root = tempfile::tempdir().unwrap();
        let fifo = root.path().join("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let started = Instant::now();

        assert!(open_fifo_writer_until(&fifo, started + Duration::from_millis(100)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn content_addressed_fifo_recovery_waits_only_for_finished_workers() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let (release_sender, release_receiver) = mpsc::channel();
        let running = std::thread::spawn(move || release_receiver.recv().unwrap());
        assert!(!wait_until_thread_finished(
            &running,
            Instant::now() + Duration::from_millis(100)
        ));
        release_sender.send(()).unwrap();
        assert!(wait_until_thread_finished(
            &running,
            Instant::now() + Duration::from_secs(1)
        ));
        running.join().unwrap();
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn content_addressed_fifo_manifest_fails_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "fifo-manifest"))
            .unwrap();
        std::fs::remove_file(&bundle.manifest_path).unwrap();

        assert_content_addressed_fifo_rejected_without_blocking(
            root.path(),
            "fifo-manifest",
            bundle.manifest_sha256,
            &bundle.manifest_path,
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn content_addressed_fifo_artifact_fails_without_blocking() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "fifo-artifact"))
            .unwrap();
        let artifact = bundle.bundle_dir.join("raw/response.bin");
        std::fs::remove_file(&artifact).unwrap();

        assert_content_addressed_fifo_rejected_without_blocking(
            root.path(),
            "fifo-artifact",
            bundle.manifest_sha256,
            &artifact,
        );
    }

    #[test]
    fn content_addressed_manifest_digest_is_authoritative_identity() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "content-addressed"))
            .unwrap();

        assert_eq!(
            bundle.manifest_sha256,
            sha256_hex(&std::fs::read(&bundle.manifest_path).unwrap())
        );
        let verified = EvidenceBundleReader
            .read_generic(
                root.path(),
                "candidate-001",
                "content-addressed",
                &bundle.manifest_sha256,
            )
            .unwrap();
        assert_eq!(verified.manifest_sha256, bundle.manifest_sha256);
        assert_eq!(verified.manifest.candidate_id, "candidate-001");
        assert_eq!(verified.artifacts.len(), 2);
        assert_eq!(
            verified
                .artifact("policy/policy-decision.json")
                .unwrap()
                .bytes,
            br#"{"decision":"allowed"}"#
        );
    }

    #[cfg(unix)]
    #[test]
    fn generic_writer_rejects_symlinked_engagement_root_before_writing() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let root_link = parent.path().join("engagement-root");
        symlink(target.path(), &root_link).unwrap();

        let result = EvidenceBundleWriter.write_generic(generic_request(&root_link, "root-link"));

        assert!(matches!(result, Err(EvidenceBundleError::UnsafePath)));
        assert!(!target.path().join("evidence").exists());
    }

    #[test]
    fn content_addressed_exact_copy_retains_identity_but_changed_bytes_fail() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(source.path(), "copy"))
            .unwrap();
        let copied = destination.path().join("evidence/candidate-001/copy");
        std::fs::create_dir_all(copied.parent().unwrap()).unwrap();
        copy_directory(&bundle.bundle_dir, &copied);

        EvidenceBundleReader
            .read_generic(
                destination.path(),
                "candidate-001",
                "copy",
                &bundle.manifest_sha256,
            )
            .unwrap();

        std::fs::write(copied.join("raw/response.bin"), b"changed").unwrap();
        assert!(matches!(
            EvidenceBundleReader.read_generic(
                destination.path(),
                "candidate-001",
                "copy",
                &bundle.manifest_sha256,
            ),
            Err(EvidenceVerificationError::ArtifactDigestMismatch { .. })
                | Err(EvidenceVerificationError::ArtifactLengthMismatch { .. })
        ));
    }

    #[test]
    fn content_addressed_manifest_or_locator_replacement_fails() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "replace"))
            .unwrap();

        std::fs::write(&bundle.manifest_path, b"{}").unwrap();
        assert!(matches!(
            EvidenceBundleReader.read_generic(
                root.path(),
                "candidate-001",
                "replace",
                &bundle.manifest_sha256,
            ),
            Err(EvidenceVerificationError::ManifestDigestMismatch)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn content_addressed_symlink_engagement_root_fails_closed() {
        use std::os::unix::fs::symlink;

        let real_root = tempfile::tempdir().unwrap();
        let locator_parent = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(real_root.path(), "root-symlink"))
            .unwrap();
        let linked_root = locator_parent.path().join("engagement-link");
        symlink(real_root.path(), &linked_root).unwrap();

        assert!(matches!(
            EvidenceBundleReader.read_generic(
                &linked_root,
                "candidate-001",
                "root-symlink",
                &bundle.manifest_sha256,
            ),
            Err(EvidenceVerificationError::UnsafeLocator)
        ));
    }

    #[test]
    fn content_addressed_repeated_separator_member_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "separator"))
            .unwrap();
        let mut manifest: GenericEvidenceManifest =
            serde_json::from_slice(&std::fs::read(&bundle.manifest_path).unwrap()).unwrap();
        manifest.artifacts[0].path = manifest.artifacts[0].path.replacen(
            "evidence/candidate-001",
            "evidence//candidate-001",
            1,
        );
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(&bundle.manifest_path, &bytes).unwrap();

        assert!(matches!(
            EvidenceBundleReader.read_generic(
                root.path(),
                "candidate-001",
                "separator",
                &sha256_hex(&bytes),
            ),
            Err(EvidenceVerificationError::InvalidManifest(_))
        ));
    }

    #[test]
    fn content_addressed_malformed_or_forged_metadata_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "metadata"))
            .unwrap();
        let mut manifest: GenericEvidenceManifest =
            serde_json::from_slice(&std::fs::read(&bundle.manifest_path).unwrap()).unwrap();
        let raw = manifest
            .artifacts
            .iter_mut()
            .find(|entry| entry.path.ends_with("raw/response.bin"))
            .unwrap();
        raw.content_type = "   ".into();
        raw.visibility = EvidenceVisibility::ModelVisibleRedacted;
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(&bundle.manifest_path, &bytes).unwrap();

        assert!(matches!(
            EvidenceBundleReader.read_generic(
                root.path(),
                "candidate-001",
                "metadata",
                &sha256_hex(&bytes),
            ),
            Err(EvidenceVerificationError::InvalidManifest(_))
        ));
    }

    #[test]
    fn content_addressed_manifest_member_cannot_rebind_locator() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "rebind"))
            .unwrap();
        let mut manifest: GenericEvidenceManifest =
            serde_json::from_slice(&std::fs::read(&bundle.manifest_path).unwrap()).unwrap();
        manifest.artifacts[0].path =
            "evidence/candidate-001/other-run/policy/policy-decision.json".into();
        let bytes = serde_json::to_vec_pretty(&manifest).unwrap();
        std::fs::write(&bundle.manifest_path, &bytes).unwrap();

        assert!(matches!(
            EvidenceBundleReader.read_generic(
                root.path(),
                "candidate-001",
                "rebind",
                &sha256_hex(&bytes),
            ),
            Err(EvidenceVerificationError::InvalidManifest(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn content_addressed_artifact_symlink_fails_closed() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "reader-symlink"))
            .unwrap();
        let artifact = bundle.bundle_dir.join("raw/response.bin");
        std::fs::remove_file(&artifact).unwrap();
        symlink(outside.path(), artifact).unwrap();

        assert!(
            EvidenceBundleReader
                .read_generic(
                    root.path(),
                    "candidate-001",
                    "reader-symlink",
                    &bundle.manifest_sha256,
                )
                .is_err()
        );
    }

    #[test]
    fn content_addressed_consumer_uses_verified_owned_bytes_after_path_mutation() {
        let root = tempfile::tempdir().unwrap();
        let bundle = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "consume"))
            .unwrap();
        let verified = EvidenceBundleReader
            .read_generic(
                root.path(),
                "candidate-001",
                "consume",
                &bundle.manifest_sha256,
            )
            .unwrap();

        std::fs::write(
            bundle.bundle_dir.join("policy/policy-decision.json"),
            b"replaced after verification",
        )
        .unwrap();

        assert_eq!(
            verified
                .artifact("policy/policy-decision.json")
                .unwrap()
                .bytes,
            br#"{"decision":"allowed"}"#
        );
        assert!(
            EvidenceBundleReader
                .read_generic(
                    root.path(),
                    "candidate-001",
                    "consume",
                    &bundle.manifest_sha256,
                )
                .is_err()
        );
    }

    fn copy_directory(source: &Path, destination: &Path) {
        std::fs::create_dir(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).unwrap();
            }
        }
    }

    #[test]
    fn generic_bundle_rejects_unsafe_and_duplicate_paths_before_writing() {
        for bad_path in [
            "/absolute.json",
            "../escape.json",
            "nested/../../escape.json",
            "windows\\separator.json",
            "",
        ] {
            let root = tempfile::tempdir().unwrap();
            let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "run")
                .with_model_visible_artifact(bad_path, b"{}".to_vec(), "application/json");
            assert_eq!(
                EvidenceBundleWriter.write_generic(request).unwrap_err(),
                EvidenceBundleError::UnsafePath
            );
            assert!(!root.path().join("evidence").exists());
        }

        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "run")
            .with_model_visible_artifact("result.json", b"{}".to_vec(), "application/json")
            .with_private_artifact("result.json", b"private".to_vec(), "text/plain");
        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::DuplicateArtifactPath("result.json".into())
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_rejects_invalid_components_root_utf8_and_oversize_before_writing() {
        let missing_root = tempfile::tempdir().unwrap().path().join("gone");
        let error = EvidenceBundleWriter
            .write_generic(GenericEvidenceBundleRequest::new(
                &missing_root,
                "candidate",
                "run",
            ))
            .unwrap_err();
        assert!(matches!(error, EvidenceBundleError::Io(_)));

        for (candidate, run) in [("../candidate", "run"), ("candidate", "a/b"), ("", "run")] {
            let root = tempfile::tempdir().unwrap();
            let request = GenericEvidenceBundleRequest::new(root.path(), candidate, run);
            assert_eq!(
                EvidenceBundleWriter.write_generic(request).unwrap_err(),
                EvidenceBundleError::UnsafePath
            );
            assert!(!root.path().join("evidence").exists());
        }

        let root = tempfile::tempdir().unwrap();
        let invalid_utf8 = GenericEvidenceBundleRequest::new(root.path(), "candidate", "utf8")
            .with_model_visible_artifact("result.json", vec![0xff], "application/json");
        assert_eq!(
            EvidenceBundleWriter
                .write_generic(invalid_utf8)
                .unwrap_err(),
            EvidenceBundleError::InvalidModelVisibleUtf8("result.json".into())
        );
        assert!(!root.path().join("evidence").exists());

        let root = tempfile::tempdir().unwrap();
        let oversized = GenericEvidenceBundleRequest::new(root.path(), "candidate", "large")
            .with_private_artifact(
                "raw/large.bin",
                vec![0; MAX_GENERIC_ARTIFACT_BYTES + 1],
                "application/octet-stream",
            );
        assert_eq!(
            EvidenceBundleWriter.write_generic(oversized).unwrap_err(),
            EvidenceBundleError::ArtifactTooLarge("raw/large.bin".into())
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_rejects_noncanonical_content_type_before_publication() {
        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "metadata")
            .with_private_artifact(
                "raw/blob.bin",
                b"private".to_vec(),
                " application/octet-stream ",
            );

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::UnsafePath
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_rejects_excessive_total_bytes_before_writing() {
        let root = tempfile::tempdir().unwrap();
        let chunk = vec![0; MAX_GENERIC_BUNDLE_BYTES / 3 + 1];
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "too-large")
            .with_private_artifact("raw/one.bin", chunk.clone(), "application/octet-stream")
            .with_private_artifact("raw/two.bin", chunk.clone(), "application/octet-stream")
            .with_private_artifact("raw/three.bin", chunk, "application/octet-stream");

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::BundleTooLarge
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_limit_includes_generated_manifest_bytes() {
        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "manifest-over")
            .with_private_artifact(
                "raw/one.bin",
                vec![0; MAX_GENERIC_ARTIFACT_BYTES],
                "application/octet-stream",
            )
            .with_private_artifact(
                "raw/two.bin",
                vec![0; MAX_GENERIC_ARTIFACT_BYTES],
                "application/octet-stream",
            );

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::BundleTooLarge
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_rejects_obvious_secrets_in_model_visible_artifacts_before_writing() {
        for leaked in [
            r#"{"authorization":"Bearer synthetic-secret"}"#,
            r#"{"cookie":"session=synthetic-session"}"#,
            r#"{"callback_token":"0123456789abcdef0123456789abcdef"}"#,
            r#"{"password":"synthetic-password"}"#,
            r#"{"api_key":"synthetic-api-key"}"#,
            r#"{"access_token":"synthetic-access-token"}"#,
            r#"{"refresh_token":"synthetic-refresh-token"}"#,
            r#"{"private_key":"synthetic-private-key"}"#,
            r#"{"apiKey":"synthetic-api-key"}"#,
            r#"{"accessToken":"synthetic-access-token"}"#,
            r#"{"refreshToken":"synthetic-refresh-token"}"#,
            r#"{"callbackToken":"synthetic-callback-token"}"#,
            r#"{"client_secret":"synthetic-client-secret"}"#,
            "-----BEGIN PRIVATE KEY-----\nsynthetic-private-key\n-----END PRIVATE KEY-----",
        ] {
            let root = tempfile::tempdir().unwrap();
            let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "secret")
                .with_model_visible_artifact(
                    "result.json",
                    leaked.as_bytes().to_vec(),
                    "application/json",
                );

            assert_eq!(
                EvidenceBundleWriter.write_generic(request).unwrap_err(),
                EvidenceBundleError::UnredactedModelVisibleArtifact("result.json".into())
            );
            assert!(!root.path().join("evidence").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn generic_bundle_rejects_non_utf8_artifact_paths_before_writing() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "non-utf8")
            .with_private_artifact(
                PathBuf::from(OsString::from_vec(vec![0xff])),
                b"private".to_vec(),
                "application/octet-stream",
            );

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::UnsafePath
        );
        assert!(!root.path().join("evidence").exists());
    }

    #[test]
    fn generic_bundle_rejects_backslashes_in_candidate_and_run_ids_before_writing() {
        for (candidate_id, run_id) in [("candidate\\alias", "run"), ("candidate", "run\\alias")] {
            let root = tempfile::tempdir().unwrap();
            let request = GenericEvidenceBundleRequest::new(root.path(), candidate_id, run_id)
                .with_private_artifact(
                    "raw/private.bin",
                    b"private".to_vec(),
                    "application/octet-stream",
                );

            assert_eq!(
                EvidenceBundleWriter.write_generic(request).unwrap_err(),
                EvidenceBundleError::UnsafePath
            );
            assert!(!root.path().join("evidence").exists());
        }
    }

    #[test]
    fn generic_bundle_never_overwrites_an_existing_run() {
        let root = tempfile::tempdir().unwrap();
        let first = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "immutable"))
            .unwrap();
        let original_manifest = std::fs::read(&first.manifest_path).unwrap();

        let error = EvidenceBundleWriter
            .write_generic(generic_request(root.path(), "immutable"))
            .unwrap_err();

        assert_eq!(error, EvidenceBundleError::RunAlreadyExists);
        assert_eq!(
            std::fs::read(&first.manifest_path).unwrap(),
            original_manifest
        );
    }

    #[test]
    fn concurrent_publishers_cannot_merge_or_overwrite_the_same_run() {
        use std::sync::{Arc, Barrier};

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().to_path_buf();
        let barrier = Arc::new(Barrier::new(2));
        let handles = (*b"ab").map(|marker| {
            let root = root_path.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let request = GenericEvidenceBundleRequest::new(&root, "candidate", "race")
                    .with_private_artifact(
                        "raw/winner.bin",
                        vec![marker; 1024],
                        "application/octet-stream",
                    );
                barrier.wait();
                EvidenceBundleWriter.write_generic(request)
            })
        });

        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(EvidenceBundleError::RunAlreadyExists)))
                .count(),
            1
        );
        let final_bytes =
            std::fs::read(root.path().join("evidence/candidate/race/raw/winner.bin")).unwrap();
        assert!(
            final_bytes.iter().all(|byte| *byte == b'a')
                || final_bytes.iter().all(|byte| *byte == b'b')
        );
        let candidate = root.path().join("evidence/candidate");
        let entries = std::fs::read_dir(candidate)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries.iter().filter(|name| *name == "race").count(), 1);
        assert_eq!(
            entries
                .iter()
                .filter(|name| name.starts_with(".failed-race-"))
                .count(),
            1
        );
        assert!(!entries.iter().any(|name| name.starts_with(".staging-")));
    }

    #[cfg(unix)]
    #[test]
    fn generic_bundle_rejects_candidate_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("evidence")).unwrap();
        symlink(outside.path(), root.path().join("evidence/candidate")).unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "run")
            .with_model_visible_artifact("result.json", b"{}".to_vec(), "application/json");

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::UnsafePath
        );
        assert!(!outside.path().join("run").exists());
    }

    #[cfg(unix)]
    #[test]
    fn generic_bundle_rejects_run_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("evidence/candidate")).unwrap();
        symlink(outside.path(), root.path().join("evidence/candidate/run")).unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "run")
            .with_model_visible_artifact("result.json", b"{}".to_vec(), "application/json");

        assert_eq!(
            EvidenceBundleWriter.write_generic(request).unwrap_err(),
            EvidenceBundleError::UnsafePath
        );
        assert_eq!(std::fs::read_dir(outside.path()).unwrap().count(), 0);
    }

    #[test]
    fn injected_write_failure_leaves_no_final_or_staging_bundle() {
        let root = tempfile::tempdir().unwrap();
        let request = generic_request(root.path(), "write-fails");

        let error = EvidenceBundleWriter
            .write_generic_with_failure(request, Some(1))
            .unwrap_err();

        assert!(matches!(error, EvidenceBundleError::Io(_)));
        let candidate = root.path().join("evidence/candidate-001");
        assert!(!candidate.join("write-fails").exists());
        let entries = std::fs::read_dir(candidate)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].starts_with(".failed-write-fails-"));
    }

    #[cfg(unix)]
    #[test]
    fn candidate_symlink_swap_during_publish_cannot_escape_open_directory_handle() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let request = generic_request(root.path(), "swap-race");

        let error = EvidenceBundleWriter
            .write_generic_with_test_hook(request, |phase, candidate, staging_name| {
                if phase != GenericWriterTestPhase::StagingCreated {
                    return;
                }
                let held = candidate.with_extension("held");
                std::fs::rename(candidate, &held).unwrap();
                symlink(outside.path(), candidate).unwrap();
                let outside_staging = outside.path().join(staging_name);
                std::fs::rename(held.join(staging_name), outside_staging).unwrap();
            })
            .unwrap_err();

        assert!(matches!(
            error,
            EvidenceBundleError::Io(message)
                if message.contains("staging cleanup failed")
                    && message.contains("No such file")
        ));
        assert!(!outside.path().join("swap-race").exists());
    }

    #[cfg(unix)]
    #[test]
    fn nested_directory_swap_before_promotion_cannot_omit_declared_artifact() {
        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "nested-swap")
            .with_private_artifact("raw/blob.bin", vec![7; 1024], "application/octet-stream");

        let result = EvidenceBundleWriter.write_generic_with_test_hook(
            request,
            |phase, candidate, staging_name| {
                if phase != GenericWriterTestPhase::StagingComplete {
                    return;
                }
                let staging = candidate.join(staging_name);
                std::fs::rename(staging.join("raw"), staging.join("raw-held")).unwrap();
                std::fs::create_dir(staging.join("raw")).unwrap();
            },
        );

        match result {
            Ok(bundle) => assert!(
                bundle.bundle_dir.join("raw/blob.bin").exists(),
                "successful manifest references a missing artifact after nested directory swap"
            ),
            Err(error) => {
                assert!(matches!(error, EvidenceBundleError::UnsafePath));
                assert!(!root.path().join("evidence/candidate/nested-swap").exists());
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn nested_directory_swap_after_promotion_cannot_return_success() {
        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "post-swap")
            .with_private_artifact("raw/blob.bin", vec![7; 1024], "application/octet-stream");

        let result = EvidenceBundleWriter.write_generic_with_test_hook(
            request,
            |phase, candidate, published_name| {
                if phase != GenericWriterTestPhase::Published {
                    return;
                }
                let published = candidate.join(published_name);
                std::fs::rename(published.join("raw"), published.join("raw-held")).unwrap();
                std::fs::create_dir(published.join("raw")).unwrap();
            },
        );

        assert!(matches!(result, Err(EvidenceBundleError::UnsafePath)));
        assert!(!root.path().join("evidence/candidate/post-swap").exists());
    }

    #[cfg(unix)]
    #[test]
    fn artifact_file_swap_before_promotion_cannot_publish_replacement_bytes() {
        let root = tempfile::tempdir().unwrap();
        let request = GenericEvidenceBundleRequest::new(root.path(), "candidate", "file-swap")
            .with_private_artifact("raw/blob.bin", vec![7; 1024], "application/octet-stream");

        let result = EvidenceBundleWriter.write_generic_with_test_hook(
            request,
            |phase, candidate, staging_name| {
                if phase != GenericWriterTestPhase::StagingComplete {
                    return;
                }
                let raw = candidate.join(staging_name).join("raw");
                std::fs::rename(raw.join("blob.bin"), raw.join("blob-held.bin")).unwrap();
                std::fs::write(raw.join("blob.bin"), vec![8; 1024]).unwrap();
            },
        );

        assert!(matches!(result, Err(EvidenceBundleError::UnsafePath)));
        assert!(!root.path().join("evidence/candidate/file-swap").exists());
    }

    #[test]
    fn cleanup_failure_is_reported_instead_of_discarded() {
        let root = tempfile::tempdir().unwrap();
        let request = generic_request(root.path(), "cleanup-fails");

        let error = EvidenceBundleWriter
            .write_generic_with_cleanup_failure(request, Some(1))
            .unwrap_err();

        assert!(matches!(
            error,
            EvidenceBundleError::Io(message)
                if message.contains("staging cleanup failed")
                    && message.contains("injected cleanup failure")
        ));
    }

    #[test]
    fn quarantine_retries_without_overwriting_an_existing_failed_bundle() {
        let root = tempfile::tempdir().unwrap();
        let candidate_path = root.path().join("candidate");
        std::fs::create_dir(&candidate_path).unwrap();
        std::fs::create_dir(candidate_path.join(".staging-run-1")).unwrap();
        let collision = candidate_path.join(format!(".failed-run-{}-7", std::process::id()));
        std::fs::create_dir(&collision).unwrap();
        std::fs::write(collision.join("marker"), b"preserve").unwrap();
        let candidate = open_directory_nofollow(&candidate_path).unwrap();
        let mut sequences = [7_u64, 8].into_iter();

        let operation = EvidenceBundleError::Io("original failure".into());
        let error = quarantine_staging_with_sequence(
            &candidate,
            ".staging-run-1",
            "run",
            operation.clone(),
            false,
            || sequences.next().unwrap(),
        );

        assert_eq!(error, operation);
        assert_eq!(
            std::fs::read(collision.join("marker")).unwrap(),
            b"preserve"
        );
        assert!(
            candidate_path
                .join(format!(".failed-run-{}-8", std::process::id()))
                .is_dir()
        );
        assert!(!candidate_path.join(".staging-run-1").exists());
    }
}
