// Author: Jeff
// Date: 2026-05-28
// Description: Engagement-root artifact path guard for autonomous hunting output
// Notes: Rejects traversal and symlink escapes before writing model-directed artifacts

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

use crate::EngagementError;

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactWriteRecord {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: usize,
}

impl ArtifactStore {
    // Create a store rooted at an existing engagement directory
    pub fn new(root: impl AsRef<Path>) -> Result<Self, EngagementError> {
        let root = root.as_ref().canonicalize()?;
        Ok(Self { root })
    }

    // Resolve a model-provided relative path without leaving the engagement root
    pub fn resolve_relative(&self, relative: &str) -> Result<PathBuf, EngagementError> {
        let path = Path::new(relative);
        if relative.trim().is_empty() || path.is_absolute() {
            return Err(EngagementError::Invalid(
                "artifact path escapes engagement root".into(),
            ));
        }

        for component in path.components() {
            if matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            ) {
                return Err(EngagementError::Invalid(
                    "artifact path escapes engagement root".into(),
                ));
            }
        }

        let candidate = self.root.join(path);
        self.ensure_existing_ancestor_inside_root(&candidate)?;
        Ok(candidate)
    }

    // Write JSON through a same-directory temp file and record its digest
    pub fn atomic_json_write<T: Serialize>(
        &self,
        relative: &str,
        value: &T,
    ) -> Result<ArtifactWriteRecord, EngagementError> {
        let path = self.resolve_relative(relative)?;
        let parent = path.parent().ok_or_else(|| {
            EngagementError::Invalid("artifact path has no parent directory".into())
        })?;
        std::fs::create_dir_all(parent)?;

        let json = serde_json::to_vec_pretty(value)?;
        let sha256 = hex::encode(Sha256::digest(&json));
        let bytes = json.len();
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| EngagementError::Invalid("artifact path has no filename".into()))?;
        let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &path)?;

        Ok(ArtifactWriteRecord {
            path,
            sha256,
            bytes,
        })
    }

    // Verify the deepest existing ancestor does not resolve outside the root
    fn ensure_existing_ancestor_inside_root(
        &self,
        candidate: &Path,
    ) -> Result<(), EngagementError> {
        let mut current = candidate;
        while !current.exists() {
            current = current.parent().ok_or_else(|| {
                EngagementError::Invalid("artifact path escapes engagement root".into())
            })?;
        }

        let canonical = current.canonicalize()?;
        if canonical.starts_with(&self.root) {
            Ok(())
        } else {
            Err(EngagementError::Invalid(
                "artifact path escapes engagement root".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::Digest;

    use crate::artifact_store::ArtifactStore;

    #[test]
    fn relative_paths_resolve_under_engagement_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let resolved = store.resolve_relative("evidence/proof.json").unwrap();

        assert!(resolved.starts_with(tmp.path().canonicalize().unwrap()));
        assert!(resolved.ends_with("evidence/proof.json"));
    }

    #[test]
    fn parent_traversal_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let err = store.resolve_relative("../escape.json").unwrap_err();

        assert!(err.to_string().contains("artifact path escapes"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let link = tmp.path().join("outside-link");
        symlink(outside.path(), &link).unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let err = store
            .resolve_relative("outside-link/escaped.json")
            .unwrap_err();

        assert!(err.to_string().contains("artifact path escapes"));
    }

    #[test]
    fn atomic_json_write_records_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let record = store
            .atomic_json_write("evidence/proof.json", &json!({ "ok": true }))
            .unwrap();

        let bytes = std::fs::read(&record.path).unwrap();
        let expected = format!("{:x}", sha2::Sha256::digest(&bytes));
        assert_eq!(record.sha256, expected);
        assert_eq!(record.bytes, bytes.len());
    }
}
