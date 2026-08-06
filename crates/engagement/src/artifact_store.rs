// Author: Jeff
// Date: 2026-05-28
// Description: Engagement-root artifact path guard for autonomous hunting output
// Notes: Rejects traversal and symlink escapes before writing model-directed artifacts

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::Arc;

use crate::EngagementError;

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    #[cfg(target_os = "linux")]
    root_dir: Arc<rustix::fd::OwnedFd>,
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
        #[cfg(target_os = "linux")]
        let root_dir = rustix::fs::open(
            &root,
            rustix::fs::OFlags::PATH
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(errno_to_io)?;

        Ok(Self {
            root,
            #[cfg(target_os = "linux")]
            root_dir: Arc::new(root_dir),
        })
    }

    // Open one normal relative path beneath the retained engagement root descriptor
    pub fn open_relative_read(&self, relative: &str) -> Result<std::fs::File, EngagementError> {
        let path = Path::new(relative);
        if relative.trim().is_empty()
            || path.is_absolute()
            || !path
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
        {
            return Err(EngagementError::Invalid(
                "artifact path must be a normal relative path".into(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let fd = rustix::fs::openat2(
                self.root_dir.as_ref(),
                path,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::NOCTTY
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
                rustix::fs::ResolveFlags::BENEATH
                    | rustix::fs::ResolveFlags::NO_SYMLINKS
                    | rustix::fs::ResolveFlags::NO_MAGICLINKS
                    | rustix::fs::ResolveFlags::NO_XDEV,
            )
            .map_err(errno_to_io)?;
            Ok(std::fs::File::from(fd))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative artifact reads require Linux openat2",
            )
            .into())
        }
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

#[cfg(target_os = "linux")]
fn errno_to_io(errno: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno.raw_os_error())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

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

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_opens_nested_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("evidence/nested")).unwrap();
        std::fs::write(tmp.path().join("evidence/nested/proof.json"), b"trusted").unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let mut file = store
            .open_relative_read("evidence/nested/proof.json")
            .unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();

        assert_eq!(bytes, b"trusted");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_rejects_non_normal_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        for path in [
            "",
            "   ",
            "/etc/passwd",
            ".",
            "./proof",
            "../proof",
            "a/../proof",
        ] {
            assert!(store.open_relative_read(path).is_err(), "accepted {path:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_rejects_final_and_intermediate_symlinks() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("actual")).unwrap();
        std::fs::write(root.path().join("actual/proof"), b"inside").unwrap();
        std::fs::write(outside.path().join("proof"), b"outside").unwrap();
        symlink("actual/proof", root.path().join("final-in-root")).unwrap();
        symlink(
            outside.path().join("proof"),
            root.path().join("final-external"),
        )
        .unwrap();
        symlink("actual", root.path().join("parent-in-root")).unwrap();
        symlink(outside.path(), root.path().join("parent-external")).unwrap();
        let store = ArtifactStore::new(root.path()).unwrap();

        for path in [
            "final-in-root",
            "final-external",
            "parent-in-root/proof",
            "parent-external/proof",
        ] {
            assert!(store.open_relative_read(path).is_err(), "followed {path}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_stays_anchored_when_root_path_is_replaced() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("root");
        let moved = parent.path().join("original-root");
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("proof"), b"inside").unwrap();
        std::fs::write(outside.path().join("proof"), b"outside").unwrap();
        let store = ArtifactStore::new(&root).unwrap();
        std::fs::rename(&root, &moved).unwrap();
        symlink(outside.path(), &root).unwrap();

        let mut file = store.open_relative_read("proof").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();

        assert_eq!(bytes, b"inside");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_opens_nonregular_objects_without_blocking() {
        use std::os::unix::net::UnixListener;

        let root = tempfile::tempdir().unwrap();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            root.path().join("fifo"),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        let _listener = UnixListener::bind(root.path().join("socket")).unwrap();
        let store = ArtifactStore::new(root.path()).unwrap();

        let fifo = store.open_relative_read("fifo").unwrap();
        assert!(!fifo.metadata().unwrap().is_file());
        assert!(store.open_relative_read("socket").is_err());

        let devices = ArtifactStore::new("/dev").unwrap();
        let null = devices.open_relative_read("null").unwrap();
        assert!(!null.metadata().unwrap().is_file());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_resists_parent_swap_race() {
        use std::io::Read;
        use std::os::unix::fs::symlink;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("traffic")).unwrap();
        std::fs::write(root.path().join("traffic/source.json"), b"inside").unwrap();
        std::fs::write(outside.path().join("source.json"), b"outside").unwrap();
        symlink(outside.path(), root.path().join("swap")).unwrap();
        let store = ArtifactStore::new(root.path()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let traffic = root.path().join("traffic");
        let swap = root.path().join("swap");
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                rustix::fs::renameat_with(
                    rustix::fs::CWD,
                    &traffic,
                    rustix::fs::CWD,
                    &swap,
                    rustix::fs::RenameFlags::EXCHANGE,
                )
                .unwrap();
            }
        });

        for _ in 0..2_000 {
            if let Ok(mut file) = store.open_relative_read("traffic/source.json") {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"inside");
            }
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn relative_read_rejects_magic_links_and_mount_crossing_when_available() {
        let proc_fd = ArtifactStore::new("/proc/self/fd").unwrap();
        assert!(proc_fd.open_relative_read("0").is_err());

        let filesystem = ArtifactStore::new("/").unwrap();
        assert!(filesystem.open_relative_read("proc/self/status").is_err());
    }
}
