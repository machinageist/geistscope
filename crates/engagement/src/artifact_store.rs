// Author: Jeff
// Date: 2026-05-28
// Description: Engagement-root artifact path guard for autonomous hunting output
// Notes: Rejects traversal and symlink escapes before writing model-directed artifacts

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;

use crate::EngagementError;

#[derive(Debug, Clone)]
pub struct ArtifactStore {
    root: PathBuf,
    #[cfg(target_os = "linux")]
    root_dir: Arc<rustix::fd::OwnedFd>,
    #[cfg(target_os = "macos")]
    root_dir: Arc<std::fs::File>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactWriteRecord {
    pub relative_path: PathBuf,
    pub locator: PathBuf,
    pub sha256: String,
    pub bytes: usize,
}

impl ArtifactStore {
    // Create a store rooted at an existing engagement directory
    pub fn new(root: impl AsRef<Path>) -> Result<Self, EngagementError> {
        let supplied_root = root.as_ref();
        let metadata = std::fs::symlink_metadata(supplied_root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(EngagementError::Invalid(
                "engagement root must be a non-symlink directory".into(),
            ));
        }
        #[cfg(target_os = "linux")]
        let root_dir = rustix::fs::open(
            supplied_root,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::DIRECTORY
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(errno_to_io)?;
        #[cfg(target_os = "macos")]
        let root_dir = open_directory_nofollow(supplied_root)?;
        let root = supplied_root.canonicalize()?;
        if !root_handle_matches_path(&root_dir, &root)? {
            return Err(EngagementError::Invalid(
                "engagement root changed while opening".into(),
            ));
        }

        Ok(Self {
            root,
            #[cfg(target_os = "linux")]
            root_dir: Arc::new(root_dir),
            #[cfg(target_os = "macos")]
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

        #[cfg(target_os = "macos")]
        {
            open_relative_read_macos(self.root_dir.as_ref(), path).map_err(Into::into)
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative artifact reads require Linux or macOS",
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
        let json = serde_json::to_vec_pretty(value)?;
        self.atomic_bytes_write(relative, &json)
    }

    // Publish bytes relative to the retained root; returned paths are locators, not authority
    pub fn atomic_bytes_write(
        &self,
        relative: &str,
        bytes: &[u8],
    ) -> Result<ArtifactWriteRecord, EngagementError> {
        if !root_handle_matches_path(self.root_dir.as_ref(), &self.root)? {
            return Err(EngagementError::Invalid(
                "engagement root changed before artifact write".into(),
            ));
        }
        let locator = self.resolve_relative(relative)?;
        let sha256 = hex::encode(Sha256::digest(bytes));
        let byte_len = bytes.len();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        atomic_write_relative(self.root_dir.as_ref(), Path::new(relative), bytes)?;
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure relative artifact writes require Linux or macOS",
        )
        .into());

        if !root_handle_matches_path(self.root_dir.as_ref(), &self.root)? {
            return Err(EngagementError::Invalid(
                "engagement root changed during artifact write".into(),
            ));
        }

        Ok(ArtifactWriteRecord {
            relative_path: PathBuf::from(relative),
            locator,
            sha256,
            bytes: byte_len,
        })
    }

    // Read and verify the exact owned bytes named by a write record
    pub fn open_verified(
        &self,
        record: &ArtifactWriteRecord,
    ) -> Result<std::io::Cursor<Vec<u8>>, EngagementError> {
        use std::io::Read;

        let relative = record.relative_path.to_str().ok_or_else(|| {
            EngagementError::Invalid("artifact relative path must be UTF-8".into())
        })?;
        let file = self.open_relative_read(relative)?;
        let limit = u64::try_from(record.bytes)
            .map_err(|_| EngagementError::Invalid("artifact length is unsupported".into()))?;
        let mut bytes = Vec::with_capacity(record.bytes.min(1024 * 1024));
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() != record.bytes || hex::encode(Sha256::digest(&bytes)) != record.sha256 {
            return Err(EngagementError::Invalid(
                "artifact bytes do not match the write record".into(),
            ));
        }
        Ok(std::io::Cursor::new(bytes))
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn atomic_write_relative(
    root: &impl std::os::fd::AsRawFd,
    relative: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};

    unsafe extern "C" {
        fn dup(fd: i32) -> i32;
        fn fsync(fd: i32) -> i32;
        fn mkdirat(dirfd: i32, path: *const std::os::raw::c_char, mode: u32) -> i32;
        fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
        fn renameat(
            olddirfd: i32,
            oldpath: *const std::os::raw::c_char,
            newdirfd: i32,
            newpath: *const std::os::raw::c_char,
        ) -> i32;
        fn unlinkat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32) -> i32;
    }

    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact path must be a normal relative path",
            )),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let (file_name, parents) = components
        .split_last()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let duplicated = unsafe { dup(root.as_raw_fd()) };
    if duplicated < 0 {
        return Err(io_context(
            "duplicate artifact root descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    let mut directory = unsafe { std::fs::File::from_raw_fd(duplicated) };

    for component in parents {
        let name = os_string_cstring(component)?;
        let created = if unsafe { mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(io_context("create artifact parent directory", error));
            }
            false
        } else {
            true
        };
        if created && unsafe { fsync(directory.as_raw_fd()) } < 0 {
            return Err(io_context(
                "sync containing artifact directory",
                std::io::Error::last_os_error(),
            ));
        }
        let fd = unsafe {
            openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                O_RDONLY_FLAG | O_DIRECTORY_FLAG | O_NOFOLLOW_FLAG | O_CLOEXEC_FLAG,
                0,
            )
        };
        if fd < 0 {
            return Err(io_context(
                "open artifact parent directory",
                std::io::Error::last_os_error(),
            ));
        }
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }

    let final_name = os_string_cstring(file_name)?;
    let mut temp = None;
    for sequence in 0..100u32 {
        let candidate =
            std::ffi::OsString::from(format!(".artifact-{}-{sequence}.tmp", std::process::id()));
        let name = os_string_cstring(&candidate)?;
        let fd = unsafe {
            openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                O_WRONLY_FLAG | O_CREATE_FLAG | O_EXCLUSIVE_FLAG | O_CLOEXEC_FLAG | O_NOFOLLOW_FLAG,
                0o600,
            )
        };
        if fd >= 0 {
            temp = Some((name, unsafe { std::fs::File::from_raw_fd(fd) }));
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(io_context("create artifact temp file", error));
        }
    }
    let (temp_name, mut temp_file) = temp.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not reserve artifact temp file",
        )
    })?;
    let result = (|| {
        temp_file
            .write_all(bytes)
            .map_err(|error| io_context("write artifact temp file", error))?;
        temp_file
            .sync_all()
            .map_err(|error| io_context("sync artifact temp file", error))?;
        if unsafe {
            renameat(
                directory.as_raw_fd(),
                temp_name.as_ptr(),
                directory.as_raw_fd(),
                final_name.as_ptr(),
            )
        } < 0
        {
            return Err(io_context(
                "rename artifact temp file",
                std::io::Error::last_os_error(),
            ));
        }
        if unsafe { fsync(directory.as_raw_fd()) } < 0 {
            return Err(io_context(
                "sync artifact parent directory",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    result
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn io_context(operation: &str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{operation}: {error}"))
}

#[cfg(target_os = "linux")]
fn root_handle_matches_path(
    root: &rustix::fd::OwnedFd,
    path: &Path,
) -> Result<bool, EngagementError> {
    use std::os::unix::fs::MetadataExt;

    let held = rustix::fs::fstat(root).map_err(errno_to_io)?;
    let current = std::fs::metadata(path)?;
    Ok(held.st_dev as u64 == current.dev() && held.st_ino as u64 == current.ino())
}

#[cfg(target_os = "macos")]
fn root_handle_matches_path(root: &std::fs::File, path: &Path) -> Result<bool, EngagementError> {
    use std::os::unix::fs::MetadataExt;

    let held = root.metadata()?;
    let current = std::fs::metadata(path)?;
    Ok(held.dev() == current.dev() && held.ino() == current.ino())
}

#[cfg(target_os = "linux")]
fn errno_to_io(errno: rustix::io::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(errno.raw_os_error())
}

#[cfg(target_os = "linux")]
const O_RDONLY_FLAG: i32 = 0;
#[cfg(target_os = "linux")]
const O_WRONLY_FLAG: i32 = 1;
#[cfg(target_os = "linux")]
const O_CREATE_FLAG: i32 = 0o100;
#[cfg(target_os = "linux")]
const O_EXCLUSIVE_FLAG: i32 = 0o200;
#[cfg(target_os = "linux")]
const O_DIRECTORY_FLAG: i32 = 0o40000;
#[cfg(target_os = "linux")]
const O_NOFOLLOW_FLAG: i32 = 0o100000;
#[cfg(target_os = "linux")]
const O_CLOEXEC_FLAG: i32 = 0o2000000;

#[cfg(target_os = "macos")]
const O_RDONLY_FLAG: i32 = 0;
#[cfg(target_os = "macos")]
const O_WRONLY_FLAG: i32 = 1;
#[cfg(target_os = "macos")]
const O_CREATE_FLAG: i32 = 0x0200;
#[cfg(target_os = "macos")]
const O_EXCLUSIVE_FLAG: i32 = 0x0800;
#[cfg(target_os = "macos")]
const O_DIRECTORY_FLAG: i32 = 0x0010_0000;
#[cfg(target_os = "macos")]
const O_NOFOLLOW_FLAG: i32 = 0x0000_0100;
#[cfg(target_os = "macos")]
const O_CLOEXEC_FLAG: i32 = 0x0100_0000;
#[cfg(target_os = "macos")]
const O_NONBLOCK_FLAG: i32 = 0x0000_0004;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn os_string_cstring(value: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(value.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(target_os = "macos")]
fn open_directory_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY_FLAG | O_NOFOLLOW_FLAG | O_CLOEXEC_FLAG)
        .open(path)
}

#[cfg(target_os = "macos")]
fn openat_file(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: i32,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(dirfd: i32, path: *const std::os::raw::c_char, flags: i32, ...) -> i32;
    }
    let name = os_string_cstring(name)?;
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr(), flags, 0) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(target_os = "macos")]
fn open_relative_read_macos(root: &std::fs::File, path: &Path) -> std::io::Result<std::fs::File> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact path must be a normal relative path",
            )),
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let (file_name, parents) = components
        .split_last()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty path"))?;
    let mut directory = root.try_clone()?;
    for component in parents {
        directory = openat_file(
            &directory,
            component,
            O_RDONLY_FLAG | O_DIRECTORY_FLAG | O_NOFOLLOW_FLAG | O_CLOEXEC_FLAG,
        )?;
    }
    let file = openat_file(
        &directory,
        file_name,
        O_RDONLY_FLAG | O_NOFOLLOW_FLAG | O_CLOEXEC_FLAG | O_NONBLOCK_FLAG,
    )?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "artifact is not a regular file",
        ));
    }
    Ok(file)
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

    #[cfg(unix)]
    #[test]
    fn symlinked_engagement_root_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let root_link = parent.path().join("engagement-root");
        symlink(target.path(), &root_link).unwrap();

        assert!(ArtifactStore::new(&root_link).is_err());
    }

    #[test]
    fn atomic_json_write_records_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(tmp.path()).unwrap();

        let record = store
            .atomic_json_write("evidence/proof.json", &json!({ "ok": true }))
            .unwrap();

        let mut verified = store.open_verified(&record).unwrap();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut verified, &mut bytes).unwrap();
        let expected = format!("{:x}", sha2::Sha256::digest(&bytes));
        assert_eq!(record.sha256, expected);
        assert_eq!(record.bytes, bytes.len());
        assert_eq!(
            record.relative_path,
            std::path::Path::new("evidence/proof.json")
        );
        assert!(
            record
                .locator
                .starts_with(tmp.path().canonicalize().unwrap())
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn atomic_json_write_stays_anchored_when_root_path_is_replaced() {
        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("engagement");
        let retained = parent.path().join("retained-engagement");
        std::fs::create_dir(&root).unwrap();
        let store = ArtifactStore::new(&root).unwrap();

        std::fs::rename(&root, &retained).unwrap();
        std::fs::create_dir(&root).unwrap();

        let result = store.atomic_json_write("evidence/proof.json", &json!({ "ok": true }));

        assert!(result.is_err());
        assert!(!root.join("evidence/proof.json").exists());
        assert!(!retained.join("evidence/proof.json").exists());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn verified_record_read_stays_descriptor_bound_after_locator_replacement() {
        use std::io::Read;

        let parent = tempfile::tempdir().unwrap();
        let root = parent.path().join("engagement");
        let retained = parent.path().join("retained-engagement");
        std::fs::create_dir(&root).unwrap();
        let store = ArtifactStore::new(&root).unwrap();
        let record = store
            .atomic_json_write("evidence/proof.json", &json!({ "ok": true }))
            .unwrap();

        std::fs::rename(&root, &retained).unwrap();
        std::fs::create_dir_all(root.join("evidence")).unwrap();
        std::fs::write(root.join("evidence/proof.json"), b"replacement").unwrap();

        let mut verified = store.open_verified(&record).unwrap();
        let mut bytes = Vec::new();
        verified.read_to_end(&mut bytes).unwrap();
        assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), record.sha256);
        assert_ne!(bytes, b"replacement");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn verified_record_read_rejects_changed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let store = ArtifactStore::new(root.path()).unwrap();
        let record = store
            .atomic_json_write("evidence/proof.json", &json!({ "ok": true }))
            .unwrap();

        std::fs::write(root.path().join("evidence/proof.json"), b"changed").unwrap();

        assert!(store.open_verified(&record).is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn atomic_json_write_rejects_intermediate_symlink_without_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join("evidence")).unwrap();
        let store = ArtifactStore::new(root.path()).unwrap();

        assert!(
            store
                .atomic_json_write("evidence/proof.json", &json!({ "ok": true }))
                .is_err()
        );
        assert!(!outside.path().join("proof.json").exists());
    }

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

    #[cfg(unix)]
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

    #[cfg(target_os = "macos")]
    #[test]
    fn relative_read_rejects_fifo_without_blocking() {
        use std::process::Command;
        use std::sync::mpsc;
        use std::time::Duration;

        let root = tempfile::tempdir().unwrap();
        assert!(
            Command::new("mkfifo")
                .arg(root.path().join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        let store = ArtifactStore::new(root.path()).unwrap();
        let (sender, receiver) = mpsc::channel();

        std::thread::spawn(move || {
            sender
                .send(store.open_relative_read("fifo").is_err())
                .unwrap();
        });

        assert_eq!(receiver.recv_timeout(Duration::from_secs(1)), Ok(true));
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
