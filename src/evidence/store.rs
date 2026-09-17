//! Evidence directory layout and artifact writing.
//!
//! # Layout
//!
//! ```text
//! CASE-001/
//!     original/    acquired evidence, never modified or replaced
//!     derived/     conversions produced from originals
//!     working/     verified copies intended for analysis tools
//!     manifests/   one immutable manifest per operation
//!     hashes/      sha256sum-compatible hash lists
//!     logs/        structured JSON Lines logs
//! ```
//!
//! # Write discipline
//!
//! Every evidence file is created with `create_new`, so an existing file causes
//! the operation to fail instead of being overwritten. The check and the
//! creation are the same syscall, which closes the check-then-open race.
//!
//! Bulk data is written to a `.partial` sibling and renamed into place only
//! after the stream ends cleanly and the digest is finalized. An interrupted or
//! failed acquisition therefore always leaves an unambiguously named partial
//! file, and a file under its final name is always a completed transfer.
//!
//! Nothing in this module deletes an artifact. The only path that removes a file
//! is the destination write probe, which removes a file it has just created
//! itself.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use tracing::debug;

use crate::error::{Error, IoResultExt, Result};
use crate::evidence::manifest::{ArtifactRecord, ArtifactRole, EvidenceClass, Manifest};
use crate::hashing::{DigestSet, HashReport, MultiHasher};
use crate::util::paths::{ensure_no_symlinked_components, join_inside, relative_slash_path};

/// Subdirectories created for every case.
pub const CASE_SUBDIRECTORIES: [&str; 6] = [
    "original",
    "derived",
    "working",
    "manifests",
    "hashes",
    "logs",
];

/// Suffix used while a bulk artifact is still being written.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// Write buffer for bulk artifact data.
const WRITE_BUFFER_SIZE: usize = 1024 * 1024;

/// A case directory on disk.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    root: PathBuf,
}

impl EvidenceStore {
    /// Creates (or adopts) the case directory structure.
    ///
    /// An existing case directory is reused, because one case legitimately holds
    /// several evidence items. Safety comes from per-file `create_new`, not from
    /// refusing an existing directory.
    pub fn create(root: &Path) -> Result<Self> {
        if let Ok(metadata) = std::fs::symlink_metadata(root) {
            if metadata.file_type().is_symlink() {
                return Err(Error::Destination(format!(
                    "`{}` is a symbolic link; refusing to use it as an evidence root",
                    root.display()
                )));
            }
            if !metadata.is_dir() {
                return Err(Error::Destination(format!(
                    "`{}` exists and is not a directory",
                    root.display()
                )));
            }
        }

        std::fs::create_dir_all(root).ctx("create directory", root)?;
        let root = canonical_root(root)?;
        for subdirectory in CASE_SUBDIRECTORIES {
            let path = root.join(subdirectory);
            std::fs::create_dir_all(&path).ctx("create directory", &path)?;
        }
        let store = Self { root };
        store.probe_writable()?;
        Ok(store)
    }

    /// Opens an existing case directory, verifying its layout.
    pub fn open(root: &Path) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(root).ctx("inspect", root)?;
        if metadata.file_type().is_symlink() {
            return Err(Error::Destination(format!(
                "`{}` is a symbolic link; refusing to use it as an evidence root",
                root.display()
            )));
        }
        if !metadata.is_dir() {
            return Err(Error::Destination(format!(
                "`{}` is not a directory",
                root.display()
            )));
        }
        let root = canonical_root(root)?;
        let manifests = root.join("manifests");
        if !manifests.is_dir() {
            return Err(Error::Destination(format!(
                "`{}` does not look like a case directory (no manifests/ subdirectory)",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn class_dir(&self, class: EvidenceClass) -> PathBuf {
        self.root.join(class.directory())
    }

    pub fn manifests_dir(&self) -> PathBuf {
        self.root.join("manifests")
    }

    pub fn hashes_dir(&self) -> PathBuf {
        self.root.join("hashes")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// Renders an absolute path inside the store as a case-relative path.
    pub fn relative(&self, path: &Path) -> Result<String> {
        relative_slash_path(&self.root, path)
    }

    /// Confirms the destination is writable by creating and removing a probe file.
    ///
    /// The probe is created with `create_new` under a name no evidence file can
    /// take, and only that file is ever removed.
    fn probe_writable(&self) -> Result<()> {
        let probe = self.root.join(".nootextract-write-probe");
        match OpenOptions::new().write(true).create_new(true).open(&probe) {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(&probe).ctx("remove write probe at", &probe)?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(Error::Destination(format!(
                "`{}` is not writable: {e}",
                self.root.display()
            ))),
        }
    }

    /// Free space available on the destination filesystem, if determinable.
    pub fn available_space(&self) -> Option<u64> {
        fs4::available_space(&self.root).ok()
    }

    /// Fails when the destination cannot hold `required` bytes plus a margin.
    ///
    /// `headroom_percent` accounts for filesystem metadata and the manifest and
    /// log files written alongside the image.
    pub fn ensure_space(&self, required: u64, headroom_percent: u64) -> Result<()> {
        let Some(available) = self.available_space() else {
            return Ok(());
        };
        let headroom = required
            .saturating_mul(headroom_percent)
            .saturating_div(100);
        let needed = required.saturating_add(headroom);
        if available < needed {
            return Err(Error::InsufficientSpace {
                path: self.root.clone(),
                required: needed,
                available,
            });
        }
        Ok(())
    }

    /// Resolves a file name inside a class directory without creating it.
    pub fn path_for(&self, class: EvidenceClass, file_name: &str) -> Result<PathBuf> {
        let relative = Path::new(class.directory()).join(file_name);
        let path = join_inside(&self.root, &relative)?;
        ensure_no_symlinked_components(&self.root, &path)?;
        Ok(path)
    }

    /// Creates a directory inside a class directory, validating every segment.
    ///
    /// Used by extraction, which must reproduce an archive's directory tree.
    /// The relative path goes through the same traversal and symlink checks as
    /// an artifact path, so a hostile archive cannot create a directory outside
    /// the case — or follow a link out of it.
    pub fn create_subdirectory(&self, class: EvidenceClass, relative: &Path) -> Result<PathBuf> {
        let path = self.path_for(
            class,
            relative.to_str().ok_or_else(|| {
                Error::Destination(format!("`{}` is not valid Unicode", relative.display()))
            })?,
        )?;
        std::fs::create_dir_all(&path).ctx("create directory", &path)?;
        // Re-checked after creation: a component could have been replaced by a
        // link between validation and the call above.
        ensure_no_symlinked_components(&self.root, &path)?;
        Ok(path)
    }

    /// Opens a new bulk artifact for writing.
    ///
    /// Both the final path and its `.partial` sibling are reserved up front so
    /// that a later rename cannot clobber an unrelated file.
    pub fn create_artifact(
        &self,
        class: EvidenceClass,
        file_name: &str,
        role: ArtifactRole,
        format: &str,
        with_sha512: bool,
    ) -> Result<ArtifactWriter> {
        let final_path = self.path_for(class, file_name)?;
        let partial_path = self.path_for(class, &format!("{file_name}{PARTIAL_SUFFIX}"))?;

        if final_path.exists() {
            return Err(Error::Destination(format!(
                "`{}` already exists; refusing to overwrite {} evidence. Choose a different \
                 --evidence-id or output directory.",
                final_path.display(),
                class
            )));
        }

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    Error::Destination(format!(
                        "`{}` already exists, which indicates an earlier interrupted \
                         acquisition. It is preserved; move or rename it before retrying.",
                        partial_path.display()
                    ))
                } else {
                    Error::io("create", &partial_path, e)
                }
            })?;

        debug!(path = %partial_path.display(), "opened artifact for writing");
        Ok(ArtifactWriter {
            root: self.root.clone(),
            final_path,
            partial_path,
            writer: Some(BufWriter::with_capacity(WRITE_BUFFER_SIZE, file)),
            hasher: MultiHasher::new(with_sha512),
            class,
            role,
            format: format.to_owned(),
            created_at: Utc::now(),
        })
    }

    /// Refuses to write into a case directory that belongs to another case.
    ///
    /// A case directory *is* the case. Writing evidence labelled `CASE-002` into
    /// the directory holding `CASE-001` produces a set whose manifests disagree
    /// about what they document, which is a chain-of-custody defect rather than
    /// a naming inconvenience — so it fails instead of warning. An empty
    /// directory adopts whatever case is written first.
    pub fn ensure_case_consistency(&self, case_id: &str) -> Result<()> {
        for (path, manifest) in self.load_manifests()? {
            if manifest.case.case_id != case_id {
                return Err(Error::Destination(format!(
                    "`{}` already holds evidence for case `{}` (see {}), but this operation is \
                     labelled `{case_id}`. Use a separate output directory for each case.",
                    self.root.display(),
                    manifest.case.case_id,
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or("its manifests")
                )));
            }
        }
        Ok(())
    }

    /// Records a file produced inside the store by an external tool.
    ///
    /// Used for formats this tool delegates to an established library rather
    /// than reimplementing. The file must already exist inside the store; it is
    /// opened read-only, hashed with the same streaming code as everything else,
    /// and returned as a normal artifact so it is manifested and verifiable.
    pub fn adopt_artifact(
        &self,
        class: EvidenceClass,
        file_name: &str,
        role: ArtifactRole,
        format: &str,
        with_sha512: bool,
        cancel: &crate::util::cancel::CancellationToken,
    ) -> Result<FinishedArtifact> {
        let path = self.path_for(class, file_name)?;
        let metadata = std::fs::symlink_metadata(&path).ctx("inspect", &path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(Error::Destination(format!(
                "`{}` is not a regular file",
                path.display()
            )));
        }

        let report = crate::hashing::hash_file(&path, with_sha512, cancel, &mut |_| {})?;
        let created_at = metadata
            .modified()
            .ok()
            .map_or_else(Utc::now, DateTime::<Utc>::from);

        Ok(FinishedArtifact {
            relative_path: relative_slash_path(&self.root, &path)?,
            path,
            size_bytes: report.bytes,
            digests: report.digests,
            complete: true,
            class,
            role,
            format: format.to_owned(),
            created_at,
            note: None,
            derived_from: None,
            segment_index: None,
        })
    }

    /// Lists file names in a class directory that start with `prefix`.
    pub fn list_class_files(&self, class: EvidenceClass, prefix: &str) -> Result<Vec<String>> {
        let dir = self.class_dir(class);
        let mut names = Vec::new();
        if !dir.is_dir() {
            return Ok(names);
        }
        let entries = std::fs::read_dir(&dir).ctx("read directory", &dir)?;
        for entry in entries {
            let entry = entry.ctx("read directory entry in", &dir)?;
            if !entry.path().is_file() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with(prefix)
            {
                names.push(name.to_owned());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Lists manifest documents in the case, sorted by file name.
    pub fn manifest_paths(&self) -> Result<Vec<PathBuf>> {
        let dir = self.manifests_dir();
        let mut paths = Vec::new();
        let entries = std::fs::read_dir(&dir).ctx("read directory", &dir)?;
        for entry in entries {
            let entry = entry.ctx("read directory entry in", &dir)?;
            let path = entry.path();
            if path.is_file()
                && path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".manifest.json"))
            {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }

    /// Loads every manifest in the case.
    pub fn load_manifests(&self) -> Result<Vec<(PathBuf, Manifest)>> {
        let mut loaded = Vec::new();
        for path in self.manifest_paths()? {
            let manifest = Manifest::load(&path)?;
            loaded.push((path, manifest));
        }
        Ok(loaded)
    }

    /// Writes a manifest and its companion hash list.
    ///
    /// The event log is ordered chronologically here, at the single point where
    /// a manifest becomes a persisted record.
    pub fn write_manifest(&self, manifest: &Manifest) -> Result<ManifestOutputs> {
        let mut manifest = manifest.clone();
        manifest.sort_events();
        let manifest = &manifest;

        let manifest_path = self.manifests_dir().join(manifest.file_name());
        ensure_no_symlinked_components(&self.root, &manifest_path)?;
        manifest.write_to(&manifest_path)?;

        let hash_name = format!(
            "{}-{}.sha256",
            manifest.case.evidence_id, manifest.operation.operation_id
        );
        let hash_path = self.hashes_dir().join(&hash_name);
        ensure_no_symlinked_components(&self.root, &hash_path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&hash_path)
            .ctx("create", &hash_path)?;
        file.write_all(manifest.hash_list().as_bytes())
            .ctx("write", &hash_path)?;
        file.sync_all().ctx("sync", &hash_path)?;

        Ok(ManifestOutputs {
            manifest_path,
            hash_list_path: hash_path,
        })
    }
}

/// Paths written by [`EvidenceStore::write_manifest`].
#[derive(Debug, Clone)]
pub struct ManifestOutputs {
    pub manifest_path: PathBuf,
    pub hash_list_path: PathBuf,
}

/// Canonicalizes the case root so later `strip_prefix` comparisons are reliable.
///
/// Uses the shared helper so a source path and the evidence root are always
/// normalized the same way; mixing normalizations made paths inside the case
/// look like paths outside it.
fn canonical_root(root: &Path) -> Result<PathBuf> {
    crate::util::paths::canonicalize(root)
}

/// A bulk artifact being written, hashed as it streams.
///
/// Digests are computed from the bytes on their way to disk, so the manifest
/// records the digest of exactly what was written, with no second full read.
#[derive(Debug)]
pub struct ArtifactWriter {
    root: PathBuf,
    final_path: PathBuf,
    partial_path: PathBuf,
    writer: Option<BufWriter<File>>,
    hasher: MultiHasher,
    class: EvidenceClass,
    role: ArtifactRole,
    format: String,
    created_at: DateTime<Utc>,
}

impl ArtifactWriter {
    /// Appends a chunk, updating the running digests.
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<()> {
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| Error::Acquisition("artifact writer is already finalized".into()))?;
        writer.write_all(chunk).map_err(|e| {
            if e.kind() == std::io::ErrorKind::StorageFull {
                Error::InsufficientSpace {
                    path: self.root.clone(),
                    required: self.hasher.bytes().saturating_add(chunk.len() as u64),
                    available: 0,
                }
            } else {
                Error::io("write", &self.partial_path, e)
            }
        })?;
        self.hasher.update(chunk);
        Ok(())
    }

    /// Bytes written so far.
    pub fn bytes_written(&self) -> u64 {
        self.hasher.bytes()
    }

    pub fn partial_path(&self) -> &Path {
        &self.partial_path
    }

    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    fn flush_to_disk(&mut self) -> Result<()> {
        let Some(mut writer) = self.writer.take() else {
            return Ok(());
        };
        writer.flush().ctx("flush", &self.partial_path)?;
        let file = writer
            .into_inner()
            .map_err(|e| Error::io("flush", &self.partial_path, e.into_error()))?;
        // fsync before the rename: the rename must not become durable ahead of
        // the data it publishes.
        file.sync_all().ctx("sync", &self.partial_path)?;
        Ok(())
    }

    /// Finalizes a completed transfer: flush, fsync and rename into place.
    pub fn finish_complete(mut self) -> Result<FinishedArtifact> {
        self.flush_to_disk()?;
        if self.final_path.exists() {
            return Err(Error::Destination(format!(
                "`{}` appeared while the acquisition was running; the acquired data is \
                 preserved at `{}`",
                self.final_path.display(),
                self.partial_path.display()
            )));
        }
        std::fs::rename(&self.partial_path, &self.final_path)
            .map_err(|e| Error::io("publish completed artifact to", &self.final_path, e))?;
        let published = self.final_path.clone();
        self.into_finished(published, true, None)
    }

    /// Finalizes an interrupted or failed transfer.
    ///
    /// The data stays under its `.partial` name. It is flushed, synced and
    /// hashed so the incomplete artifact is still a documented, verifiable
    /// object rather than an unknown quantity.
    pub fn finish_incomplete(mut self, note: impl Into<String>) -> Result<FinishedArtifact> {
        self.flush_to_disk()?;
        let path = self.partial_path.clone();
        self.into_finished(path, false, Some(note.into()))
    }

    fn into_finished(
        self,
        path: PathBuf,
        complete: bool,
        note: Option<String>,
    ) -> Result<FinishedArtifact> {
        let HashReport { bytes, digests } = self.hasher.finish();
        let relative = relative_slash_path(&self.root, &path)?;
        Ok(FinishedArtifact {
            path,
            relative_path: relative,
            size_bytes: bytes,
            digests,
            complete,
            class: self.class,
            role: self.role,
            format: self.format,
            created_at: self.created_at,
            note,
            derived_from: None,
            segment_index: None,
        })
    }
}

/// A finalized artifact and everything the manifest needs to record it.
#[derive(Debug, Clone)]
pub struct FinishedArtifact {
    pub path: PathBuf,
    pub relative_path: String,
    pub size_bytes: u64,
    pub digests: DigestSet,
    pub complete: bool,
    pub class: EvidenceClass,
    pub role: ArtifactRole,
    pub format: String,
    pub created_at: DateTime<Utc>,
    pub note: Option<String>,
    pub derived_from: Option<String>,
    pub segment_index: Option<u32>,
}

impl FinishedArtifact {
    #[must_use]
    pub fn derived_from(mut self, source: impl Into<String>) -> Self {
        self.derived_from = Some(source.into());
        self
    }

    #[must_use]
    pub fn with_segment_index(mut self, index: u32) -> Self {
        self.segment_index = Some(index);
        self
    }

    pub fn to_record(&self) -> ArtifactRecord {
        ArtifactRecord {
            path: self.relative_path.clone(),
            classification: self.class,
            role: self.role,
            format: self.format.clone(),
            size_bytes: self.size_bytes,
            hashes: self.digests.clone(),
            complete: self.complete,
            created_at: self.created_at,
            derived_from: self.derived_from.clone(),
            segment_index: self.segment_index,
            notes: self.note.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::default_trait_access,
        clippy::format_push_string,
        clippy::integer_division,
        clippy::cast_sign_loss
    )]
    use super::*;

    fn store() -> (tempfile::TempDir, EvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("CASE-001");
        let store = EvidenceStore::create(&root).unwrap();
        (dir, store)
    }

    #[test]
    fn creates_the_full_layout() {
        let (_guard, store) = store();
        for subdirectory in CASE_SUBDIRECTORIES {
            assert!(
                store.root().join(subdirectory).is_dir(),
                "missing {subdirectory}/"
            );
        }
    }

    #[test]
    fn create_is_idempotent_for_an_existing_case() {
        let (_guard, store) = store();
        let again = EvidenceStore::create(store.root()).unwrap();
        assert_eq!(again.root(), store.root());
    }

    #[test]
    fn refuses_a_file_as_evidence_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-dir");
        std::fs::write(&path, b"x").unwrap();
        let err = EvidenceStore::create(&path).unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 6);
    }

    #[test]
    fn open_rejects_a_directory_without_the_layout() {
        let dir = tempfile::tempdir().unwrap();
        assert!(EvidenceStore::open(dir.path()).is_err());
    }

    #[test]
    fn writes_and_publishes_a_complete_artifact() {
        let (_guard, store) = store();
        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.tar",
                ArtifactRole::LogicalArchive,
                "tar",
                false,
            )
            .unwrap();

        assert!(writer.partial_path().exists());
        assert!(!writer.final_path().exists());

        writer.write_chunk(b"abc").unwrap();
        assert_eq!(writer.bytes_written(), 3);
        let finished = writer.finish_complete().unwrap();

        assert!(finished.complete);
        assert_eq!(finished.size_bytes, 3);
        assert_eq!(
            finished.digests.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(finished.relative_path, "original/EV-1.tar");
        assert!(finished.path.exists());
        assert!(!store.root().join("original/EV-1.tar.partial").exists());
        assert_eq!(std::fs::read(&finished.path).unwrap(), b"abc");
    }

    #[test]
    fn keeps_partial_data_for_an_incomplete_artifact() {
        let (_guard, store) = store();
        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                false,
            )
            .unwrap();
        writer.write_chunk(b"partial data").unwrap();
        let finished = writer.finish_incomplete("interrupted by operator").unwrap();

        assert!(!finished.complete);
        assert!(finished.relative_path.ends_with(".partial"));
        assert!(finished.path.exists());
        assert_eq!(std::fs::read(&finished.path).unwrap(), b"partial data");
        // The final name must stay free so the partial cannot be mistaken for
        // a complete image.
        assert!(!store.root().join("original/EV-1.raw").exists());
        assert_eq!(finished.note.as_deref(), Some("interrupted by operator"));
    }

    #[test]
    fn refuses_to_overwrite_an_existing_original() {
        let (_guard, store) = store();
        let existing = store.root().join("original").join("EV-1.raw");
        std::fs::write(&existing, b"original evidence").unwrap();

        let err = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                false,
            )
            .unwrap_err();

        assert_eq!(err.exit_code().as_i32(), 6);
        assert!(err.to_string().contains("already exists"), "{err}");
        // The pre-existing file must be untouched.
        assert_eq!(std::fs::read(&existing).unwrap(), b"original evidence");
    }

    #[test]
    fn refuses_to_reuse_an_existing_partial_file() {
        let (_guard, store) = store();
        let partial = store.root().join("original").join("EV-1.raw.partial");
        std::fs::write(&partial, b"earlier attempt").unwrap();

        let err = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                false,
            )
            .unwrap_err();

        assert!(err.to_string().contains("interrupted"), "{err}");
        assert_eq!(std::fs::read(&partial).unwrap(), b"earlier attempt");
    }

    #[test]
    fn rejects_artifact_names_that_escape_the_case_root() {
        let (_guard, store) = store();
        for bad in ["../escape.raw", "sub/../../escape.raw"] {
            assert!(
                store
                    .create_artifact(
                        EvidenceClass::Original,
                        bad,
                        ArtifactRole::PhysicalImage,
                        "raw",
                        false,
                    )
                    .is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    #[test]
    fn hashes_large_chunked_writes_consistently() {
        let (_guard, store) = store();
        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-big.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                true,
            )
            .unwrap();

        let data: Vec<u8> = (0..300_000).map(|i| (i % 253) as u8).collect();
        for chunk in data.chunks(4096) {
            writer.write_chunk(chunk).unwrap();
        }
        let finished = writer.finish_complete().unwrap();

        assert_eq!(finished.size_bytes, data.len() as u64);
        let on_disk = crate::hashing::hash_file(
            &finished.path,
            true,
            &crate::util::cancel::CancellationToken::new(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(on_disk.digests, finished.digests);
    }

    #[test]
    fn reports_free_space() {
        let (_guard, store) = store();
        assert!(store.available_space().is_some());
        assert!(store.ensure_space(1024, 5).is_ok());
    }

    #[test]
    fn rejects_an_impossible_space_requirement() {
        let (_guard, store) = store();
        let err = store.ensure_space(u64::MAX / 2, 5).unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 7);
    }

    #[test]
    fn space_requirement_does_not_overflow() {
        let (_guard, store) = store();
        // The headroom multiplication must saturate rather than wrap.
        let err = store.ensure_space(u64::MAX, 50).unwrap_err();
        assert!(matches!(err, Error::InsufficientSpace { .. }));
    }

    #[test]
    fn writes_a_manifest_and_hash_list() {
        let (_guard, store) = store();
        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.tar",
                ArtifactRole::LogicalArchive,
                "tar",
                false,
            )
            .unwrap();
        writer.write_chunk(b"abc").unwrap();
        let artifact = writer.finish_complete().unwrap();

        let started = Utc::now();
        let mut manifest = Manifest::new(
            crate::evidence::manifest::CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: None,
                notes: None,
            },
            crate::evidence::manifest::OperationRecord {
                operation_id: crate::evidence::manifest::operation_id("acq", started),
                method: "test".to_owned(),
                method_description: "test".to_owned(),
                source: crate::evidence::manifest::SourceRecord {
                    source_id: "ABC".to_owned(),
                    source_path: None,
                    remote_command: None,
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(Utc::now()),
                duration_ms: Some(1),
                status: crate::evidence::manifest::AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        manifest.artifacts.push(artifact.to_record());

        let outputs = store.write_manifest(&manifest).unwrap();
        assert!(outputs.manifest_path.is_file());
        assert!(outputs.hash_list_path.is_file());

        let hash_list = std::fs::read_to_string(&outputs.hash_list_path).unwrap();
        assert!(hash_list.contains("original/EV-1.tar"));
        assert!(hash_list.starts_with("ba7816bf"));

        let reloaded = store.load_manifests().unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].1.case.evidence_id, "EV-1");
    }

    #[test]
    fn writing_the_same_manifest_twice_fails_rather_than_overwriting() {
        let (_guard, store) = store();
        let started = Utc::now();
        let manifest = Manifest::new(
            crate::evidence::manifest::CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: None,
                notes: None,
            },
            crate::evidence::manifest::OperationRecord {
                operation_id: "acq-fixed".to_owned(),
                method: "test".to_owned(),
                method_description: "test".to_owned(),
                source: crate::evidence::manifest::SourceRecord {
                    source_id: "ABC".to_owned(),
                    source_path: None,
                    remote_command: None,
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(started),
                duration_ms: Some(0),
                status: crate::evidence::manifest::AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        store.write_manifest(&manifest).unwrap();
        // The hash list is created with create_new, so the second write fails.
        assert!(store.write_manifest(&manifest).is_err());
    }
}
