//! Safe extraction of a logical acquisition archive.
//!
//! A logical acquisition produces a tar archive. Analysis tools that expect
//! files rather than a container need it unpacked, and unpacking is where a
//! forensic tool is most exposed: every path in the archive was chosen by the
//! device, and tar has no rule against an entry named `../../etc/passwd`, an
//! absolute path, or a symlink pointing anywhere at all.
//!
//! Running the system `tar` and hoping is not good enough, for two reasons.
//! Extraction safety would depend on which implementation happens to be
//! installed, and the resulting files would be unaccounted for — a later
//! `verify` would report every one of them as `EXTRA`. This module extracts
//! through the evidence store instead, so each file is validated, hashed and
//! recorded like any other artifact.
//!
//! # Extraction policy
//!
//! * Regular files are extracted, hashed and manifested.
//! * Directories are created.
//! * Symbolic links, hard links, character and block devices, and FIFOs are
//!   **never created**. They are recorded as skipped, with the reason. A link
//!   is an instruction to the filesystem, not evidence content, and recreating
//!   one during extraction is how an archive escapes its destination.
//! * An entry whose path is unsafe is refused, not sanitized. Silently renaming
//!   a file would put a name in the record that never existed on the device.
//! * An entry the host filesystem rejects — a name legal on Android but not on
//!   Windows — is recorded as skipped with the operating-system error, so the
//!   shortfall is visible rather than discovered later as a missing file.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::acquisition::backend::ProgressSink;
use crate::error::{Error, IoResultExt, Result};
use crate::evidence::manifest::{ArtifactRole, EvidenceClass};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::util::cancel::CancellationToken;

/// Default cap on the number of entries extracted from one archive.
///
/// Bounds both the work done and the size of the resulting manifest, which
/// gains one record per extracted file.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;

/// Default cap on the total bytes written by one extraction.
///
/// An archive can declare far more content than its own size; without a ceiling
/// a small file can fill the destination.
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Maximum accepted length of a single path component.
const MAX_COMPONENT_LEN: usize = 255;

/// Options controlling an extraction.
#[derive(Debug, Clone, Copy)]
pub struct ExtractionOptions {
    pub with_sha512: bool,
    pub max_entries: usize,
    pub max_total_bytes: u64,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            with_sha512: false,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

/// An archive entry that was deliberately not extracted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    /// The entry name as the archive declared it, sanitized for display.
    pub path: String,
    pub reason: String,
}

/// Result of extracting an archive.
#[derive(Debug)]
pub struct ExtractionResult {
    pub files: Vec<FinishedArtifact>,
    pub directories: usize,
    pub skipped: Vec<SkippedEntry>,
    pub total_bytes: u64,
    /// Set when a cap stopped the extraction before the archive was exhausted.
    pub truncated: bool,
}

impl ExtractionResult {
    /// Whether every entry in the archive was accounted for.
    pub fn complete(&self) -> bool {
        !self.truncated
    }
}

/// Why an archive entry may not be extracted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Absolute,
    ParentTraversal,
    ControlCharacter,
    Empty,
    ComponentTooLong,
    NotUnicode,
}

impl Refusal {
    fn reason(self) -> &'static str {
        match self {
            Self::Absolute => "entry path is absolute",
            Self::ParentTraversal => "entry path contains a parent-directory reference",
            Self::ControlCharacter => "entry path contains control characters",
            Self::Empty => "entry path is empty",
            Self::ComponentTooLong => "entry path component exceeds the maximum length",
            Self::NotUnicode => "entry path is not valid Unicode",
        }
    }
}

/// Validates an archive entry path for extraction.
///
/// Returns the relative path to use, or the reason it is refused. Nothing is
/// rewritten: a path is either safe to use exactly as declared, or refused.
fn validate_entry_path(raw: &Path) -> std::result::Result<PathBuf, Refusal> {
    use std::path::Component;

    let text = raw.to_str().ok_or(Refusal::NotUnicode)?;
    if text.is_empty() {
        return Err(Refusal::Empty);
    }
    if text.chars().any(char::is_control) {
        return Err(Refusal::ControlCharacter);
    }

    let mut out = PathBuf::new();
    let mut components = 0usize;
    for component in raw.components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_str().ok_or(Refusal::NotUnicode)?;
                if part.len() > MAX_COMPONENT_LEN {
                    return Err(Refusal::ComponentTooLong);
                }
                if part == ".." {
                    return Err(Refusal::ParentTraversal);
                }
                out.push(part);
                components += 1;
            }
            // `tar` stores `./x` routinely; a leading `.` is not an escape.
            Component::CurDir => {}
            Component::ParentDir => return Err(Refusal::ParentTraversal),
            Component::RootDir | Component::Prefix(_) => return Err(Refusal::Absolute),
        }
    }

    if components == 0 {
        return Err(Refusal::Empty);
    }
    Ok(out)
}

/// Extracts `source` into `working/<base_name>/`.
///
/// The source is opened read-only and is never modified.
pub fn extract_tar(
    store: &EvidenceStore,
    source: &Path,
    base_name: &str,
    options: ExtractionOptions,
    cancel: &CancellationToken,
    progress: &mut dyn ProgressSink,
) -> Result<ExtractionResult> {
    let metadata = std::fs::symlink_metadata(source).ctx("inspect", source)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Destination(format!(
            "`{}` is a symbolic link; refusing to follow it",
            source.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::InvalidData(format!(
            "`{}` is not a regular file",
            source.display()
        )));
    }

    // The archive's own size is a floor, not a bound: entries may expand well
    // past it. It is still the best pre-flight estimate available.
    store.ensure_space(metadata.len(), 10)?;
    let root = store.create_subdirectory(EvidenceClass::Working, Path::new(base_name))?;
    drop(root);

    let file = std::fs::File::open(source).ctx("open", source)?;
    let mut archive = tar::Archive::new(std::io::BufReader::with_capacity(1 << 20, file));
    // Ownership and permissions are not reapplied: this is a working copy for
    // analysis, and the authoritative metadata stays in the original archive.
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);

    let entries = archive.entries().map_err(|e| {
        Error::InvalidData(format!(
            "`{}` is not a readable tar archive: {e}",
            source.display()
        ))
    })?;

    let mut result = ExtractionResult {
        files: Vec::new(),
        directories: 0,
        skipped: Vec::new(),
        total_bytes: 0,
        truncated: false,
    };

    progress.start(Some(metadata.len()));
    let mut seen = 0usize;

    for entry in entries {
        cancel.check()?;
        let mut entry = entry.map_err(|e| {
            Error::InvalidData(format!(
                "`{}` contains a malformed entry: {e}",
                source.display()
            ))
        })?;

        seen += 1;
        if seen > options.max_entries {
            result.truncated = true;
            warn!(
                limit = options.max_entries,
                "extraction stopped at the entry limit"
            );
            break;
        }

        let declared = entry
            .path()
            .map_err(|e| Error::InvalidData(format!("an entry path could not be read: {e}")))?;
        let entry_name = crate::util::paths::sanitize_device_string(&declared.to_string_lossy());

        let relative = match validate_entry_path(&declared) {
            Ok(path) => path,
            Err(refusal) => {
                warn!(entry = %entry_name, reason = refusal.reason(), "refusing archive entry");
                result.skipped.push(SkippedEntry {
                    path: entry_name,
                    reason: refusal.reason().to_owned(),
                });
                continue;
            }
        };

        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            let inside = Path::new(base_name).join(&relative);
            match store.create_subdirectory(EvidenceClass::Working, &inside) {
                Ok(_) => result.directories += 1,
                Err(e) => result.skipped.push(SkippedEntry {
                    path: entry_name,
                    reason: format!("directory could not be created: {e}"),
                }),
            }
            continue;
        }

        if !entry_type.is_file() {
            result.skipped.push(SkippedEntry {
                path: entry_name,
                reason: format!(
                    "entry type `{}` is not extracted; links and device nodes are never created",
                    describe_entry_type(entry_type)
                ),
            });
            continue;
        }

        if result.total_bytes >= options.max_total_bytes {
            result.truncated = true;
            warn!(
                limit = options.max_total_bytes,
                "extraction stopped at the total size limit"
            );
            break;
        }

        let file_name = Path::new(base_name).join(&relative);
        let Some(file_name) = file_name.to_str() else {
            result.skipped.push(SkippedEntry {
                path: entry_name,
                reason: "destination path is not valid Unicode".to_owned(),
            });
            continue;
        };

        // The parent chain is created first; the store validates every segment.
        if let Some(parent) = Path::new(file_name).parent()
            && !parent.as_os_str().is_empty()
            && let Err(e) = store.create_subdirectory(EvidenceClass::Working, parent)
        {
            result.skipped.push(SkippedEntry {
                path: entry_name,
                reason: format!("parent directory could not be created: {e}"),
            });
            continue;
        }

        let mut writer = match store.create_artifact(
            EvidenceClass::Working,
            file_name,
            ArtifactRole::ExtractedFile,
            "file",
            options.with_sha512,
        ) {
            Ok(writer) => writer,
            Err(e) => {
                // A name legal on the device but rejected by this host lands
                // here. It is reported rather than renamed.
                result.skipped.push(SkippedEntry {
                    path: entry_name,
                    reason: format!("could not be created on this filesystem: {e}"),
                });
                continue;
            }
        };

        let mut buffer = vec![0u8; 256 * 1024];
        let mut written: u64 = 0;
        loop {
            cancel.check()?;
            let read = entry.read(&mut buffer).map_err(|e| {
                Error::InvalidData(format!(
                    "reading `{entry_name}` from the archive failed: {e}"
                ))
            })?;
            if read == 0 {
                break;
            }
            writer.write_chunk(buffer.get(..read).unwrap_or(&[]))?;
            written = written.saturating_add(read as u64);
            result.total_bytes = result.total_bytes.saturating_add(read as u64);
            progress.update(result.total_bytes);

            if result.total_bytes > options.max_total_bytes {
                result.truncated = true;
                break;
            }
        }

        let artifact = if result.truncated {
            writer.finish_incomplete("extraction stopped at the total size limit")?
        } else {
            writer.finish_complete()?
        };
        result.files.push(artifact);

        if result.truncated {
            break;
        }
        let _ = written;
    }

    progress.finish(result.total_bytes);
    Ok(result)
}

fn describe_entry_type(entry_type: tar::EntryType) -> &'static str {
    match entry_type {
        tar::EntryType::Symlink => "symbolic link",
        tar::EntryType::Link => "hard link",
        tar::EntryType::Char => "character device",
        tar::EntryType::Block => "block device",
        tar::EntryType::Fifo => "fifo",
        _ => "unsupported",
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
    use crate::acquisition::backend::NullProgress;

    fn store() -> (tempfile::TempDir, EvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        (dir, store)
    }

    /// Builds a tar archive in the case's `original/` directory.
    fn archive_with(
        store: &EvidenceStore,
        build: impl FnOnce(&mut tar::Builder<std::fs::File>),
    ) -> PathBuf {
        let path = store.root().join("original").join("EV-1.tar");
        let file = std::fs::File::create(&path).unwrap();
        let mut builder = tar::Builder::new(file);
        build(&mut builder);
        builder.finish().unwrap();
        path
    }

    /// Builds a raw USTAR header, bypassing any library-side path validation.
    ///
    /// `tar::Builder` refuses to *write* `..` or absolute paths, so a hostile
    /// archive cannot be produced through it. A real archive from a device is
    /// under no such constraint, so the headers are assembled by hand here —
    /// otherwise the extractor's refusal path would never be exercised.
    fn raw_header(name: &str, size: usize, type_flag: u8) -> Vec<u8> {
        fn put(header: &mut [u8], offset: usize, text: &str) {
            header[offset..offset + text.len()].copy_from_slice(text.as_bytes());
        }

        let mut header = vec![0u8; 512];
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() < 100, "test name too long for a v7 header");
        header[..name_bytes.len()].copy_from_slice(name_bytes);

        put(&mut header, 100, "0000644\0"); // mode
        put(&mut header, 108, "0000000\0"); // uid
        put(&mut header, 116, "0000000\0"); // gid
        put(&mut header, 124, &format!("{size:011o}\0")); // size
        put(&mut header, 136, "00000000000\0"); // mtime
        header[156] = type_flag;
        put(&mut header, 257, "ustar\0");
        put(&mut header, 263, "00");

        // The checksum is computed with its own field read as spaces.
        header[148..156].fill(b' ');
        let sum: u32 = header.iter().map(|b| u32::from(*b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        header
    }

    /// Writes a tar archive from raw entries, with arbitrary names.
    fn raw_archive(store: &EvidenceStore, entries: &[(&str, &[u8], u8)]) -> PathBuf {
        let mut bytes = Vec::new();
        for (name, content, type_flag) in entries {
            bytes.extend_from_slice(&raw_header(name, content.len(), *type_flag));
            bytes.extend_from_slice(content);
            let padding = (512 - (content.len() % 512)) % 512;
            bytes.extend(std::iter::repeat_n(0u8, padding));
        }
        // Two zero blocks terminate the archive.
        bytes.extend(std::iter::repeat_n(0u8, 1024));

        let path = store.root().join("original").join("EV-raw.tar");
        std::fs::write(&path, &bytes).unwrap();
        path
    }

    fn append_file(builder: &mut tar::Builder<std::fs::File>, name: &str, content: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, content).unwrap();
    }

    fn extract(store: &EvidenceStore, path: &Path) -> ExtractionResult {
        extract_tar(
            store,
            path,
            "extracted",
            ExtractionOptions::default(),
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap()
    }

    #[test]
    fn extracts_regular_files_and_records_each_one() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            append_file(builder, "DCIM/photo.jpg", b"image bytes");
            append_file(builder, "Download/notes.txt", b"text");
        });

        let result = extract(&store, &path);

        assert_eq!(result.files.len(), 2);
        assert!(result.skipped.is_empty(), "{:?}", result.skipped);
        assert_eq!(result.total_bytes, 15);
        assert!(result.complete());

        let paths: Vec<&str> = result
            .files
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert!(
            paths.contains(&"working/extracted/DCIM/photo.jpg"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"working/extracted/Download/notes.txt"),
            "{paths:?}"
        );

        // Every extracted file is a recorded artifact with a real digest.
        for artifact in &result.files {
            assert_eq!(artifact.role, ArtifactRole::ExtractedFile);
            assert_eq!(artifact.class, EvidenceClass::Working);
            assert_eq!(artifact.digests.sha256.len(), 64);
            assert!(artifact.complete);
            assert!(artifact.path.is_file());
        }

        let extracted = store.root().join("working/extracted/DCIM/photo.jpg");
        assert_eq!(std::fs::read(extracted).unwrap(), b"image bytes");
    }

    #[test]
    fn refuses_entries_that_escape_the_destination() {
        let (_guard, store) = store();
        let outside = store.root().parent().unwrap().join("escaped.txt");
        let sibling = store.root().join("original").join("escaped.txt");

        let path = raw_archive(
            &store,
            &[
                ("../escaped.txt", b"escaped", b'0'),
                ("../../escaped.txt", b"escaped", b'0'),
                ("a/../../escaped.txt", b"escaped", b'0'),
                ("safe.txt", b"safe", b'0'),
            ],
        );

        let result = extract(&store, &path);

        assert_eq!(result.files.len(), 1, "only the safe entry may be written");
        assert_eq!(result.files[0].relative_path, "working/extracted/safe.txt");
        assert_eq!(result.skipped.len(), 3, "{:?}", result.skipped);
        assert!(
            result
                .skipped
                .iter()
                .all(|s| s.reason.contains("parent-directory")),
            "{:?}",
            result.skipped
        );
        assert!(!outside.exists(), "an entry escaped the case directory");
        assert!(!sibling.exists(), "an entry escaped into another class");
    }

    #[test]
    fn refuses_absolute_entry_paths() {
        let (_guard, store) = store();
        let path = raw_archive(&store, &[("/tmp/nootextract-escape", b"payload", b'0')]);

        let result = extract(&store, &path);

        assert!(result.files.is_empty(), "{:?}", result.files);
        assert_eq!(result.skipped.len(), 1);
        assert!(
            result.skipped[0].reason.contains("absolute"),
            "{:?}",
            result.skipped
        );
        assert!(!Path::new("/tmp/nootextract-escape").exists());
    }

    #[test]
    fn refuses_entry_paths_containing_control_characters() {
        let (_guard, store) = store();
        let path = raw_archive(&store, &[("a\u{7}b.txt", b"payload", b'0')]);

        let result = extract(&store, &path);
        assert!(result.files.is_empty());
        assert_eq!(result.skipped.len(), 1);
        assert!(result.skipped[0].reason.contains("control characters"));
    }

    #[test]
    fn never_creates_links_or_device_nodes() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            append_file(builder, "real.txt", b"content");

            let mut link = tar::Header::new_gnu();
            link.set_size(0);
            link.set_entry_type(tar::EntryType::Symlink);
            link.set_mode(0o777);
            builder
                .append_link(&mut link, "evil-link", "/etc/passwd")
                .unwrap();

            let mut fifo = tar::Header::new_gnu();
            fifo.set_size(0);
            fifo.set_entry_type(tar::EntryType::Fifo);
            fifo.set_mode(0o644);
            fifo.set_cksum();
            builder.append_data(&mut fifo, "pipe", &[][..]).unwrap();
        });

        let result = extract(&store, &path);

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].relative_path, "working/extracted/real.txt");
        assert_eq!(result.skipped.len(), 2);
        assert!(
            result
                .skipped
                .iter()
                .any(|s| s.reason.contains("symbolic link"))
        );
        assert!(result.skipped.iter().any(|s| s.reason.contains("fifo")));

        let link_path = store.root().join("working/extracted/evil-link");
        assert!(
            !link_path.exists() && link_path.symlink_metadata().is_err(),
            "a link was created"
        );
    }

    #[test]
    fn creates_directories_declared_by_the_archive() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, "empty-dir/", &[][..])
                .unwrap();
        });

        let result = extract(&store, &path);
        assert_eq!(result.directories, 1);
        assert!(store.root().join("working/extracted/empty-dir").is_dir());
    }

    #[test]
    fn stops_at_the_entry_limit() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            for i in 0..20 {
                append_file(builder, &format!("file{i:03}.txt"), b"x");
            }
        });

        let result = extract_tar(
            &store,
            &path,
            "extracted",
            ExtractionOptions {
                max_entries: 5,
                ..ExtractionOptions::default()
            },
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();

        assert_eq!(
            result.files.len(),
            5,
            "exactly max_entries entries are processed"
        );
        assert!(result.truncated);
        assert!(!result.complete());
    }

    #[test]
    fn stops_at_the_total_size_limit() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            for i in 0..10 {
                append_file(builder, &format!("big{i}.bin"), &vec![0u8; 4096]);
            }
        });

        let result = extract_tar(
            &store,
            &path,
            "extracted",
            ExtractionOptions {
                max_total_bytes: 10_000,
                ..ExtractionOptions::default()
            },
            &CancellationToken::new(),
            &mut NullProgress,
        )
        .unwrap();

        assert!(result.truncated);
        assert!(result.total_bytes <= 10_000 + 4096);
        assert!(!result.complete());
    }

    #[test]
    fn leaves_the_source_archive_untouched() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            append_file(builder, "a.txt", b"content");
        });
        let before = std::fs::read(&path).unwrap();

        extract(&store, &path);

        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn cancellation_stops_extraction() {
        let (_guard, store) = store();
        let path = archive_with(&store, |builder| {
            append_file(builder, "a.txt", b"content");
        });
        let token = CancellationToken::new();
        token.cancel();

        let err = extract_tar(
            &store,
            &path,
            "extracted",
            ExtractionOptions::default(),
            &token,
            &mut NullProgress,
        )
        .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 130);
    }

    #[test]
    fn rejects_a_file_that_is_not_a_tar_archive() {
        let (_guard, store) = store();
        let path = store.root().join("original").join("not-a-tar.bin");
        std::fs::write(&path, vec![0xab; 4096]).unwrap();

        let result = extract_tar(
            &store,
            &path,
            "extracted",
            ExtractionOptions::default(),
            &CancellationToken::new(),
            &mut NullProgress,
        );
        // Either the archive fails to parse, or it yields no usable entry.
        match result {
            Err(e) => assert!(matches!(e, Error::InvalidData(_)), "{e:?}"),
            Ok(outcome) => assert!(outcome.files.is_empty()),
        }
    }

    #[test]
    fn validates_entry_paths() {
        assert!(validate_entry_path(Path::new("a/b/c.txt")).is_ok());
        assert!(validate_entry_path(Path::new("./a/b.txt")).is_ok());

        assert_eq!(
            validate_entry_path(Path::new("../x")),
            Err(Refusal::ParentTraversal)
        );
        assert_eq!(
            validate_entry_path(Path::new("a/../../x")),
            Err(Refusal::ParentTraversal)
        );
        assert_eq!(validate_entry_path(Path::new("")), Err(Refusal::Empty));
        assert_eq!(validate_entry_path(Path::new("./")), Err(Refusal::Empty));
        assert_eq!(
            validate_entry_path(Path::new("a\u{7}b")),
            Err(Refusal::ControlCharacter)
        );
        assert_eq!(
            validate_entry_path(Path::new(&"a".repeat(MAX_COMPONENT_LEN + 1))),
            Err(Refusal::ComponentTooLong)
        );

        #[cfg(unix)]
        assert_eq!(
            validate_entry_path(Path::new("/etc/passwd")),
            Err(Refusal::Absolute)
        );
    }

    #[test]
    fn every_refusal_has_a_reason() {
        for refusal in [
            Refusal::Absolute,
            Refusal::ParentTraversal,
            Refusal::ControlCharacter,
            Refusal::Empty,
            Refusal::ComponentTooLong,
            Refusal::NotUnicode,
        ] {
            assert!(!refusal.reason().is_empty());
        }
    }
}
