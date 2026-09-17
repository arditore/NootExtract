//! Logical acquisition over ADB.
//!
//! Captures a directory subtree as a single `tar` stream produced on the device
//! and written directly to an evidence artifact. A tar container is used rather
//! than `adb pull` because it preserves the tree in one hashable object, keeps
//! POSIX metadata (mode, ownership, timestamps) that a host-side copy would
//! lose, and avoids any host filesystem interpreting device-controlled file
//! names.
//!
//! # What this backend can and cannot see
//!
//! A logical acquisition reads through the device's filesystem layer as the ADB
//! shell user. It therefore captures what that user is allowed to read while the
//! device is unlocked, and nothing more. It does not read unallocated space, it
//! does not read areas protected by file-based encryption for other users, and
//! it does not recover deleted content. Those are properties of the method, not
//! defects to be worked around.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::acquisition::adb::{ArtifactTarget, stream_to_artifact};
use crate::acquisition::backend::{
    AcquisitionBackend, AcquisitionContext, AcquisitionKind, AcquisitionOutcome, BackendInfo,
    Preflight, ProgressSink,
};
use crate::adb::remote::validate_remote_path;
use crate::adb::{AdbClient, RemoteCommand};
use crate::error::{Error, Result};
use crate::evidence::manifest::{ArtifactRole, EventRecord, SourceRecord};

/// Default acquisition scope: shared external storage.
pub const DEFAULT_SOURCE_PATH: &str = "/sdcard";

/// Backend identifier used by `--method`.
pub const METHOD_ID: &str = "adb-logical-tar";

/// A completed transfer capturing less than this fraction of the estimated
/// scope is reported as suspect. The estimate is advisory, so the threshold is
/// deliberately loose: it is meant to catch a scope that was not read at all,
/// not to second-guess normal variance between `du` and a tar stream.
const SHORTFALL_FRACTION: u64 = 8;

const REQUIREMENTS: &[&str] = &[
    "USB debugging enabled and this host's ADB key authorized on the device",
    "the device unlocked, so file-based-encryption protected directories are readable",
    "a `tar` implementation on the device (present in Android's toybox since Android 6)",
];

/// Logical acquisition backend.
#[derive(Debug, Clone)]
pub struct LogicalTarBackend {
    client: Arc<AdbClient>,
}

impl LogicalTarBackend {
    pub fn new(client: Arc<AdbClient>) -> Self {
        Self { client }
    }

    /// Resolves and validates the acquisition scope.
    fn source_path(context: &AcquisitionContext<'_>) -> Result<String> {
        let requested = context
            .options
            .source_path
            .as_deref()
            .unwrap_or(DEFAULT_SOURCE_PATH);
        validate_remote_path(requested)
    }

    /// Best-effort size estimate, used for the free-space check and progress.
    ///
    /// `du` reports allocated size in 1 KiB blocks, which over-estimates the tar
    /// stream for sparse trees and under-estimates it for many small files
    /// because of per-entry headers. It is treated as advisory only.
    ///
    /// `-L` is required: without it `du` measures a symlink given on the command
    /// line rather than what it points at, and reports 0 for `/sdcard`.
    ///
    /// A zero result is returned as unknown rather than as a size. Zero would
    /// otherwise satisfy the free-space check trivially and be displayed as a
    /// fact, and for a scope that is genuinely empty there is nothing to
    /// estimate anyway.
    fn estimate_size(&self, device_id: &str, path: &str) -> Option<u64> {
        let command = RemoteCommand::new("du")
            .arg("-s")
            .arg("-k")
            .arg("-L")
            .arg(path);
        let output = self.client.exec_out(device_id, &command).ok()?;
        if !output.success() {
            return None;
        }
        let text = output.stdout_text();
        let first = text.lines().next()?;
        let kib = first.split_whitespace().next()?.parse::<u64>().ok()?;
        kib.checked_mul(1024).filter(|bytes| *bytes > 0)
    }
}

impl AcquisitionBackend for LogicalTarBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            id: METHOD_ID,
            summary: "Logical acquisition of a directory subtree as a tar stream over ADB",
            kind: AcquisitionKind::Logical,
            output_format: "tar",
            requirements: REQUIREMENTS,
            platform_notes: "Identical on Linux, macOS and Windows: all bytes are relayed \
                             through `adb exec-out`, which is binary-clean on every host.",
        }
    }

    fn preflight(&self, context: &AcquisitionContext<'_>) -> Result<Preflight> {
        let device = self.client.require_acquirable_device(&context.device_id)?;
        let requested = Self::source_path(context)?;
        let mut warnings = Vec::new();

        // `/sdcard` is a symlink on every modern Android build, and `tar` does
        // not follow a symlink named on its command line: archiving it directly
        // captures the link entry and nothing else, while still succeeding. The
        // scope is therefore resolved before anything is archived.
        let path = match self
            .client
            .resolve_remote_path(&context.device_id, &requested)?
        {
            Some(resolved) if resolved != requested => {
                warnings.push(format!(
                    "`{requested}` is a symbolic link to `{resolved}`; the acquisition follows \
                     it and archives the target, which is what the manifest records"
                ));
                resolved
            }
            _ => requested.clone(),
        };

        if !self
            .client
            .remote_tool_available(&context.device_id, "tar")?
        {
            return Err(Error::Unsupported(format!(
                "device `{}` does not provide a `tar` utility, so this backend cannot run. \
                 No alternative method is attempted automatically.",
                context.device_id
            )));
        }

        if !self.client.remote_path_exists(&context.device_id, &path)? {
            return Err(Error::Unsupported(format!(
                "`{path}` is not readable by the ADB shell on device `{}`. This is an \
                 access-control result and is reported rather than circumvented.",
                context.device_id
            )));
        }

        let metadata = self.client.metadata(&context.device_id)?;
        if metadata.reports_encrypted_userdata() {
            warnings.push(
                "the device reports encrypted userdata; a logical acquisition captures only \
                 what the ADB shell can read while the device is unlocked"
                    .to_owned(),
            );
        }
        if metadata.shell_uid.is_some_and(|uid| uid != 0) {
            warnings.push(format!(
                "the ADB shell runs as UID {}; directories readable only by other users or by \
                 root are outside the scope of this acquisition",
                metadata.shell_uid.unwrap_or_default()
            ));
        }
        warnings.push(format!(
            "scope is limited to `{path}`; unallocated space and deleted content are not \
             captured by a logical acquisition"
        ));

        let estimated_size = self.estimate_size(&context.device_id, &path);
        if estimated_size.is_none() {
            warnings.push(
                "the device could not report the size of the acquisition scope; the \
                 free-space check and progress reporting are indeterminate"
                    .to_owned(),
            );
        }

        let command = tar_command(&path);
        let mut parameters = BTreeMap::new();
        parameters.insert("requested_path".to_owned(), requested.clone());
        parameters.insert("source_path".to_owned(), path.clone());
        parameters.insert("container".to_owned(), "tar".to_owned());
        parameters.insert(
            "allow_source_read_errors".to_owned(),
            context.options.allow_source_read_errors.to_string(),
        );
        parameters.insert("device_state".to_owned(), device.state.label().to_owned());

        Ok(Preflight {
            method_description: format!(
                "Logical acquisition of `{path}` as a tar stream via `adb exec-out`"
            ),
            source: SourceRecord {
                source_id: context.device_id.clone(),
                source_path: Some(path),
                remote_command: Some(command.argv().to_vec()),
                reported_size_bytes: estimated_size,
            },
            estimated_size,
            warnings,
            parameters,
        })
    }

    fn acquire(
        &self,
        context: &AcquisitionContext<'_>,
        preflight: &Preflight,
        progress: &mut dyn ProgressSink,
    ) -> Result<AcquisitionOutcome> {
        let path =
            preflight.source.source_path.clone().ok_or_else(|| {
                Error::Acquisition("preflight did not resolve a source path".into())
            })?;

        let command = tar_command(&path);
        let file_name = context.artifact_name("logical", "tar");
        let target = ArtifactTarget {
            file_name: &file_name,
            role: ArtifactRole::LogicalArchive,
            format: "tar",
        };

        let result = stream_to_artifact(
            &self.client,
            context,
            &command,
            &target,
            preflight.estimated_size,
            progress,
        )?;

        let mut outcome = AcquisitionOutcome::new(result.status);
        outcome.events.push(
            EventRecord::new("logical-acquisition", result.status.as_str())
                .with_detail(format!("scope `{path}`")),
        );
        outcome.events.extend(result.events);
        outcome.errors = result.errors;
        outcome.warnings = result.warnings;

        // A transfer that exits cleanly having captured a small fraction of the
        // expected scope is the dangerous case: it looks like success. Rather
        // than trust the exit status alone, the written size is compared against
        // the estimate and a large shortfall is stated plainly.
        if let Some(expected) = preflight.estimated_size
            && result.status.is_complete()
        {
            let floor = expected.saturating_div(SHORTFALL_FRACTION);
            if result.artifact.size_bytes < floor {
                outcome.warnings.push(format!(
                    "the scope was estimated at {expected} bytes but only {} bytes were \
                     captured. Inspect the archive before relying on it: a clean exit does \
                     not by itself mean the scope was readable.",
                    result.artifact.size_bytes
                ));
            }
        }

        outcome.artifacts.push(result.artifact);
        Ok(outcome)
    }
}

/// Builds the remote `tar` invocation.
///
/// `-f -` writes the archive to stdout, which `adb exec-out` relays verbatim.
fn tar_command(path: &str) -> RemoteCommand {
    RemoteCommand::new("tar")
        .arg("-c")
        .arg("-f")
        .arg("-")
        .arg(path)
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

    #[test]
    fn builds_a_quoted_tar_command() {
        let command = tar_command("/sdcard/DCIM");
        assert_eq!(command.render(), "tar -c -f - /sdcard/DCIM");
        assert_eq!(
            command.argv(),
            ["tar", "-c", "-f", "-", "/sdcard/DCIM"].map(String::from)
        );
    }

    #[test]
    fn quotes_paths_containing_shell_metacharacters() {
        let command = tar_command("/sdcard/a b;id");
        assert_eq!(command.render(), "tar -c -f - '/sdcard/a b;id'");
    }

    #[test]
    fn default_scope_is_shared_storage() {
        assert_eq!(DEFAULT_SOURCE_PATH, "/sdcard");
        assert!(validate_remote_path(DEFAULT_SOURCE_PATH).is_ok());
    }

    #[test]
    fn backend_declares_its_requirements() {
        let client = Arc::new(AdbClient::new("adb"));
        let info = LogicalTarBackend::new(client).info();
        assert_eq!(info.id, METHOD_ID);
        assert_eq!(info.kind, AcquisitionKind::Logical);
        assert_eq!(info.output_format, "tar");
        assert!(!info.requirements.is_empty());
    }
}
