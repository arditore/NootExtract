//! Physical acquisition over ADB.
//!
//! Streams a block device from the handset with `dd` and writes it to a raw
//! image. This is a bit-stream copy of whatever the named block device exposes.
//!
//! # Authorization model
//!
//! Reading a raw block device requires an ADB shell that *already* runs as root
//! — typically an engineering or userdebug build, or a device whose owner has
//! made a root shell available. This backend checks that condition and stops
//! with a reported limitation when it is not met.
//!
//! It never tries to obtain that access: no `su` invocation, no `adb root`
//! restart of the daemon, no exploitation of any kind. If the shell is
//! unprivileged, the correct answer is that physical acquisition is unavailable
//! through this path, and that is what is reported.
//!
//! # Encryption
//!
//! On a device with file-based or metadata encryption, a raw image of
//! `userdata` contains ciphertext. This backend acquires and documents those
//! bytes; it does not decrypt them and provides no mechanism to do so.

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
use crate::util::paths::sanitize_filename_fragment;

/// Backend identifier used by `--method`.
pub const METHOD_ID: &str = "adb-physical-dd";

/// Block size used by the remote `dd`.
const BLOCK_SIZE: &str = "1M";

/// Conventional prefix for Android block devices.
const BLOCK_DEVICE_PREFIX: &str = "/dev/block/";

const REQUIREMENTS: &[&str] = &[
    "USB debugging enabled and this host's ADB key authorized on the device",
    "an ADB shell that already runs as UID 0; this backend never attempts to obtain privileges",
    "an explicit --source block device path, which is never guessed",
    "a `dd` utility on the device (present in Android's toybox)",
];

/// Physical acquisition backend.
#[derive(Debug, Clone)]
pub struct PhysicalDdBackend {
    client: Arc<AdbClient>,
}

impl PhysicalDdBackend {
    pub fn new(client: Arc<AdbClient>) -> Self {
        Self { client }
    }

    fn source_path(context: &AcquisitionContext<'_>) -> Result<String> {
        let requested = context.options.source_path.as_deref().ok_or_else(|| {
            Error::Usage(format!(
                "`{METHOD_ID}` requires --source with the block device to image, for example \
                 --source /dev/block/by-name/userdata. The partition is never guessed."
            ))
        })?;
        validate_remote_path(requested)
    }
}

impl AcquisitionBackend for PhysicalDdBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            id: METHOD_ID,
            summary: "Physical acquisition of a block device as a raw image over ADB",
            kind: AcquisitionKind::Physical,
            output_format: "raw",
            requirements: REQUIREMENTS,
            platform_notes: "Identical on Linux, macOS and Windows. Availability depends \
                             entirely on the device build, not on the examination host.",
        }
    }

    fn preflight(&self, context: &AcquisitionContext<'_>) -> Result<Preflight> {
        let device = self.client.require_acquirable_device(&context.device_id)?;
        let path = Self::source_path(context)?;
        let mut warnings = Vec::new();

        let uid = self.client.shell_uid(&context.device_id)?;
        if uid != 0 {
            return Err(Error::Unsupported(format!(
                "physical acquisition requires a root ADB shell, but the shell on device `{}` \
                 runs as UID {uid}. NootExtract does not attempt to obtain privileges it was \
                 not granted. Use a logical acquisition, or a device build that provides a \
                 root shell.",
                context.device_id
            )));
        }

        if !self
            .client
            .remote_tool_available(&context.device_id, "dd")?
        {
            return Err(Error::Unsupported(format!(
                "device `{}` does not provide a `dd` utility, so this backend cannot run.",
                context.device_id
            )));
        }

        if !self.client.remote_path_exists(&context.device_id, &path)? {
            return Err(Error::Unsupported(format!(
                "`{path}` does not exist or is not readable on device `{}`.",
                context.device_id
            )));
        }

        if !path.starts_with(BLOCK_DEVICE_PREFIX) {
            warnings.push(format!(
                "`{path}` is outside `{BLOCK_DEVICE_PREFIX}`; confirm it is the intended \
                 acquisition source"
            ));
        }

        let metadata = self.client.metadata(&context.device_id)?;
        if metadata.reports_encrypted_userdata() {
            warnings.push(
                "the device reports encrypted userdata; a raw image of an encrypted partition \
                 contains ciphertext, which this tool acquires but does not decrypt"
                    .to_owned(),
            );
        }

        let estimated_size = self.client.remote_block_size(&context.device_id, &path)?;
        if estimated_size.is_none() {
            warnings.push(
                "the size of the block device could not be determined; the free-space check \
                 and progress reporting are indeterminate"
                    .to_owned(),
            );
        }

        if context.options.allow_source_read_errors {
            warnings.push(
                "--allow-source-read-errors adds `conv=noerror,sync` to the remote dd: \
                 unreadable blocks are replaced with zeroes, so the image will differ from \
                 the source media at those offsets. Every occurrence is recorded."
                    .to_owned(),
            );
        }

        let command = dd_command(&path, context.options.allow_source_read_errors);
        let mut parameters = BTreeMap::new();
        parameters.insert("source_path".to_owned(), path.clone());
        parameters.insert("block_size".to_owned(), BLOCK_SIZE.to_owned());
        parameters.insert("shell_uid".to_owned(), uid.to_string());
        parameters.insert(
            "allow_source_read_errors".to_owned(),
            context.options.allow_source_read_errors.to_string(),
        );
        parameters.insert("device_state".to_owned(), device.state.label().to_owned());

        Ok(Preflight {
            method_description: format!(
                "Physical acquisition of block device `{path}` as a raw image via `adb exec-out dd`"
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

        let command = dd_command(&path, context.options.allow_source_read_errors);
        let suffix = partition_suffix(&path);
        let file_name = context.artifact_name(&suffix, "raw");
        let target = ArtifactTarget {
            file_name: &file_name,
            role: ArtifactRole::PhysicalImage,
            format: "raw",
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
            EventRecord::new("physical-acquisition", result.status.as_str())
                .with_detail(format!("source `{path}`")),
        );
        outcome.events.extend(result.events);
        outcome.errors = result.errors;
        outcome.warnings = result.warnings;

        // A short read against a known device size is a silent-truncation risk,
        // so it is promoted to an explicit inconsistency rather than a footnote.
        if let Some(expected) = preflight.estimated_size
            && result.status.is_complete()
            && result.artifact.size_bytes != expected
        {
            outcome.warnings.push(format!(
                "the device reported {expected} bytes but {} bytes were written; compare \
                 against the source before relying on this image",
                result.artifact.size_bytes
            ));
        }

        outcome.artifacts.push(result.artifact);
        Ok(outcome)
    }
}

/// Builds the remote `dd` invocation.
fn dd_command(path: &str, tolerate_read_errors: bool) -> RemoteCommand {
    let command = RemoteCommand::new("dd")
        .arg(format!("if={path}"))
        .arg(format!("bs={BLOCK_SIZE}"));
    if tolerate_read_errors {
        command.arg("conv=noerror,sync")
    } else {
        command
    }
}

/// Derives a file-name fragment from a block device path.
fn partition_suffix(path: &str) -> String {
    path.rsplit('/')
        .find(|segment| !segment.is_empty())
        .and_then(sanitize_filename_fragment)
        .unwrap_or_else(|| "physical".to_owned())
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
    fn builds_a_dd_command() {
        let command = dd_command("/dev/block/by-name/userdata", false);
        assert_eq!(command.render(), "dd if=/dev/block/by-name/userdata bs=1M");
    }

    #[test]
    fn adds_error_tolerance_only_when_requested() {
        let command = dd_command("/dev/block/sda", true);
        assert!(command.render().contains("conv=noerror,sync"));
        assert!(
            !dd_command("/dev/block/sda", false)
                .render()
                .contains("conv")
        );
    }

    #[test]
    fn quotes_hostile_source_paths() {
        let command = dd_command("/dev/block/x;reboot", false);
        assert_eq!(command.render(), "dd 'if=/dev/block/x;reboot' bs=1M");
    }

    #[test]
    fn derives_safe_file_name_suffixes() {
        assert_eq!(partition_suffix("/dev/block/by-name/userdata"), "userdata");
        assert_eq!(partition_suffix("/dev/block/mmcblk0"), "mmcblk0");
        assert_eq!(partition_suffix("/dev/block/"), "block");
        assert_eq!(partition_suffix("/"), "physical");
        // A name that sanitizes to nothing must still produce a usable suffix.
        assert_eq!(partition_suffix("/dev/block/***"), "physical");
    }

    #[test]
    fn backend_declares_that_it_never_escalates() {
        let client = Arc::new(AdbClient::new("adb"));
        let info = PhysicalDdBackend::new(client).info();
        assert_eq!(info.id, METHOD_ID);
        assert_eq!(info.kind, AcquisitionKind::Physical);
        assert_eq!(info.output_format, "raw");
        assert!(
            info.requirements
                .iter()
                .any(|r| r.contains("never attempts to obtain privileges"))
        );
    }
}
