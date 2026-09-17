//! Shared plumbing for ADB-based backends.
//!
//! Streams a remote command's stdout into an evidence artifact, hashing as it
//! goes, and turns the process outcome into an explicit
//! [`AcquisitionStatus`]. The rules encoded here are the ones that must hold for
//! every ADB backend, so they live in one place rather than being restated:
//!
//! * A non-zero remote exit status is never treated as success.
//! * Data written before a failure is preserved and marked incomplete.
//! * A published artifact is re-read from disk and compared against the digest
//!   computed during the transfer, which catches corruption introduced between
//!   the write and the rename.

use std::sync::Arc;

use tracing::{info, warn};

use crate::acquisition::backend::{AcquisitionContext, ProgressSink};
use crate::adb::{AdbClient, RemoteCommand};
use crate::error::{Error, Result};
use crate::evidence::manifest::{AcquisitionStatus, ArtifactRole, EventRecord, EvidenceClass};
use crate::evidence::store::FinishedArtifact;
use crate::hashing::hash_file;
use crate::util::paths::sanitize_device_string;

/// Maximum number of remote stderr lines retained in the manifest.
const MAX_RECORDED_STDERR_LINES: usize = 200;

/// Outcome of streaming one remote command into one artifact.
#[derive(Debug)]
pub(crate) struct StreamResult {
    pub artifact: FinishedArtifact,
    pub status: AcquisitionStatus,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub events: Vec<EventRecord>,
}

/// Describes the artifact a stream will produce.
#[derive(Debug, Clone)]
pub(crate) struct ArtifactTarget<'a> {
    pub file_name: &'a str,
    pub role: ArtifactRole,
    pub format: &'a str,
}

/// Streams `command` from the device into a new original-evidence artifact.
pub(crate) fn stream_to_artifact(
    client: &Arc<AdbClient>,
    context: &AcquisitionContext<'_>,
    command: &RemoteCommand,
    target: &ArtifactTarget<'_>,
    estimated_size: Option<u64>,
    progress: &mut dyn ProgressSink,
) -> Result<StreamResult> {
    let mut writer = context.store.create_artifact(
        EvidenceClass::Original,
        target.file_name,
        target.role,
        target.format,
        context.options.with_sha512,
    )?;

    let mut events = vec![
        EventRecord::new("transfer-started", "ok")
            .with_detail(format!("writing to {}", writer.partial_path().display())),
    ];

    progress.start(estimated_size);

    // The closure borrows the writer mutably; the inner scope releases that
    // borrow before the writer is finalized below.
    let stream_outcome = {
        let writer = &mut writer;
        let progress = &mut *progress;
        let mut on_chunk = move |chunk: &[u8]| -> Result<()> {
            writer.write_chunk(chunk)?;
            progress.update(writer.bytes_written());
            Ok(())
        };
        client.stream_exec_out(&context.device_id, command, &context.cancel, &mut on_chunk)
    };

    let bytes_written = writer.bytes_written();
    progress.finish(bytes_written);

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let status = match &stream_outcome {
        Ok(outcome) => {
            let stderr_lines = collect_stderr_lines(&outcome.stderr_text());
            if outcome.stderr_truncated {
                warnings.push("device error output was truncated at the capture limit".to_owned());
            }

            if outcome.cancelled {
                errors.push("the transfer was interrupted by the operator".to_owned());
                errors.extend(stderr_lines);
                AcquisitionStatus::Cancelled
            } else if outcome.exit_code == Some(0) {
                warnings.extend(stderr_lines);
                AcquisitionStatus::Completed
            } else {
                let code = outcome
                    .exit_code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string());
                errors.push(format!(
                    "the remote command exited with status {code} after {bytes_written} bytes"
                ));
                errors.extend(stderr_lines);
                if context.options.allow_source_read_errors && bytes_written > 0 {
                    AcquisitionStatus::CompletedWithErrors
                } else {
                    AcquisitionStatus::Failed
                }
            }
        }
        Err(Error::Cancelled) => {
            errors.push("the transfer was interrupted by the operator".to_owned());
            AcquisitionStatus::Cancelled
        }
        Err(e) => {
            errors.push(format!("the transfer failed: {e}"));
            AcquisitionStatus::Failed
        }
    };

    if status.is_complete() && bytes_written == 0 {
        warnings.push(
            "the source produced no data; the acquisition scope may be empty or unreadable"
                .to_owned(),
        );
    }

    let artifact = if status.is_complete() {
        let artifact = writer.finish_complete()?;
        events.push(
            EventRecord::new("artifact-published", "ok")
                .with_detail(artifact.relative_path.clone()),
        );
        info!(
            device_id = %context.device_id,
            acquisition_id = %context.operation_id,
            artifact = %artifact.relative_path,
            bytes = artifact.size_bytes,
            "artifact published"
        );

        if context.options.post_write_verify {
            let verified = hash_file(
                &artifact.path,
                context.options.with_sha512,
                &context.cancel,
                &mut |_| {},
            )?;
            if verified.bytes != artifact.size_bytes || !verified.digests.matches(&artifact.digests)
            {
                return Err(Error::Integrity(format!(
                    "the published artifact `{}` does not match the digest computed during \
                     transfer; the written data is not trustworthy",
                    artifact.relative_path
                )));
            }
            events.push(EventRecord::new("post-write-verification", "match"));
        } else {
            warnings.push(
                "post-write verification was disabled; the artifact digest was not re-read \
                 from disk"
                    .to_owned(),
            );
        }
        artifact
    } else {
        let note = format!("incomplete transfer: acquisition status `{status}`");
        let artifact = writer.finish_incomplete(note)?;
        warn!(
            device_id = %context.device_id,
            acquisition_id = %context.operation_id,
            artifact = %artifact.relative_path,
            bytes = artifact.size_bytes,
            status = %status,
            "partial data preserved"
        );
        events.push(
            EventRecord::new("partial-data-preserved", status.as_str())
                .with_detail(artifact.relative_path.clone()),
        );
        artifact
    };

    // A relay error (for example a full destination disk) is surfaced only
    // after the partial artifact has been flushed, hashed and recorded.
    if let Err(e) = stream_outcome
        && !matches!(e, Error::Cancelled)
    {
        return Err(e);
    }

    Ok(StreamResult {
        artifact,
        status,
        errors,
        warnings,
        events,
    })
}

/// Normalizes device stderr into bounded, sanitized lines.
fn collect_stderr_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .lines()
        .map(sanitize_device_string)
        .filter(|line| !line.is_empty())
        .take(MAX_RECORDED_STDERR_LINES)
        .collect();
    if text.lines().count() > MAX_RECORDED_STDERR_LINES {
        lines.push(format!(
            "... device error output truncated after {MAX_RECORDED_STDERR_LINES} lines"
        ));
    }
    lines
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
    fn stderr_lines_are_sanitized_and_bounded() {
        let text = (0..(MAX_RECORDED_STDERR_LINES + 20))
            .map(|i| format!("tar: cannot read file {i}\u{1b}[0m"))
            .collect::<Vec<_>>()
            .join("\n");
        let lines = collect_stderr_lines(&text);
        assert_eq!(lines.len(), MAX_RECORDED_STDERR_LINES + 1);
        assert!(lines.last().unwrap().contains("truncated"));
        assert!(!lines[0].contains('\u{1b}'));
    }

    #[test]
    fn empty_stderr_yields_no_lines() {
        assert!(collect_stderr_lines("").is_empty());
        assert!(collect_stderr_lines("\n\n  \n").is_empty());
    }
}
