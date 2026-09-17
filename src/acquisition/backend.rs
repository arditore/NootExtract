//! The acquisition backend interface.
//!
//! A backend knows how to obtain bytes from a source. It does not decide where
//! they are stored, how they are named, how they are hashed or how they are
//! recorded: that belongs to [`crate::evidence`]. A new backend therefore only
//! implements [`AcquisitionBackend`] and is added to the registry in
//! [`crate::acquisition::registry`], with no change to evidence handling.
//!
//! Every backend must honour three rules:
//!
//! 1. Never attempt to defeat a protection mechanism. If the authorized path is
//!    unavailable, return [`crate::error::Error::Unsupported`] describing the
//!    limitation.
//! 2. Never report success after a partial transfer. Return the real status and
//!    let the caller record it.
//! 3. Never write outside the [`EvidenceStore`] it is given.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};

use crate::error::Result;
use crate::evidence::manifest::{AcquisitionStatus, CaseRecord, EventRecord, SourceRecord};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::util::cancel::CancellationToken;

/// Whether a backend produces a logical or a physical acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquisitionKind {
    /// A selection of files as presented by the device's filesystem layer.
    Logical,
    /// A bit-stream copy of a block device.
    Physical,
}

impl AcquisitionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logical => "logical",
            Self::Physical => "physical",
        }
    }
}

impl fmt::Display for AcquisitionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Static description of a backend, used by `--help` and by the manifest.
#[derive(Debug, Clone)]
pub struct BackendInfo {
    /// Stable identifier used by `--method`.
    pub id: &'static str,
    pub summary: &'static str,
    pub kind: AcquisitionKind,
    /// Container format of the artifact produced, for example `tar` or `raw`.
    pub output_format: &'static str,
    /// Requirements the operator must satisfy for this backend to work.
    pub requirements: &'static [&'static str],
    /// Host-platform caveats, stated rather than assumed away.
    pub platform_notes: &'static str,
}

/// Operator-selected acquisition parameters.
#[derive(Debug, Clone)]
pub struct AcquisitionOptions {
    /// Compute SHA-512 in addition to the mandatory SHA-256.
    pub with_sha512: bool,
    /// Backend-specific source scope (a directory or a block device path).
    pub source_path: Option<String>,
    /// Record source-side read errors and continue instead of failing.
    ///
    /// Off by default. When enabled the status becomes
    /// [`AcquisitionStatus::CompletedWithErrors`] and every reported error is
    /// listed in the manifest, so continuing is never silent.
    pub allow_source_read_errors: bool,
    /// Re-read the published artifact from disk and compare digests.
    pub post_write_verify: bool,
    /// Extra free space required beyond the estimated image size, in percent.
    pub space_headroom_percent: u64,
}

impl Default for AcquisitionOptions {
    fn default() -> Self {
        Self {
            with_sha512: false,
            source_path: None,
            allow_source_read_errors: false,
            post_write_verify: true,
            space_headroom_percent: 5,
        }
    }
}

/// Everything a backend needs for one acquisition.
#[derive(Debug)]
pub struct AcquisitionContext<'a> {
    pub device_id: String,
    pub case: CaseRecord,
    pub operation_id: String,
    pub started_at: DateTime<Utc>,
    pub store: &'a EvidenceStore,
    pub options: AcquisitionOptions,
    pub cancel: CancellationToken,
}

impl AcquisitionContext<'_> {
    /// Builds a safe artifact file name from the evidence ID and a suffix.
    ///
    /// The evidence ID is already validated, and `suffix` comes from the
    /// backend, never from the device.
    pub fn artifact_name(&self, suffix: &str, extension: &str) -> String {
        if suffix.is_empty() {
            format!("{}.{extension}", self.case.evidence_id)
        } else {
            format!("{}-{suffix}.{extension}", self.case.evidence_id)
        }
    }
}

/// Result of the pre-acquisition checks.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// Human-readable description recorded in the manifest.
    pub method_description: String,
    pub source: SourceRecord,
    /// Estimated artifact size, when the source could report one.
    pub estimated_size: Option<u64>,
    /// Conditions the operator should know about but that do not block the run.
    pub warnings: Vec<String>,
    /// Effective parameters, recorded for reproducibility.
    pub parameters: BTreeMap<String, String>,
}

/// Result of a completed (or failed) acquisition.
#[derive(Debug)]
pub struct AcquisitionOutcome {
    pub status: AcquisitionStatus,
    pub artifacts: Vec<FinishedArtifact>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub events: Vec<EventRecord>,
}

impl AcquisitionOutcome {
    pub fn new(status: AcquisitionStatus) -> Self {
        Self {
            status,
            artifacts: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            events: Vec::new(),
        }
    }
}

/// Progress sink for long transfers.
///
/// Implemented by the CLI for a progress bar and by tests for assertions, so
/// backends never depend on a terminal being present.
pub trait ProgressSink: Send {
    /// Called once before the first byte, with the expected size when known.
    fn start(&mut self, total_bytes: Option<u64>);
    /// Called with the cumulative byte count as data is written.
    fn update(&mut self, written_bytes: u64);
    /// Called once when the transfer stops, successfully or not.
    fn finish(&mut self, written_bytes: u64);
}

/// A [`ProgressSink`] that discards everything.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullProgress;

impl ProgressSink for NullProgress {
    fn start(&mut self, _total_bytes: Option<u64>) {}
    fn update(&mut self, _written_bytes: u64) {}
    fn finish(&mut self, _written_bytes: u64) {}
}

/// An acquisition method.
pub trait AcquisitionBackend: fmt::Debug + Send + Sync {
    fn info(&self) -> BackendInfo;

    /// Validates that the method can run and describes what it will do.
    ///
    /// Must not transfer evidence. Returning
    /// [`crate::error::Error::Unsupported`] here is the documented way to
    /// report a limitation.
    fn preflight(&self, context: &AcquisitionContext<'_>) -> Result<Preflight>;

    /// Performs the transfer.
    fn acquire(
        &self,
        context: &AcquisitionContext<'_>,
        preflight: &Preflight,
        progress: &mut dyn ProgressSink,
    ) -> Result<AcquisitionOutcome>;
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
    use crate::evidence::manifest::CaseRecord;

    fn context(store: &EvidenceStore) -> AcquisitionContext<'_> {
        AcquisitionContext {
            device_id: "ABC123".to_owned(),
            case: CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EVIDENCE-001".to_owned(),
                examiner: None,
                notes: None,
            },
            operation_id: "acq-test".to_owned(),
            started_at: Utc::now(),
            store,
            options: AcquisitionOptions::default(),
            cancel: CancellationToken::new(),
        }
    }

    #[test]
    fn artifact_names_are_built_from_validated_identifiers() {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        let context = context(&store);
        assert_eq!(
            context.artifact_name("logical", "tar"),
            "EVIDENCE-001-logical.tar"
        );
        assert_eq!(context.artifact_name("", "raw"), "EVIDENCE-001.raw");
    }

    #[test]
    fn defaults_favour_integrity_over_speed() {
        let options = AcquisitionOptions::default();
        assert!(
            options.post_write_verify,
            "published artifacts must be re-read by default"
        );
        assert!(
            !options.allow_source_read_errors,
            "source read errors must fail the run unless explicitly allowed"
        );
    }

    #[test]
    fn acquisition_kinds_are_labelled() {
        assert_eq!(AcquisitionKind::Logical.to_string(), "logical");
        assert_eq!(AcquisitionKind::Physical.to_string(), "physical");
    }
}
