//! EWF (`.E01`) production by delegation to libewf.
//!
//! EWF is a documented but non-trivial container with its own compression,
//! chunk checksums and metadata sections. libewf is the mature, widely reviewed
//! implementation, and reimplementing it here would add risk without adding
//! capability. This module therefore drives libewf's `ewfacquire` as an
//! external process and treats its output as a derived artifact like any other:
//! hashed, manifested and verifiable.
//!
//! # Availability
//!
//! libewf is not bundled. When `ewfacquire` is absent the conversion reports a
//! missing-tool error with installation guidance and exits with the documented
//! code; it never silently produces something else.
//!
//! # Verification status
//!
//! The produced container is verified with `ewfverify` when that tool is
//! present, and the result is recorded in the manifest. See
//! `docs/IMAGE_FORMATS.md` for what has and has not been tested.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use tracing::info;

use crate::adb::runner::{CommandRunner, DEFAULT_OUTPUT_LIMIT};
use crate::error::{Error, Result};
use crate::evidence::manifest::{ArtifactRole, EvidenceClass};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::util::cancel::CancellationToken;
use crate::util::paths::sanitize_device_string;

/// libewf acquisition tool.
pub const DEFAULT_ACQUIRE_PROGRAM: &str = "ewfacquire";
/// libewf verification tool.
pub const DEFAULT_VERIFY_PROGRAM: &str = "ewfverify";

/// Format identifier passed to `ewfacquire -f`.
///
/// `encase6` is the EWF variant Autopsy and The Sleuth Kit read most reliably.
const EWF_FORMAT: &str = "encase6";

/// Metadata embedded in the EWF container.
#[derive(Debug, Clone)]
pub struct EwfParameters {
    pub case_id: String,
    pub evidence_id: String,
    pub description: String,
    pub examiner: Option<String>,
    pub notes: Option<String>,
    /// Segment size in bytes.
    pub segment_size: u64,
    /// `ewfacquire -c` compression argument, for example `deflate:none`.
    pub compression: String,
    /// `ewfacquire -m` media type.
    pub media_type: String,
    /// `ewfacquire -M` media flags.
    pub media_flags: String,
}

impl EwfParameters {
    pub fn new(case_id: &str, evidence_id: &str, description: &str, segment_size: u64) -> Self {
        Self {
            case_id: case_id.to_owned(),
            evidence_id: evidence_id.to_owned(),
            description: description.to_owned(),
            examiner: None,
            notes: None,
            segment_size,
            compression: "deflate:none".to_owned(),
            media_type: "fixed".to_owned(),
            media_flags: "physical".to_owned(),
        }
    }

    fn as_parameter_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("ewf_format".to_owned(), EWF_FORMAT.to_owned());
        map.insert("compression".to_owned(), self.compression.clone());
        map.insert(
            "segment_size_bytes".to_owned(),
            self.segment_size.to_string(),
        );
        map.insert("media_type".to_owned(), self.media_type.clone());
        map.insert("media_flags".to_owned(), self.media_flags.clone());
        map
    }
}

/// Result of running `ewfverify` over the produced container.
#[derive(Debug, Clone)]
pub struct EwfVerification {
    pub performed: bool,
    pub succeeded: bool,
    pub detail: String,
}

/// Result of an EWF conversion.
#[derive(Debug)]
pub struct EwfConversion {
    pub segments: Vec<FinishedArtifact>,
    pub tool_version: String,
    pub verification: EwfVerification,
    pub parameters: BTreeMap<String, String>,
    pub warnings: Vec<String>,
}

/// Driver for libewf's command-line tools.
#[derive(Debug, Clone)]
pub struct EwfConverter {
    acquire_program: String,
    verify_program: String,
    runner: Arc<dyn CommandRunner>,
}

impl EwfConverter {
    pub fn new(
        acquire_program: impl Into<String>,
        verify_program: impl Into<String>,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        Self {
            acquire_program: acquire_program.into(),
            verify_program: verify_program.into(),
            runner,
        }
    }

    /// Returns the `ewfacquire` version string, or a missing-tool error.
    pub fn version(&self) -> Result<String> {
        let output = self
            .runner
            .run(
                &self.acquire_program,
                &["-V".to_owned()],
                DEFAULT_OUTPUT_LIMIT,
            )
            .map_err(|e| match e {
                Error::MissingTool { tool, .. } => Error::MissingTool {
                    tool,
                    hint: "install libewf (Debian/Ubuntu: `apt install ewf-tools`, \
                           macOS: `brew install libewf`, Windows: libewf release binaries) \
                           or pass --ewfacquire-path"
                        .to_owned(),
                },
                other => other,
            })?;
        Ok(output
            .stdout_text()
            .lines()
            .next()
            .map(sanitize_device_string)
            .unwrap_or_default())
    }

    /// Whether libewf's acquisition tool is usable.
    pub fn is_available(&self) -> bool {
        self.version().is_ok()
    }

    /// Converts a raw image into an EWF container inside `derived/`.
    ///
    /// The source is passed to `ewfacquire` as a read-only input and is not
    /// modified. The target stem is reserved beforehand: if any file that
    /// `ewfacquire` would write already exists, the conversion fails instead of
    /// letting the external tool decide.
    pub fn convert(
        &self,
        store: &EvidenceStore,
        source: &Path,
        base_name: &str,
        parameters: &EwfParameters,
        with_sha512: bool,
        cancel: &CancellationToken,
    ) -> Result<EwfConversion> {
        // The destination is checked before the tool is probed, so an occupied
        // output is reported as such rather than as a missing dependency.
        let existing = store.list_class_files(EvidenceClass::Derived, &format!("{base_name}.E"))?;
        if !existing.is_empty() {
            return Err(Error::Destination(format!(
                "`derived/` already contains {} for base name `{base_name}`; choose a \
                 different --name or output directory",
                existing.join(", ")
            )));
        }

        let tool_version = self.version()?;
        cancel.check()?;

        let target_stem = store.path_for(EvidenceClass::Derived, base_name)?;
        let target_arg = target_stem.to_str().ok_or_else(|| {
            Error::Destination("the derived output path is not valid UTF-8".into())
        })?;
        let source_arg = source
            .to_str()
            .ok_or_else(|| Error::InvalidData("the source image path is not valid UTF-8".into()))?;

        let mut args = vec![
            // Unattended: never block waiting for terminal input.
            "-u".to_owned(),
            "-t".to_owned(),
            target_arg.to_owned(),
            "-f".to_owned(),
            EWF_FORMAT.to_owned(),
            "-c".to_owned(),
            parameters.compression.clone(),
            "-S".to_owned(),
            parameters.segment_size.to_string(),
            "-C".to_owned(),
            parameters.case_id.clone(),
            "-E".to_owned(),
            parameters.evidence_id.clone(),
            "-D".to_owned(),
            parameters.description.clone(),
            "-m".to_owned(),
            parameters.media_type.clone(),
            "-M".to_owned(),
            parameters.media_flags.clone(),
        ];
        if let Some(examiner) = &parameters.examiner {
            args.push("-e".to_owned());
            args.push(examiner.clone());
        }
        if let Some(notes) = &parameters.notes {
            args.push("-N".to_owned());
            args.push(notes.clone());
        }
        args.push(source_arg.to_owned());

        info!(
            program = %self.acquire_program,
            target = %target_stem.display(),
            "delegating EWF creation to libewf"
        );

        let output = self
            .runner
            .run(&self.acquire_program, &args, DEFAULT_OUTPUT_LIMIT)?;
        if !output.success() {
            return Err(Error::Acquisition(format!(
                "`{}` exited with {:?}: {}",
                self.acquire_program,
                output.exit_code,
                sanitize_device_string(&output.stderr_text())
            )));
        }

        let produced = store.list_class_files(EvidenceClass::Derived, &format!("{base_name}.E"))?;
        if produced.is_empty() {
            return Err(Error::Acquisition(format!(
                "`{}` reported success but produced no EWF segment for `{base_name}`",
                self.acquire_program
            )));
        }

        let mut segments = Vec::new();
        for (position, name) in produced.iter().enumerate() {
            cancel.check()?;
            let index = u32::try_from(position + 1).unwrap_or(u32::MAX);
            let artifact = store
                .adopt_artifact(
                    EvidenceClass::Derived,
                    name,
                    ArtifactRole::ConvertedImage,
                    "ewf",
                    with_sha512,
                    cancel,
                )?
                .with_segment_index(index);
            segments.push(artifact);
        }

        let verification = self.verify(&target_stem, &produced);
        let mut warnings = Vec::new();
        if !verification.performed {
            warnings.push(format!(
                "`{}` was not available, so the EWF container was not verified with libewf; \
                 run `ewfverify` manually before relying on it",
                self.verify_program
            ));
        }

        Ok(EwfConversion {
            segments,
            tool_version,
            verification,
            parameters: parameters.as_parameter_map(),
            warnings,
        })
    }

    /// Runs `ewfverify` against the produced container, if available.
    fn verify(&self, target_stem: &Path, produced: &[String]) -> EwfVerification {
        let first = produced.first().map(String::as_str).unwrap_or_default();
        let container = target_stem.with_file_name(first);
        let Some(container) = container.to_str() else {
            return EwfVerification {
                performed: false,
                succeeded: false,
                detail: "the container path is not valid UTF-8".to_owned(),
            };
        };

        match self.runner.run(
            &self.verify_program,
            &[container.to_owned()],
            DEFAULT_OUTPUT_LIMIT,
        ) {
            Ok(output) if output.success() => EwfVerification {
                performed: true,
                succeeded: true,
                detail: format!("`{}` reported success", self.verify_program),
            },
            Ok(output) => EwfVerification {
                performed: true,
                succeeded: false,
                detail: format!(
                    "`{}` exited with {:?}: {}",
                    self.verify_program,
                    output.exit_code,
                    sanitize_device_string(&output.stderr_text())
                ),
            },
            Err(e) => EwfVerification {
                performed: false,
                succeeded: false,
                detail: format!("`{}` could not be run: {e}", self.verify_program),
            },
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
    use crate::adb::runner::SystemRunner;

    #[test]
    fn missing_libewf_is_reported_as_a_missing_tool_with_guidance() {
        let converter = EwfConverter::new(
            "nootextract-absent-ewfacquire",
            "nootextract-absent-ewfverify",
            SystemRunner::shared(),
        );
        let err = converter.version().unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 8);
        let message = err.to_string();
        assert!(message.contains("libewf"), "{message}");
        assert!(message.contains("ewf-tools"), "{message}");
        assert!(!converter.is_available());
    }

    #[test]
    fn conversion_fails_cleanly_when_libewf_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        let source = store.root().join("original").join("image.raw");
        std::fs::write(&source, b"raw image").unwrap();

        let converter = EwfConverter::new(
            "nootextract-absent-ewfacquire",
            "nootextract-absent-ewfverify",
            SystemRunner::shared(),
        );
        let parameters = EwfParameters::new("CASE-001", "EV-1", "test image", 1 << 30);
        let err = converter
            .convert(
                &store,
                &source,
                "image",
                &parameters,
                false,
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert_eq!(err.exit_code().as_i32(), 8);
        // Nothing may have been written to derived/.
        assert!(
            store
                .list_class_files(EvidenceClass::Derived, "")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn refuses_to_overwrite_an_existing_ewf_set() {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        let source = store.root().join("original").join("image.raw");
        std::fs::write(&source, b"raw image").unwrap();
        std::fs::write(store.root().join("derived").join("image.E01"), b"existing").unwrap();

        // The destination check runs before tool discovery, so an absent libewf
        // must not mask the occupied-destination error.
        let converter = EwfConverter::new(
            "nootextract-absent-ewfacquire",
            "nootextract-absent-ewfverify",
            SystemRunner::shared(),
        );
        let parameters = EwfParameters::new("CASE-001", "EV-1", "test image", 1 << 30);
        let err = converter
            .convert(
                &store,
                &source,
                "image",
                &parameters,
                false,
                &CancellationToken::new(),
            )
            .unwrap_err();

        assert_eq!(err.exit_code().as_i32(), 6);
        assert_eq!(
            std::fs::read(store.root().join("derived").join("image.E01")).unwrap(),
            b"existing"
        );
    }

    #[test]
    fn parameters_are_recorded_for_the_manifest() {
        let parameters = EwfParameters::new("CASE-001", "EV-1", "Android userdata", 1 << 31);
        let map = parameters.as_parameter_map();
        assert_eq!(map.get("ewf_format").map(String::as_str), Some("encase6"));
        assert_eq!(
            map.get("segment_size_bytes").map(String::as_str),
            Some("2147483648")
        );
        assert_eq!(map.get("media_flags").map(String::as_str), Some("physical"));
    }
}
