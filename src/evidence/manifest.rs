//! Acquisition manifest: the machine-readable record of what was acquired.
//!
//! # Schema stability
//!
//! The document carries `manifest_version` as `MAJOR.MINOR`. Within a major
//! version, readers must ignore unknown fields and tolerate new optional ones;
//! a major bump signals an incompatible change. The full schema is documented
//! in `docs/MANIFEST_SCHEMA.md`.
//!
//! # Immutability
//!
//! Manifests are append-only records, never edited in place. A conversion or a
//! working-copy operation writes a *new* manifest that references the source
//! artifact, so the record of the original acquisition can never be rewritten
//! by a later derived operation.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::device::DeviceMetadata;
use crate::error::{Error, IoResultExt, Result};
use crate::hashing::DigestSet;

/// Schema version emitted by this build.
pub const MANIFEST_VERSION: &str = "1.0";
/// Major version this build can read.
const SUPPORTED_MAJOR: u32 = 1;
/// Minor version this build understands in full.
const SUPPORTED_MINOR: u32 = 0;

/// Fixed-precision RFC 3339 timestamp serialization.
///
/// Chrono's default rendering varies the number of fractional digits with the
/// value, so two manifests could describe the same instant with different text.
/// A forensic record should be byte-reproducible and textually sortable, so
/// every timestamp is emitted with nanosecond precision and a `Z` suffix.
/// Parsing accepts any valid RFC 3339 input, so manifests written by other
/// implementations still load.
pub mod rfc3339 {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Nanos, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let text = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&text)
            .map(|value| value.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }

    /// The same encoding for optional timestamps.
    pub mod option {
        use chrono::{DateTime, SecondsFormat, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(
            value: &Option<DateTime<Utc>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => {
                    serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Nanos, true))
                }
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            let text = Option::<String>::deserialize(deserializer)?;
            match text {
                Some(text) => DateTime::parse_from_rfc3339(&text)
                    .map(|value| Some(value.with_timezone(&Utc)))
                    .map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }
}

/// Evidence classification.
///
/// The distinction is structural, not cosmetic: `Original` artifacts are never
/// modified, never deleted by the tool, and never written twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceClass {
    /// Produced directly by an acquisition from the source device.
    Original,
    /// Produced from an original (or another derived) artifact by conversion.
    Derived,
    /// A copy intended for analysis, which may be consumed by other tools.
    Working,
}

impl EvidenceClass {
    pub fn directory(self) -> &'static str {
        match self {
            Self::Original => "original",
            Self::Derived => "derived",
            Self::Working => "working",
        }
    }

    /// Whether the tool must refuse to modify or replace artifacts of this class.
    pub fn is_write_protected(self) -> bool {
        matches!(self, Self::Original)
    }
}

impl fmt::Display for EvidenceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.directory())
    }
}

/// What an artifact represents inside its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRole {
    /// A bit-stream image of a block device.
    PhysicalImage,
    /// A logical collection of files captured as an archive.
    LogicalArchive,
    /// One segment of a segmented image set.
    ImageSegment,
    /// An image produced by converting another artifact.
    ConvertedImage,
    /// A verified copy intended for analysis.
    WorkingCopy,
    /// A single extracted file.
    ExtractedFile,
}

impl ArtifactRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PhysicalImage => "physical-image",
            Self::LogicalArchive => "logical-archive",
            Self::ImageSegment => "image-segment",
            Self::ConvertedImage => "converted-image",
            Self::WorkingCopy => "working-copy",
            Self::ExtractedFile => "extracted-file",
        }
    }
}

/// Terminal state of an acquisition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionStatus {
    /// Every byte the source offered was written and verified.
    Completed,
    /// The transfer finished, but the source reported recoverable read errors
    /// that the operator explicitly allowed. Every error is listed in `errors`.
    CompletedWithErrors,
    /// The transfer stopped before the source was exhausted. Whatever was
    /// written is preserved and marked incomplete.
    Failed,
    /// The operator interrupted the transfer. Partial data is preserved.
    Cancelled,
}

impl AcquisitionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::CompletedWithErrors => "completed-with-errors",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Whether the resulting artifact set may be treated as a complete image.
    pub fn is_complete(self) -> bool {
        matches!(self, Self::Completed | Self::CompletedWithErrors)
    }
}

impl fmt::Display for AcquisitionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Identification of the tool build that produced the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRecord {
    pub name: String,
    pub version: String,
    /// External programs used, with the version string they reported.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub external_tools: BTreeMap<String, String>,
}

impl Default for ToolRecord {
    fn default() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME").to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            external_tools: BTreeMap::new(),
        }
    }
}

/// Examination host description.
///
/// Deliberately coarse: enough to reproduce the environment, not enough to
/// identify the examiner's machine beyond what the case record already states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRecord {
    pub os: String,
    pub arch: String,
    pub family: String,
}

impl Default for HostRecord {
    fn default() -> Self {
        Self {
            os: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            family: std::env::consts::FAMILY.to_owned(),
        }
    }
}

/// Case and evidence identification supplied by the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseRecord {
    pub case_id: String,
    pub evidence_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examiner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Where the bytes came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    /// ADB serial, or the path of a source artifact for derived manifests.
    pub source_id: String,
    /// Scope on the device, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    /// Exact argument vector executed on the device, for reproducibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_command: Option<Vec<String>>,
    /// Size the source reported before the transfer, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reported_size_bytes: Option<u64>,
}

/// Record of one acquisition or conversion operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_id: String,
    /// Backend or converter identifier, for example `adb-logical-tar`.
    pub method: String,
    pub method_description: String,
    pub source: SourceRecord,
    #[serde(with = "rfc3339")]
    pub started_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "rfc3339::option"
    )]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    pub status: AcquisitionStatus,
    /// Backend parameters in effect, recorded so a run can be reproduced.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub parameters: BTreeMap<String, String>,
}

/// One file produced by the operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    /// Path relative to the case root, always with forward slashes.
    pub path: String,
    pub classification: EvidenceClass,
    pub role: ArtifactRole,
    /// Container format identifier, for example `raw`, `tar`, `raw-segmented`.
    pub format: String,
    pub size_bytes: u64,
    pub hashes: DigestSet,
    /// False when the transfer did not run to completion.
    pub complete: bool,
    #[serde(with = "rfc3339")]
    pub created_at: DateTime<Utc>,
    /// Path of the artifact this one was produced from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<String>,
    /// Position in a segmented set, starting at 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segment_index: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// A timestamped step in the operation's history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    #[serde(with = "rfc3339")]
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub result: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl EventRecord {
    pub fn new(event: impl Into<String>, result: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            event: event.into(),
            result: result.into(),
            detail: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// The manifest document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_version: String,
    pub manifest_id: String,
    #[serde(with = "rfc3339")]
    pub generated_at: DateTime<Utc>,
    pub tool: ToolRecord,
    pub host: HostRecord,
    pub case: CaseRecord,
    pub operation: OperationRecord,
    /// Device identification, absent for manifests describing conversions of a
    /// file that was acquired elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceMetadata>,
    pub artifacts: Vec<ArtifactRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<EventRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl Manifest {
    pub fn new(case: CaseRecord, operation: OperationRecord) -> Self {
        Self {
            manifest_version: MANIFEST_VERSION.to_owned(),
            manifest_id: operation.operation_id.clone(),
            generated_at: Utc::now(),
            tool: ToolRecord::default(),
            host: HostRecord::default(),
            case,
            operation,
            device: None,
            artifacts: Vec::new(),
            events: Vec::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn push_event(&mut self, event: EventRecord) {
        self.events.push(event);
    }

    /// Conventional file name for this manifest inside `manifests/`.
    pub fn file_name(&self) -> String {
        format!(
            "{}-{}.manifest.json",
            self.case.evidence_id, self.operation.operation_id
        )
    }

    /// Validates schema compatibility and internal consistency.
    ///
    /// Returns a list of non-fatal observations; incompatibilities are errors.
    pub fn validate(&self) -> Result<Vec<String>> {
        let mut notes = Vec::new();

        let (major, minor) = parse_version(&self.manifest_version)?;
        if major != SUPPORTED_MAJOR {
            return Err(Error::InvalidData(format!(
                "manifest schema major version {major} is not supported by this build \
                 (supports {SUPPORTED_MAJOR}.x)"
            )));
        }
        if minor > SUPPORTED_MINOR {
            notes.push(format!(
                "manifest declares schema {major}.{minor}; this build understands \
                 {SUPPORTED_MAJOR}.{SUPPORTED_MINOR} and ignored any newer fields"
            ));
        }

        if self.artifacts.is_empty() {
            notes.push("manifest lists no artifacts".to_owned());
        }
        for artifact in &self.artifacts {
            if artifact.path.starts_with('/') || artifact.path.contains("..") {
                return Err(Error::InvalidData(format!(
                    "artifact path `{}` is not a safe relative path",
                    artifact.path
                )));
            }
            if artifact.hashes.sha256.len() != 64
                || !artifact
                    .hashes
                    .sha256
                    .chars()
                    .all(|c| c.is_ascii_hexdigit())
            {
                return Err(Error::InvalidData(format!(
                    "artifact `{}` has a malformed SHA-256 digest",
                    artifact.path
                )));
            }
            if let Some(sha512) = &artifact.hashes.sha512
                && (sha512.len() != 128 || !sha512.chars().all(|c| c.is_ascii_hexdigit()))
            {
                return Err(Error::InvalidData(format!(
                    "artifact `{}` has a malformed SHA-512 digest",
                    artifact.path
                )));
            }
            if !artifact.complete && self.operation.status.is_complete() {
                notes.push(format!(
                    "artifact `{}` is marked incomplete although the operation status is `{}`",
                    artifact.path, self.operation.status
                ));
            }
        }

        if self.operation.status.is_complete() && self.operation.completed_at.is_none() {
            notes.push("operation is marked complete but has no completion time".to_owned());
        }

        Ok(notes)
    }

    /// Artifacts of a given classification.
    pub fn artifacts_of(&self, class: EvidenceClass) -> impl Iterator<Item = &ArtifactRecord> {
        self.artifacts
            .iter()
            .filter(move |artifact| artifact.classification == class)
    }

    /// Renders a `sha256sum`-compatible hash list for the artifacts.
    ///
    /// The format matches coreutils so third-party tooling can verify the
    /// evidence set without parsing the manifest.
    pub fn hash_list(&self) -> String {
        let mut out = String::new();
        for artifact in &self.artifacts {
            out.push_str(&artifact.hashes.sha256);
            out.push_str("  ");
            out.push_str(&artifact.path);
            out.push('\n');
        }
        out
    }

    /// Orders the event log chronologically.
    ///
    /// Events are appended by several layers as an operation unfolds, so the
    /// insertion order does not necessarily match the order in which things
    /// happened. A record that reads out of sequence is misleading, so the log
    /// is sorted by timestamp before it is written.
    pub fn sort_events(&mut self) {
        self.events.sort_by_key(|event| event.timestamp);
    }

    /// Writes the manifest atomically.
    ///
    /// The document is written to a uniquely named temporary file in the same
    /// directory, flushed and fsynced, then renamed over the target. A crash
    /// therefore leaves either no manifest or a complete one, never a truncated
    /// document that would misrepresent the evidence.
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| Error::Destination(format!("`{}` has no parent", path.display())))?;
        let temp = unique_temp_path(parent, path)?;

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .ctx("create", &temp)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, self)
            .map_err(|e| Error::InvalidData(format!("serializing manifest failed: {e}")))?;
        writer.write_all(b"\n").ctx("write", &temp)?;
        let file = writer
            .into_inner()
            .map_err(|e| Error::io("flush", &temp, e.into_error()))?;
        file.sync_all().ctx("sync", &temp)?;
        drop(file);

        std::fs::rename(&temp, path).map_err(|e| {
            // Leave the temporary file in place on failure rather than removing
            // data that may be the only copy of the record.
            Error::io("rename manifest into place at", path, e)
        })?;
        Ok(())
    }

    /// Reads and validates a manifest from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let file = File::open(path).ctx("open", path)?;
        let reader = BufReader::new(file);
        let manifest: Self = serde_json::from_reader(reader).map_err(|e| {
            Error::InvalidData(format!("`{}` is not a valid manifest: {e}", path.display()))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// RFC 3339 rendering of the generation time, for operator output.
    pub fn generated_at_rfc3339(&self) -> String {
        self.generated_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    }
}

fn parse_version(value: &str) -> Result<(u32, u32)> {
    let (major, minor) = value.split_once('.').ok_or_else(|| {
        Error::InvalidData(format!(
            "manifest_version `{value}` is not of the form MAJOR.MINOR"
        ))
    })?;
    let major = major.parse::<u32>().map_err(|_| {
        Error::InvalidData(format!(
            "manifest_version `{value}` has a non-numeric major"
        ))
    })?;
    let minor = minor.parse::<u32>().map_err(|_| {
        Error::InvalidData(format!(
            "manifest_version `{value}` has a non-numeric minor"
        ))
    })?;
    Ok((major, minor))
}

/// Builds a temporary path next to `target` that does not yet exist.
///
/// The name embeds the process id and a counter; `create_new` on the caller's
/// side turns any residual collision into an error rather than an overwrite.
fn unique_temp_path(parent: &Path, target: &Path) -> Result<PathBuf> {
    let stem = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Destination(format!("`{}` has no file name", target.display())))?;
    let pid = std::process::id();
    for attempt in 0..64u32 {
        let candidate = parent.join(format!(".{stem}.{pid}.{attempt}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(Error::Destination(format!(
        "could not allocate a temporary file next to `{}`",
        target.display()
    )))
}

/// Generates an operation identifier.
///
/// The value is reproducible from the recorded start time and sortable in
/// lexicographic order, which keeps a case directory readable over time.
pub fn operation_id(prefix: &str, started_at: DateTime<Utc>) -> String {
    format!("{prefix}-{}", started_at.format("%Y%m%dT%H%M%S%.3fZ"))
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

    fn sample_manifest() -> Manifest {
        let started = Utc::now();
        let case = CaseRecord {
            case_id: "CASE-001".to_owned(),
            evidence_id: "EVIDENCE-001".to_owned(),
            examiner: None,
            notes: None,
        };
        let operation = OperationRecord {
            operation_id: operation_id("acq", started),
            method: "adb-logical-tar".to_owned(),
            method_description: "Logical acquisition".to_owned(),
            source: SourceRecord {
                source_id: "ABC123".to_owned(),
                source_path: Some("/sdcard".to_owned()),
                remote_command: Some(vec!["tar".to_owned(), "-cf".to_owned()]),
                reported_size_bytes: None,
            },
            started_at: started,
            completed_at: Some(started),
            duration_ms: Some(0),
            status: AcquisitionStatus::Completed,
            parameters: BTreeMap::new(),
        };
        let mut manifest = Manifest::new(case, operation);
        manifest.artifacts.push(ArtifactRecord {
            path: "original/EVIDENCE-001.tar".to_owned(),
            classification: EvidenceClass::Original,
            role: ArtifactRole::LogicalArchive,
            format: "tar".to_owned(),
            size_bytes: 3,
            hashes: DigestSet {
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_owned(),
                sha512: None,
            },
            complete: true,
            created_at: started,
            derived_from: None,
            segment_index: None,
            notes: None,
        });
        manifest
    }

    #[test]
    fn timestamps_use_fixed_nanosecond_precision() {
        // Variable fractional digits would make otherwise identical records
        // differ textually and would break lexicographic ordering.
        let mut manifest = sample_manifest();
        manifest.generated_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .unwrap()
            .with_timezone(&Utc);
        manifest.operation.started_at = DateTime::parse_from_rfc3339("2026-01-02T03:04:05.5Z")
            .unwrap()
            .with_timezone(&Utc);

        let json = serde_json::to_value(&manifest).unwrap();
        assert_eq!(json["generated_at"], "2026-01-02T03:04:05.000000000Z");
        assert_eq!(
            json["operation"]["started_at"],
            "2026-01-02T03:04:05.500000000Z"
        );

        for rendered in [
            json["generated_at"].as_str().unwrap(),
            json["operation"]["started_at"].as_str().unwrap(),
            json["artifacts"][0]["created_at"].as_str().unwrap(),
        ] {
            assert_eq!(rendered.len(), "2026-01-02T03:04:05.000000000Z".len());
            assert!(rendered.ends_with('Z'), "{rendered}");
        }
    }

    #[test]
    fn timestamps_of_any_precision_can_still_be_read() {
        let mut json = serde_json::to_value(sample_manifest()).unwrap();
        json["generated_at"] = serde_json::json!("2026-01-02T03:04:05Z");
        json["operation"]["started_at"] = serde_json::json!("2026-01-02T04:04:05+01:00");
        let parsed: Manifest = serde_json::from_value(json).unwrap();
        // The offset form denotes the same instant as the UTC one.
        assert_eq!(parsed.generated_at, parsed.operation.started_at);
    }

    #[test]
    fn declares_the_current_schema_version() {
        assert_eq!(sample_manifest().manifest_version, "1.0");
    }

    #[test]
    fn round_trips_through_json() {
        let manifest = sample_manifest();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: Manifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn json_contains_the_required_fields() {
        let json = serde_json::to_value(sample_manifest()).unwrap();
        for key in [
            "manifest_version",
            "manifest_id",
            "generated_at",
            "tool",
            "host",
            "case",
            "operation",
            "artifacts",
        ] {
            assert!(json.get(key).is_some(), "missing `{key}`");
        }
        assert_eq!(json["case"]["case_id"], "CASE-001");
        assert_eq!(json["case"]["evidence_id"], "EVIDENCE-001");
        assert_eq!(json["operation"]["method"], "adb-logical-tar");
        assert_eq!(json["operation"]["status"], "completed");
        assert_eq!(json["artifacts"][0]["classification"], "original");
        assert_eq!(json["tool"]["name"], "nootextract");
    }

    #[test]
    fn validates_a_well_formed_manifest() {
        assert!(sample_manifest().validate().unwrap().is_empty());
    }

    #[test]
    fn rejects_an_incompatible_major_version() {
        let mut manifest = sample_manifest();
        manifest.manifest_version = "2.0".to_owned();
        let err = manifest.validate().unwrap_err();
        assert!(err.to_string().contains("not supported"), "{err}");
    }

    #[test]
    fn accepts_a_newer_minor_version_with_a_note() {
        let mut manifest = sample_manifest();
        manifest.manifest_version = "1.7".to_owned();
        let notes = manifest.validate().unwrap();
        assert!(notes.iter().any(|n| n.contains("1.7")), "{notes:?}");
    }

    #[test]
    fn rejects_a_malformed_version() {
        let mut manifest = sample_manifest();
        manifest.manifest_version = "one".to_owned();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn rejects_artifact_paths_that_escape_the_case_root() {
        for bad in ["../secret", "/etc/passwd", "original/../../x"] {
            let mut manifest = sample_manifest();
            manifest.artifacts[0].path = bad.to_owned();
            assert!(
                manifest.validate().is_err(),
                "`{bad}` must be rejected by validation"
            );
        }
    }

    #[test]
    fn rejects_malformed_digests() {
        let mut manifest = sample_manifest();
        manifest.artifacts[0].hashes.sha256 = "deadbeef".to_owned();
        assert!(manifest.validate().is_err());

        let mut manifest = sample_manifest();
        manifest.artifacts[0].hashes.sha256 = "z".repeat(64);
        assert!(manifest.validate().is_err());

        let mut manifest = sample_manifest();
        manifest.artifacts[0].hashes.sha512 = Some("abc".to_owned());
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn notes_inconsistent_completeness() {
        let mut manifest = sample_manifest();
        manifest.artifacts[0].complete = false;
        let notes = manifest.validate().unwrap();
        assert!(notes.iter().any(|n| n.contains("incomplete")), "{notes:?}");
    }

    #[test]
    fn unknown_fields_are_ignored_when_reading() {
        let mut json = serde_json::to_value(sample_manifest()).unwrap();
        json["a_field_from_the_future"] = serde_json::json!({"x": 1});
        let parsed: Manifest = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.case.case_id, "CASE-001");
    }

    #[test]
    fn writes_and_reloads_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = sample_manifest();
        let path = dir.path().join(manifest.file_name());
        manifest.write_to(&path).unwrap();

        let loaded = Manifest::load(&path).unwrap();
        assert_eq!(loaded, manifest);

        // No temporary files must remain behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn loading_a_corrupt_manifest_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken.manifest.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert!(matches!(err, Error::InvalidData(_)), "{err:?}");
    }

    #[test]
    fn loading_a_truncated_manifest_fails_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = sample_manifest();
        let path = dir.path().join("t.json");
        let full = serde_json::to_string(&manifest).unwrap();
        std::fs::write(&path, &full[..full.len() / 2]).unwrap();
        assert!(Manifest::load(&path).is_err());
    }

    #[test]
    fn hash_list_is_sha256sum_compatible() {
        let manifest = sample_manifest();
        let artifact = &manifest.artifacts[0];
        let expected = format!("{}  {}\n", artifact.hashes.sha256, artifact.path);
        assert_eq!(manifest.hash_list(), expected);
        // Two spaces between digest and path, exactly as coreutils emits.
        assert!(manifest.hash_list().contains("ad  original/"));
    }

    #[test]
    fn file_names_are_unique_per_operation() {
        let a = sample_manifest();
        let mut b = sample_manifest();
        b.operation.operation_id = "acq-other".to_owned();
        assert_ne!(a.file_name(), b.file_name());
        assert!(a.file_name().ends_with(".manifest.json"));
    }

    #[test]
    fn evidence_classes_map_to_directories() {
        assert_eq!(EvidenceClass::Original.directory(), "original");
        assert_eq!(EvidenceClass::Derived.directory(), "derived");
        assert_eq!(EvidenceClass::Working.directory(), "working");
        assert!(EvidenceClass::Original.is_write_protected());
        assert!(!EvidenceClass::Derived.is_write_protected());
        assert!(!EvidenceClass::Working.is_write_protected());
    }

    #[test]
    fn status_completeness_is_explicit() {
        assert!(AcquisitionStatus::Completed.is_complete());
        assert!(AcquisitionStatus::CompletedWithErrors.is_complete());
        assert!(!AcquisitionStatus::Failed.is_complete());
        assert!(!AcquisitionStatus::Cancelled.is_complete());
    }

    #[test]
    fn operation_ids_sort_chronologically() {
        let earlier = DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let later = DateTime::parse_from_rfc3339("2024-06-01T12:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(operation_id("acq", earlier) < operation_id("acq", later));
    }
}
