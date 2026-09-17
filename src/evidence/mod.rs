//! Evidence management: on-disk layout, manifests and verification.
//!
//! This layer knows nothing about Android or ADB. Acquisition backends hand it
//! bytes and metadata; it owns where those bytes land, how they are hashed and
//! how they are recorded. Keeping the boundary strict is what allows new
//! acquisition backends to be added without touching evidence handling.

pub mod manifest;
pub mod store;
pub mod verify;

pub use manifest::{
    AcquisitionStatus, ArtifactRecord, ArtifactRole, CaseRecord, EventRecord, EvidenceClass,
    MANIFEST_VERSION, Manifest, OperationRecord, SourceRecord, operation_id,
};
pub use store::{ArtifactWriter, EvidenceStore, FinishedArtifact, ManifestOutputs};
pub use verify::{VerificationOutcome, VerificationReport, VerifyOptions, verify_case};
