//! Acquisition backends and their registry.
//!
//! Adding a method means implementing [`AcquisitionBackend`] and listing it in
//! [`available_backends`]. Nothing in [`crate::evidence`] changes, because
//! backends receive an [`crate::evidence::EvidenceStore`] and return
//! [`AcquisitionOutcome`] rather than deciding anything about layout, naming,
//! hashing or manifests themselves.

pub(crate) mod adb;
pub mod backend;
pub mod logical;
pub mod physical;

use std::sync::Arc;

pub use backend::{
    AcquisitionBackend, AcquisitionContext, AcquisitionKind, AcquisitionOptions,
    AcquisitionOutcome, BackendInfo, NullProgress, Preflight, ProgressSink,
};

use crate::adb::AdbClient;
use crate::error::{Error, Result};

/// Method used when `--method` is not given.
///
/// Logical acquisition is the default because it is the method available on an
/// ordinary, unmodified device with debugging authorized.
pub const DEFAULT_METHOD: &str = logical::METHOD_ID;

/// Every backend this build provides.
pub fn available_backends(client: Arc<AdbClient>) -> Vec<Box<dyn AcquisitionBackend>> {
    vec![
        Box::new(logical::LogicalTarBackend::new(client.clone())),
        Box::new(physical::PhysicalDdBackend::new(client)),
    ]
}

/// Static descriptions of every backend, without needing a client.
pub fn backend_catalog() -> Vec<BackendInfo> {
    let client = Arc::new(AdbClient::new(crate::adb::DEFAULT_ADB_PROGRAM));
    available_backends(client)
        .iter()
        .map(|backend| backend.info())
        .collect()
}

/// Resolves a `--method` value to a backend.
pub fn backend_by_id(id: &str, client: Arc<AdbClient>) -> Result<Box<dyn AcquisitionBackend>> {
    available_backends(client)
        .into_iter()
        .find(|backend| backend.info().id == id)
        .ok_or_else(|| {
            let known = backend_catalog()
                .iter()
                .map(|info| info.id)
                .collect::<Vec<_>>()
                .join(", ");
            Error::Usage(format!(
                "unknown acquisition method `{id}` (available methods: {known})"
            ))
        })
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
    fn default_method_resolves() {
        let client = Arc::new(AdbClient::new("adb"));
        let backend = backend_by_id(DEFAULT_METHOD, client).unwrap();
        assert_eq!(backend.info().id, DEFAULT_METHOD);
    }

    #[test]
    fn unknown_methods_are_a_usage_error_listing_the_alternatives() {
        let client = Arc::new(AdbClient::new("adb"));
        let err = backend_by_id("magic-bypass", client).unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 2);
        assert!(err.to_string().contains("adb-logical-tar"), "{err}");
    }

    #[test]
    fn catalog_entries_are_unique_and_described() {
        let catalog = backend_catalog();
        assert!(catalog.len() >= 2);
        let mut ids: Vec<_> = catalog.iter().map(|info| info.id).collect();
        ids.sort_unstable();
        let unique = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), unique, "backend identifiers must be unique");

        for info in &catalog {
            assert!(!info.summary.is_empty(), "{} has no summary", info.id);
            assert!(
                !info.requirements.is_empty(),
                "{} declares no requirements",
                info.id
            );
            assert!(
                !info.platform_notes.is_empty(),
                "{} has no platform notes",
                info.id
            );
        }
    }

    #[test]
    fn both_acquisition_kinds_are_represented() {
        let catalog = backend_catalog();
        assert!(catalog.iter().any(|i| i.kind == AcquisitionKind::Logical));
        assert!(catalog.iter().any(|i| i.kind == AcquisitionKind::Physical));
    }
}
