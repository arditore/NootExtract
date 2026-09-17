//! Evidence verification.
//!
//! Verification recomputes digests from the files on disk and compares them
//! against every manifest in the case. Four outcomes are reported, matching the
//! documented contract:
//!
//! * `MATCH`    — the file exists and its digests equal the recorded ones.
//! * `MISMATCH` — the file exists but its content differs from the record.
//! * `MISSING`  — a manifest records the file but it is not on disk.
//! * `EXTRA`    — a file exists under `original/`, `derived/` or `working/`
//!   that no manifest accounts for.
//!
//! Files are opened read-only and hashed with the same streaming code used at
//! acquisition time, so verification never modifies the evidence it checks.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{IoResultExt, Result};
use crate::evidence::manifest::{EvidenceClass, Manifest};
use crate::evidence::store::EvidenceStore;
use crate::hashing::{DigestSet, hash_file};
use crate::util::cancel::CancellationToken;

/// Result for one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum VerificationOutcome {
    Match,
    Mismatch,
    Missing,
    Extra,
}

impl VerificationOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "MATCH",
            Self::Mismatch => "MISMATCH",
            Self::Missing => "MISSING",
            Self::Extra => "EXTRA",
        }
    }
}

impl fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verification result for a single artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileVerification {
    /// Case-relative path.
    pub path: String,
    pub outcome: VerificationOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification: Option<EvidenceClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<DigestSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<DigestSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregate verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub case_root: String,
    pub manifests_checked: Vec<String>,
    pub results: Vec<FileVerification>,
    pub counts: BTreeMap<String, usize>,
    /// Whether extra files were treated as a failure for this run.
    pub extra_files_are_failures: bool,
}

impl VerificationReport {
    pub fn count(&self, outcome: VerificationOutcome) -> usize {
        self.counts.get(outcome.as_str()).copied().unwrap_or(0)
    }

    /// Whether the evidence set passed.
    ///
    /// A mismatch or a missing artifact always fails. Unaccounted files fail by
    /// default, because a file in an evidence directory that no manifest
    /// describes is itself a chain-of-custody finding; `--ignore-extra`
    /// downgrades that to a reported observation.
    pub fn is_success(&self) -> bool {
        if self.count(VerificationOutcome::Mismatch) > 0
            || self.count(VerificationOutcome::Missing) > 0
        {
            return false;
        }
        !(self.extra_files_are_failures && self.count(VerificationOutcome::Extra) > 0)
    }
}

/// Verification options.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// Treat unaccounted files as observations rather than failures.
    pub ignore_extra: bool,
    /// Also recompute SHA-512 when the manifest recorded it.
    pub verify_sha512: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            ignore_extra: false,
            verify_sha512: true,
        }
    }
}

/// Verifies every artifact recorded by every manifest in the case.
pub fn verify_case(
    store: &EvidenceStore,
    options: VerifyOptions,
    cancel: &CancellationToken,
    progress: &mut dyn FnMut(&str, u64),
) -> Result<VerificationReport> {
    let manifests = store.load_manifests()?;
    verify_with_manifests(store, &manifests, options, cancel, progress)
}

/// Verifies against an explicit manifest list.
pub fn verify_with_manifests(
    store: &EvidenceStore,
    manifests: &[(PathBuf, Manifest)],
    options: VerifyOptions,
    cancel: &CancellationToken,
    progress: &mut dyn FnMut(&str, u64),
) -> Result<VerificationReport> {
    let mut results = Vec::new();
    let mut accounted: BTreeSet<String> = BTreeSet::new();

    for (_, manifest) in manifests {
        for artifact in &manifest.artifacts {
            cancel.check()?;
            // The same artifact may legitimately appear in several manifests
            // (for example an original referenced by a conversion record).
            if !accounted.insert(artifact.path.clone()) {
                continue;
            }

            let path = store
                .root()
                .join(artifact.path.replace('/', std::path::MAIN_SEPARATOR_STR));
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    results.push(FileVerification {
                        path: artifact.path.clone(),
                        outcome: VerificationOutcome::Missing,
                        classification: Some(artifact.classification),
                        expected: Some(artifact.hashes.clone()),
                        actual: None,
                        expected_size_bytes: Some(artifact.size_bytes),
                        actual_size_bytes: None,
                        detail: Some("recorded in a manifest but not present on disk".to_owned()),
                    });
                    continue;
                }
                Err(e) => return Err(crate::error::Error::io("inspect", &path, e)),
            };

            if metadata.file_type().is_symlink() {
                results.push(FileVerification {
                    path: artifact.path.clone(),
                    outcome: VerificationOutcome::Mismatch,
                    classification: Some(artifact.classification),
                    expected: Some(artifact.hashes.clone()),
                    actual: None,
                    expected_size_bytes: Some(artifact.size_bytes),
                    actual_size_bytes: None,
                    detail: Some(
                        "evidence path is a symbolic link; it was not followed".to_owned(),
                    ),
                });
                continue;
            }

            let want_sha512 = options.verify_sha512 && artifact.hashes.sha512.is_some();
            let relative = artifact.path.clone();
            let report = hash_file(&path, want_sha512, cancel, &mut |bytes| {
                progress(&relative, bytes);
            })?;

            let size_matches = report.bytes == artifact.size_bytes;
            let digest_matches = report.digests.matches(&artifact.hashes);
            let outcome = if size_matches && digest_matches {
                VerificationOutcome::Match
            } else {
                VerificationOutcome::Mismatch
            };
            let detail = if outcome == VerificationOutcome::Mismatch {
                Some(if size_matches {
                    "digest differs from the recorded value".to_owned()
                } else {
                    format!(
                        "size differs: recorded {} bytes, found {} bytes",
                        artifact.size_bytes, report.bytes
                    )
                })
            } else {
                None
            };

            results.push(FileVerification {
                path: artifact.path.clone(),
                outcome,
                classification: Some(artifact.classification),
                expected: Some(artifact.hashes.clone()),
                actual: Some(report.digests),
                expected_size_bytes: Some(artifact.size_bytes),
                actual_size_bytes: Some(report.bytes),
                detail,
            });
        }
    }

    for path in scan_evidence_files(store)? {
        cancel.check()?;
        if accounted.contains(&path) {
            continue;
        }
        results.push(FileVerification {
            path,
            outcome: VerificationOutcome::Extra,
            classification: None,
            expected: None,
            actual: None,
            expected_size_bytes: None,
            actual_size_bytes: None,
            detail: Some(
                "present in an evidence directory but not recorded in any manifest".to_owned(),
            ),
        });
    }

    results.sort_by(|a, b| a.path.cmp(&b.path));

    let mut counts = BTreeMap::new();
    for outcome in [
        VerificationOutcome::Match,
        VerificationOutcome::Mismatch,
        VerificationOutcome::Missing,
        VerificationOutcome::Extra,
    ] {
        counts.insert(outcome.as_str().to_owned(), 0);
    }
    for result in &results {
        *counts
            .entry(result.outcome.as_str().to_owned())
            .or_insert(0) += 1;
    }

    Ok(VerificationReport {
        case_root: store.root().display().to_string(),
        manifests_checked: manifests
            .iter()
            .filter_map(|(path, _)| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .map(ToOwned::to_owned)
            })
            .collect(),
        results,
        counts,
        extra_files_are_failures: !options.ignore_extra,
    })
}

/// Lists every regular file under the evidence class directories.
fn scan_evidence_files(store: &EvidenceStore) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for class in [
        EvidenceClass::Original,
        EvidenceClass::Derived,
        EvidenceClass::Working,
    ] {
        let dir = store.class_dir(class);
        if dir.is_dir() {
            collect_files(store.root(), &dir, &mut found)?;
        }
    }
    Ok(found)
}

fn collect_files(root: &Path, dir: &Path, found: &mut BTreeSet<String>) -> Result<()> {
    let entries = std::fs::read_dir(dir).ctx("read directory", dir)?;
    for entry in entries {
        let entry = entry.ctx("read directory entry in", dir)?;
        let path = entry.path();
        let metadata = entry.metadata().ctx("inspect", &path)?;
        if metadata.is_dir() {
            collect_files(root, &path, found)?;
        } else if let Ok(relative) = crate::util::paths::relative_slash_path(root, &path) {
            found.insert(relative);
        }
    }
    Ok(())
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
    use crate::evidence::manifest::{
        AcquisitionStatus, ArtifactRole, CaseRecord, Manifest, OperationRecord, SourceRecord,
        operation_id,
    };
    use chrono::Utc;

    struct Fixture {
        _guard: tempfile::TempDir,
        store: EvidenceStore,
    }

    /// Builds a case containing one complete original artifact and its manifest.
    fn fixture(content: &[u8]) -> Fixture {
        let guard = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&guard.path().join("CASE-001")).unwrap();

        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                false,
            )
            .unwrap();
        writer.write_chunk(content).unwrap();
        let artifact = writer.finish_complete().unwrap();

        let started = Utc::now();
        let mut manifest = Manifest::new(
            CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: None,
                notes: None,
            },
            OperationRecord {
                operation_id: operation_id("acq", started),
                method: "test".to_owned(),
                method_description: "test".to_owned(),
                source: SourceRecord {
                    source_id: "ABC".to_owned(),
                    source_path: None,
                    remote_command: None,
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(Utc::now()),
                duration_ms: Some(1),
                status: AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        manifest.artifacts.push(artifact.to_record());
        store.write_manifest(&manifest).unwrap();

        Fixture {
            _guard: guard,
            store,
        }
    }

    fn verify(fixture: &Fixture, options: VerifyOptions) -> VerificationReport {
        verify_case(
            &fixture.store,
            options,
            &CancellationToken::new(),
            &mut |_, _| {},
        )
        .unwrap()
    }

    #[test]
    fn reports_match_for_intact_evidence() {
        let fixture = fixture(b"forensic image content");
        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Match), 1);
        assert_eq!(report.count(VerificationOutcome::Mismatch), 0);
        assert_eq!(report.count(VerificationOutcome::Missing), 0);
        assert_eq!(report.count(VerificationOutcome::Extra), 0);
        assert!(report.is_success());
    }

    #[test]
    fn detects_a_modified_artifact() {
        let fixture = fixture(b"forensic image content");
        let path = fixture.store.root().join("original").join("EV-1.raw");
        // Same length, different content: only the digest can catch this.
        std::fs::write(&path, b"forensic image CONTENT").unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Mismatch), 1);
        assert!(!report.is_success());

        let result = &report.results[0];
        assert_eq!(result.outcome, VerificationOutcome::Mismatch);
        assert!(result.detail.as_deref().unwrap().contains("digest differs"));
    }

    #[test]
    fn detects_a_truncated_artifact() {
        let fixture = fixture(b"forensic image content");
        let path = fixture.store.root().join("original").join("EV-1.raw");
        std::fs::write(&path, b"forensic").unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Mismatch), 1);
        assert!(
            report.results[0]
                .detail
                .as_deref()
                .unwrap()
                .contains("size differs")
        );
        assert!(!report.is_success());
    }

    #[test]
    fn detects_a_missing_artifact() {
        let fixture = fixture(b"forensic image content");
        let path = fixture.store.root().join("original").join("EV-1.raw");
        std::fs::remove_file(&path).unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Missing), 1);
        assert!(!report.is_success());
    }

    #[test]
    fn detects_an_unaccounted_file() {
        let fixture = fixture(b"forensic image content");
        std::fs::write(
            fixture.store.root().join("original").join("stray.bin"),
            b"unaccounted",
        )
        .unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Extra), 1);
        assert_eq!(report.count(VerificationOutcome::Match), 1);
        assert!(!report.is_success());

        let extra = report
            .results
            .iter()
            .find(|r| r.outcome == VerificationOutcome::Extra)
            .unwrap();
        assert_eq!(extra.path, "original/stray.bin");
    }

    #[test]
    fn extra_files_can_be_downgraded_to_observations() {
        let fixture = fixture(b"forensic image content");
        std::fs::write(
            fixture
                .store
                .root()
                .join("working")
                .join("analysis-copy.raw"),
            b"copy",
        )
        .unwrap();

        let report = verify(
            &fixture,
            VerifyOptions {
                ignore_extra: true,
                verify_sha512: true,
            },
        );
        assert_eq!(report.count(VerificationOutcome::Extra), 1);
        assert!(report.is_success());
    }

    #[test]
    fn manifests_and_logs_are_not_reported_as_extra() {
        let fixture = fixture(b"forensic image content");
        std::fs::write(fixture.store.logs_dir().join("run.jsonl"), b"{}").unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert_eq!(report.count(VerificationOutcome::Extra), 0);
        assert!(report.is_success());
    }

    #[test]
    fn nested_files_are_scanned() {
        let fixture = fixture(b"forensic image content");
        let nested = fixture.store.root().join("derived").join("set-a");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("part.001"), b"x").unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        let extra = report
            .results
            .iter()
            .find(|r| r.outcome == VerificationOutcome::Extra)
            .unwrap();
        assert_eq!(extra.path, "derived/set-a/part.001");
    }

    #[test]
    fn verification_does_not_modify_the_evidence() {
        let fixture = fixture(b"forensic image content");
        let path = fixture.store.root().join("original").join("EV-1.raw");
        let before = std::fs::metadata(&path).unwrap();
        let before_content = std::fs::read(&path).unwrap();

        let report = verify(&fixture, VerifyOptions::default());
        assert!(report.is_success());

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before_content);
        assert_eq!(before.len(), after.len());
        if let (Ok(a), Ok(b)) = (before.modified(), after.modified()) {
            assert_eq!(a, b, "verification must not change the modification time");
        }
    }

    #[test]
    fn cancellation_aborts_verification() {
        let fixture = fixture(b"forensic image content");
        let token = CancellationToken::new();
        token.cancel();
        let err = verify_case(
            &fixture.store,
            VerifyOptions::default(),
            &token,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 130);
    }

    #[test]
    fn outcome_labels_match_the_documented_contract() {
        assert_eq!(VerificationOutcome::Match.to_string(), "MATCH");
        assert_eq!(VerificationOutcome::Mismatch.to_string(), "MISMATCH");
        assert_eq!(VerificationOutcome::Missing.to_string(), "MISSING");
        assert_eq!(VerificationOutcome::Extra.to_string(), "EXTRA");
    }
}
