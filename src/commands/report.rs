//! Case reporting.
//!
//! A manifest is written for a machine. An examiner attaching evidence to a case
//! file needs one document that says what was acquired, from what, when, by what
//! method, with which digests, and what the tool could not do. This renders that
//! from the manifests themselves, so the report cannot drift from the record.
//!
//! Markdown rather than HTML, deliberately: it is diffable, hashable, reviewable
//! in a pull request, and convertible to HTML or PDF by whatever the lab already
//! uses. It also cannot execute anything, which matters because much of its
//! content is device-controlled text.
//!
//! The report is derived, never authoritative. Nothing here is written into the
//! case directory unless the operator asks for it.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use crate::cli::ReportArgs;
use crate::commands::CommandContext;
use crate::error::{IoResultExt, Result};
use crate::evidence::manifest::{ArtifactRecord, EvidenceClass, Manifest};
use crate::evidence::store::EvidenceStore;
use crate::evidence::verify::{VerificationOutcome, VerifyOptions, verify_case};
use crate::output::print_line;
use crate::util::bytes::format_bytes;

/// Artifacts listed individually before the table is summarized instead.
///
/// An extraction can record tens of thousands of files; printing them all would
/// bury the acquisition record that the report exists to present.
const MAX_LISTED_ARTIFACTS: usize = 200;

/// `nootextract report <PATH>`
pub fn run(context: &CommandContext, args: &ReportArgs) -> Result<()> {
    let store = EvidenceStore::open(&args.path)?;
    let manifests = store.load_manifests()?;

    let verification = if args.verify {
        Some(verify_case(
            &store,
            VerifyOptions::default(),
            &context.cancel,
            &mut |_, _| {},
        )?)
    } else {
        None
    };

    let mut report = String::new();
    render(&mut report, &store, &manifests, verification.as_ref());

    if let Some(path) = args.output.as_deref() {
        std::fs::write(path, report.as_bytes()).ctx("write report to", path)?;
        print_line(
            context.mode,
            &format!("report written to {}", path.display()),
        );
    } else {
        print!("{report}");
    }

    // A report requested with --verify inherits verification's exit contract:
    // a document asserting integrity must not be produced quietly over a
    // mismatch.
    if let Some(report) = verification
        && !report.is_success()
    {
        return Err(crate::error::Error::Integrity(format!(
            "{} MISMATCH, {} MISSING, {} EXTRA; the report records the failure",
            report.count(VerificationOutcome::Mismatch),
            report.count(VerificationOutcome::Missing),
            report.count(VerificationOutcome::Extra),
        )));
    }
    Ok(())
}

fn render(
    out: &mut String,
    store: &EvidenceStore,
    manifests: &[(std::path::PathBuf, Manifest)],
    verification: Option<&crate::evidence::verify::VerificationReport>,
) {
    let case_ids: BTreeSet<&str> = manifests
        .iter()
        .map(|(_, m)| m.case.case_id.as_str())
        .collect();
    let title = case_ids.iter().copied().collect::<Vec<_>>().join(", ");

    let _ = writeln!(
        out,
        "# Evidence report{}\n",
        if title.is_empty() {
            String::new()
        } else {
            format!(" — {title}")
        }
    );

    let _ = writeln!(
        out,
        "Generated {} by {} {}.\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        crate::NAME,
        crate::VERSION
    );
    let _ = writeln!(out, "Case directory: `{}`\n", store.root().display());

    if manifests.is_empty() {
        let _ = writeln!(
            out,
            "This case contains no manifests. Nothing has been acquired into it.\n"
        );
        return;
    }

    render_summary(out, manifests, verification);
    render_operations(out, manifests);
    render_artifacts(out, manifests);
    render_findings(out, manifests);
    render_footer(out);
}

fn render_summary(
    out: &mut String,
    manifests: &[(std::path::PathBuf, Manifest)],
    verification: Option<&crate::evidence::verify::VerificationReport>,
) {
    let artifacts: Vec<&ArtifactRecord> = manifests
        .iter()
        .flat_map(|(_, m)| m.artifacts.iter())
        .collect();
    let total_bytes: u64 = artifacts.iter().map(|a| a.size_bytes).sum();
    let incomplete = artifacts.iter().filter(|a| !a.complete).count();

    let _ = writeln!(out, "## Summary\n");
    let _ = writeln!(out, "| Item | Value |");
    let _ = writeln!(out, "|---|---|");
    let _ = writeln!(out, "| Operations | {} |", manifests.len());
    let _ = writeln!(out, "| Artifacts | {} |", artifacts.len());
    let _ = writeln!(out, "| Total size | {} |", format_bytes(total_bytes));
    for class in [
        EvidenceClass::Original,
        EvidenceClass::Derived,
        EvidenceClass::Working,
    ] {
        let count = artifacts
            .iter()
            .filter(|a| a.classification == class)
            .count();
        let _ = writeln!(out, "| {class} artifacts | {count} |");
    }
    if incomplete > 0 {
        let _ = writeln!(out, "| **Incomplete artifacts** | **{incomplete}** |");
    }

    match verification {
        Some(report) => {
            let _ = writeln!(
                out,
                "| Verification | {} MATCH, {} MISMATCH, {} MISSING, {} EXTRA |",
                report.count(VerificationOutcome::Match),
                report.count(VerificationOutcome::Mismatch),
                report.count(VerificationOutcome::Missing),
                report.count(VerificationOutcome::Extra),
            );
            let _ = writeln!(
                out,
                "| Verification result | **{}** |",
                if report.is_success() {
                    "PASSED"
                } else {
                    "FAILED"
                }
            );
        }
        None => {
            let _ = writeln!(
                out,
                "| Verification | not performed for this report (`--verify` re-reads every artifact) |"
            );
        }
    }
    let _ = writeln!(out);
}

fn render_operations(out: &mut String, manifests: &[(std::path::PathBuf, Manifest)]) {
    let _ = writeln!(out, "## Operations\n");

    for (path, manifest) in manifests {
        let operation = &manifest.operation;
        let _ = writeln!(
            out,
            "### {} — {}\n",
            operation.operation_id, operation.method
        );
        let _ = writeln!(out, "{}\n", operation.method_description);

        let _ = writeln!(out, "| Field | Value |");
        let _ = writeln!(out, "|---|---|");
        let _ = writeln!(out, "| Manifest | `{}` |", file_name(path));
        let _ = writeln!(out, "| Schema | {} |", manifest.manifest_version);
        let _ = writeln!(out, "| Case | {} |", manifest.case.case_id);
        let _ = writeln!(out, "| Evidence | {} |", manifest.case.evidence_id);
        if let Some(examiner) = &manifest.case.examiner {
            let _ = writeln!(out, "| Examiner | {examiner} |");
        }
        if let Some(notes) = &manifest.case.notes {
            let _ = writeln!(out, "| Notes | {notes} |");
        }
        let _ = writeln!(out, "| Status | **{}** |", operation.status);
        let _ = writeln!(out, "| Started | {} |", operation.started_at.to_rfc3339());
        if let Some(completed) = operation.completed_at {
            let _ = writeln!(out, "| Completed | {} |", completed.to_rfc3339());
        }
        if let Some(duration) = operation.duration_ms {
            let _ = writeln!(out, "| Duration | {duration} ms |");
        }
        let _ = writeln!(out, "| Source | `{}` |", operation.source.source_id);
        if let Some(source_path) = &operation.source.source_path {
            let _ = writeln!(out, "| Scope | `{source_path}` |");
        }
        if let Some(command) = &operation.source.remote_command {
            let _ = writeln!(out, "| Device command | `{}` |", command.join(" "));
        }
        let _ = writeln!(
            out,
            "| Tool | {} {} on {}/{} |",
            manifest.tool.name, manifest.tool.version, manifest.host.os, manifest.host.arch
        );
        for (tool, version) in &manifest.tool.external_tools {
            let _ = writeln!(out, "| External tool | `{tool}` — {version} |");
        }
        let _ = writeln!(out);

        if let Some(device) = &manifest.device {
            let _ = writeln!(out, "**Device**\n");
            let _ = writeln!(out, "| Property | Value |");
            let _ = writeln!(out, "|---|---|");
            let _ = writeln!(out, "| Serial | {} |", device.serial);
            for (label, value) in [
                ("Manufacturer", &device.manufacturer),
                ("Model", &device.model),
                ("Android release", &device.android_release),
                ("Android SDK", &device.android_sdk),
                ("Security patch", &device.security_patch),
                ("Build ID", &device.build_id),
                ("Build fingerprint", &device.build_fingerprint),
                ("Build type", &device.build_type),
                ("Userdata encryption", &device.crypto_state),
            ] {
                if let Some(value) = value {
                    let _ = writeln!(out, "| {label} | {value} |");
                }
            }
            if let Some(uid) = device.shell_uid {
                let _ = writeln!(out, "| ADB shell UID | {uid} |");
            }
            let _ = writeln!(out);
        }

        if !operation.parameters.is_empty() {
            let _ = writeln!(out, "**Parameters**\n");
            for (key, value) in &operation.parameters {
                let _ = writeln!(out, "- `{key}` = `{value}`");
            }
            let _ = writeln!(out);
        }
    }
}

fn render_artifacts(out: &mut String, manifests: &[(std::path::PathBuf, Manifest)]) {
    let artifacts: Vec<&ArtifactRecord> = manifests
        .iter()
        .flat_map(|(_, m)| m.artifacts.iter())
        .collect();

    let _ = writeln!(out, "## Artifacts\n");
    if artifacts.is_empty() {
        let _ = writeln!(out, "No artifact is recorded.\n");
        return;
    }

    if artifacts.len() > MAX_LISTED_ARTIFACTS {
        let _ = writeln!(
            out,
            "{} artifacts are recorded, which is more than this report lists \
             individually. The full set, with every digest, is in the manifests and the \
             `hashes/` side files.\n",
            artifacts.len()
        );
        let _ = writeln!(out, "| Classification | Count | Size |");
        let _ = writeln!(out, "|---|---|---|");
        for class in [
            EvidenceClass::Original,
            EvidenceClass::Derived,
            EvidenceClass::Working,
        ] {
            let of_class: Vec<_> = artifacts
                .iter()
                .filter(|a| a.classification == class)
                .collect();
            if !of_class.is_empty() {
                let bytes: u64 = of_class.iter().map(|a| a.size_bytes).sum();
                let _ = writeln!(
                    out,
                    "| {class} | {} | {} |",
                    of_class.len(),
                    format_bytes(bytes)
                );
            }
        }
        let _ = writeln!(out);
        return;
    }

    let _ = writeln!(out, "| Path | Class | Role | Size | State | SHA-256 |");
    let _ = writeln!(out, "|---|---|---|---|---|---|");
    for artifact in &artifacts {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} | `{}` |",
            artifact.path,
            artifact.classification,
            artifact.role.as_str(),
            format_bytes(artifact.size_bytes),
            if artifact.complete {
                "complete"
            } else {
                "**INCOMPLETE**"
            },
            artifact.hashes.sha256
        );
    }
    let _ = writeln!(out);

    if artifacts.iter().any(|a| a.hashes.sha512.is_some()) {
        let _ = writeln!(out, "**SHA-512**\n");
        for artifact in &artifacts {
            if let Some(sha512) = &artifact.hashes.sha512 {
                let _ = writeln!(out, "- `{}`: `{sha512}`", artifact.path);
            }
        }
        let _ = writeln!(out);
    }
}

/// Renders errors and warnings, which is the part an examiner must read.
fn render_findings(out: &mut String, manifests: &[(std::path::PathBuf, Manifest)]) {
    let errors: Vec<(&str, &String)> = manifests
        .iter()
        .flat_map(|(_, m)| {
            m.errors
                .iter()
                .map(move |e| (m.operation.operation_id.as_str(), e))
        })
        .collect();
    let warnings: Vec<(&str, &String)> = manifests
        .iter()
        .flat_map(|(_, m)| {
            m.warnings
                .iter()
                .map(move |w| (m.operation.operation_id.as_str(), w))
        })
        .collect();

    let _ = writeln!(out, "## Findings\n");

    if errors.is_empty() && warnings.is_empty() {
        let _ = writeln!(out, "No error or warning was recorded.\n");
        return;
    }

    if !errors.is_empty() {
        let _ = writeln!(out, "### Errors\n");
        for (operation, error) in &errors {
            let _ = writeln!(out, "- **{operation}**: {error}");
        }
        let _ = writeln!(out);
    }

    if !warnings.is_empty() {
        let _ = writeln!(out, "### Warnings\n");
        for (operation, warning) in &warnings {
            let _ = writeln!(out, "- *{operation}*: {warning}");
        }
        let _ = writeln!(out);
    }
}

fn render_footer(out: &mut String) {
    let _ = writeln!(out, "## Scope of this report\n");
    let _ = writeln!(
        out,
        "This document is rendered from the manifests in the case directory and is \
         derived, not authoritative: the manifests and the artifacts they describe are \
         the record. It states what the tool did and what it recorded, and makes no claim \
         about the completeness or admissibility of the evidence, which depend on \
         authorization, procedure and jurisdiction.\n"
    );
    let _ = writeln!(
        out,
        "Digests shown here were recorded when each artifact was written. Re-reading them \
         from disk is a separate operation: run `nootextract verify <case>`, or regenerate \
         this report with `--verify`.\n"
    );
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("(unnamed)")
        .to_owned()
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::default_trait_access
    )]
    use super::*;
    use crate::evidence::manifest::{
        AcquisitionStatus, ArtifactRole, CaseRecord, Manifest, OperationRecord, SourceRecord,
        operation_id,
    };
    use crate::hashing::DigestSet;
    use chrono::Utc;

    fn case_with_artifact(root: &Path) -> EvidenceStore {
        let store = EvidenceStore::create(root).unwrap();
        let mut writer = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.tar",
                ArtifactRole::LogicalArchive,
                "tar",
                false,
            )
            .unwrap();
        writer.write_chunk(b"evidence").unwrap();
        let artifact = writer.finish_complete().unwrap();

        let started = Utc::now();
        let mut manifest = Manifest::new(
            CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: Some("A. Examiner".to_owned()),
                notes: None,
            },
            OperationRecord {
                operation_id: operation_id("acq", started),
                method: "adb-logical-tar".to_owned(),
                method_description: "Logical acquisition".to_owned(),
                source: SourceRecord {
                    source_id: "SERIAL123".to_owned(),
                    source_path: Some("/storage/emulated/0".to_owned()),
                    remote_command: Some(vec!["tar".to_owned(), "-c".to_owned()]),
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(Utc::now()),
                duration_ms: Some(12),
                status: AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        manifest.artifacts.push(artifact.to_record());
        manifest
            .warnings
            .push("the device reports encrypted userdata".to_owned());
        store.write_manifest(&manifest).unwrap();
        store
    }

    fn render_case(store: &EvidenceStore) -> String {
        let manifests = store.load_manifests().unwrap();
        let mut out = String::new();
        render(&mut out, store, &manifests, None);
        out
    }

    #[test]
    fn reports_the_acquisition_record() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"));
        let report = render_case(&store);

        assert!(report.starts_with("# Evidence report — CASE-001"));
        assert!(report.contains("adb-logical-tar"));
        assert!(report.contains("SERIAL123"));
        assert!(report.contains("/storage/emulated/0"));
        assert!(report.contains("A. Examiner"));
        assert!(report.contains("original/EV-1.tar"));
        assert!(report.contains("completed"));
    }

    #[test]
    fn the_recorded_digest_appears_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"));
        let manifests = store.load_manifests().unwrap();
        let digest = manifests[0].1.artifacts[0].hashes.sha256.clone();

        assert!(render_case(&store).contains(&digest));
    }

    #[test]
    fn warnings_are_surfaced_not_buried() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"));
        let report = render_case(&store);
        assert!(report.contains("## Findings"));
        assert!(report.contains("encrypted userdata"));
    }

    #[test]
    fn an_unverified_report_says_so_rather_than_implying_integrity() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"));
        let report = render_case(&store);
        assert!(report.contains("not performed for this report"));
        assert!(report.contains("nootextract verify"));
    }

    #[test]
    fn the_report_disclaims_authority() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"));
        let report = render_case(&store);
        assert!(report.contains("derived, not authoritative"));
        assert!(report.contains("makes no claim"));
    }

    #[test]
    fn an_empty_case_reports_that_nothing_was_acquired() {
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-EMPTY")).unwrap();
        let report = render_case(&store);
        assert!(report.contains("no manifests"));
        assert!(!report.contains("## Artifacts"));
    }

    #[test]
    fn an_incomplete_artifact_is_marked_prominently() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("CASE-001");
        let store = EvidenceStore::create(&root).unwrap();

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
                method: "adb-logical-tar".to_owned(),
                method_description: "Interrupted".to_owned(),
                source: SourceRecord {
                    source_id: "S".to_owned(),
                    source_path: None,
                    remote_command: None,
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(Utc::now()),
                duration_ms: Some(1),
                status: AcquisitionStatus::Failed,
                parameters: Default::default(),
            },
        );
        manifest.artifacts.push(ArtifactRecord {
            path: "original/EV-1.tar.partial".to_owned(),
            classification: EvidenceClass::Original,
            role: ArtifactRole::LogicalArchive,
            format: "tar".to_owned(),
            size_bytes: 10,
            hashes: DigestSet {
                sha256: "a".repeat(64),
                sha512: None,
            },
            complete: false,
            created_at: started,
            derived_from: None,
            segment_index: None,
            notes: None,
        });
        manifest
            .errors
            .push("the transfer stopped early".to_owned());
        store.write_manifest(&manifest).unwrap();

        let report = render_case(&store);
        assert!(report.contains("**INCOMPLETE**"));
        assert!(report.contains("**Incomplete artifacts** | **1**"));
        assert!(report.contains("### Errors"));
        assert!(report.contains("stopped early"));
    }

    #[test]
    fn a_large_artifact_set_is_summarized_instead_of_listed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("CASE-001");
        let store = EvidenceStore::create(&root).unwrap();

        let started = Utc::now();
        let mut manifest = Manifest::new(
            CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: None,
                notes: None,
            },
            OperationRecord {
                operation_id: operation_id("ext", started),
                method: "archive-extraction".to_owned(),
                method_description: "Extraction".to_owned(),
                source: SourceRecord {
                    source_id: "original/EV-1.tar".to_owned(),
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
        for i in 0..(MAX_LISTED_ARTIFACTS + 10) {
            manifest.artifacts.push(ArtifactRecord {
                path: format!("working/extracted/file{i:05}.bin"),
                classification: EvidenceClass::Working,
                role: ArtifactRole::ExtractedFile,
                format: "file".to_owned(),
                size_bytes: 100,
                hashes: DigestSet {
                    sha256: "b".repeat(64),
                    sha512: None,
                },
                complete: true,
                created_at: started,
                derived_from: None,
                segment_index: None,
                notes: None,
            });
        }
        store.write_manifest(&manifest).unwrap();

        let report = render_case(&store);
        assert!(report.contains("more than this report lists"));
        assert!(
            !report.contains("file00007.bin"),
            "the table must be summarized"
        );
        assert!(report.contains("| working |"));
    }
}
