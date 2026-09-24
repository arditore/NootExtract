//! Case reporting.
//!
//! A manifest is written for a machine. An examiner attaching evidence to a case
//! file needs one document that says what was acquired, from what, when, by what
//! method, with which digests, and what the tool could not do. This renders that
//! from the manifests themselves, so the report cannot drift from the record.
//!
//! Markdown rather than HTML, deliberately: it is diffable, hashable, reviewable
//! in a pull request, and convertible to HTML or PDF by whatever the lab already
//! uses.
//!
//! # Untrusted content
//!
//! Most of what appears here was chosen by the device: model and build strings
//! from `getprop`, paths, archive entry names, the stderr behind every recorded
//! error. A tampered manifest is a second source of the same kind.
//!
//! Markdown does not execute anything by itself, but it permits inline HTML, and
//! this report exists to be converted to HTML or PDF. A device reporting its
//! model as `<script>…</script>` would therefore put active content into an
//! examiner's document. Pipes break table structure, and backticks escape a code
//! span. Every interpolated value is consequently escaped through [`md`], and
//! untrusted values are never wrapped in code spans: entities are not decoded
//! inside one, so a single backtick in the content would break out of it.
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
            format!(" — {}", md(&title))
        }
    );

    let _ = writeln!(
        out,
        "Generated {} by {} {}.\n",
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        crate::NAME,
        crate::VERSION
    );
    let _ = writeln!(
        out,
        "Case directory: {}\n",
        md(&store.root().display().to_string())
    );

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
            md(&operation.operation_id),
            md(&operation.method)
        );
        let _ = writeln!(out, "{}\n", md(&operation.method_description));

        let _ = writeln!(out, "| Field | Value |");
        let _ = writeln!(out, "|---|---|");
        let _ = writeln!(out, "| Manifest | {} |", md(&file_name(path)));
        let _ = writeln!(out, "| Schema | {} |", md(&manifest.manifest_version));
        let _ = writeln!(out, "| Case | {} |", md(&manifest.case.case_id));
        let _ = writeln!(out, "| Evidence | {} |", md(&manifest.case.evidence_id));
        if let Some(examiner) = &manifest.case.examiner {
            let _ = writeln!(out, "| Examiner | {} |", md(examiner));
        }
        if let Some(notes) = &manifest.case.notes {
            let _ = writeln!(out, "| Notes | {} |", md(notes));
        }
        let _ = writeln!(out, "| Status | **{}** |", operation.status);
        let _ = writeln!(out, "| Started | {} |", operation.started_at.to_rfc3339());
        if let Some(completed) = operation.completed_at {
            let _ = writeln!(out, "| Completed | {} |", completed.to_rfc3339());
        }
        if let Some(duration) = operation.duration_ms {
            let _ = writeln!(out, "| Duration | {duration} ms |");
        }
        let _ = writeln!(out, "| Source | {} |", md(&operation.source.source_id));
        if let Some(source_path) = &operation.source.source_path {
            let _ = writeln!(out, "| Scope | {} |", md_path(source_path));
        }
        if let Some(command) = &operation.source.remote_command {
            let _ = writeln!(out, "| Device command | {} |", md(&command.join(" ")));
        }
        let _ = writeln!(
            out,
            "| Tool | {} {} on {}/{} |",
            md(&manifest.tool.name),
            md(&manifest.tool.version),
            md(&manifest.host.os),
            md(&manifest.host.arch)
        );
        for (tool, version) in &manifest.tool.external_tools {
            let _ = writeln!(out, "| External tool | {} — {} |", md(tool), md(version));
        }
        let _ = writeln!(out);

        if let Some(device) = &manifest.device {
            let _ = writeln!(out, "**Device**\n");
            let _ = writeln!(out, "| Property | Value |");
            let _ = writeln!(out, "|---|---|");
            let _ = writeln!(out, "| Serial | {} |", md(&device.serial));
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
                    let _ = writeln!(out, "| {label} | {} |", md(value));
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
                let _ = writeln!(out, "- {} = {}", md(key), md(value));
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
            "| {} | {} | {} | {} | {} | {} |",
            md_path(&artifact.path),
            artifact.classification,
            artifact.role.as_str(),
            format_bytes(artifact.size_bytes),
            if artifact.complete {
                "complete"
            } else {
                "**INCOMPLETE**"
            },
            md(&artifact.hashes.sha256)
        );
    }
    let _ = writeln!(out);

    if artifacts.iter().any(|a| a.hashes.sha512.is_some()) {
        let _ = writeln!(out, "**SHA-512**\n");
        for artifact in &artifacts {
            if let Some(sha512) = &artifact.hashes.sha512 {
                let _ = writeln!(out, "- {}: {}", md_path(&artifact.path), md(sha512));
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
            let _ = writeln!(out, "- **{}**: {}", md(operation), md(error));
        }
        let _ = writeln!(out);
    }

    if !warnings.is_empty() {
        let _ = writeln!(out, "### Warnings\n");
        for (operation, warning) in &warnings {
            let _ = writeln!(out, "- *{}*: {}", md(operation), md(warning));
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

/// Escapes a value so it is inert wherever it lands in the document.
///
/// Three separate problems, all reachable from a device-controlled string:
///
/// * `<` and `>` open inline HTML, which most Markdown renderers pass through
///   and every HTML or PDF conversion honours. These become entities.
/// * `|` ends a table cell, letting one value forge extra columns or rows.
/// * A backtick escapes a code span, and `[`, `]` and `*` restructure the text.
///   These are backslash-escaped, which CommonMark renders literally.
///
/// Line breaks are folded to spaces so a single field cannot become several
/// table rows. Control characters are dropped: they are invisible in the source
/// and can repaint a terminal when the report is catted.
fn md(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            // Ampersand first, so the entities emitted below are not re-escaped.
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '|' => out.push_str("&#124;"),
            '`' => out.push_str("&#96;"),
            '\\' => out.push_str("&#92;"),
            '[' => out.push_str("&#91;"),
            ']' => out.push_str("&#93;"),
            '*' => out.push_str("&#42;"),
            '_' => out.push_str("&#95;"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Escapes a path for display. Kept separate so the intent is visible at the
/// call sites, which are the ones carrying archive entry names.
fn md_path(path: &str) -> String {
    md(path)
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

    /// Builds a case whose device reported hostile identification strings.
    ///
    /// This is the realistic path: the values go through `getprop` parsing and
    /// `sanitize_device_string` first, which strips control characters but
    /// leaves Markdown and HTML metacharacters intact.
    fn case_with_hostile_device(root: &Path, model: &str) -> EvidenceStore {
        let store = EvidenceStore::create(root).unwrap();
        let started = Utc::now();

        let mut properties = std::collections::BTreeMap::new();
        properties.insert("ro.product.model".to_owned(), model.to_owned());
        properties.insert("ro.product.manufacturer".to_owned(), model.to_owned());

        let mut manifest = Manifest::new(
            CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: Some(model.to_owned()),
                notes: Some(model.to_owned()),
            },
            OperationRecord {
                operation_id: operation_id("acq", started),
                method: "adb-logical-tar".to_owned(),
                method_description: format!("Logical acquisition of {model}"),
                source: SourceRecord {
                    source_id: model.to_owned(),
                    source_path: Some(model.to_owned()),
                    remote_command: Some(vec!["tar".to_owned(), model.to_owned()]),
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(Utc::now()),
                duration_ms: Some(1),
                status: AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        manifest.device = Some(crate::device::DeviceMetadata::from_properties(
            model,
            &properties,
        ));
        manifest.artifacts.push(ArtifactRecord {
            path: format!("working/extracted/{model}"),
            classification: EvidenceClass::Working,
            role: ArtifactRole::ExtractedFile,
            format: "file".to_owned(),
            size_bytes: 1,
            hashes: DigestSet {
                sha256: "c".repeat(64),
                sha512: None,
            },
            complete: true,
            created_at: started,
            derived_from: None,
            segment_index: None,
            notes: None,
        });
        manifest.warnings.push(format!("device said: {model}"));
        manifest.errors.push(format!("device said: {model}"));
        store.write_manifest(&manifest).unwrap();
        store
    }

    #[test]
    fn inline_html_from_the_device_never_reaches_the_report() {
        // The report exists to be converted to HTML or PDF. A device that names
        // itself with a script tag must not put active content into an
        // examiner's document.
        let dir = tempfile::tempdir().unwrap();
        let store =
            case_with_hostile_device(&dir.path().join("CASE-001"), "<script>alert(1)</script>");
        let report = render_case(&store);

        assert!(!report.contains("<script"), "raw HTML reached the report");
        assert!(!report.contains("</script"), "raw HTML reached the report");
        assert!(
            !report.contains("alert(1)</"),
            "the payload kept its closing tag"
        );
        // The value is still present, escaped, so the record is not falsified.
        assert!(
            report.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "{report}"
        );

        // The only angle brackets left are in the tool's own example command,
        // inside a code span, where they are literal.
        for line in report.lines().filter(|line| line.contains('<')) {
            assert!(
                line.contains("nootextract verify `<case>`") || line.contains("verify <case>"),
                "unexpected raw angle bracket: {line}"
            );
        }
    }

    #[test]
    fn an_image_onerror_payload_is_inert() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_hostile_device(
            &dir.path().join("CASE-001"),
            "<img src=x onerror=fetch(evil)>",
        );
        let report = render_case(&store);
        assert!(!report.contains("<img"), "{report}");
        assert!(!report.contains("onerror=fetch(evil)>"), "{report}");
        assert!(
            report.contains("&lt;img src=x onerror=fetch(evil)&gt;"),
            "{report}"
        );
    }

    #[test]
    fn a_pipe_cannot_forge_table_columns() {
        // Every row of a two-column table must stay two columns, whatever the
        // device called itself.
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_hostile_device(&dir.path().join("CASE-001"), "Pixel | evil | extra");
        let report = render_case(&store);

        for line in report.lines() {
            if line.starts_with("| Serial ") || line.starts_with("| Model ") {
                assert_eq!(
                    line.matches('|').count(),
                    3,
                    "a value forged extra columns: {line}"
                );
            }
        }
        assert!(report.contains("&#124;"), "the pipe was not escaped");
    }

    #[test]
    fn a_backtick_cannot_escape_into_running_text() {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_hostile_device(&dir.path().join("CASE-001"), "Pixel` # heading `x");
        let report = render_case(&store);
        assert!(report.contains("&#96;"), "the backtick was not escaped");
        assert!(!report.contains("Pixel`"), "{report}");
    }

    #[test]
    fn a_newline_cannot_become_a_second_table_row() {
        // The device path strips control characters, but a hand-edited manifest
        // is a second source for the same value.
        let dir = tempfile::tempdir().unwrap();
        let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
        let started = Utc::now();
        let mut manifest = Manifest::new(
            CaseRecord {
                case_id: "CASE-001".to_owned(),
                evidence_id: "EV-1".to_owned(),
                examiner: Some("real\n| Status | **FORGED** |".to_owned()),
                notes: None,
            },
            OperationRecord {
                operation_id: operation_id("acq", started),
                method: "m".to_owned(),
                method_description: "d".to_owned(),
                source: SourceRecord {
                    source_id: "s".to_owned(),
                    source_path: None,
                    remote_command: None,
                    reported_size_bytes: None,
                },
                started_at: started,
                completed_at: Some(started),
                duration_ms: Some(0),
                status: AcquisitionStatus::Completed,
                parameters: Default::default(),
            },
        );
        manifest.artifacts.push(ArtifactRecord {
            path: "original/a".to_owned(),
            classification: EvidenceClass::Original,
            role: ArtifactRole::LogicalArchive,
            format: "tar".to_owned(),
            size_bytes: 1,
            hashes: DigestSet {
                sha256: "d".repeat(64),
                sha512: None,
            },
            complete: true,
            created_at: started,
            derived_from: None,
            segment_index: None,
            notes: None,
        });
        store.write_manifest(&manifest).unwrap();

        let report = render_case(&store);
        assert!(
            !report.contains("**FORGED**"),
            "a forged row survived: {report}"
        );
    }

    #[test]
    fn an_archive_entry_name_cannot_restructure_the_artifact_table() {
        // Extraction records one artifact per archive entry, and entry names
        // come from the device.
        let dir = tempfile::tempdir().unwrap();
        let store =
            case_with_hostile_device(&dir.path().join("CASE-001"), "photo.jpg | 99 | forged");
        let report = render_case(&store);

        for line in report.lines() {
            if line.starts_with("| working/") {
                assert_eq!(
                    line.matches('|').count(),
                    7,
                    "an entry name forged columns: {line}"
                );
            }
        }
    }

    #[test]
    fn escaping_leaves_ordinary_text_readable() {
        // Over-escaping would make every report unreadable, so the common case
        // has to come through untouched.
        assert_eq!(md("Pixel 7a"), "Pixel 7a");
        assert_eq!(md("/storage/emulated/0"), "/storage/emulated/0");
        assert_eq!(md("2026-01-02T03:04:05Z"), "2026-01-02T03:04:05Z");
        assert_eq!(md("adb-logical-tar"), "adb-logical-tar");
    }

    #[test]
    fn escaping_neutralises_every_structural_character() {
        for (input, forbidden) in [
            ("<b>", '<'),
            ("a>b", '>'),
            ("a|b", '|'),
            ("a`b", '`'),
            ("a[b]", '['),
            ("a*b", '*'),
            ("a_b", '_'),
        ] {
            let escaped = md(input);
            assert!(
                !escaped.contains(forbidden),
                "`{input}` still contains `{forbidden}` after escaping: {escaped}"
            );
        }
    }

    #[test]
    fn escaping_drops_control_characters_and_folds_line_breaks() {
        assert_eq!(md("a\nb"), "a b");
        assert_eq!(md("a\tb"), "a b");
        assert_eq!(md("a\u{7}b"), "ab");
        // An ANSI sequence must not survive into a report someone will `cat`.
        assert!(!md("esc\u{1b}[31m").contains('\u{1b}'));
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
