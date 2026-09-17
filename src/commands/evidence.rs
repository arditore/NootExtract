//! Hashing, verification and manifest inspection.

use std::path::Path;

use serde::Serialize;
use tracing::{error, info};

use crate::acquisition::backend::ProgressSink;
use crate::cli::{HashArgs, ManifestArgs, VerifyArgs};
use crate::commands::CommandContext;
use crate::error::{Error, Result};
use crate::evidence::manifest::Manifest;
use crate::evidence::store::EvidenceStore;
use crate::evidence::verify::{VerificationOutcome, VerificationReport, VerifyOptions};
use crate::hashing::hash_file;
use crate::imaging::format;
use crate::output::{BarProgress, print_json, print_line, print_table};
use crate::util::bytes::format_bytes;

/// JSON shape of `nootextract hash`.
#[derive(Debug, Serialize)]
struct HashOutput {
    path: String,
    size_bytes: u64,
    format: String,
    format_evidence: String,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha512: Option<String>,
}

/// `nootextract hash <PATH>`
pub fn hash(context: &CommandContext, args: &HashArgs) -> Result<()> {
    let probe = format::probe(&args.path)?;
    let mut progress = BarProgress::new(context.mode, "hashing");
    progress.start(Some(probe.size_bytes));

    let report = {
        let progress = &mut progress;
        hash_file(&args.path, args.sha512, &context.cancel, &mut |bytes| {
            progress.update(bytes);
        })?
    };
    progress.finish(report.bytes);

    info!(
        path = %args.path.display(),
        bytes = report.bytes,
        "hashing completed"
    );

    if context.mode.json {
        return print_json(&HashOutput {
            path: args.path.display().to_string(),
            size_bytes: report.bytes,
            format: probe.format.as_str().to_owned(),
            format_evidence: format!("{:?}", probe.evidence).to_lowercase(),
            sha256: report.digests.sha256,
            sha512: report.digests.sha512,
        });
    }

    // sha256sum-compatible first line, so the output can be piped directly.
    println!("{}  {}", report.digests.sha256, args.path.display());
    if let Some(sha512) = &report.digests.sha512 {
        println!("{sha512}  {}", args.path.display());
    }
    print_line(
        context.mode,
        &format!(
            "size: {} ({} bytes), format: {}",
            format_bytes(report.bytes),
            report.bytes,
            probe.describe()
        ),
    );
    Ok(())
}

/// `nootextract verify <PATH>`
pub fn verify(context: &CommandContext, args: &VerifyArgs) -> Result<()> {
    let options = VerifyOptions {
        ignore_extra: args.ignore_extra,
        verify_sha512: !args.no_sha512,
    };

    let report = if args.path.is_dir() {
        let store = EvidenceStore::open(&args.path)?;
        run_verification(context, &store, None, options)?
    } else {
        let manifest = Manifest::load(&args.path)?;
        let root = case_root_for_manifest(&args.path)?;
        let store = EvidenceStore::open(&root)?;
        run_verification(
            context,
            &store,
            Some(vec![(args.path.clone(), manifest)]),
            options,
        )?
    };

    if context.mode.json {
        print_json(&report)?;
    } else {
        render_verification(context, &report);
    }

    if report.is_success() {
        info!(
            matched = report.count(VerificationOutcome::Match),
            "verification passed"
        );
        Ok(())
    } else {
        error!(
            mismatch = report.count(VerificationOutcome::Mismatch),
            missing = report.count(VerificationOutcome::Missing),
            extra = report.count(VerificationOutcome::Extra),
            "verification failed"
        );
        Err(Error::Integrity(format!(
            "{} MISMATCH, {} MISSING, {} EXTRA across {} manifest(s)",
            report.count(VerificationOutcome::Mismatch),
            report.count(VerificationOutcome::Missing),
            report.count(VerificationOutcome::Extra),
            report.manifests_checked.len()
        )))
    }
}

fn run_verification(
    context: &CommandContext,
    store: &EvidenceStore,
    manifests: Option<Vec<(std::path::PathBuf, Manifest)>>,
    options: VerifyOptions,
) -> Result<VerificationReport> {
    let mut progress = BarProgress::new(context.mode, "verifying");
    progress.start(None);

    // The callback borrows the progress bar; the inner scope releases that
    // borrow before the bar is finished below.
    let report = {
        let progress = &mut progress;
        let mut callback = move |_path: &str, bytes: u64| progress.update(bytes);
        match manifests {
            Some(list) => crate::evidence::verify::verify_with_manifests(
                store,
                &list,
                options,
                &context.cancel,
                &mut callback,
            )?,
            None => crate::evidence::verify::verify_case(
                store,
                options,
                &context.cancel,
                &mut callback,
            )?,
        }
    };

    let total: u64 = report
        .results
        .iter()
        .map(|result| result.actual_size_bytes.unwrap_or(0))
        .sum();
    progress.finish(total);
    Ok(report)
}

fn render_verification(context: &CommandContext, report: &VerificationReport) {
    let rows: Vec<Vec<String>> = report
        .results
        .iter()
        .map(|result| {
            vec![
                result.outcome.to_string(),
                result.path.clone(),
                result
                    .classification
                    .map_or_else(|| "-".to_owned(), |c| c.to_string()),
                result.detail.clone().unwrap_or_else(|| "-".to_owned()),
            ]
        })
        .collect();

    if rows.is_empty() {
        print_line(context.mode, "No artifacts are recorded for this case.");
    } else {
        print_table(context.mode, &["RESULT", "PATH", "CLASS", "DETAIL"], &rows);
    }

    print_line(
        context.mode,
        &format!(
            "\n{} MATCH, {} MISMATCH, {} MISSING, {} EXTRA ({} manifest(s) checked)",
            report.count(VerificationOutcome::Match),
            report.count(VerificationOutcome::Mismatch),
            report.count(VerificationOutcome::Missing),
            report.count(VerificationOutcome::Extra),
            report.manifests_checked.len(),
        ),
    );
    if report.count(VerificationOutcome::Extra) > 0 && !report.extra_files_are_failures {
        print_line(
            context.mode,
            "Unaccounted files were reported but not treated as failures (--ignore-extra).",
        );
    }
}

/// Derives the case root from a manifest path inside `manifests/`.
fn case_root_for_manifest(manifest_path: &Path) -> Result<std::path::PathBuf> {
    manifest_path
        .parent()
        .filter(|parent| parent.file_name().is_some_and(|name| name == "manifests"))
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            Error::Usage(format!(
                "`{}` is not inside a case `manifests/` directory; pass the case directory \
                 instead",
                manifest_path.display()
            ))
        })
}

/// JSON shape of `nootextract manifest`.
#[derive(Debug, Serialize)]
struct ManifestOutput {
    path: String,
    valid: bool,
    notes: Vec<String>,
    manifest: Manifest,
}

/// `nootextract manifest <PATH>`
pub fn manifest(context: &CommandContext, args: &ManifestArgs) -> Result<()> {
    if args.path.is_dir() {
        return list_manifests(context, &args.path);
    }

    let manifest = Manifest::load(&args.path)?;
    let notes = manifest.validate()?;

    if context.mode.json {
        return print_json(&ManifestOutput {
            path: args.path.display().to_string(),
            valid: true,
            notes,
            manifest,
        });
    }

    let rows = vec![
        vec![
            "manifest version".to_owned(),
            manifest.manifest_version.clone(),
        ],
        vec!["manifest id".to_owned(), manifest.manifest_id.clone()],
        vec!["generated at".to_owned(), manifest.generated_at_rfc3339()],
        vec![
            "tool".to_owned(),
            format!("{} {}", manifest.tool.name, manifest.tool.version),
        ],
        vec![
            "host".to_owned(),
            format!("{} / {}", manifest.host.os, manifest.host.arch),
        ],
        vec!["case id".to_owned(), manifest.case.case_id.clone()],
        vec!["evidence id".to_owned(), manifest.case.evidence_id.clone()],
        vec!["method".to_owned(), manifest.operation.method.clone()],
        vec!["status".to_owned(), manifest.operation.status.to_string()],
        vec![
            "started at".to_owned(),
            manifest.operation.started_at.to_rfc3339(),
        ],
        vec![
            "completed at".to_owned(),
            manifest
                .operation
                .completed_at
                .map_or_else(|| "-".to_owned(), |t| t.to_rfc3339()),
        ],
        vec![
            "device".to_owned(),
            manifest
                .device
                .as_ref()
                .map_or_else(|| "-".to_owned(), |d| d.serial.clone()),
        ],
        vec!["artifacts".to_owned(), manifest.artifacts.len().to_string()],
        vec!["errors".to_owned(), manifest.errors.len().to_string()],
        vec!["warnings".to_owned(), manifest.warnings.len().to_string()],
    ];
    print_table(context.mode, &["FIELD", "VALUE"], &rows);

    let artifact_rows: Vec<Vec<String>> = manifest
        .artifacts
        .iter()
        .map(|artifact| {
            vec![
                artifact.path.clone(),
                artifact.classification.to_string(),
                artifact.role.as_str().to_owned(),
                artifact.format.clone(),
                format_bytes(artifact.size_bytes),
                if artifact.complete {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
                .to_owned(),
                artifact.hashes.sha256.clone(),
            ]
        })
        .collect();
    if !artifact_rows.is_empty() {
        print_line(context.mode, "");
        print_table(
            context.mode,
            &[
                "PATH", "CLASS", "ROLE", "FORMAT", "SIZE", "STATE", "SHA-256",
            ],
            &artifact_rows,
        );
    }

    for warning in &manifest.warnings {
        print_line(context.mode, &format!("warning: {warning}"));
    }
    for issue in &manifest.errors {
        print_line(context.mode, &format!("error: {issue}"));
    }
    for note in &notes {
        print_line(context.mode, &format!("note: {note}"));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct ManifestListEntry {
    path: String,
    evidence_id: String,
    method: String,
    status: String,
    artifacts: usize,
    generated_at: String,
}

fn list_manifests(context: &CommandContext, root: &Path) -> Result<()> {
    let store = EvidenceStore::open(root)?;
    let loaded = store.load_manifests()?;

    let entries: Vec<ManifestListEntry> = loaded
        .iter()
        .map(|(path, manifest)| ManifestListEntry {
            path: path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned(),
            evidence_id: manifest.case.evidence_id.clone(),
            method: manifest.operation.method.clone(),
            status: manifest.operation.status.to_string(),
            artifacts: manifest.artifacts.len(),
            generated_at: manifest.generated_at_rfc3339(),
        })
        .collect();

    if context.mode.json {
        return print_json(&entries);
    }

    if entries.is_empty() {
        print_line(context.mode, "This case contains no manifests.");
        return Ok(());
    }

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            vec![
                entry.path.clone(),
                entry.evidence_id.clone(),
                entry.method.clone(),
                entry.status.clone(),
                entry.artifacts.to_string(),
                entry.generated_at.clone(),
            ]
        })
        .collect();
    print_table(
        context.mode,
        &[
            "MANIFEST",
            "EVIDENCE ID",
            "METHOD",
            "STATUS",
            "ARTIFACTS",
            "GENERATED",
        ],
        &rows,
    );
    Ok(())
}
