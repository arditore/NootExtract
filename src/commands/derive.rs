//! Derived-evidence commands: `convert` and `copy`.
//!
//! Both follow the same discipline:
//!
//! 1. Resolve the case the source belongs to.
//! 2. Verify the source against the manifest that records it, before deriving
//!    anything from it. Deriving from an artifact that has already changed would
//!    propagate the corruption silently.
//! 3. Write the new artifact under `derived/` or `working/`, never over the
//!    source.
//! 4. Emit a new manifest that links the derived artifact to its source. The
//!    original acquisition manifest is never rewritten.

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;
use tracing::{info, warn};

use crate::acquisition::backend::ProgressSink;
use crate::cli::{ConvertArgs, CopyArgs};
use crate::commands::{CommandContext, find_case_root};
use crate::error::{Error, IoResultExt, Result};
use crate::evidence::manifest::{
    AcquisitionStatus, ArtifactRecord, ArtifactRole, CaseRecord, EventRecord, EvidenceClass,
    Manifest, OperationRecord, SourceRecord, operation_id,
};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::hashing::{DigestSet, hash_file};
use crate::imaging::ewf::{EwfConverter, EwfParameters};
use crate::imaging::format::{ImageFormat, probe};
use crate::imaging::segmented::{DEFAULT_SEGMENT_SIZE, segment_image};
use crate::output::{BarProgress, print_json, print_line, print_table};
use crate::util::bytes::{format_bytes, parse_size};
use crate::util::paths::{sanitize_filename_fragment, validate_identifier};

/// Copy block size.
const COPY_BUFFER_SIZE: usize = 1024 * 1024;

/// JSON shape of `convert` and `copy`.
#[derive(Debug, Serialize)]
struct DeriveOutput {
    case_root: String,
    manifest: String,
    hash_list: String,
    operation: String,
    source: String,
    source_sha256: String,
    artifacts: Vec<DerivedSummary>,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DerivedSummary {
    path: String,
    classification: String,
    size_bytes: u64,
    sha256: String,
}

/// A source artifact resolved inside its case.
struct ResolvedSource {
    store: EvidenceStore,
    path: PathBuf,
    relative: String,
    record: Option<ArtifactRecord>,
}

/// Locates the case containing `path` and the manifest entry describing it.
fn resolve_source(path: &Path, output: Option<&Path>) -> Result<ResolvedSource> {
    let metadata = std::fs::symlink_metadata(path).ctx("inspect", path)?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Destination(format!(
            "`{}` is a symbolic link; refusing to follow it",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(Error::InvalidData(format!(
            "`{}` is not a regular file",
            path.display()
        )));
    }

    let root = if let Some(root) = output {
        EvidenceStore::create(root)?
    } else {
        let discovered = find_case_root(path).ok_or_else(|| {
            Error::Usage(format!(
                "`{}` is not inside a case directory; pass --output to name the case \
                 directory to write into",
                path.display()
            ))
        })?;
        EvidenceStore::open(&discovered)?
    };

    let canonical = crate::util::paths::canonicalize(path)?;
    let relative = root.relative(&canonical).map_err(|_| {
        Error::Usage(format!(
            "`{}` is outside the case directory `{}`; derived artifacts must be produced \
             inside the case that owns the source",
            path.display(),
            root.root().display()
        ))
    })?;

    let record = root
        .load_manifests()?
        .into_iter()
        .flat_map(|(_, manifest)| manifest.artifacts)
        .find(|artifact| artifact.path == relative);

    Ok(ResolvedSource {
        store: root,
        path: canonical,
        relative,
        record,
    })
}

/// Recomputes the source digest and compares it with its manifest record.
fn verify_source(
    context: &CommandContext,
    source: &ResolvedSource,
    with_sha512: bool,
) -> Result<(DigestSet, Vec<String>)> {
    let mut warnings = Vec::new();
    let need_sha512 = with_sha512
        || source
            .record
            .as_ref()
            .is_some_and(|record| record.hashes.sha512.is_some());

    let mut progress = BarProgress::new(context.mode, "verifying source");
    progress.start(source.record.as_ref().map(|record| record.size_bytes));
    let report = {
        let progress = &mut progress;
        hash_file(&source.path, need_sha512, &context.cancel, &mut |bytes| {
            progress.update(bytes);
        })?
    };
    progress.finish(report.bytes);

    if let Some(record) = &source.record {
        if record.size_bytes != report.bytes || !record.hashes.matches(&report.digests) {
            return Err(Error::Integrity(format!(
                "`{}` does not match the digest recorded in the case manifest; refusing to \
                 derive evidence from an artifact that has changed",
                source.relative
            )));
        }
        if !record.complete {
            warnings.push(format!(
                "`{}` is recorded as an incomplete acquisition; the derived artifact \
                 inherits that limitation",
                source.relative
            ));
        }
        info!(source = %source.relative, "source verified against its manifest");
    } else {
        warnings.push(format!(
            "`{}` is not recorded in any manifest in this case, so its integrity could \
             not be checked against a prior record",
            source.relative
        ));
        warn!(source = %source.relative, "source is not recorded in any manifest");
    }

    Ok((report.digests, warnings))
}

/// `nootextract convert <PATH> --format <FORMAT>`
pub fn convert(context: &CommandContext, args: &ConvertArgs) -> Result<()> {
    let target_format: ImageFormat = args.format.parse()?;
    if !target_format.is_supported_conversion_target() {
        return Err(Error::Unsupported(format!(
            "`{target_format}` is not a conversion target this build can produce \
             (supported: raw-segmented, ewf)"
        )));
    }

    let source = resolve_source(&args.path, args.output.as_deref())?;
    let source_probe = probe(&source.path)?;
    if !source_probe.format.is_supported_conversion_source() {
        return Err(Error::Unsupported(format!(
            "`{}` is {}; this build converts only raw and tar sources. Changing a file \
             extension is not a conversion.",
            source.relative,
            source_probe.describe()
        )));
    }

    let (source_digests, mut warnings) = verify_source(context, &source, args.sha512)?;
    warnings.push(format!(
        "source format was determined as {}",
        source_probe.describe()
    ));

    let base_name = derived_base_name(args.name.as_deref(), &source.path)?;
    let started_at = Utc::now();
    let started_id = operation_id("cnv", started_at);

    let (artifacts, mut parameters, extra_warnings) = match target_format {
        ImageFormat::RawSegmented => {
            let segment_size = match &args.segment_size {
                Some(value) => parse_size(value)?,
                None => DEFAULT_SEGMENT_SIZE,
            };
            let mut progress = BarProgress::new(context.mode, "segmenting");
            let result = {
                let progress = &mut progress;
                segment_image(
                    &source.store,
                    &source.path,
                    &base_name,
                    segment_size,
                    args.sha512,
                    &context.cancel,
                    progress,
                )?
            };
            // Compare only the algorithms both sides computed: the source may
            // have been verified with SHA-512 because its manifest records one,
            // while the conversion was asked for SHA-256 only. A set-equality
            // check would call that a mismatch.
            if !result.source_digests.matches(&source_digests) {
                return Err(Error::Integrity(format!(
                    "`{}` changed while it was being converted",
                    source.relative
                )));
            }
            let mut parameters = std::collections::BTreeMap::new();
            parameters.insert("segment_size_bytes".to_owned(), segment_size.to_string());
            parameters.insert(
                "segment_count".to_owned(),
                result.segments.len().to_string(),
            );
            (result.segments, parameters, Vec::new())
        }
        ImageFormat::Ewf => {
            let segment_size = match &args.segment_size {
                Some(value) => parse_size(value)?,
                None => DEFAULT_SEGMENT_SIZE,
            };
            let converter = EwfConverter::new(
                args.ewfacquire_path.clone(),
                args.ewfverify_path.clone(),
                crate::adb::SystemRunner::shared(),
            );
            let mut parameters = EwfParameters::new(
                args.case_id.as_deref().unwrap_or("unspecified"),
                args.evidence_id.as_deref().unwrap_or(&base_name),
                &format!("NootExtract derived image of {}", source.relative),
                segment_size,
            );
            parameters.examiner.clone_from(&args.examiner);

            let conversion = converter.convert(
                &source.store,
                &source.path,
                &base_name,
                &parameters,
                args.sha512,
                &context.cancel,
            )?;

            let mut recorded = conversion.parameters;
            recorded.insert("ewfacquire_version".to_owned(), conversion.tool_version);
            recorded.insert(
                "ewfverify_performed".to_owned(),
                conversion.verification.performed.to_string(),
            );
            recorded.insert(
                "ewfverify_result".to_owned(),
                conversion.verification.detail.clone(),
            );
            if conversion.verification.performed && !conversion.verification.succeeded {
                return Err(Error::Integrity(format!(
                    "libewf reported that the produced container failed verification: {}",
                    conversion.verification.detail
                )));
            }
            (conversion.segments, recorded, conversion.warnings)
        }
        other => {
            return Err(Error::Unsupported(format!(
                "`{other}` is not a conversion target this build can produce"
            )));
        }
    };

    warnings.extend(extra_warnings);
    parameters.insert("target_format".to_owned(), target_format.to_string());
    parameters.insert("source_format".to_owned(), source_probe.format.to_string());

    let artifacts: Vec<FinishedArtifact> = artifacts
        .into_iter()
        .map(|artifact| artifact.derived_from(source.relative.clone()))
        .collect();

    let case = derived_case_record(
        args.case_id.as_deref(),
        args.evidence_id.as_deref(),
        &source,
        &base_name,
        args.examiner.clone(),
    )?;

    let manifest = build_derived_manifest(
        case,
        started_id,
        format!("convert-{target_format}"),
        format!(
            "Conversion of `{}` to {target_format} as a derived artifact",
            source.relative
        ),
        &source,
        started_at,
        parameters,
        &artifacts,
        warnings.clone(),
    );

    finish(
        context,
        &source.store,
        &manifest,
        &source,
        &source_digests,
        &artifacts,
        &warnings,
    )
}

/// `nootextract copy <PATH>`
pub fn copy(context: &CommandContext, args: &CopyArgs) -> Result<()> {
    let source = resolve_source(&args.path, args.output.as_deref())?;
    let (source_digests, mut warnings) = verify_source(context, &source, args.sha512)?;

    let file_name = match &args.name {
        Some(name) => sanitize_filename_fragment(name)
            .ok_or_else(|| Error::Usage(format!("`{name}` does not yield a usable file name")))?,
        None => source
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(sanitize_filename_fragment)
            .ok_or_else(|| {
                Error::Usage("the source file name does not yield a usable copy name".into())
            })?,
    };

    let started_at = Utc::now();
    let started_id = operation_id("cpy", started_at);

    let mut progress = BarProgress::new(context.mode, "copying");
    let artifact = {
        let progress = &mut progress;
        copy_stream(
            &source.store,
            &source.path,
            &file_name,
            args.sha512,
            context,
            progress,
        )?
    };

    if !artifact.digests.matches(&source_digests) {
        return Err(Error::Integrity(format!(
            "the working copy `{}` does not match the source digest",
            artifact.relative_path
        )));
    }
    warnings.push(
        "working copies may be modified by analysis tools; the original remains the \
         authoritative artifact"
            .to_owned(),
    );

    let artifacts = vec![artifact.derived_from(source.relative.clone())];

    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert("target_class".to_owned(), "working".to_owned());

    let case = derived_case_record(
        args.case_id.as_deref(),
        args.evidence_id.as_deref(),
        &source,
        &file_name,
        None,
    )?;

    let manifest = build_derived_manifest(
        case,
        started_id,
        "working-copy".to_owned(),
        format!("Verified working copy of `{}`", source.relative),
        &source,
        started_at,
        parameters,
        &artifacts,
        warnings.clone(),
    );

    finish(
        context,
        &source.store,
        &manifest,
        &source,
        &source_digests,
        &artifacts,
        &warnings,
    )
}

/// Streams a source file into `working/` with digests computed on the way.
fn copy_stream(
    store: &EvidenceStore,
    source: &Path,
    file_name: &str,
    with_sha512: bool,
    context: &CommandContext,
    progress: &mut dyn ProgressSink,
) -> Result<FinishedArtifact> {
    let size = std::fs::metadata(source).ctx("inspect", source)?.len();
    store.ensure_space(size, 2)?;

    let file = File::open(source).ctx("open", source)?;
    let mut reader = BufReader::with_capacity(COPY_BUFFER_SIZE, file);
    let mut writer = store.create_artifact(
        EvidenceClass::Working,
        file_name,
        ArtifactRole::WorkingCopy,
        "raw",
        with_sha512,
    )?;

    progress.start(Some(size));
    let mut buffer = vec![0u8; COPY_BUFFER_SIZE];
    loop {
        context.cancel.check()?;
        let read = reader.read(&mut buffer).ctx("read", source)?;
        if read == 0 {
            break;
        }
        writer.write_chunk(buffer.get(..read).unwrap_or(&[]))?;
        progress.update(writer.bytes_written());
    }
    let written = writer.bytes_written();
    progress.finish(written);
    writer.finish_complete()
}

/// Builds a base name for a derived artifact set.
fn derived_base_name(requested: Option<&str>, source: &Path) -> Result<String> {
    let candidate = match requested {
        Some(name) => name.to_owned(),
        None => source
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("derived")
            .to_owned(),
    };
    sanitize_filename_fragment(&candidate)
        .ok_or_else(|| Error::Usage(format!("`{candidate}` does not yield a usable file name")))
}

fn derived_case_record(
    case_id: Option<&str>,
    evidence_id: Option<&str>,
    source: &ResolvedSource,
    fallback_evidence_id: &str,
    examiner: Option<String>,
) -> Result<CaseRecord> {
    // Inherit from the manifest that actually records this source, so a derived
    // artifact keeps the identity of the evidence it came from. Falling back to
    // an arbitrary manifest in the case would attach it to the wrong item.
    let manifests = source.store.load_manifests()?;
    let inherited = manifests
        .iter()
        .find(|(_, manifest)| {
            manifest
                .artifacts
                .iter()
                .any(|artifact| artifact.path == source.relative)
        })
        .or_else(|| manifests.first())
        .map(|(_, manifest)| manifest.case.clone());

    let case_id = match case_id {
        Some(value) => validate_identifier(value, "--case-id")?,
        None => match &inherited {
            Some(case) => case.case_id.clone(),
            None => {
                return Err(Error::Usage(
                    "this case contains no manifest to inherit --case-id from; pass it \
                     explicitly"
                        .into(),
                ));
            }
        },
    };

    let evidence_id = match (evidence_id, &inherited) {
        (Some(value), _) => validate_identifier(value, "--evidence-id")?,
        (None, Some(case)) => case.evidence_id.clone(),
        (None, None) => validate_identifier(fallback_evidence_id, "derived evidence id")
            .or_else(|_| validate_identifier("derived", "derived evidence id"))?,
    };

    Ok(CaseRecord {
        case_id,
        evidence_id,
        examiner,
        notes: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_derived_manifest(
    case: CaseRecord,
    operation_id: String,
    method: String,
    description: String,
    source: &ResolvedSource,
    started_at: chrono::DateTime<Utc>,
    parameters: std::collections::BTreeMap<String, String>,
    artifacts: &[FinishedArtifact],
    warnings: Vec<String>,
) -> Manifest {
    let completed_at = Utc::now();
    let operation = OperationRecord {
        operation_id,
        method,
        method_description: description,
        source: SourceRecord {
            source_id: source.relative.clone(),
            source_path: Some(source.relative.clone()),
            remote_command: None,
            reported_size_bytes: source.record.as_ref().map(|record| record.size_bytes),
        },
        started_at,
        completed_at: Some(completed_at),
        duration_ms: (completed_at - started_at)
            .num_milliseconds()
            .try_into()
            .ok(),
        status: AcquisitionStatus::Completed,
        parameters,
    };

    let mut manifest = Manifest::new(case, operation);
    manifest.artifacts = artifacts.iter().map(FinishedArtifact::to_record).collect();
    manifest.warnings = warnings;
    manifest.push_event(EventRecord::new("derived-artifact-created", "completed"));
    manifest
}

fn finish(
    context: &CommandContext,
    store: &EvidenceStore,
    manifest: &Manifest,
    source: &ResolvedSource,
    source_digests: &DigestSet,
    artifacts: &[FinishedArtifact],
    warnings: &[String],
) -> Result<()> {
    let outputs = store.write_manifest(manifest)?;
    info!(
        manifest = %outputs.manifest_path.display(),
        artifacts = artifacts.len(),
        "derived artifacts recorded"
    );

    let summaries: Vec<DerivedSummary> = artifacts
        .iter()
        .map(|artifact| DerivedSummary {
            path: artifact.relative_path.clone(),
            classification: artifact.class.to_string(),
            size_bytes: artifact.size_bytes,
            sha256: artifact.digests.sha256.clone(),
        })
        .collect();

    if context.mode.json {
        return print_json(&DeriveOutput {
            case_root: store.root().display().to_string(),
            manifest: outputs.manifest_path.display().to_string(),
            hash_list: outputs.hash_list_path.display().to_string(),
            operation: manifest.operation.method.clone(),
            source: source.relative.clone(),
            source_sha256: source_digests.sha256.clone(),
            artifacts: summaries,
            warnings: warnings.to_vec(),
        });
    }

    let rows: Vec<Vec<String>> = artifacts
        .iter()
        .map(|artifact| {
            vec![
                artifact.relative_path.clone(),
                artifact.class.to_string(),
                format_bytes(artifact.size_bytes),
                artifact.digests.sha256.clone(),
            ]
        })
        .collect();
    print_table(
        context.mode,
        &["ARTIFACT", "CLASS", "SIZE", "SHA-256"],
        &rows,
    );

    print_line(
        context.mode,
        &format!(
            "\nsource:    {} ({})",
            source.relative, source_digests.sha256
        ),
    );
    print_line(
        context.mode,
        &format!("manifest:  {}", outputs.manifest_path.display()),
    );
    print_line(
        context.mode,
        &format!("hash list: {}", outputs.hash_list_path.display()),
    );
    print_line(context.mode, "The source artifact was not modified.");
    for warning in warnings {
        print_line(context.mode, &format!("warning: {warning}"));
    }
    Ok(())
}
