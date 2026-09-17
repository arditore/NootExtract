//! The `acquire` command.
//!
//! Sequence, in order:
//!
//! 1. Validate operator identifiers and the device serial.
//! 2. Validate and prepare the destination.
//! 3. Record the acquisition start time.
//! 4. Run the backend preflight, which reports limitations rather than working
//!    around them.
//! 5. Record device metadata and the acquisition method.
//! 6. Check free space where the source size is known.
//! 7. Execute the transfer, hashing as it streams.
//! 8. Preserve whatever was written, complete or not.
//! 9. Write the manifest and the hash list — on every path, including failure.
//! 10. Exit non-zero unless the acquisition completed.
//!
//! A manifest is produced even when the acquisition fails. An undocumented
//! partial artifact would be worse than a documented one.

use std::collections::BTreeSet;

use chrono::Utc;
use serde::Serialize;
use tracing::{error, info, warn};

use crate::acquisition::backend::{AcquisitionContext, AcquisitionOptions};
use crate::acquisition::{AcquisitionOutcome, BackendInfo, Preflight, backend_by_id};
use crate::cli::AcquireArgs;
use crate::commands::CommandContext;
use crate::device::{DeviceMetadata, validate_serial};
use crate::error::{Error, Result};
use crate::evidence::manifest::{
    AcquisitionStatus, ArtifactRole, CaseRecord, EventRecord, EvidenceClass, Manifest,
    OperationRecord, operation_id,
};
use crate::evidence::store::{EvidenceStore, FinishedArtifact};
use crate::output::{BarProgress, print_json, print_line, print_table};
use crate::util::bytes::format_bytes;
use crate::util::paths::validate_identifier;

/// JSON shape of a completed or failed acquisition.
#[derive(Debug, Serialize)]
struct AcquireOutput {
    case_root: String,
    manifest: String,
    hash_list: String,
    status: String,
    artifacts: Vec<ArtifactSummary>,
    warnings: Vec<String>,
    errors: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactSummary {
    path: String,
    size_bytes: u64,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha512: Option<String>,
    complete: bool,
}

/// JSON shape of `--dry-run`.
#[derive(Debug, Serialize)]
struct DryRunOutput {
    case_root: String,
    device_id: String,
    method: String,
    method_description: String,
    acquisition_kind: String,
    output_format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    estimated_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    available_space_bytes: Option<u64>,
    remote_command: Option<Vec<String>>,
    warnings: Vec<String>,
}

/// `nootextract acquire <DEVICE_ID> ...`
pub fn run(context: &CommandContext, args: &AcquireArgs) -> Result<()> {
    let case_id = validate_identifier(&args.case_id, "--case-id")?;
    let evidence_id = validate_identifier(&args.evidence_id, "--evidence-id")?;
    let device_id = validate_serial(&args.device_id)?;

    let store = EvidenceStore::create(&args.output)?;
    let started_at = Utc::now();
    let acquisition_id = operation_id("acq", started_at);

    info!(
        device_id = %device_id,
        acquisition_id = %acquisition_id,
        case_id = %case_id,
        evidence_id = %evidence_id,
        method = %args.method,
        case_root = %store.root().display(),
        "acquisition starting"
    );

    let backend = backend_by_id(&args.method, context.adb.clone())?;
    let backend_info = backend.info();

    let options = AcquisitionOptions {
        with_sha512: args.sha512,
        source_path: args.source.clone(),
        allow_source_read_errors: args.allow_source_read_errors,
        post_write_verify: !args.no_post_verify,
        ..AcquisitionOptions::default()
    };

    let case = CaseRecord {
        case_id,
        evidence_id: evidence_id.clone(),
        examiner: args.examiner.clone(),
        notes: args.notes.clone(),
    };

    let acquisition = AcquisitionContext {
        device_id: device_id.clone(),
        case: case.clone(),
        operation_id: acquisition_id.clone(),
        started_at,
        store: &store,
        options,
        cancel: context.cancel.clone(),
    };

    // Preflight reports limitations; it never transfers evidence.
    let preflight = backend.preflight(&acquisition)?;
    for warning in &preflight.warnings {
        warn!(device_id = %device_id, acquisition_id = %acquisition_id, "{warning}");
    }

    let device_metadata = match context.adb.metadata(&device_id) {
        Ok(metadata) => Some(metadata),
        Err(e) => {
            warn!(device_id = %device_id, error = %e, "device metadata could not be read");
            None
        }
    };

    if let Some(size) = preflight.estimated_size {
        store.ensure_space(size, acquisition.options.space_headroom_percent)?;
    } else {
        warn!(
            device_id = %device_id,
            "the source size is unknown; the free-space precheck was skipped"
        );
    }

    if args.dry_run {
        return report_dry_run(context, &store, &acquisition, &backend_info, &preflight);
    }

    let mut progress = BarProgress::new(
        context.mode,
        format!("acquiring {} from {device_id}", backend_info.output_format),
    );

    let completed_at;
    let result = {
        let progress = &mut progress;
        let outcome = backend.acquire(&acquisition, &preflight, progress);
        completed_at = Utc::now();
        outcome
    };

    // A hard failure keeps its own error so the exit code stays precise: an
    // occupied destination must not be reported as a generic transfer failure.
    let mut fatal: Option<Error> = None;
    let (status, artifacts, mut errors, mut warnings, events) = match result {
        Ok(outcome) => unpack(outcome),
        Err(e) => {
            error!(
                device_id = %device_id,
                acquisition_id = %acquisition_id,
                error = %e,
                "acquisition failed"
            );
            let residue = adopt_residue(&store, &evidence_id, args.sha512, context)?;
            let message = e.to_string();
            fatal = Some(e);
            (
                AcquisitionStatus::Failed,
                residue,
                vec![message.clone()],
                Vec::new(),
                vec![EventRecord::new("acquisition", "failed").with_detail(message)],
            )
        }
    };

    warnings.extend(preflight.warnings.iter().cloned());
    if !status.is_complete() {
        errors.push(
            "this acquisition did not complete; any data written is preserved and recorded \
             as incomplete"
                .to_owned(),
        );
    }

    let manifest = build_manifest(
        context,
        &acquisition,
        &backend_info,
        &preflight,
        device_metadata,
        status,
        completed_at,
        &artifacts,
        errors.clone(),
        warnings.clone(),
        events,
    );

    let outputs = store.write_manifest(&manifest)?;
    info!(
        acquisition_id = %acquisition_id,
        manifest = %outputs.manifest_path.display(),
        status = %status,
        "manifest written"
    );

    let summaries: Vec<ArtifactSummary> = artifacts
        .iter()
        .map(|artifact| ArtifactSummary {
            path: artifact.relative_path.clone(),
            size_bytes: artifact.size_bytes,
            sha256: artifact.digests.sha256.clone(),
            sha512: artifact.digests.sha512.clone(),
            complete: artifact.complete,
        })
        .collect();

    if context.mode.json {
        print_json(&AcquireOutput {
            case_root: store.root().display().to_string(),
            manifest: outputs.manifest_path.display().to_string(),
            hash_list: outputs.hash_list_path.display().to_string(),
            status: status.to_string(),
            artifacts: summaries,
            warnings: warnings.clone(),
            errors: errors.clone(),
        })?;
    } else {
        render_summary(
            context, &store, &outputs, status, &artifacts, &warnings, &errors,
        );
    }

    if let Some(error) = fatal {
        return Err(error);
    }

    match status {
        AcquisitionStatus::Completed | AcquisitionStatus::CompletedWithErrors => Ok(()),
        AcquisitionStatus::Cancelled => Err(Error::Cancelled),
        AcquisitionStatus::Failed => Err(Error::Acquisition(format!(
            "acquisition `{acquisition_id}` did not complete; see {}",
            outputs.manifest_path.display()
        ))),
    }
}

type UnpackedOutcome = (
    AcquisitionStatus,
    Vec<FinishedArtifact>,
    Vec<String>,
    Vec<String>,
    Vec<EventRecord>,
);

fn unpack(outcome: AcquisitionOutcome) -> UnpackedOutcome {
    (
        outcome.status,
        outcome.artifacts,
        outcome.errors,
        outcome.warnings,
        outcome.events,
    )
}

/// Records files left in `original/` by a failed run that no manifest covers.
///
/// Without this, a hard failure could leave a partial artifact on disk that no
/// manifest describes. Adopting it keeps every byte in the evidence directory
/// accounted for and verifiable.
fn adopt_residue(
    store: &EvidenceStore,
    evidence_id: &str,
    with_sha512: bool,
    context: &CommandContext,
) -> Result<Vec<FinishedArtifact>> {
    let mut recorded: BTreeSet<String> = BTreeSet::new();
    for (_, manifest) in store.load_manifests()? {
        for artifact in &manifest.artifacts {
            recorded.insert(artifact.path.clone());
        }
    }

    let mut adopted = Vec::new();
    for name in store.list_class_files(EvidenceClass::Original, evidence_id)? {
        let relative = format!("original/{name}");
        if recorded.contains(&relative) {
            continue;
        }
        let artifact = store.adopt_artifact(
            EvidenceClass::Original,
            &name,
            ArtifactRole::PhysicalImage,
            "unknown",
            with_sha512,
            &context.cancel,
        )?;
        let complete = !name.ends_with(crate::evidence::store::PARTIAL_SUFFIX);
        let mut artifact = artifact;
        artifact.complete = complete;
        artifact.note = Some(
            "recorded after a failed acquisition; the transfer did not complete and this \
             artifact must not be treated as a full image"
                .to_owned(),
        );
        warn!(artifact = %artifact.relative_path, "recording residue from a failed acquisition");
        adopted.push(artifact);
    }
    Ok(adopted)
}

#[allow(clippy::too_many_arguments)]
fn build_manifest(
    context: &CommandContext,
    acquisition: &AcquisitionContext<'_>,
    backend_info: &BackendInfo,
    preflight: &Preflight,
    device: Option<DeviceMetadata>,
    status: AcquisitionStatus,
    completed_at: chrono::DateTime<Utc>,
    artifacts: &[FinishedArtifact],
    errors: Vec<String>,
    warnings: Vec<String>,
    events: Vec<EventRecord>,
) -> Manifest {
    let duration_ms = (completed_at - acquisition.started_at)
        .num_milliseconds()
        .try_into()
        .ok();

    let mut parameters = preflight.parameters.clone();
    parameters.insert(
        "post_write_verify".to_owned(),
        acquisition.options.post_write_verify.to_string(),
    );
    parameters.insert(
        "sha512".to_owned(),
        acquisition.options.with_sha512.to_string(),
    );

    let operation = OperationRecord {
        operation_id: acquisition.operation_id.clone(),
        method: backend_info.id.to_owned(),
        method_description: preflight.method_description.clone(),
        source: preflight.source.clone(),
        started_at: acquisition.started_at,
        completed_at: Some(completed_at),
        duration_ms,
        status,
        parameters,
    };

    let mut manifest = Manifest::new(acquisition.case.clone(), operation);
    manifest.device = device;
    manifest.artifacts = artifacts.iter().map(FinishedArtifact::to_record).collect();
    manifest.errors = errors;
    manifest.warnings = warnings;
    manifest.events = events;
    manifest.push_event(EventRecord::new("manifest-generated", status.as_str()));

    if let Ok(version) = context.adb.version() {
        manifest
            .tool
            .external_tools
            .insert(context.adb.program().to_owned(), version);
    }
    manifest
}

fn report_dry_run(
    context: &CommandContext,
    store: &EvidenceStore,
    acquisition: &AcquisitionContext<'_>,
    backend_info: &BackendInfo,
    preflight: &Preflight,
) -> Result<()> {
    let output = DryRunOutput {
        case_root: store.root().display().to_string(),
        device_id: acquisition.device_id.clone(),
        method: backend_info.id.to_owned(),
        method_description: preflight.method_description.clone(),
        acquisition_kind: backend_info.kind.as_str().to_owned(),
        output_format: backend_info.output_format.to_owned(),
        source_path: preflight.source.source_path.clone(),
        estimated_size_bytes: preflight.estimated_size,
        available_space_bytes: store.available_space(),
        remote_command: preflight.source.remote_command.clone(),
        warnings: preflight.warnings.clone(),
    };

    if context.mode.json {
        return print_json(&output);
    }

    let rows = vec![
        vec!["case root".to_owned(), output.case_root.clone()],
        vec!["device".to_owned(), output.device_id.clone()],
        vec!["method".to_owned(), output.method.clone()],
        vec!["description".to_owned(), output.method_description.clone()],
        vec![
            "acquisition kind".to_owned(),
            output.acquisition_kind.clone(),
        ],
        vec!["output format".to_owned(), output.output_format.clone()],
        vec![
            "source".to_owned(),
            output.source_path.clone().unwrap_or_else(|| "-".to_owned()),
        ],
        vec![
            "estimated size".to_owned(),
            output
                .estimated_size_bytes
                .map_or_else(|| "unknown".to_owned(), format_bytes),
        ],
        vec![
            "free space".to_owned(),
            output
                .available_space_bytes
                .map_or_else(|| "unknown".to_owned(), format_bytes),
        ],
        vec![
            "device command".to_owned(),
            output
                .remote_command
                .clone()
                .map_or_else(|| "-".to_owned(), |argv| argv.join(" ")),
        ],
    ];
    print_table(context.mode, &["FIELD", "VALUE"], &rows);
    for warning in &output.warnings {
        print_line(context.mode, &format!("warning: {warning}"));
    }
    print_line(
        context.mode,
        "\nDry run: no data was transferred and no evidence file was written.",
    );
    Ok(())
}

fn render_summary(
    context: &CommandContext,
    store: &EvidenceStore,
    outputs: &crate::evidence::store::ManifestOutputs,
    status: AcquisitionStatus,
    artifacts: &[FinishedArtifact],
    warnings: &[String],
    errors: &[String],
) {
    let rows: Vec<Vec<String>> = artifacts
        .iter()
        .map(|artifact| {
            vec![
                artifact.relative_path.clone(),
                format_bytes(artifact.size_bytes),
                if artifact.complete {
                    "complete"
                } else {
                    "INCOMPLETE"
                }
                .to_owned(),
                artifact.digests.sha256.clone(),
            ]
        })
        .collect();

    if rows.is_empty() {
        print_line(context.mode, "No artifact was produced.");
    } else {
        print_table(
            context.mode,
            &["ARTIFACT", "SIZE", "STATE", "SHA-256"],
            &rows,
        );
    }

    print_line(context.mode, &format!("\nstatus:    {status}"));
    print_line(
        context.mode,
        &format!("case root: {}", store.root().display()),
    );
    print_line(
        context.mode,
        &format!("manifest:  {}", outputs.manifest_path.display()),
    );
    print_line(
        context.mode,
        &format!("hash list: {}", outputs.hash_list_path.display()),
    );

    for warning in warnings {
        print_line(context.mode, &format!("warning: {warning}"));
    }
    for issue in errors {
        print_line(context.mode, &format!("error:   {issue}"));
    }
}
