//! Command implementations.
//!
//! Each command receives a [`CommandContext`] and returns a
//! [`crate::error::Result`]. Exit codes are derived from the error type in
//! `main`, so no command calls `std::process::exit` itself and every failure
//! path is forced through the documented contract.

pub mod acquire;
pub mod derive;
pub mod device;
pub mod doctor;
pub mod evidence;
pub mod report;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::adb::AdbClient;
use crate::cli::{Cli, Command};
use crate::error::Result;
use crate::output::OutputMode;
use crate::util::cancel::CancellationToken;

/// Shared state handed to every command.
#[derive(Debug, Clone)]
pub struct CommandContext {
    pub mode: OutputMode,
    pub adb: Arc<AdbClient>,
    pub cancel: CancellationToken,
}

impl CommandContext {
    pub fn new(cli: &Cli, cancel: CancellationToken) -> Self {
        Self {
            mode: OutputMode {
                json: cli.global.json,
                quiet: cli.global.quiet,
                progress: !cli.global.no_progress,
            },
            adb: Arc::new(AdbClient::new(cli.global.adb_path.clone())),
            cancel,
        }
    }
}

/// Dispatches to the selected command.
///
/// A bare invocation carries no subcommand and starts the guided session; the
/// caller has already established that a terminal is attached.
pub fn dispatch(cli: Cli, cancel: CancellationToken) -> Result<()> {
    let context = CommandContext::new(&cli, cancel);
    let global = cli.global.clone();
    let Some(command) = cli.command else {
        return crate::interactive::run(&context, &global);
    };
    run_command(&context, &global, command)
}

/// Runs one parsed command.
///
/// Split out so the interactive shell dispatches through exactly the same path
/// as the command line, rather than reimplementing it.
pub fn run_command(
    context: &CommandContext,
    global: &crate::cli::GlobalArgs,
    command: Command,
) -> Result<()> {
    match command {
        Command::Devices(args) => device::devices(context, &args),
        Command::Info(args) => device::info(context, &args),
        Command::Methods => device::methods(context),
        Command::Acquire(args) => acquire::run(context, &args),
        Command::Hash(args) => evidence::hash(context, &args),
        Command::Verify(args) => evidence::verify(context, &args),
        Command::Manifest(args) => evidence::manifest(context, &args),
        Command::Convert(args) => derive::convert(context, &args),
        Command::Copy(args) => derive::copy(context, &args),
        Command::Extract(args) => derive::extract(context, &args),
        Command::Doctor(args) => doctor::run(context, &args),
        Command::Report(args) => report::run(context, &args),
        Command::Interactive => crate::interactive::run(context, global),
    }
}

#[cfg(test)]
impl CommandContext {
    /// Builds a context for unit tests, with progress and JSON disabled.
    pub(crate) fn for_tests(adb_path: &str) -> Self {
        Self {
            mode: OutputMode {
                json: false,
                quiet: true,
                progress: false,
            },
            adb: Arc::new(AdbClient::new(adb_path)),
            cancel: CancellationToken::new(),
        }
    }
}

/// Walks up from `path` to find the case directory containing it.
///
/// A case directory is recognized by its `manifests/` subdirectory. Returns
/// `None` rather than guessing when no ancestor qualifies.
pub fn find_case_root(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()?.to_path_buf()
    };
    let mut current = Some(start.as_path());
    while let Some(candidate) = current {
        if candidate.join("manifests").is_dir() {
            return Some(candidate.to_path_buf());
        }
        current = candidate.parent();
    }
    None
}

/// Case-log path for a run, when the command writes into a case directory.
///
/// Computed before logging is initialized so acquisition and derivation runs are
/// recorded in the case itself, not only on the operator's terminal.
pub fn case_log_path(command: &Command) -> Option<PathBuf> {
    let root = match command {
        Command::Acquire(args) => {
            // An invocation that will be rejected must not leave a case
            // directory behind, so the identifiers are checked before any
            // directory is prepared for the log.
            crate::util::paths::validate_identifier(&args.case_id, "--case-id").ok()?;
            crate::util::paths::validate_identifier(&args.evidence_id, "--evidence-id").ok()?;
            crate::device::validate_serial(&args.device_id).ok()?;
            Some(args.output.clone())
        }
        Command::Convert(args) => args.output.clone().or_else(|| find_case_root(&args.path)),
        Command::Copy(args) => args.output.clone().or_else(|| find_case_root(&args.path)),
        _ => None,
    }?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    Some(root.join("logs").join(format!("nootextract-{stamp}.jsonl")))
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
    fn finds_the_case_root_from_an_artifact_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("CASE-001");
        std::fs::create_dir_all(root.join("manifests")).unwrap();
        std::fs::create_dir_all(root.join("original")).unwrap();
        let artifact = root.join("original").join("image.raw");
        std::fs::write(&artifact, b"x").unwrap();

        assert_eq!(find_case_root(&artifact).as_deref(), Some(root.as_path()));
        assert_eq!(find_case_root(&root).as_deref(), Some(root.as_path()));
    }

    #[test]
    fn returns_none_outside_a_case_directory() {
        let dir = tempfile::tempdir().unwrap();
        let stray = dir.path().join("image.raw");
        std::fs::write(&stray, b"x").unwrap();
        assert!(find_case_root(&stray).is_none());
    }

    fn acquire_command(case_id: &str, evidence_id: &str, device_id: &str) -> Command {
        Command::Acquire(Box::new(crate::cli::AcquireArgs {
            device_id: device_id.to_owned(),
            case_id: case_id.to_owned(),
            evidence_id: evidence_id.to_owned(),
            output: PathBuf::from("evidence/CASE-001"),
            method: crate::acquisition::DEFAULT_METHOD.to_owned(),
            source: None,
            sha512: false,
            examiner: None,
            notes: None,
            allow_source_read_errors: false,
            no_post_verify: false,
            dry_run: false,
        }))
    }

    #[test]
    fn a_valid_acquisition_gets_a_case_log() {
        let path = case_log_path(&acquire_command("CASE-001", "EV-1", "ABC123"))
            .expect("a valid acquisition must be logged into its case");
        assert!(path.starts_with("evidence/CASE-001"));
        assert!(path.to_string_lossy().contains("logs"));
        assert!(path.extension().is_some_and(|ext| ext == "jsonl"));
    }

    #[test]
    fn a_rejected_acquisition_prepares_no_case_log() {
        // Preparing the log creates directories, so an invocation that will be
        // rejected must not reach that point.
        for (case_id, evidence_id, device_id) in [
            ("../evil", "EV-1", "ABC123"),
            ("CASE-001", "../evil", "ABC123"),
            ("CASE-001", "EV-1", "-rf"),
            ("CON", "EV-1", "ABC123"),
        ] {
            assert!(
                case_log_path(&acquire_command(case_id, evidence_id, device_id)).is_none(),
                "case `{case_id}` / evidence `{evidence_id}` / device `{device_id}` \
                 must not prepare a case log"
            );
        }
    }

    #[test]
    fn commands_without_a_case_directory_have_no_case_log() {
        use crate::cli::{DevicesArgs, InfoArgs};
        assert!(case_log_path(&Command::Methods).is_none());
        assert!(case_log_path(&Command::Devices(DevicesArgs { no_details: false })).is_none());
        assert!(
            case_log_path(&Command::Info(InfoArgs {
                device_id: "ABC".to_owned()
            }))
            .is_none()
        );
    }
}
