//! Command-line interface definition.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

use crate::acquisition::DEFAULT_METHOD;
use crate::adb::DEFAULT_ADB_PROGRAM;
use crate::imaging::ewf::{DEFAULT_ACQUIRE_PROGRAM, DEFAULT_VERIFY_PROGRAM};

/// Long description shown by `--help`.
const ABOUT: &str = "Acquisition and evidence preparation for authorized Android \
digital-forensics workflows.";

const LONG_ABOUT: &str = "\
NootExtract acquires evidence from Android devices over authorized channels, \
records what it did in a versioned manifest, and prepares the result for \
analysis tools such as Autopsy.

It uses only access the device already grants: USB debugging authorized for this \
host, and, for physical acquisition, a shell that is already privileged. It does \
not attempt to defeat lock screens, encryption, verified boot or any other \
protection mechanism. Where an authorized method cannot reach the data, the \
limitation is reported.

Original evidence is never modified, never overwritten and never deleted by this \
tool. Conversions and copies are written as separate derived artifacts.

EXIT CODES
  0    success; all integrity checks passed
  1    unclassified runtime failure
  2    command-line usage error
  3    device absent, offline, unauthorized or otherwise unusable
  4    acquisition started but did not complete
  5    integrity verification reported MISMATCH, MISSING or EXTRA
  6    unsafe destination (already occupied, not a directory, not writable)
  7    insufficient free space on the destination
  8    a required external tool was not found
  9    the operation is not supported by the available authorized methods
  130  interrupted by the operator";

#[derive(Debug, Parser)]
#[command(
    name = "nootextract",
    version,
    about = ABOUT,
    long_about = LONG_ABOUT,
    propagate_version = true,
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalArgs,

    #[command(subcommand)]
    pub command: Command,
}

/// Options accepted by every subcommand.
#[derive(Debug, Args, Clone)]
pub struct GlobalArgs {
    /// Increase log verbosity (-v for debug, -vv for trace).
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Suppress tables, summaries and informational logs.
    ///
    /// Errors are always reported, the exit code is unaffected, and `--json`
    /// output is still written. `hash` still prints its sha256sum-compatible
    /// digest line, which is the command's machine-readable result.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Emit machine-readable JSON on stdout and JSON logs on stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable the progress bar.
    #[arg(long, global = true)]
    pub no_progress: bool,

    /// Path to the `adb` executable.
    #[arg(long, global = true, value_name = "PATH", default_value = DEFAULT_ADB_PROGRAM)]
    pub adb_path: String,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List connected devices and their authorization state.
    Devices(DevicesArgs),

    /// Show identification metadata for one device.
    Info(InfoArgs),

    /// Acquire evidence from a device into a case directory.
    Acquire(Box<AcquireArgs>),

    /// Compute cryptographic digests of a file.
    Hash(HashArgs),

    /// Verify evidence against the manifests that describe it.
    Verify(VerifyArgs),

    /// Inspect and validate a manifest.
    Manifest(ManifestArgs),

    /// Convert an image into another format as a new derived artifact.
    Convert(Box<ConvertArgs>),

    /// Create a verified working copy of an artifact for analysis.
    Copy(CopyArgs),

    /// List the acquisition methods this build provides.
    Methods,
}

#[derive(Debug, Args)]
pub struct DevicesArgs {
    /// Do not read identification metadata from authorized devices.
    ///
    /// Listing stays limited to what the ADB server already reports.
    #[arg(long)]
    pub no_details: bool,
}

#[derive(Debug, Args)]
pub struct InfoArgs {
    /// ADB serial of the device.
    pub device_id: String,
}

#[derive(Debug, Args)]
pub struct AcquireArgs {
    /// ADB serial of the device to acquire.
    pub device_id: String,

    /// Case identifier recorded in the manifest.
    #[arg(long, value_name = "ID")]
    pub case_id: String,

    /// Evidence identifier recorded in the manifest and used in file names.
    #[arg(long, value_name = "ID")]
    pub evidence_id: String,

    /// Case directory to write into. Created if it does not exist.
    #[arg(short, long, value_name = "DIR")]
    pub output: PathBuf,

    /// Acquisition method. See `nootextract methods`.
    #[arg(long, value_name = "METHOD", default_value = DEFAULT_METHOD)]
    pub method: String,

    /// Source path on the device (directory for logical, block device for physical).
    #[arg(long, value_name = "PATH")]
    pub source: Option<String>,

    /// Also compute SHA-512 alongside the mandatory SHA-256.
    #[arg(long)]
    pub sha512: bool,

    /// Examiner name recorded in the manifest.
    #[arg(long, value_name = "NAME")]
    pub examiner: Option<String>,

    /// Free-text note recorded in the manifest.
    #[arg(long, value_name = "TEXT")]
    pub notes: Option<String>,

    /// Record source-side read errors and continue instead of failing.
    ///
    /// The acquisition status becomes `completed-with-errors` and every error
    /// is listed in the manifest. Continuing is never silent.
    #[arg(long)]
    pub allow_source_read_errors: bool,

    /// Skip re-reading the published artifact to confirm its digest.
    ///
    /// Halves the I/O at the cost of not detecting corruption introduced
    /// between the write and the rename.
    #[arg(long)]
    pub no_post_verify: bool,

    /// Report what would be done, without transferring any data.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct HashArgs {
    /// File to hash.
    pub path: PathBuf,

    /// Also compute SHA-512.
    #[arg(long)]
    pub sha512: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Case directory, or a single manifest to verify against.
    pub path: PathBuf,

    /// Report files that no manifest accounts for without failing.
    #[arg(long)]
    pub ignore_extra: bool,

    /// Skip SHA-512 recomputation even where the manifest recorded it.
    #[arg(long)]
    pub no_sha512: bool,
}

#[derive(Debug, Args)]
pub struct ManifestArgs {
    /// Manifest file, or a case directory whose manifests should be listed.
    pub path: PathBuf,
}

#[derive(Debug, Args)]
pub struct ConvertArgs {
    /// Source image. Must be inside the case directory.
    pub path: PathBuf,

    /// Target format: raw-segmented or ewf.
    #[arg(long, value_name = "FORMAT")]
    pub format: String,

    /// Case directory. Defaults to the case containing the source.
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Base name for the derived artifact set.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Segment size, for example 2G or 640M.
    #[arg(long, value_name = "SIZE")]
    pub segment_size: Option<String>,

    /// Case identifier recorded in the derived manifest.
    #[arg(long, value_name = "ID")]
    pub case_id: Option<String>,

    /// Evidence identifier recorded in the derived manifest.
    #[arg(long, value_name = "ID")]
    pub evidence_id: Option<String>,

    /// Examiner name recorded in the derived manifest.
    #[arg(long, value_name = "NAME")]
    pub examiner: Option<String>,

    /// Also compute SHA-512 for the derived artifacts.
    #[arg(long)]
    pub sha512: bool,

    /// Path to libewf's acquisition tool.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_ACQUIRE_PROGRAM)]
    pub ewfacquire_path: String,

    /// Path to libewf's verification tool.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_VERIFY_PROGRAM)]
    pub ewfverify_path: String,
}

#[derive(Debug, Args)]
pub struct CopyArgs {
    /// Artifact to copy. Must be inside the case directory.
    pub path: PathBuf,

    /// Case directory. Defaults to the case containing the source.
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// File name for the working copy. Defaults to the source file name.
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// Case identifier recorded in the derived manifest.
    #[arg(long, value_name = "ID")]
    pub case_id: Option<String>,

    /// Evidence identifier recorded in the derived manifest.
    #[arg(long, value_name = "ID")]
    pub evidence_id: Option<String>,

    /// Also compute SHA-512 for the working copy.
    #[arg(long)]
    pub sha512: bool,
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
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_an_acquisition_invocation() {
        let cli = Cli::try_parse_from([
            "nootextract",
            "acquire",
            "ABC123",
            "--case-id",
            "CASE-001",
            "--evidence-id",
            "EVIDENCE-001",
            "--output",
            "./evidence/CASE-001",
        ])
        .unwrap();

        let Command::Acquire(args) = cli.command else {
            panic!("expected the acquire subcommand");
        };
        assert_eq!(args.device_id, "ABC123");
        assert_eq!(args.case_id, "CASE-001");
        assert_eq!(args.evidence_id, "EVIDENCE-001");
        assert_eq!(args.output, PathBuf::from("./evidence/CASE-001"));
        assert_eq!(args.method, DEFAULT_METHOD);
        assert!(!args.sha512);
        assert!(!args.allow_source_read_errors);
        assert!(!args.no_post_verify);
    }

    #[test]
    fn acquisition_requires_case_and_evidence_identifiers() {
        assert!(
            Cli::try_parse_from(["nootextract", "acquire", "ABC123", "--output", "."]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "nootextract",
                "acquire",
                "ABC123",
                "--case-id",
                "CASE-001",
                "--output",
                "."
            ])
            .is_err()
        );
    }

    #[test]
    fn acquisition_requires_an_output_directory() {
        assert!(
            Cli::try_parse_from([
                "nootextract",
                "acquire",
                "ABC123",
                "--case-id",
                "CASE-001",
                "--evidence-id",
                "EV-1"
            ])
            .is_err()
        );
    }

    #[test]
    fn global_flags_are_accepted_after_the_subcommand() {
        let cli = Cli::try_parse_from(["nootextract", "devices", "--json", "-v"]).unwrap();
        assert!(cli.global.json);
        assert_eq!(cli.global.verbose, 1);
    }

    #[test]
    fn quiet_and_verbose_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["nootextract", "devices", "-q", "-v"]).is_err());
    }

    #[test]
    fn parses_every_documented_subcommand() {
        for argv in [
            vec!["nootextract", "devices"],
            vec!["nootextract", "info", "ABC123"],
            vec!["nootextract", "hash", "image.raw"],
            vec!["nootextract", "verify", "./evidence/CASE-001"],
            vec!["nootextract", "manifest", "./m.manifest.json"],
            vec![
                "nootextract",
                "convert",
                "image.raw",
                "--format",
                "raw-segmented",
            ],
            vec!["nootextract", "copy", "image.raw"],
            vec!["nootextract", "methods"],
        ] {
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "failed to parse {argv:?}"
            );
        }
    }

    #[test]
    fn unknown_subcommands_are_rejected() {
        assert!(Cli::try_parse_from(["nootextract", "bypass-lockscreen"]).is_err());
        assert!(Cli::try_parse_from(["nootextract", "crack"]).is_err());
    }

    #[test]
    fn exit_code_contract_is_documented_in_help() {
        for code in ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "130"] {
            assert!(
                LONG_ABOUT.contains(code),
                "exit code {code} is not documented"
            );
        }
    }

    #[test]
    fn adb_path_defaults_to_the_program_name() {
        let cli = Cli::try_parse_from(["nootextract", "devices"]).unwrap();
        assert_eq!(cli.global.adb_path, DEFAULT_ADB_PROGRAM);
    }

    #[test]
    fn adb_path_can_be_overridden() {
        let cli =
            Cli::try_parse_from(["nootextract", "devices", "--adb-path", "/opt/adb"]).unwrap();
        assert_eq!(cli.global.adb_path, "/opt/adb");
    }
}
