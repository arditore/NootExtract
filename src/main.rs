//! Binary entry point.
//!
//! Responsibilities are deliberately narrow: parse arguments, install the
//! cancellation handler, initialize logging, dispatch, and translate the
//! outcome into the documented exit code. All work happens in the library so it
//! can be tested without spawning a process.

use std::process::ExitCode;

use clap::Parser;
use nootextract::cli::Cli;
use nootextract::commands;
use nootextract::error::{Error, Result};
use nootextract::logging::{self, Verbosity};
use nootextract::util::cancel;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.global.json;

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error, json);
            ExitCode::from(exit_status(&error))
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let cancel = cancel::install_signal_handler()?;

    let verbosity = Verbosity {
        verbose: cli.global.verbose,
        quiet: cli.global.quiet,
    };
    let log_file = commands::case_log_path(&cli.command);
    if let Some(warning) = logging::init(verbosity, cli.global.json, log_file.as_deref())? {
        tracing::warn!("{warning}");
    }

    commands::dispatch(cli, cancel)
}

/// Renders the error for the operator.
///
/// Errors always go to stderr so that stdout carries only command results.
fn report(error: &Error, json: bool) {
    if json {
        let payload = serde_json::json!({
            "error": {
                "kind": error.kind(),
                "message": error.to_string(),
                "exit_code": error.exit_code().as_i32(),
            }
        });
        // stdout may already hold partial results, so diagnostics go to stderr.
        if let Ok(rendered) = serde_json::to_string_pretty(&payload) {
            eprintln!("{rendered}");
        }
        return;
    }

    if matches!(error, Error::Cancelled) {
        eprintln!("nootextract: interrupted; any data already written has been preserved");
    } else {
        eprintln!("nootextract: error: {error}");
    }

    // Surface the underlying cause, which carries the actionable detail for I/O
    // failures.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

fn exit_status(error: &Error) -> u8 {
    let code = error.exit_code().as_i32();
    u8::try_from(code).unwrap_or(1)
}
