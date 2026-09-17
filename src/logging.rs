//! Structured logging setup.
//!
//! Two sinks are configured:
//!
//! * **stderr** — operator-facing. Human-readable by default, JSON when
//!   `--json` is in effect so a wrapper can consume a single machine-readable
//!   stream. Never stdout, which carries command results.
//! * **case log** — `logs/<operation-id>.jsonl` inside the evidence directory,
//!   always JSON Lines, one object per event, so the run is reconstructable
//!   after the fact.
//!
//! Every record carries a timestamp, a level, the target module, the message and
//! whatever structured fields the call site attached — `device_id`,
//! `acquisition_id`, `artifact`, `bytes`, `status`. Device-controlled strings
//! are sanitized before they are logged, so a hostile property value cannot
//! forge a log line.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::error::{Error, IoResultExt, Result};

/// Environment variable that overrides the computed filter.
const FILTER_ENV: &str = "NOOTEXTRACT_LOG";

/// Console verbosity selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verbosity {
    pub verbose: u8,
    pub quiet: bool,
}

impl Verbosity {
    pub fn level(self) -> Level {
        if self.quiet {
            // Errors are never suppressed: a silent failure is worse than noise.
            return Level::ERROR;
        }
        match self.verbose {
            0 => Level::INFO,
            1 => Level::DEBUG,
            _ => Level::TRACE,
        }
    }
}

/// A file sink shared between layers.
#[derive(Debug, Clone)]
struct SharedFile(Arc<Mutex<std::fs::File>>);

impl Write for SharedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut file = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex was poisoned"))?;
        file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut file = self
            .0
            .lock()
            .map_err(|_| std::io::Error::other("log file mutex was poisoned"))?;
        file.flush()
    }
}

impl<'a> MakeWriter<'a> for SharedFile {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Initializes the global subscriber.
///
/// Must be called at most once per process; a second call is reported as an
/// error rather than silently ignored. Returns a warning when the case log
/// could not be opened but console logging is in place.
pub fn init(
    verbosity: Verbosity,
    json_console: bool,
    log_file: Option<&Path>,
) -> Result<Option<String>> {
    let filter = EnvFilter::try_from_env(FILTER_ENV)
        .unwrap_or_else(|_| EnvFilter::new(verbosity.level().as_str().to_lowercase()));

    let console = if json_console {
        tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(false)
            .with_writer(std::io::stderr)
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_writer(std::io::stderr)
            .boxed()
    };

    // A case log that cannot be opened must not abort the command. The
    // destination is validated by the command itself, which reports the real
    // problem with the right exit code; failing here would mask it behind a
    // logging error. The shortfall is returned so the caller can warn about it.
    let mut warning = None;
    let file_layer = match log_file {
        Some(path) => match open_case_log(path) {
            Ok(writer) => Some(
                tracing_subscriber::fmt::layer()
                    .json()
                    .flatten_event(true)
                    .with_current_span(false)
                    .with_ansi(false)
                    .with_writer(writer)
                    .boxed(),
            ),
            Err(e) => {
                warning = Some(format!(
                    "the case log `{}` could not be opened, so this run is only recorded on \
                     the console: {e}",
                    path.display()
                ));
                None
            }
        },
        None => None,
    };

    tracing_subscriber::registry()
        .with(filter)
        .with(console)
        .with(file_layer)
        .try_init()
        .map_err(|e| Error::InvalidData(format!("logging is already initialized: {e}")))?;

    Ok(warning)
}

fn open_case_log(path: &Path) -> Result<SharedFile> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ctx("create directory", parent)?;
    }
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ctx("open log file", path)?;
    Ok(SharedFile(Arc::new(Mutex::new(file))))
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
    fn verbosity_maps_to_levels() {
        assert_eq!(
            Verbosity {
                verbose: 0,
                quiet: false
            }
            .level(),
            Level::INFO
        );
        assert_eq!(
            Verbosity {
                verbose: 1,
                quiet: false
            }
            .level(),
            Level::DEBUG
        );
        assert_eq!(
            Verbosity {
                verbose: 5,
                quiet: false
            }
            .level(),
            Level::TRACE
        );
    }

    #[test]
    fn quiet_still_reports_errors() {
        let level = Verbosity {
            verbose: 0,
            quiet: true,
        }
        .level();
        assert_eq!(level, Level::ERROR);
    }

    #[test]
    fn quiet_overrides_verbose() {
        assert_eq!(
            Verbosity {
                verbose: 3,
                quiet: true
            }
            .level(),
            Level::ERROR
        );
    }

    #[test]
    fn shared_file_writes_through() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("log.jsonl");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        let mut writer = SharedFile(Arc::new(Mutex::new(file)));
        writer.write_all(b"{\"event\":\"test\"}\n").unwrap();
        writer.flush().unwrap();
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("\"event\":\"test\"")
        );
    }
}
