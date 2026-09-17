//! Operator-facing output.
//!
//! Command results go to stdout; diagnostics and progress go to stderr. That
//! separation is what makes `nootextract ... --json | jq` usable while a
//! progress bar is on screen.
//!
//! Nothing here formats a success claim on its own: callers pass the result they
//! actually obtained.

use std::io::{IsTerminal, Write};

use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::acquisition::backend::ProgressSink;
use crate::error::{Error, Result};
use crate::util::bytes::format_bytes;

/// How results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutputMode {
    pub json: bool,
    pub quiet: bool,
    pub progress: bool,
}

impl OutputMode {
    /// Whether a progress bar should be drawn.
    ///
    /// Suppressed when output is machine-readable, when the operator asked for
    /// quiet, or when stderr is not a terminal — a progress bar in a log file
    /// is noise.
    pub fn show_progress(self) -> bool {
        self.progress && !self.json && !self.quiet && std::io::stderr().is_terminal()
    }
}

impl Default for OutputMode {
    fn default() -> Self {
        Self {
            json: false,
            quiet: false,
            progress: true,
        }
    }
}

/// Writes a value to stdout as pretty JSON.
pub fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|e| Error::InvalidData(format!("serializing output failed: {e}")))?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .map_err(|e| Error::io("write", "<stdout>", e))?;
    stdout
        .write_all(b"\n")
        .map_err(|e| Error::io("write", "<stdout>", e))?;
    Ok(())
}

/// Writes a line to stdout unless quiet is in effect.
pub fn print_line(mode: OutputMode, line: &str) {
    if !mode.quiet {
        println!("{line}");
    }
}

/// Prints a table unless quiet is in effect.
///
/// Tables are the human presentation of a result. `--quiet` suppresses them;
/// the same data remains available through `--json`, and the exit code is
/// unaffected either way.
pub fn print_table(mode: OutputMode, headers: &[&str], rows: &[Vec<String>]) {
    if !mode.quiet {
        print!("{}", render_table(headers, rows));
    }
}

/// Renders a fixed-width table.
///
/// Column widths are computed from the content, and every cell is printed as
/// given: callers sanitize device-controlled strings before they get here.
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    use std::fmt::Write as _;

    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(cell.chars().count());
            }
        }
    }

    let mut out = String::new();
    for (index, header) in headers.iter().enumerate() {
        let width = widths.get(index).copied().unwrap_or(0);
        let _ = write!(out, "{header:<width$}  ");
    }
    out.push('\n');
    for (index, _) in headers.iter().enumerate() {
        let width = widths.get(index).copied().unwrap_or(0);
        out.push_str(&"-".repeat(width));
        out.push_str("  ");
    }
    out.push('\n');
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            let width = widths.get(index).copied().unwrap_or(0);
            let _ = write!(out, "{cell:<width$}  ");
        }
        out.push('\n');
    }
    out
}

/// A [`ProgressSink`] backed by an `indicatif` bar.
#[derive(Debug)]
pub struct BarProgress {
    bar: Option<ProgressBar>,
    label: String,
}

impl BarProgress {
    /// Creates a bar, or an inert sink when progress is suppressed.
    pub fn new(mode: OutputMode, label: impl Into<String>) -> Self {
        Self {
            bar: mode.show_progress().then(ProgressBar::hidden),
            label: label.into(),
        }
    }
}

impl ProgressSink for BarProgress {
    fn start(&mut self, total_bytes: Option<u64>) {
        let Some(bar) = self.bar.as_mut() else {
            return;
        };
        let new_bar = if let Some(total) = total_bytes {
            let bar = ProgressBar::new(total);
            if let Ok(style) = ProgressStyle::with_template(
                "{msg} [{bar:32}] {bytes}/{total_bytes} ({bytes_per_sec}, eta {eta})",
            ) {
                bar.set_style(style.progress_chars("=> "));
            }
            bar
        } else {
            let bar = ProgressBar::new_spinner();
            if let Ok(style) =
                ProgressStyle::with_template("{msg} {spinner} {bytes} ({bytes_per_sec})")
            {
                bar.set_style(style);
            }
            bar
        };
        new_bar.set_message(self.label.clone());
        *bar = new_bar;
    }

    fn update(&mut self, written_bytes: u64) {
        if let Some(bar) = self.bar.as_ref() {
            bar.set_position(written_bytes);
        }
    }

    fn finish(&mut self, written_bytes: u64) {
        if let Some(bar) = self.bar.as_ref() {
            bar.set_position(written_bytes);
            bar.finish_with_message(format!(
                "{} — {} written",
                self.label,
                format_bytes(written_bytes)
            ));
        }
    }
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
    fn json_mode_suppresses_progress() {
        let mode = OutputMode {
            json: true,
            quiet: false,
            progress: true,
        };
        assert!(!mode.show_progress());
    }

    #[test]
    fn quiet_mode_suppresses_progress() {
        let mode = OutputMode {
            json: false,
            quiet: true,
            progress: true,
        };
        assert!(!mode.show_progress());
    }

    #[test]
    fn disabled_progress_stays_disabled() {
        let mode = OutputMode {
            json: false,
            quiet: false,
            progress: false,
        };
        assert!(!mode.show_progress());
    }

    #[test]
    fn inert_progress_sink_is_safe_to_drive() {
        let mut progress = BarProgress::new(
            OutputMode {
                json: true,
                quiet: false,
                progress: true,
            },
            "acquiring",
        );
        progress.start(Some(100));
        progress.update(50);
        progress.finish(100);
        assert!(progress.bar.is_none());
    }

    #[test]
    fn renders_an_aligned_table() {
        let table = render_table(
            &["SERIAL", "STATE"],
            &[
                vec!["ABC123".to_owned(), "authorized".to_owned()],
                vec!["LONGER-SERIAL-1".to_owned(), "offline".to_owned()],
            ],
        );
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("SERIAL "));
        assert!(lines[1].starts_with("---"));
        assert!(lines[2].contains("ABC123"));
        assert!(lines[3].contains("LONGER-SERIAL-1"));
        // The state column must line up across rows.
        let authorized = lines[2].find("authorized").unwrap();
        let offline = lines[3].find("offline").unwrap();
        assert_eq!(authorized, offline);
    }

    #[test]
    fn renders_an_empty_table() {
        let table = render_table(&["A", "B"], &[]);
        assert_eq!(table.lines().count(), 2);
    }
}
