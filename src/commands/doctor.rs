//! Environment diagnostics.
//!
//! Most first-run failures are environmental rather than forensic: `adb` is not
//! installed, the device prompt was never accepted, a driver is missing, the
//! destination is full. Discovering that halfway through an acquisition wastes
//! the one thing an examiner may not get back — access to the device.
//!
//! `doctor` runs those checks up front and says what to do about each one. It is
//! strictly read-only: it starts no acquisition, writes no evidence, and touches
//! the device only with the same metadata commands the rest of the tool uses.

use std::path::Path;

use serde::Serialize;

use crate::cli::DoctorArgs;
use crate::commands::CommandContext;
use crate::error::Result;
use crate::evidence::store::EvidenceStore;
use crate::imaging::ewf::EwfConverter;
use crate::output::{print_json, print_line, print_table};
use crate::util::bytes::format_bytes;

/// Severity of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// The check passed.
    Ok,
    /// Usable, but something is worth knowing before starting.
    Warn,
    /// A core capability is unavailable.
    Fail,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

/// One diagnostic result.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
    /// What the operator can do about it, when there is something to do.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Check {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Ok,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn warn(name: &str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Warn,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }

    fn fail(name: &str, detail: impl Into<String>, remedy: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            status: Status::Fail,
            detail: detail.into(),
            remedy: Some(remedy.into()),
        }
    }
}

/// JSON shape of `nootextract doctor`.
#[derive(Debug, Serialize)]
struct DoctorOutput {
    checks: Vec<Check>,
    ready_to_acquire: bool,
}

/// `nootextract doctor`
pub fn run(context: &CommandContext, args: &DoctorArgs) -> Result<()> {
    let mut checks = vec![check_tool_version()];

    checks.push(check_adb(context));
    checks.extend(check_devices(context));
    checks.push(check_ewf(&args.ewfacquire_path));
    if let Some(output) = args.output.as_deref() {
        checks.push(check_destination(output));
    }

    // Readiness means an acquisition could start now, not that everything is
    // perfect: warnings are informative, failures are blocking.
    let ready = !checks.iter().any(|check| check.status == Status::Fail)
        && checks
            .iter()
            .any(|check| check.name == "device" && check.status == Status::Ok);

    if context.mode.json {
        return print_json(&DoctorOutput {
            checks,
            ready_to_acquire: ready,
        });
    }

    let rows: Vec<Vec<String>> = checks
        .iter()
        .map(|check| {
            vec![
                check.status.label().to_owned(),
                check.name.clone(),
                check.detail.clone(),
            ]
        })
        .collect();
    print_table(context.mode, &["STATUS", "CHECK", "DETAIL"], &rows);

    let remedies: Vec<&Check> = checks
        .iter()
        .filter(|check| check.remedy.is_some())
        .collect();
    if !remedies.is_empty() {
        print_line(context.mode, "");
        for check in remedies {
            if let Some(remedy) = &check.remedy {
                print_line(context.mode, &format!("{}: {remedy}", check.name));
            }
        }
    }

    print_line(
        context.mode,
        &format!(
            "\n{}",
            if ready {
                "Ready: an authorized device is connected and the environment is usable."
            } else {
                "Not ready: resolve the items above before acquiring."
            }
        ),
    );
    Ok(())
}

fn check_tool_version() -> Check {
    Check::ok(
        "nootextract",
        format!(
            "{} {} on {}/{}",
            crate::NAME,
            crate::VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    )
}

fn check_adb(context: &CommandContext) -> Check {
    match context.adb.version() {
        Ok(version) => Check::ok("adb", version),
        Err(e) => Check::fail(
            "adb",
            e.to_string(),
            "install the Android SDK platform-tools and put `adb` on PATH, or pass --adb-path",
        ),
    }
}

/// Lists transports and reports each one's usability separately.
fn check_devices(context: &CommandContext) -> Vec<Check> {
    let devices = match context.adb.list_devices() {
        Ok(devices) => devices,
        Err(e) => {
            return vec![Check::fail(
                "device",
                e.to_string(),
                "confirm the ADB server starts: run `adb devices` directly",
            )];
        }
    };

    if devices.is_empty() {
        return vec![Check::warn(
            "device",
            "no device is connected",
            "connect the device by USB, select a data-transfer mode, enable USB debugging \
             in Developer options, and accept the prompt shown on the device",
        )];
    }

    devices
        .into_iter()
        .map(|device| {
            if device.state.is_acquirable() {
                let model = device.display_model();
                Check::ok("device", format!("{} ({model}) authorized", device.serial))
            } else {
                let reason = device
                    .state
                    .blocking_reason()
                    .unwrap_or("not in an acquirable state");
                Check::warn(
                    "device",
                    format!("{} is {}", device.serial, device.state.label()),
                    reason.to_owned(),
                )
            }
        })
        .collect()
}

fn check_ewf(program: &str) -> Check {
    let converter = EwfConverter::new(program, program, crate::adb::SystemRunner::shared());
    match converter.version() {
        Ok(version) => Check::ok("libewf", version),
        Err(_) => Check::warn(
            "libewf",
            "not available; E01 conversion is unavailable",
            "optional. Install libewf (apt install ewf-tools / brew install libewf) only if \
             you need E01 output; raw and segmented raw need nothing extra",
        ),
    }
}

/// Confirms a destination can actually hold an acquisition.
fn check_destination(path: &Path) -> Check {
    match EvidenceStore::create(path) {
        Ok(store) => {
            let space = store.available_space();
            let detail = match space {
                Some(bytes) => format!("{} writable, {} free", path.display(), format_bytes(bytes)),
                None => format!("{} writable, free space unknown", path.display()),
            };
            // A logical acquisition of shared storage is routinely several
            // gigabytes, so a nearly full destination is worth flagging early.
            match space {
                Some(bytes) if bytes < 2 * 1024 * 1024 * 1024 => Check::warn(
                    "destination",
                    detail,
                    "less than 2 GiB free; an acquisition will probably not fit",
                ),
                _ => Check::ok("destination", detail),
            }
        }
        Err(e) => Check::fail(
            "destination",
            e.to_string(),
            "choose a directory you can write to, outside the evidence you are acquiring",
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(Status::Ok.label(), "OK");
        assert_eq!(Status::Warn.label(), "WARN");
        assert_eq!(Status::Fail.label(), "FAIL");
    }

    #[test]
    fn the_tool_check_always_passes_and_names_the_build() {
        let check = check_tool_version();
        assert_eq!(check.status, Status::Ok);
        assert!(check.detail.contains(crate::VERSION));
        assert!(check.remedy.is_none(), "a passing check needs no remedy");
    }

    #[test]
    fn a_missing_adb_fails_with_a_remedy() {
        let context = CommandContext::for_tests("nootextract-absent-adb");
        let check = check_adb(&context);
        assert_eq!(check.status, Status::Fail);
        assert!(check.remedy.unwrap().contains("platform-tools"));
    }

    #[test]
    fn a_missing_libewf_warns_rather_than_fails() {
        // E01 is optional, so its absence must not block an acquisition.
        let check = check_ewf("nootextract-absent-ewfacquire");
        assert_eq!(check.status, Status::Warn);
        assert!(check.remedy.unwrap().contains("optional"));
    }

    #[test]
    fn a_writable_destination_passes() {
        let dir = tempfile::tempdir().unwrap();
        let check = check_destination(&dir.path().join("CASE-001"));
        assert_eq!(check.status, Status::Ok, "{check:?}");
        assert!(check.detail.contains("writable"));
    }

    #[test]
    fn a_destination_that_is_a_file_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-a-directory");
        std::fs::write(&path, b"x").unwrap();
        let check = check_destination(&path);
        assert_eq!(check.status, Status::Fail);
        assert!(check.remedy.is_some());
    }

    #[test]
    fn every_non_passing_check_carries_a_remedy() {
        // A diagnostic that reports a problem without saying what to do about
        // it is not a diagnostic.
        let checks = [
            check_adb(&CommandContext::for_tests("nootextract-absent-adb")),
            check_ewf("nootextract-absent-ewfacquire"),
        ];
        for check in checks {
            if check.status != Status::Ok {
                assert!(
                    check.remedy.is_some(),
                    "`{}` reports {:?} without a remedy",
                    check.name,
                    check.status
                );
            }
        }
    }
}
