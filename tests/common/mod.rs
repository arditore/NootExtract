//! Shared helpers for the integration tests.
//!
//! No test in this suite touches a physical device. Device behaviour is
//! supplied by the scripted `nootextract-fake-adb` binary, and everything else
//! runs against synthetic fixtures in a temporary directory.

#![allow(dead_code, unreachable_pub)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::default_trait_access,
    clippy::integer_division
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

/// Serial advertised by the scripted ADB stand-in.
pub const FAKE_SERIAL: &str = "FAKEDEVICE01";

/// A command targeting the real `nootextract` binary under test.
pub fn nootextract() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nootextract"))
}

/// Creates an isolated working directory.
pub fn workspace() -> TempDir {
    tempfile::tempdir().expect("could not create a temporary directory")
}

/// Writes a synthetic fixture file and returns its path.
pub fn fixture(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("could not write fixture");
    path
}

/// Reads a file as UTF-8.
pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("could not read file")
}

/// Parses a command's stdout as JSON.
pub fn json(output: &std::process::Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!("stdout was not valid JSON ({e}):\n{text}");
    })
}

/// Exit code of a finished command, or `None` when it was signalled.
pub fn code(output: &std::process::Output) -> Option<i32> {
    output.status.code()
}

/// Lists file names directly inside a directory.
pub fn list_dir(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// Finds the single file in a directory whose name ends with `suffix`.
pub fn find_file(dir: &Path, suffix: &str) -> PathBuf {
    let matches: Vec<String> = list_dir(dir)
        .into_iter()
        .filter(|name| name.ends_with(suffix))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `*{suffix}` in {}, found {matches:?}",
        dir.display()
    );
    dir.join(matches.first().expect("checked above"))
}
