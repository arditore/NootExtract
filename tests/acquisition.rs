//! End-to-end acquisition, verification, conversion and copy workflows.
//!
//! Device behaviour comes from the scripted `nootextract-fake-adb` binary, so
//! these tests exercise the real command paths — argument construction, stream
//! handling, hashing, manifest generation and exit codes — without a handset.
//! They do not, and cannot, demonstrate that any particular physical device or
//! Android version behaves as modelled here.

#![cfg(feature = "test-support")]
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

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{FAKE_SERIAL, code, find_file, json, list_dir, nootextract, workspace};
use tempfile::TempDir;

/// Path of the scripted ADB stand-in.
fn fake_adb() -> &'static str {
    env!("CARGO_BIN_EXE_nootextract-fake-adb")
}

/// A case directory plus the scenario the scripted device will play.
struct Fixture {
    guard: TempDir,
    scenario: String,
    payload_bytes: Option<u64>,
}

impl Fixture {
    fn new(scenario: &str) -> Self {
        Self {
            guard: workspace(),
            scenario: scenario.to_owned(),
            payload_bytes: None,
        }
    }

    fn with_payload(mut self, bytes: u64) -> Self {
        self.payload_bytes = Some(bytes);
        self
    }

    fn case_root(&self) -> PathBuf {
        self.guard.path().join("CASE-001")
    }

    /// Builds a command with the scripted device wired in.
    fn command(&self) -> Command {
        let mut command = nootextract();
        command.env("FAKE_ADB_SCENARIO", &self.scenario).args([
            "--adb-path",
            fake_adb(),
            "--no-progress",
        ]);
        if let Some(bytes) = self.payload_bytes {
            command.env("FAKE_ADB_PAYLOAD_BYTES", bytes.to_string());
        }
        command
    }

    fn acquire(&self, extra: &[&str]) -> std::process::Output {
        let mut command = self.command();
        command
            .arg("acquire")
            .arg(FAKE_SERIAL)
            .args(["--case-id", "CASE-001", "--evidence-id", "EVIDENCE-001"])
            .arg("--output")
            .arg(self.case_root())
            .args(extra);
        command.output().expect("acquire failed to run")
    }

    fn verify(&self, extra: &[&str]) -> std::process::Output {
        self.command()
            .arg("verify")
            .arg(self.case_root())
            .args(extra)
            .output()
            .expect("verify failed to run")
    }

    fn original(&self, name: &str) -> PathBuf {
        self.case_root().join("original").join(name)
    }
}

fn sole_manifest(root: &Path) -> serde_json::Value {
    let path = find_file(&root.join("manifests"), ".manifest.json");
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn devices_reports_an_authorized_device_as_acquirable() {
    let fixture = Fixture::new("authorized");
    let output = fixture
        .command()
        .args(["devices", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(0));

    let value = json(&output);
    let devices = value["devices"].as_array().unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["serial"], FAKE_SERIAL);
    assert_eq!(devices[0]["state"], "authorized");
    assert_eq!(devices[0]["acquirable"], true);
    assert_eq!(devices[0]["metadata"]["model"], "Fake Model X");
    assert_eq!(devices[0]["metadata"]["android_release"], "14");
}

#[test]
fn an_unauthorized_device_is_never_presented_as_available() {
    let fixture = Fixture::new("unauthorized");
    let output = fixture
        .command()
        .args(["devices", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(0));

    let value = json(&output);
    let device = &value["devices"][0];
    assert_eq!(device["state"], "unauthorized");
    assert_eq!(device["acquirable"], false);
    assert!(
        device["blocked_reason"]
            .as_str()
            .unwrap()
            .contains("USB debugging prompt")
    );
}

#[test]
fn mixed_device_states_are_distinguished() {
    let fixture = Fixture::new("mixed");
    let output = fixture
        .command()
        .args(["devices", "--json"])
        .output()
        .unwrap();
    let value = json(&output);
    let devices = value["devices"].as_array().unwrap();

    let states: Vec<&str> = devices
        .iter()
        .filter_map(|device| device["state"].as_str())
        .collect();
    assert!(states.contains(&"authorized"));
    assert!(states.contains(&"unauthorized"));
    assert!(states.contains(&"offline"));

    let acquirable = devices
        .iter()
        .filter(|device| device["acquirable"] == true)
        .count();
    assert_eq!(
        acquirable, 1,
        "only the authorized device may be acquirable"
    );
}

#[test]
fn info_reports_identification_metadata() {
    let fixture = Fixture::new("authorized");
    let output = fixture
        .command()
        .args(["info", FAKE_SERIAL, "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(0));

    let value = json(&output);
    assert_eq!(value["metadata"]["manufacturer"], "FakeVendor");
    assert_eq!(value["metadata"]["build_id"], "FAKE.240101.001");
    assert_eq!(value["metadata"]["crypto_state"], "encrypted");
    assert_eq!(value["metadata"]["shell_uid"], 2000);
    // No telephony, account or subscriber identifier may be collected.
    let rendered = value.to_string();
    for forbidden in ["imei", "phone", "subscriber", "account"] {
        assert!(
            !rendered.contains(forbidden),
            "`{forbidden}` must not appear"
        );
    }
}

#[test]
fn info_on_an_absent_device_uses_the_device_exit_code() {
    let fixture = Fixture::new("empty");
    let output = fixture
        .command()
        .args(["info", FAKE_SERIAL])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(3));
}

#[test]
fn a_logical_acquisition_produces_a_hashed_and_manifested_artifact() {
    let fixture = Fixture::new("authorized").with_payload(65_536);
    let output = fixture.acquire(&["--json"]);
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = json(&output);
    assert_eq!(result["status"], "completed");
    let artifact = &result["artifacts"][0];
    assert_eq!(artifact["path"], "original/EVIDENCE-001-logical.tar");
    assert_eq!(artifact["size_bytes"], 65_536);
    assert_eq!(artifact["complete"], true);

    let image = fixture.original("EVIDENCE-001-logical.tar");
    assert!(image.is_file());
    assert_eq!(std::fs::metadata(&image).unwrap().len(), 65_536);
    // No partial file may survive a completed transfer.
    assert!(
        !fixture
            .original("EVIDENCE-001-logical.tar.partial")
            .exists()
    );

    // The digest recorded must be the digest of the file on disk.
    let hash_output = fixture
        .command()
        .args(["hash", "--json"])
        .arg(&image)
        .output()
        .unwrap();
    assert_eq!(json(&hash_output)["sha256"], artifact["sha256"]);

    // Every companion record exists.
    assert_eq!(list_dir(&fixture.case_root().join("manifests")).len(), 1);
    assert_eq!(list_dir(&fixture.case_root().join("hashes")).len(), 1);
    assert_eq!(list_dir(&fixture.case_root().join("logs")).len(), 1);
}

#[test]
fn the_manifest_records_everything_the_schema_requires() {
    let fixture = Fixture::new("authorized").with_payload(8192);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let manifest = sole_manifest(&fixture.case_root());
    assert_eq!(manifest["manifest_version"], "1.0");
    assert_eq!(manifest["case"]["case_id"], "CASE-001");
    assert_eq!(manifest["case"]["evidence_id"], "EVIDENCE-001");
    assert_eq!(manifest["tool"]["name"], "nootextract");
    assert_eq!(manifest["tool"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(manifest["operation"]["method"], "adb-logical-tar");
    assert_eq!(manifest["operation"]["status"], "completed");
    assert!(manifest["operation"]["started_at"].is_string());
    assert!(manifest["operation"]["completed_at"].is_string());
    assert!(manifest["host"]["os"].is_string());
    assert_eq!(manifest["device"]["model"], "Fake Model X");
    assert_eq!(manifest["device"]["serial"], FAKE_SERIAL);

    let artifact = &manifest["artifacts"][0];
    assert_eq!(artifact["classification"], "original");
    assert_eq!(artifact["role"], "logical-archive");
    assert_eq!(artifact["format"], "tar");
    assert_eq!(artifact["size_bytes"], 8192);
    assert_eq!(artifact["hashes"]["sha256"].as_str().unwrap().len(), 64);

    // The remote command is recorded verbatim for reproducibility.
    let remote = manifest["operation"]["source"]["remote_command"]
        .as_array()
        .unwrap();
    assert_eq!(remote[0], "tar");
    assert_eq!(remote.last().unwrap(), "/sdcard");
}

#[test]
fn the_event_log_reads_in_chronological_order() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let manifest = sole_manifest(&fixture.case_root());
    let events = manifest["events"].as_array().unwrap();
    assert!(events.len() >= 4, "{events:?}");

    let timestamps: Vec<&str> = events
        .iter()
        .filter_map(|event| event["timestamp"].as_str())
        .collect();
    let mut sorted = timestamps.clone();
    sorted.sort_unstable();
    assert_eq!(
        timestamps, sorted,
        "events must read in the order they happened"
    );

    let names: Vec<&str> = events
        .iter()
        .filter_map(|event| event["event"].as_str())
        .collect();
    assert_eq!(names.first(), Some(&"transfer-started"));
    assert_eq!(names.last(), Some(&"manifest-generated"));
    assert!(names.contains(&"post-write-verification"));
}

#[test]
fn sha512_is_recorded_when_requested() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&["--sha512"])), Some(0));

    let manifest = sole_manifest(&fixture.case_root());
    let hashes = &manifest["artifacts"][0]["hashes"];
    assert_eq!(hashes["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(hashes["sha512"].as_str().unwrap().len(), 128);
}

#[test]
fn the_case_log_is_machine_readable() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let log = find_file(&fixture.case_root().join("logs"), ".jsonl");
    let text = std::fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert!(!lines.is_empty(), "the case log must not be empty");

    for line in &lines {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("log line is not JSON ({e}): {line}"));
        assert!(value["timestamp"].is_string());
        assert!(value["level"].is_string());
    }
    assert!(text.contains("acquisition starting"));
    assert!(text.contains(FAKE_SERIAL));
}

#[test]
fn verification_passes_for_freshly_acquired_evidence() {
    let fixture = Fixture::new("authorized").with_payload(16_384);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let output = fixture.verify(&["--json"]);
    assert_eq!(code(&output), Some(0));

    let report = json(&output);
    assert_eq!(report["counts"]["MATCH"], 1);
    assert_eq!(report["counts"]["MISMATCH"], 0);
    assert_eq!(report["counts"]["MISSING"], 0);
    assert_eq!(report["counts"]["EXTRA"], 0);
}

#[test]
fn verification_detects_a_modified_artifact() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    // Flip content while keeping the length identical.
    let image = fixture.original("EVIDENCE-001-logical.tar");
    let mut bytes = std::fs::read(&image).unwrap();
    bytes[0] ^= 0xff;
    std::fs::write(&image, &bytes).unwrap();

    let output = fixture.verify(&["--json"]);
    assert_eq!(
        code(&output),
        Some(5),
        "a mismatch must not exit successfully"
    );

    let report = json(&output);
    assert_eq!(report["counts"]["MISMATCH"], 1);
    assert_eq!(report["results"][0]["outcome"], "MISMATCH");
}

#[test]
fn verification_detects_a_truncated_artifact() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let image = fixture.original("EVIDENCE-001-logical.tar");
    std::fs::write(&image, b"truncated").unwrap();

    let output = fixture.verify(&["--json"]);
    assert_eq!(code(&output), Some(5));
    let report = json(&output);
    assert!(
        report["results"][0]["detail"]
            .as_str()
            .unwrap()
            .contains("size differs")
    );
}

#[test]
fn verification_detects_a_missing_artifact() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    std::fs::remove_file(fixture.original("EVIDENCE-001-logical.tar")).unwrap();

    let output = fixture.verify(&["--json"]);
    assert_eq!(code(&output), Some(5));
    assert_eq!(json(&output)["counts"]["MISSING"], 1);
}

#[test]
fn verification_detects_an_unaccounted_file() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    std::fs::write(
        fixture.original("planted.bin"),
        b"not from this acquisition",
    )
    .unwrap();

    let output = fixture.verify(&["--json"]);
    assert_eq!(code(&output), Some(5));
    assert_eq!(json(&output)["counts"]["EXTRA"], 1);

    // The same case passes once extra files are explicitly tolerated.
    let tolerated = fixture.verify(&["--json", "--ignore-extra"]);
    assert_eq!(code(&tolerated), Some(0));
    assert_eq!(json(&tolerated)["counts"]["EXTRA"], 1);
}

#[test]
fn an_unauthorized_device_cannot_be_acquired() {
    let fixture = Fixture::new("unauthorized");
    let output = fixture.acquire(&[]);
    assert_eq!(code(&output), Some(3));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unauthorized"), "{stderr}");
    // Nothing may have been written into original/.
    assert!(list_dir(&fixture.case_root().join("original")).is_empty());
    assert!(list_dir(&fixture.case_root().join("manifests")).is_empty());
}

#[test]
fn an_offline_device_cannot_be_acquired() {
    let fixture = Fixture::new("offline");
    assert_eq!(code(&fixture.acquire(&[])), Some(3));
    assert!(list_dir(&fixture.case_root().join("original")).is_empty());
}

#[test]
fn a_missing_device_utility_is_reported_as_a_limitation() {
    let fixture = Fixture::new("no-tar");
    let output = fixture.acquire(&[]);
    assert_eq!(
        code(&output),
        Some(9),
        "a limitation uses the unsupported code"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("tar"), "{stderr}");
    assert!(list_dir(&fixture.case_root().join("original")).is_empty());
}

#[test]
fn an_interrupted_transfer_preserves_partial_data_and_fails() {
    let fixture = Fixture::new("fail-mid").with_payload(32_768);
    let output = fixture.acquire(&[]);
    assert_eq!(
        code(&output),
        Some(4),
        "a failed acquisition must not exit 0"
    );

    // The partial data is preserved under an unambiguous name.
    let partial = fixture.original("EVIDENCE-001-logical.tar.partial");
    assert!(partial.is_file(), "partial data must be preserved");
    assert_eq!(std::fs::metadata(&partial).unwrap().len(), 16_384);
    // The final name stays free, so nothing can be mistaken for a full image.
    assert!(!fixture.original("EVIDENCE-001-logical.tar").exists());

    // The failure is documented rather than silent.
    let manifest = sole_manifest(&fixture.case_root());
    assert_eq!(manifest["operation"]["status"], "failed");
    assert_eq!(manifest["artifacts"][0]["complete"], false);
    assert!(
        manifest["artifacts"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with(".partial")
    );
    let errors = manifest["errors"].as_array().unwrap();
    assert!(!errors.is_empty(), "the failure must be recorded");
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("Permission denied"))
    );

    // Even a failed acquisition leaves a verifiable evidence set.
    assert_eq!(code(&fixture.verify(&["--json"])), Some(0));
}

#[test]
fn source_read_errors_can_be_recorded_instead_of_failing() {
    let fixture = Fixture::new("fail-mid").with_payload(32_768);
    let output = fixture.acquire(&["--allow-source-read-errors", "--json"]);
    assert_eq!(code(&output), Some(0));

    let result = json(&output);
    assert_eq!(result["status"], "completed-with-errors");
    assert!(
        !result["errors"].as_array().unwrap().is_empty(),
        "continuing must never be silent"
    );

    let manifest = sole_manifest(&fixture.case_root());
    assert_eq!(manifest["operation"]["status"], "completed-with-errors");
    assert_eq!(
        manifest["operation"]["parameters"]["allow_source_read_errors"],
        "true"
    );
}

#[test]
fn device_warnings_do_not_turn_into_a_failure() {
    let fixture = Fixture::new("stderr-noise").with_payload(4096);
    let output = fixture.acquire(&["--json"]);
    assert_eq!(code(&output), Some(0));

    let result = json(&output);
    assert_eq!(result["status"], "completed");
    let warnings = result["warnings"].to_string();
    assert!(warnings.contains("removing leading"), "{warnings}");
}

#[test]
fn an_existing_original_is_never_overwritten() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let image = fixture.original("EVIDENCE-001-logical.tar");
    let first = std::fs::read(&image).unwrap();

    // A second run with the same evidence identifier must refuse.
    let output = fixture.acquire(&[]);
    assert_eq!(code(&output), Some(6));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("already exists"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&image).unwrap(),
        first,
        "the original changed"
    );
}

#[test]
fn an_abandoned_partial_file_blocks_a_silent_retry() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    std::fs::create_dir_all(fixture.case_root().join("original")).unwrap();
    let partial = fixture.original("EVIDENCE-001-logical.tar.partial");
    std::fs::write(&partial, b"data from an earlier attempt").unwrap();

    let output = fixture.acquire(&[]);
    assert_eq!(code(&output), Some(6));
    assert_eq!(
        std::fs::read(&partial).unwrap(),
        b"data from an earlier attempt"
    );
}

#[test]
fn a_dry_run_transfers_nothing() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    let output = fixture.acquire(&["--dry-run", "--json"]);
    assert_eq!(code(&output), Some(0));

    let plan = json(&output);
    assert_eq!(plan["method"], "adb-logical-tar");
    assert_eq!(plan["acquisition_kind"], "logical");
    assert_eq!(plan["source_path"], "/sdcard");
    assert!(plan["warnings"].as_array().unwrap().iter().any(|warning| {
        warning
            .as_str()
            .unwrap_or_default()
            .contains("encrypted userdata")
    }));

    assert!(list_dir(&fixture.case_root().join("original")).is_empty());
    assert!(list_dir(&fixture.case_root().join("manifests")).is_empty());
}

#[test]
fn physical_acquisition_requires_an_explicit_source() {
    let fixture = Fixture::new("root");
    let output = fixture.acquire(&["--method", "adb-physical-dd"]);
    assert_eq!(code(&output), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("never guessed"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn physical_acquisition_reports_an_unprivileged_shell_as_a_limitation() {
    let fixture = Fixture::new("authorized");
    let output = fixture.acquire(&[
        "--method",
        "adb-physical-dd",
        "--source",
        "/dev/block/by-name/userdata",
    ]);
    assert_eq!(code(&output), Some(9));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not attempt to obtain privileges"),
        "{stderr}"
    );
    assert!(list_dir(&fixture.case_root().join("original")).is_empty());
}

#[test]
fn physical_acquisition_works_on_an_already_privileged_shell() {
    let fixture = Fixture::new("root").with_payload(65_536);
    let output = fixture.acquire(&[
        "--method",
        "adb-physical-dd",
        "--source",
        "/dev/block/by-name/userdata",
        "--json",
    ]);
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = json(&output);
    assert_eq!(result["status"], "completed");
    assert_eq!(
        result["artifacts"][0]["path"],
        "original/EVIDENCE-001-userdata.raw"
    );
    assert_eq!(result["artifacts"][0]["size_bytes"], 65_536);

    let manifest = sole_manifest(&fixture.case_root());
    assert_eq!(manifest["operation"]["method"], "adb-physical-dd");
    assert_eq!(manifest["artifacts"][0]["role"], "physical-image");
    assert_eq!(manifest["operation"]["parameters"]["shell_uid"], "0");
    assert_eq!(code(&fixture.verify(&[])), Some(0));
}

#[test]
fn an_unknown_method_lists_the_available_ones() {
    let fixture = Fixture::new("authorized");
    let output = fixture.acquire(&["--method", "jtag-chipoff"]);
    assert_eq!(code(&output), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("adb-logical-tar"));
}

#[test]
fn a_raw_image_converts_into_a_segmented_set() {
    let fixture = Fixture::new("root").with_payload(3 * 1024 * 1024);
    assert_eq!(
        code(&fixture.acquire(&[
            "--method",
            "adb-physical-dd",
            "--source",
            "/dev/block/by-name/userdata",
        ])),
        Some(0)
    );

    let image = fixture.original("EVIDENCE-001-userdata.raw");
    let before = std::fs::read(&image).unwrap();

    let output = fixture
        .command()
        .arg("convert")
        .arg(&image)
        .args([
            "--format",
            "raw-segmented",
            "--segment-size",
            "1M",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = json(&output);
    let artifacts = result["artifacts"].as_array().unwrap();
    assert_eq!(artifacts.len(), 3);
    assert_eq!(artifacts[0]["path"], "derived/EVIDENCE-001-userdata.001");
    assert_eq!(artifacts[2]["path"], "derived/EVIDENCE-001-userdata.003");
    assert!(artifacts.iter().all(|a| a["classification"] == "derived"));

    // Concatenating the segments reproduces the original byte for byte.
    let mut rebuilt = Vec::new();
    for index in 1..=3 {
        let segment = fixture
            .case_root()
            .join("derived")
            .join(format!("EVIDENCE-001-userdata.{index:03}"));
        rebuilt.extend_from_slice(&std::fs::read(&segment).unwrap());
    }
    assert_eq!(rebuilt, before);

    // The original is untouched and both manifests coexist.
    assert_eq!(std::fs::read(&image).unwrap(), before);
    assert_eq!(list_dir(&fixture.case_root().join("manifests")).len(), 2);
    assert_eq!(code(&fixture.verify(&[])), Some(0));
}

#[test]
fn converting_a_sha512_source_without_requesting_sha512_is_not_a_mismatch() {
    // The source is verified with SHA-512 because its manifest records one,
    // while the conversion computes SHA-256 only. Comparing whole digest sets
    // instead of their common algorithms would report a false integrity failure.
    let fixture = Fixture::new("root").with_payload(4 * 1024 * 1024);
    assert_eq!(
        code(&fixture.acquire(&[
            "--sha512",
            "--method",
            "adb-physical-dd",
            "--source",
            "/dev/block/by-name/userdata",
        ])),
        Some(0)
    );

    let output = fixture
        .command()
        .arg("convert")
        .arg(fixture.original("EVIDENCE-001-userdata.raw"))
        .args([
            "--format",
            "raw-segmented",
            "--segment-size",
            "2M",
            "--json",
        ])
        .output()
        .unwrap();

    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(json(&output)["artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(code(&fixture.verify(&[])), Some(0));
}

#[test]
fn conversion_refuses_a_source_that_no_longer_matches_its_manifest() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let image = fixture.original("EVIDENCE-001-logical.tar");
    let mut bytes = std::fs::read(&image).unwrap();
    bytes[10] ^= 0xff;
    std::fs::write(&image, &bytes).unwrap();

    let output = fixture
        .command()
        .arg("convert")
        .arg(&image)
        .args(["--format", "raw-segmented"])
        .output()
        .unwrap();

    assert_eq!(code(&output), Some(5));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing to derive"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(list_dir(&fixture.case_root().join("derived")).is_empty());
}

#[test]
fn conversion_to_ewf_reports_a_missing_libewf_clearly() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let output = fixture
        .command()
        .arg("convert")
        .arg(fixture.original("EVIDENCE-001-logical.tar"))
        .args([
            "--format",
            "ewf",
            "--ewfacquire-path",
            "nootextract-absent-ewfacquire",
        ])
        .output()
        .unwrap();

    assert_eq!(code(&output), Some(8));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("libewf"), "{stderr}");
    assert!(list_dir(&fixture.case_root().join("derived")).is_empty());
}

#[test]
fn a_working_copy_is_verified_against_its_source() {
    let fixture = Fixture::new("authorized").with_payload(32_768);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let image = fixture.original("EVIDENCE-001-logical.tar");
    let original = std::fs::read(&image).unwrap();

    let output = fixture
        .command()
        .arg("copy")
        .arg(&image)
        .args(["--name", "analysis-copy.tar", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let result = json(&output);
    assert_eq!(result["artifacts"][0]["classification"], "working");
    assert_eq!(result["artifacts"][0]["path"], "working/analysis-copy.tar");
    assert_eq!(result["artifacts"][0]["sha256"], result["source_sha256"]);

    let copy = fixture
        .case_root()
        .join("working")
        .join("analysis-copy.tar");
    assert_eq!(std::fs::read(&copy).unwrap(), original);
    assert_eq!(std::fs::read(&image).unwrap(), original);
    assert_eq!(code(&fixture.verify(&[])), Some(0));
}

#[test]
fn derived_artifacts_reference_their_source() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let image = fixture.original("EVIDENCE-001-logical.tar");
    assert_eq!(
        code(
            &fixture
                .command()
                .arg("copy")
                .arg(&image)
                .args(["--name", "copy.tar"])
                .output()
                .unwrap()
        ),
        Some(0)
    );

    let manifests = list_dir(&fixture.case_root().join("manifests"));
    assert_eq!(manifests.len(), 2);

    let derived = manifests
        .iter()
        .map(|name| {
            let text =
                std::fs::read_to_string(fixture.case_root().join("manifests").join(name)).unwrap();
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        })
        .find(|manifest| manifest["operation"]["method"] == "working-copy")
        .expect("a working-copy manifest must exist");

    assert_eq!(
        derived["artifacts"][0]["derived_from"],
        "original/EVIDENCE-001-logical.tar"
    );
    // A derived artifact inherits the identity of the evidence it came from.
    assert_eq!(derived["case"]["case_id"], "CASE-001");
    assert_eq!(derived["case"]["evidence_id"], "EVIDENCE-001");
}

#[test]
fn derived_artifacts_inherit_the_right_evidence_item() {
    // Two evidence items in one case: a derived artifact must inherit from the
    // manifest that records its own source, not from whichever came first.
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let second = fixture
        .command()
        .arg("acquire")
        .arg(FAKE_SERIAL)
        .args(["--case-id", "CASE-001", "--evidence-id", "EVIDENCE-002"])
        .arg("--output")
        .arg(fixture.case_root())
        .output()
        .unwrap();
    assert_eq!(code(&second), Some(0));

    // Copy the *second* item's artifact.
    let output = fixture
        .command()
        .arg("copy")
        .arg(fixture.original("EVIDENCE-002-logical.tar"))
        .args(["--name", "copy-of-second.tar", "--json"])
        .output()
        .unwrap();
    assert_eq!(
        code(&output),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let derived = list_dir(&fixture.case_root().join("manifests"))
        .iter()
        .map(|name| {
            let text =
                std::fs::read_to_string(fixture.case_root().join("manifests").join(name)).unwrap();
            serde_json::from_str::<serde_json::Value>(&text).unwrap()
        })
        .find(|manifest| manifest["operation"]["method"] == "working-copy")
        .expect("a working-copy manifest must exist");

    assert_eq!(derived["case"]["evidence_id"], "EVIDENCE-002");
    assert_eq!(
        derived["artifacts"][0]["derived_from"],
        "original/EVIDENCE-002-logical.tar"
    );
}

#[test]
fn the_manifest_command_lists_and_validates_case_records() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let listing = fixture
        .command()
        .arg("manifest")
        .arg(fixture.case_root())
        .args(["--json"])
        .output()
        .unwrap();
    assert_eq!(code(&listing), Some(0));
    let entries = json(&listing);
    assert_eq!(entries.as_array().unwrap().len(), 1);
    assert_eq!(entries[0]["method"], "adb-logical-tar");

    let single = fixture
        .command()
        .arg("manifest")
        .arg(find_file(
            &fixture.case_root().join("manifests"),
            ".manifest.json",
        ))
        .args(["--json"])
        .output()
        .unwrap();
    assert_eq!(code(&single), Some(0));
    assert_eq!(json(&single)["valid"], true);
}

#[test]
fn the_hash_list_is_sha256sum_compatible() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let hash_list = find_file(&fixture.case_root().join("hashes"), ".sha256");
    let text = std::fs::read_to_string(&hash_list).unwrap();
    let line = text.lines().next().unwrap();

    let (digest, path) = line.split_once("  ").expect("two-space separator");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(path, "original/EVIDENCE-001-logical.tar");

    let manifest = sole_manifest(&fixture.case_root());
    assert_eq!(manifest["artifacts"][0]["hashes"]["sha256"], digest);
}

#[test]
fn several_evidence_items_can_share_one_case() {
    let fixture = Fixture::new("authorized").with_payload(4096);
    assert_eq!(code(&fixture.acquire(&[])), Some(0));

    let second = fixture
        .command()
        .arg("acquire")
        .arg(FAKE_SERIAL)
        .args(["--case-id", "CASE-001", "--evidence-id", "EVIDENCE-002"])
        .arg("--output")
        .arg(fixture.case_root())
        .output()
        .unwrap();
    assert_eq!(code(&second), Some(0));

    assert!(fixture.original("EVIDENCE-001-logical.tar").is_file());
    assert!(fixture.original("EVIDENCE-002-logical.tar").is_file());
    assert_eq!(list_dir(&fixture.case_root().join("manifests")).len(), 2);
    assert_eq!(code(&fixture.verify(&[])), Some(0));
}

#[test]
fn acquisition_refuses_a_destination_that_is_a_file() {
    let fixture = Fixture::new("authorized");
    std::fs::write(fixture.case_root(), b"not a directory").unwrap();

    let output = fixture.acquire(&[]);
    assert_eq!(code(&output), Some(6));
    assert_eq!(
        std::fs::read(fixture.case_root()).unwrap(),
        b"not a directory"
    );
}
