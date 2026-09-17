//! CLI surface, exit-code contract, hashing and malformed-input handling.
//!
//! These tests need no device and no feature flags.

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

use common::{code, fixture, json, nootextract, read, workspace};
use predicates::prelude::*;

/// SHA-256 of `b"abc"`, from FIPS 180-4.
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ABC_SHA512: &str = concat!(
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
    "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);

#[test]
fn help_documents_the_exit_code_contract() {
    let output = nootextract().arg("--help").output().unwrap();
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    for fragment in [
        "0    success",
        "2    command-line usage error",
        "3    device",
        "4    acquisition",
        "5    integrity",
        "6    unsafe destination",
        "7    insufficient free space",
        "8    a required external tool",
        "9    the operation is not supported",
        "130  interrupted",
    ] {
        assert!(text.contains(fragment), "`{fragment}` missing from --help");
    }
}

#[test]
fn help_states_what_the_tool_does_not_do() {
    let output = nootextract().arg("--help").output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("does \nnot attempt to defeat") || text.contains("not attempt to defeat")
    );
    assert!(text.contains("never modified"));
}

#[test]
fn version_is_reported() {
    let output = nootextract().arg("--version").output().unwrap();
    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "{text}");
}

#[test]
fn unknown_subcommands_exit_with_the_usage_code() {
    for argv in [["bypass"], ["crack"], ["unlock"]] {
        let output = nootextract().args(argv).output().unwrap();
        assert_eq!(
            code(&output),
            Some(2),
            "`{}` must be a usage error",
            argv[0]
        );
    }
}

#[test]
fn missing_required_arguments_exit_with_the_usage_code() {
    let output = nootextract()
        .args(["acquire", "ABC123", "--case-id", "CASE-001"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
}

#[test]
fn methods_are_listed_with_their_requirements() {
    let output = nootextract().args(["methods", "--json"]).output().unwrap();
    assert_eq!(code(&output), Some(0));

    let value = json(&output);
    let entries = value.as_array().expect("methods output must be an array");
    assert!(entries.len() >= 2);

    let ids: Vec<&str> = entries
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert!(ids.contains(&"adb-logical-tar"), "{ids:?}");
    assert!(ids.contains(&"adb-physical-dd"), "{ids:?}");

    let physical = entries
        .iter()
        .find(|entry| entry["id"] == "adb-physical-dd")
        .unwrap();
    let requirements = physical["requirements"].to_string();
    assert!(
        requirements.contains("never attempts to obtain privileges"),
        "{requirements}"
    );
}

#[test]
fn hash_emits_sha256sum_compatible_output() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");

    let output = nootextract().arg("hash").arg(&path).output().unwrap();
    assert_eq!(code(&output), Some(0));

    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next().unwrap();
    assert!(first.starts_with(ABC_SHA256), "{first}");
    // Exactly two spaces separate digest and path, as coreutils emits.
    assert!(first.contains(&format!("{ABC_SHA256}  ")), "{first}");
}

#[test]
fn hash_computes_sha512_on_request() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");

    let output = nootextract()
        .args(["hash", "--sha512", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(0));

    let value = json(&output);
    assert_eq!(value["sha256"], ABC_SHA256);
    assert_eq!(value["sha512"], ABC_SHA512);
    assert_eq!(value["size_bytes"], 3);
}

#[test]
fn hash_of_an_empty_file_succeeds() {
    let dir = workspace();
    let path = fixture(dir.path(), "empty.raw", b"");
    let output = nootextract()
        .args(["hash", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(0));
    assert_eq!(
        json(&output)["sha256"],
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hash_of_a_missing_file_fails_without_a_digest() {
    let dir = workspace();
    let output = nootextract()
        .arg("hash")
        .arg(dir.path().join("absent.raw"))
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(1));
    assert!(output.stdout.is_empty(), "no digest may be printed");
}

#[test]
fn hash_of_a_directory_fails() {
    let dir = workspace();
    let output = nootextract().arg("hash").arg(dir.path()).output().unwrap();
    assert_eq!(code(&output), Some(1));
}

#[test]
fn arguments_containing_shell_metacharacters_are_never_executed() {
    // Drives the real binary with a path full of shell syntax. If any layer
    // handed this to a shell, `whoami` would run and the file name would be
    // split. Instead the literal name is reported as missing.
    let payload = "a; whoami && echo pwned | tee /tmp/x";
    let output = nootextract().arg("hash").arg(payload).output().unwrap();

    assert_eq!(code(&output), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("whoami"), "{stderr}");
    assert!(!stderr.contains("pwned\n"), "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn case_identifiers_that_traverse_paths_are_rejected() {
    let dir = workspace();
    for bad in ["../evil", "CASE/001", ".hidden", "CON"] {
        let output = nootextract()
            .args([
                "acquire",
                "ABC123",
                "--case-id",
                bad,
                "--evidence-id",
                "EV-1",
            ])
            .arg("--output")
            .arg(dir.path().join("case"))
            .output()
            .unwrap();
        assert_eq!(
            code(&output),
            Some(2),
            "`{bad}` must be rejected as a usage error"
        );
    }
    // Nothing may have been created for a rejected identifier.
    assert!(!dir.path().join("case").exists());
}

#[test]
fn evidence_identifiers_that_traverse_paths_are_rejected() {
    let dir = workspace();
    let output = nootextract()
        .args([
            "acquire",
            "ABC123",
            "--case-id",
            "CASE-001",
            "--evidence-id",
            "../../escape",
        ])
        .arg("--output")
        .arg(dir.path().join("case"))
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
}

#[test]
fn device_identifiers_that_look_like_flags_are_rejected() {
    let dir = workspace();
    let output = nootextract()
        .args([
            "acquire",
            "--case-id",
            "CASE-001",
            "--evidence-id",
            "EV-1",
            "--",
            "-rf",
        ])
        .arg("--output")
        .arg(dir.path().join("case"))
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
}

#[test]
fn verify_on_a_directory_without_a_case_layout_fails_safely() {
    let dir = workspace();
    let output = nootextract()
        .arg("verify")
        .arg(dir.path())
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(6));
}

#[test]
fn manifest_rejects_malformed_json() {
    let dir = workspace();
    let path = fixture(dir.path(), "broken.manifest.json", b"{ not json at all");
    let output = nootextract().arg("manifest").arg(&path).output().unwrap();
    assert_eq!(code(&output), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not a valid manifest"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manifest_rejects_an_incompatible_schema_version() {
    let dir = workspace();
    let document = serde_json::json!({
        "manifest_version": "9.0",
        "manifest_id": "acq-1",
        "generated_at": "2025-01-01T00:00:00Z",
        "tool": {"name": "nootextract", "version": "0.1.0"},
        "host": {"os": "linux", "arch": "x86_64", "family": "unix"},
        "case": {"case_id": "CASE-001", "evidence_id": "EV-1"},
        "operation": {
            "operation_id": "acq-1",
            "method": "adb-logical-tar",
            "method_description": "test",
            "source": {"source_id": "ABC"},
            "started_at": "2025-01-01T00:00:00Z",
            "status": "completed"
        },
        "artifacts": []
    });
    let path = fixture(
        dir.path(),
        "future.manifest.json",
        document.to_string().as_bytes(),
    );

    let output = nootextract().arg("manifest").arg(&path).output().unwrap();
    assert_eq!(code(&output), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not supported"));
}

#[test]
fn manifest_rejects_artifact_paths_that_escape_the_case_root() {
    let dir = workspace();
    let document = serde_json::json!({
        "manifest_version": "1.0",
        "manifest_id": "acq-1",
        "generated_at": "2025-01-01T00:00:00Z",
        "tool": {"name": "nootextract", "version": "0.1.0"},
        "host": {"os": "linux", "arch": "x86_64", "family": "unix"},
        "case": {"case_id": "CASE-001", "evidence_id": "EV-1"},
        "operation": {
            "operation_id": "acq-1",
            "method": "adb-logical-tar",
            "method_description": "test",
            "source": {"source_id": "ABC"},
            "started_at": "2025-01-01T00:00:00Z",
            "status": "completed"
        },
        "artifacts": [{
            "path": "../../etc/passwd",
            "classification": "original",
            "role": "physical-image",
            "format": "raw",
            "size_bytes": 1,
            "hashes": {"sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
            "complete": true,
            "created_at": "2025-01-01T00:00:00Z"
        }]
    });
    let path = fixture(
        dir.path(),
        "escape.manifest.json",
        document.to_string().as_bytes(),
    );

    let output = nootextract().arg("manifest").arg(&path).output().unwrap();
    assert_eq!(code(&output), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("safe relative path"));
}

#[test]
fn json_errors_carry_a_machine_readable_shape() {
    let dir = workspace();
    let output = nootextract()
        .args(["hash", "--json"])
        .arg(dir.path().join("absent.raw"))
        .output()
        .unwrap();

    assert_eq!(code(&output), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let value: serde_json::Value = serde_json::from_str(&stderr)
        .unwrap_or_else(|e| panic!("stderr was not JSON ({e}):\n{stderr}"));
    assert_eq!(value["error"]["kind"], "io");
    assert_eq!(value["error"]["exit_code"], 1);
}

#[test]
fn convert_rejects_unknown_target_formats() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");
    let output = nootextract()
        .arg("convert")
        .arg(&path)
        .args(["--format", "qcow2"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
}

#[test]
fn convert_refuses_a_source_outside_a_case_directory() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");
    let output = nootextract()
        .arg("convert")
        .arg(&path)
        .args(["--format", "raw-segmented"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not inside a case directory"));
}

#[test]
fn quiet_and_verbose_cannot_be_combined() {
    let output = nootextract()
        .args(["methods", "-q", "-v"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(2));
}

#[test]
fn missing_adb_is_reported_as_a_missing_tool() {
    let output = nootextract()
        .args(["devices", "--adb-path", "nootextract-absent-adb-binary"])
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(8));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("platform-tools") || stderr.contains("not found"),
        "{stderr}"
    );
}

#[test]
fn hash_output_is_stable_across_runs() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", &vec![0x42u8; 300_000]);

    let first = nootextract()
        .args(["hash", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    let second = nootextract()
        .args(["hash", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(json(&first)["sha256"], json(&second)["sha256"]);
}

#[test]
fn format_identification_does_not_overstate_certainty() {
    let dir = workspace();
    // A misleading extension over unidentifiable content.
    let path = fixture(dir.path(), "image.e01", &[0xab; 600]);
    let output = nootextract()
        .args(["hash", "--json"])
        .arg(&path)
        .output()
        .unwrap();
    let value = json(&output);
    assert_eq!(value["format"], "ewf");
    assert_eq!(value["format_evidence"], "filename");
}

#[test]
fn a_file_is_not_modified_by_hashing_it() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();

    nootextract().arg("hash").arg(&path).output().unwrap();

    let after = std::fs::metadata(&path).unwrap().modified().unwrap();
    assert_eq!(before, after);
    assert_eq!(read(&path), "abc");
}

#[test]
fn quiet_suppresses_tables_but_not_the_exit_code() {
    let noisy = nootextract().args(["methods"]).output().unwrap();
    assert_eq!(code(&noisy), Some(0));
    assert!(!noisy.stdout.is_empty());

    let quiet = nootextract().args(["methods", "--quiet"]).output().unwrap();
    assert_eq!(code(&quiet), Some(0));
    assert!(
        quiet.stdout.is_empty(),
        "--quiet must not print a listing: {}",
        String::from_utf8_lossy(&quiet.stdout)
    );

    // JSON output is a result, not informational noise, so it survives --quiet.
    let quiet_json = nootextract()
        .args(["methods", "--quiet", "--json"])
        .output()
        .unwrap();
    assert_eq!(code(&quiet_json), Some(0));
    assert!(json(&quiet_json).as_array().is_some_and(|a| !a.is_empty()));
}

#[test]
fn quiet_still_prints_the_hash_digest() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");
    let output = nootextract()
        .args(["hash", "--quiet"])
        .arg(&path)
        .output()
        .unwrap();

    assert_eq!(code(&output), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.starts_with(ABC_SHA256), "{text}");
    // Only the digest line; the size/format summary is suppressed.
    assert_eq!(text.lines().count(), 1, "{text}");
}

#[test]
fn quiet_still_reports_errors() {
    let dir = workspace();
    let output = nootextract()
        .args(["hash", "--quiet"])
        .arg(dir.path().join("absent.raw"))
        .output()
        .unwrap();
    assert_eq!(code(&output), Some(1));
    assert!(
        !output.stderr.is_empty(),
        "errors must never be silenced by --quiet"
    );
}

#[test]
fn stdout_stays_clean_for_json_consumers() {
    let dir = workspace();
    let path = fixture(dir.path(), "image.raw", b"abc");
    let output = nootextract()
        .args(["hash", "--json", "-v"])
        .arg(&path)
        .output()
        .unwrap();

    // Logs go to stderr, so stdout must parse as a single JSON document.
    let value = json(&output);
    assert_eq!(value["sha256"], ABC_SHA256);
    assert!(
        predicate::str::is_empty()
            .not()
            .eval(&String::from_utf8_lossy(&output.stderr))
    );
}
