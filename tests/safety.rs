//! Filesystem-safety and hostile-input behaviour of the evidence layer.
//!
//! These tests exercise the library directly, so they can assert on states that
//! are awkward to reach through the CLI: symlinked evidence paths, concurrent
//! creation, corrupted images and oversized device output.

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

use std::path::Path;

use nootextract::evidence::manifest::{
    AcquisitionStatus, ArtifactRole, CaseRecord, EvidenceClass, Manifest, OperationRecord,
    SourceRecord, operation_id,
};
use nootextract::evidence::store::EvidenceStore;
use nootextract::evidence::verify::{VerificationOutcome, VerifyOptions, verify_case};
use nootextract::util::cancel::CancellationToken;

/// Builds a case containing one original artifact and its manifest.
fn case_with_artifact(root: &Path, content: &[u8]) -> EvidenceStore {
    let store = EvidenceStore::create(root).unwrap();
    let mut writer = store
        .create_artifact(
            EvidenceClass::Original,
            "EV-1.raw",
            ArtifactRole::PhysicalImage,
            "raw",
            false,
        )
        .unwrap();
    writer.write_chunk(content).unwrap();
    let artifact = writer.finish_complete().unwrap();

    let started = chrono::Utc::now();
    let mut manifest = Manifest::new(
        CaseRecord {
            case_id: "CASE-001".to_owned(),
            evidence_id: "EV-1".to_owned(),
            examiner: None,
            notes: None,
        },
        OperationRecord {
            operation_id: operation_id("acq", started),
            method: "test".to_owned(),
            method_description: "synthetic fixture".to_owned(),
            source: SourceRecord {
                source_id: "FIXTURE".to_owned(),
                source_path: None,
                remote_command: None,
                reported_size_bytes: None,
            },
            started_at: started,
            completed_at: Some(chrono::Utc::now()),
            duration_ms: Some(0),
            status: AcquisitionStatus::Completed,
            parameters: std::collections::BTreeMap::new(),
        },
    );
    manifest.artifacts.push(artifact.to_record());
    store.write_manifest(&manifest).unwrap();
    store
}

#[test]
fn an_original_artifact_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), b"original evidence");
    let path = store.root().join("original").join("EV-1.raw");

    for _ in 0..3 {
        let err = store
            .create_artifact(
                EvidenceClass::Original,
                "EV-1.raw",
                ArtifactRole::PhysicalImage,
                "raw",
                false,
            )
            .unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 6);
    }
    assert_eq!(std::fs::read(&path).unwrap(), b"original evidence");
}

#[test]
fn artifact_names_cannot_escape_the_case_directory() {
    let dir = tempfile::tempdir().unwrap();
    let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
    let outside = dir.path().join("outside.raw");
    std::fs::write(&outside, b"must not be touched").unwrap();

    for name in [
        "../outside.raw",
        "../../outside.raw",
        "sub/../../outside.raw",
        "sub/../outside.raw",
    ] {
        assert!(
            store
                .create_artifact(
                    EvidenceClass::Original,
                    name,
                    ArtifactRole::PhysicalImage,
                    "raw",
                    false,
                )
                .is_err(),
            "`{name}` must be rejected"
        );
    }
    assert_eq!(std::fs::read(&outside).unwrap(), b"must not be touched");

    // A leading `./` is not an escape: it resolves inside the class directory,
    // and the artifact must land there rather than anywhere else.
    let writer = store
        .create_artifact(
            EvidenceClass::Original,
            "./inside.raw",
            ArtifactRole::PhysicalImage,
            "raw",
            false,
        )
        .unwrap();
    let artifact = writer.finish_complete().unwrap();
    assert_eq!(artifact.relative_path, "original/inside.raw");
    assert!(artifact.path.starts_with(store.root()));
}

#[cfg(unix)]
#[test]
fn a_symlinked_evidence_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();

    let root = dir.path().join("CASE-001");
    let store = EvidenceStore::create(&root).unwrap();
    // Replace original/ with a link pointing out of the case.
    std::fs::remove_dir(root.join("original")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("original")).unwrap();

    let err = store
        .create_artifact(
            EvidenceClass::Original,
            "EV-1.raw",
            ArtifactRole::PhysicalImage,
            "raw",
            false,
        )
        .unwrap_err();
    assert_eq!(err.exit_code().as_i32(), 6);
    assert!(err.to_string().contains("symbolic link"), "{err}");
    assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
}

#[cfg(unix)]
#[test]
fn a_symlinked_artifact_is_reported_as_a_mismatch_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), b"original evidence");

    let path = store.root().join("original").join("EV-1.raw");
    let decoy = dir.path().join("decoy.raw");
    std::fs::write(&decoy, b"original evidence").unwrap();
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&decoy, &path).unwrap();

    let report = verify_case(
        &store,
        VerifyOptions::default(),
        &CancellationToken::new(),
        &mut |_, _| {},
    )
    .unwrap();

    // Even though the link target has identical content, the substitution is
    // reported rather than silently accepted.
    assert_eq!(report.count(VerificationOutcome::Mismatch), 1);
    assert!(!report.is_success());
}

#[test]
fn a_corrupted_image_fails_verification_for_every_kind_of_damage() {
    let content: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();

    for (label, damage) in [
        ("single flipped bit", 0usize),
        ("byte in the middle", 50_000),
        ("last byte", 99_999),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = case_with_artifact(&dir.path().join("CASE-001"), &content);
        let path = store.root().join("original").join("EV-1.raw");

        let mut bytes = std::fs::read(&path).unwrap();
        bytes[damage] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        let report = verify_case(
            &store,
            VerifyOptions::default(),
            &CancellationToken::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert_eq!(
            report.count(VerificationOutcome::Mismatch),
            1,
            "{label} was not detected"
        );
        assert!(!report.is_success(), "{label} must not pass verification");
    }
}

#[test]
fn a_zero_length_replacement_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), b"original evidence");
    std::fs::write(store.root().join("original").join("EV-1.raw"), b"").unwrap();

    let report = verify_case(
        &store,
        VerifyOptions::default(),
        &CancellationToken::new(),
        &mut |_, _| {},
    )
    .unwrap();
    assert_eq!(report.count(VerificationOutcome::Mismatch), 1);
}

#[test]
fn verification_reads_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), &vec![7u8; 200_000]);
    let path = store.root().join("original").join("EV-1.raw");

    let before = std::fs::metadata(&path).unwrap();
    let before_modified = before.modified().unwrap();

    for _ in 0..3 {
        let report = verify_case(
            &store,
            VerifyOptions::default(),
            &CancellationToken::new(),
            &mut |_, _| {},
        )
        .unwrap();
        assert!(report.is_success());
    }

    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(before.len(), after.len());
    assert_eq!(before_modified, after.modified().unwrap());
}

#[test]
fn a_partial_artifact_keeps_its_data_and_its_label() {
    let dir = tempfile::tempdir().unwrap();
    let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();

    let mut writer = store
        .create_artifact(
            EvidenceClass::Original,
            "EV-1.raw",
            ArtifactRole::PhysicalImage,
            "raw",
            false,
        )
        .unwrap();
    writer.write_chunk(b"the first half").unwrap();
    let artifact = writer.finish_incomplete("transfer interrupted").unwrap();

    assert!(!artifact.complete);
    assert!(artifact.relative_path.ends_with(".partial"));
    assert_eq!(std::fs::read(&artifact.path).unwrap(), b"the first half");
    // The name reserved for a complete image stays free.
    assert!(!store.root().join("original").join("EV-1.raw").exists());
}

#[test]
fn a_manifest_is_never_written_over_an_existing_one() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), b"original evidence");

    let manifests = store.manifest_paths().unwrap();
    assert_eq!(manifests.len(), 1);
    let original = std::fs::read(&manifests[0]).unwrap();

    let manifest = Manifest::load(&manifests[0]).unwrap();
    assert!(
        store.write_manifest(&manifest).is_err(),
        "re-writing the same operation record must fail"
    );
    assert_eq!(std::fs::read(&manifests[0]).unwrap(), original);
}

#[test]
fn no_temporary_files_survive_a_successful_run() {
    let dir = tempfile::tempdir().unwrap();
    let store = case_with_artifact(&dir.path().join("CASE-001"), b"original evidence");

    let mut leftovers = Vec::new();
    for subdirectory in ["original", "derived", "working", "manifests", "hashes"] {
        for entry in std::fs::read_dir(store.root().join(subdirectory)).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            let is_temporary = Path::new(&name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("tmp"));
            if is_temporary || name.starts_with('.') {
                leftovers.push(format!("{subdirectory}/{name}"));
            }
        }
    }
    assert!(
        leftovers.is_empty(),
        "leftover temporary files: {leftovers:?}"
    );
}

#[test]
fn free_space_checks_do_not_overflow() {
    let dir = tempfile::tempdir().unwrap();
    let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();

    // Values chosen so a naive `size + size * pct / 100` would wrap.
    for (required, headroom) in [(u64::MAX, 5u64), (u64::MAX / 2, 100), (u64::MAX, 0)] {
        let result = store.ensure_space(required, headroom);
        assert!(
            result.is_err(),
            "requesting {required} bytes must not succeed"
        );
        assert_eq!(result.unwrap_err().exit_code().as_i32(), 7);
    }
}

#[test]
fn hostile_manifest_documents_are_rejected_before_use() {
    let dir = tempfile::tempdir().unwrap();
    let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();
    let manifests = store.manifests_dir();

    let cases: [(&str, &[u8]); 5] = [
        ("empty.manifest.json", b""),
        ("truncated.manifest.json", b"{\"manifest_version\": \"1.0\""),
        ("wrong-type.manifest.json", b"[]"),
        ("null.manifest.json", b"null"),
        (
            "deep.manifest.json",
            b"{\"manifest_version\":\"1.0\",\"artifacts\":\"not an array\"}",
        ),
    ];

    for (name, content) in cases {
        let path = manifests.join(name);
        std::fs::write(&path, content).unwrap();
        assert!(Manifest::load(&path).is_err(), "`{name}` must be rejected");
        // A case containing an unreadable manifest fails rather than silently
        // verifying the rest.
        assert!(store.load_manifests().is_err());
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn case_layout_is_created_exactly_as_documented() {
    let dir = tempfile::tempdir().unwrap();
    let store = EvidenceStore::create(&dir.path().join("CASE-001")).unwrap();

    let mut entries: Vec<String> = std::fs::read_dir(store.root())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();

    assert_eq!(
        entries,
        vec![
            "derived",
            "hashes",
            "logs",
            "manifests",
            "original",
            "working"
        ]
    );
}
