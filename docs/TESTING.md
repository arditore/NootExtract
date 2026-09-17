# 🧪 Testing

> *What was actually checked — and what was not.*

## ▶️ Running the suite

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
bash scripts/e2e-check.sh
```

`--all-features` enables `test-support`, which builds the scripted ADB stand-in.
Without it the acquisition integration tests are compiled out and skipped, so use
it for a complete run.

## 🤖 Continuous integration

`.github/workflows/ci.yml` runs three jobs:

| Job | What it covers |
|---|---|
| `test` | `fmt`, `clippy -D warnings`, `cargo test --all-features` and `scripts/e2e-check.sh`, on Linux, macOS **and** Windows |
| `msrv` | Reads `rust-version` from `Cargo.toml`, installs exactly that toolchain and runs the suite on it, so the declared floor is verified rather than assumed |
| `no-default-features` | Builds and tests without `test-support`, and asserts the scripted ADB stand-in is absent from a default release build |

The Linux and macOS legs matter specifically: the Unix-only symlink tests are
compiled out on Windows, so they have never run in this environment.

**This workflow has never been executed.** The repository has no remote and the
development environment had no network access, so CI results are a design, not a
result. The first push is what will turn it into evidence.

## 🗂️ Layout

| Location | Kind | Covers |
|---|---|---|
| `src/**/mod tests` | Unit | Parsing, quoting, path safety, hashing vectors, manifest schema, store write discipline, segmentation, verification outcomes |
| `tests/cli.rs` | CLI integration | Exit-code contract, help text, hashing output format, malformed manifests, rejected identifiers, shell-metacharacter handling, `--quiet` and `--json` behaviour |
| `tests/acquisition.rs` | End-to-end | Full acquire → verify → convert → copy workflows against the scripted device |
| `tests/safety.rs` | Filesystem safety | Overwrite refusal, traversal, symlinks, corruption detection, overflow, hostile manifests |
| `scripts/validate_evidence.py` | Independent cross-check | Re-implements the manifest rules and digests in Python, sharing no code with the Rust implementation |
| `scripts/e2e-check.sh` | Workflow check | Drives the release binary through acquire → convert → copy → verify, then cross-checks with the Python validator, coreutils `sha256sum`, segment reassembly and a tampering probe |

## 🎭 The scripted device

`src/bin/fake_adb.rs` is a small binary, behind the `test-support` feature, that
speaks the subset of the ADB command surface NootExtract uses. It is driven by
environment variables:

| `FAKE_ADB_SCENARIO` | Behaviour |
|---|---|
| `authorized` | One authorized device (default) |
| `unauthorized` | A device that has not accepted this host's key |
| `offline` | A device reported as offline |
| `mixed` | One device in each state |
| `empty` | No devices connected |
| `no-tar` | Authorized device with no `tar` utility |
| `root` | Authorized device whose shell runs as UID 0 |
| `fail-mid` | Transfer emits half the data, then exits non-zero |
| `stderr-noise` | Transfer succeeds but writes warnings to stderr |

`FAKE_ADB_PAYLOAD_BYTES` sets the transfer size.

The integration tests run the **real** `nootextract` binary against it with
`--adb-path`, so argument construction, stream relaying, hashing, manifest
generation, status determination and exit codes are all exercised on the
production code path.

## ✅ What is actually verified

Automated, on every run:

- SHA-256 and SHA-512 against FIPS 180-4 vectors, plus equality between
  single-shot, chunked and file-based hashing of the same multi-megabyte input.
- The `hashes/*.sha256` side file is byte-compatible with coreutils format.
- Original artifacts are never overwritten; a second acquisition with the same
  evidence identifier fails with exit 6 and the existing file is unchanged.
- An interrupted transfer leaves a `.partial` file, exits 4, and records the
  failure in a manifest that still verifies.
- Verification reports `MATCH`, `MISMATCH`, `MISSING` and `EXTRA`, and any
  mismatch or missing artifact exits 5.
- Corruption is detected for single-bit flips at the start, middle and end of an
  image, for truncation and for zero-length replacement.
- Unauthorized and offline devices are never presented as acquirable and cannot
  be acquired (exit 3).
- Physical acquisition against an unprivileged shell reports a limitation
  (exit 9) and writes nothing.
- Shell metacharacters in remote paths are quoted into a single inert word,
  checked by re-parsing with a POSIX word splitter.
- Path traversal, symlinked components, overflowing size arithmetic and hostile
  manifest documents are rejected.
- Segmented conversion reassembles byte for byte into the source.
- A conversion source that no longer matches its manifest is refused (exit 5).
- Manifest timestamps are emitted at fixed nanosecond precision and the event log
  reads in chronological order.

Manually executed during development, recorded here as one-off results:

- `sha256sum -c` (GNU coreutils) against a NootExtract-produced hash list:
  reported `OK`.
- The release binary driven through a complete workflow — physical acquisition
  with `--sha512`, conversion to a three-segment raw set, and a working copy —
  then checked by `scripts/validate_evidence.py`: `5 MATCH, 0 MISMATCH,
  0 MISSING, 0 EXTRA` across 3 manifests, `PASSED`, agreeing with
  `nootextract verify` (exit 0).
- The same validator against a case with one byte flipped: `MISMATCH` plus a
  hash-list mismatch, exit 5 — agreeing with the Rust implementation's detection.

That end-to-end run is worth keeping in the release checklist: it is what caught
a digest-set comparison defect that every unit test had missed, because the
defect only appeared when a source verified with SHA-512 was converted with
SHA-256 only.

## 🚫 What was NOT tested

Stated explicitly so nothing here is mistaken for a compatibility claim:

- **No physical Android device was used.** No handset, no emulator, and no real
  `adb` transport were exercised at any point. Device behaviour is modelled by
  the scripted stand-in, which is a model, not evidence about any real device.
- **No Android version was tested.** Statements about toybox `tar`, `dd`,
  `getprop` output and file-based encryption come from Android's documented
  behaviour, not from observation on a device.
- **Autopsy was not run.** No import was performed into Autopsy, The Sleuth Kit,
  X-Ways, EnCase or AXIOM. The procedures in
  [INTEROPERABILITY.md](INTEROPERABILITY.md) are derived from those tools'
  documentation.
- **The E01 conversion path was never executed.** libewf was not available in the
  development environment, so `ewfacquire` and `ewfverify` were never invoked.
  Only the missing-tool and occupied-destination paths are covered by tests.
- **Only Windows was used.** The suite was developed and executed on Windows 11
  with Rust 1.96.0. The Unix-only symlink tests are compiled out there and have
  never run anywhere. The CI workflow is configured to run them on Linux and
  macOS, but has not yet been executed.
- **The declared MSRV was not compiled.** `rust-version = "1.88"` is derived
  from the language features used (let chains on edition 2024), not from a build
  on 1.88. The `msrv` CI job exists to check it.
- **No performance measurement was made** on a multi-gigabyte image. Bounded
  memory use is a property of the code (fixed-size buffers, streaming I/O), not
  something measured here.

Before relying on any of the above, validate it in your own environment on
non-evidential test data.

## 🧫 Fixtures

All fixtures are synthetic and generated at test time — deterministic byte
patterns, hand-constructed manifests and temporary directories. The repository
contains no seized-device data, personal data, credentials, keys or real case
information, and none should ever be added.

## ➕ Adding tests

- Assert the property, not the message text, wherever possible. The
  shell-quoting tests re-parse the output rather than grepping for a substring,
  because a substring check there gives a false sense of coverage.
- Any test asserting that something is refused should also assert that the thing
  it was protecting is still intact.
- Test modules carry an inner `#![allow(...)]` for `unwrap_used` and friends;
  those lints are denied in non-test code and should stay that way.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
