# 🔧 Development

> *Joining the colony.*

## 🦀 Toolchain

Stable Rust, edition 2024, `rust-version = 1.85`. Developed and tested against
1.96.0.

```sh
rustup toolchain install stable
rustup component add rustfmt clippy
```

## 🛠️ Build

```sh
cargo build                  # debug
cargo build --release        # release: thin LTO, one codegen unit, stripped
cargo build --all-features   # also builds the scripted ADB stand-in
```

The release profile sets `panic = "abort"`. A panic during an acquisition is a
defect, and unwinding through a half-written artifact has no recovery path worth
preserving; the `.partial` file on disk is the record either way.

## ✅ Checks

```sh
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

All three must pass. Lints are configured in `Cargo.toml` rather than in source
attributes, so they apply uniformly:

- `unsafe_code = "forbid"` — there is no `unsafe` in this crate.
- `clippy::all` and `clippy::pedantic`.
- `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `integer_division`
  and the numeric-cast lints, which catch the failure modes that matter most for
  large-image handling: a wrapped length, a truncated size, a panic mid-transfer.

Test modules opt out of the panic-related lints with an inner `#![allow(...)]`.
Non-test code must not.

## 📦 Dependencies

Each one is present for a stated reason.

| Crate | Why |
|---|---|
| `clap` | CLI parsing, help and version generation |
| `serde`, `serde_json` | Manifest and `--json` serialization |
| `thiserror` | Typed error model mapped onto the exit codes |
| `sha2` | SHA-256 / SHA-512 |
| `chrono` | RFC 3339 UTC timestamps; default features off |
| `tracing`, `tracing-subscriber` | Structured logging to console and case log |
| `indicatif` | Progress reporting for long transfers |
| `ctrlc` | SIGINT handling, so an interrupt ends deterministically |
| `fs4` | Free-space interrogation for the pre-acquisition check |

Dev-only: `tempfile`, `assert_cmd`, `predicates`.

Deliberately absent:

- **`tokio`** — the workload is one subprocess pipe feeding one file write. An
  async runtime would add a large dependency without improving throughput.
- **`anyhow`** — exit codes are derived from the error type, so every failure
  needs a typed variant. A catch-all error type would undermine that.
- **`hex`, `walkdir`, `regex`** — a few lines each in this crate; not worth a
  dependency.

Before adding a dependency, state what it does that cannot reasonably be written
here, and note whether it pulls in `unsafe`.

## 🗣️ Languages

Rust is the implementation language. Python appears only in
`scripts/validate_evidence.py`, where a second, independent implementation of the
manifest and digest rules provides a genuine cross-check — a bug present in both
would have to be written twice, independently.

No shell script contains forensic logic. No C or C++ is compiled. libewf is used
through its command-line tools rather than through FFI, so no C toolchain is
needed to build NootExtract.

## 💻 Platform setup

### Linux

```sh
sudo apt install android-sdk-platform-tools     # or your distribution's package
sudo apt install ewf-tools                      # optional, for E01 conversion
```

USB device access needs udev rules. Without them a connected device reports
`no permissions`, which is a host configuration problem rather than a device
lock.

### macOS

```sh
brew install --cask android-platform-tools
brew install libewf                             # optional
```

### Windows

Install the Android SDK platform-tools and ensure `adb.exe` is on `PATH`, or pass
`--adb-path`. Some vendors require an OEM USB driver before ADB sees the device.
libewf release binaries must be installed separately and pointed at with
`--ewfacquire-path`.

Note when working in Git Bash: MSYS rewrites arguments that look like Unix paths,
so `--source /dev/block/by-name/userdata` arrives mangled. Set
`MSYS_NO_PATHCONV=1` for those invocations.

## 🗂️ Project structure

See [ARCHITECTURE.md](ARCHITECTURE.md). The rule to keep in mind: acquisition
backends never decide where bytes land, how they are named, how they are hashed
or what goes into a manifest. If a change needs to cross that boundary, the
boundary is probably in the wrong place — discuss before moving it.

## ➕ Adding an acquisition backend

Covered step by step in [ARCHITECTURE.md](ARCHITECTURE.md). In short: implement
`AcquisitionBackend`, declare honest requirements and platform notes, report
limitations with `Error::Unsupported` instead of working around them, return the
real status, and register it in `available_backends()`.

## 📏 Conventions

- All source, comments, documentation, CLI output and error messages are in
  English.
- Comments explain *why*, not *what*. Do not narrate the code.
- Error messages name the operation and the path, and say what the operator can
  do about it.
- Do not claim a device, Android version, image format or analysis-tool workflow
  was tested unless it actually was. [TESTING.md](TESTING.md) records what was
  and was not verified, and must be updated alongside any such claim.
- Avoid unsupported absolutes — "forensically sound", "guaranteed", "100%",
  "unbreakable". State the specific behaviour instead.

## 🚀 Release checklist

1. `cargo fmt --all --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-features`
4. Run `scripts/validate_evidence.py` against a freshly produced case.
5. Confirm the documentation matches the implementation, particularly
   [TESTING.md](TESTING.md) and [IMAGE_FORMATS.md](IMAGE_FORMATS.md).
6. Confirm no evidence, personal data, credentials or case material has entered
   the repository.
7. Bump the version in `Cargo.toml`. It is recorded in every manifest, so it is
   part of the evidentiary record.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
