# NootExtract

```text
     .--.
    |o_o |     N O O T E X T R A C T
    |:_/ |
   //   \ \    Android forensic acquisition
  (|     | )   and evidence preparation
 /'\_   _/`\
 \___)=(___/   noot noot.
```

*The colony keeps what it catches. Nothing thaws, nothing is eaten.*

<div align="center">

[![CI](https://img.shields.io/badge/CI-linux%20%7C%20macos%20%7C%20windows-2b4c6f)](.github/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-2b4c6f)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-4a90a4)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-347%20passing-3f7f6f)](docs/TESTING.md)
[![unsafe](https://img.shields.io/badge/unsafe-forbidden-5a6b7c)](docs/SECURITY.md)

</div>

---

NootExtract acquires evidence from Android devices over channels the device
already grants, records exactly what it did in a versioned JSON manifest, and
prepares the result for analysis tools such as Autopsy.

It is written in Rust, uses no `unsafe`, and streams everything — a 256 GB image
costs the same memory as a 4 KB one.

## 🧭 Scope and limits

NootExtract uses only access that has already been authorized: USB debugging
accepted for this host's ADB key, and — for physical acquisition — an ADB shell
that is *already* privileged.

It does not attempt to defeat PINs, passwords, biometrics, lock screens, file- or
metadata-based encryption, verified boot, OEM protections or enterprise controls,
and it contains no exploit or privilege-escalation code. Where an authorized
method cannot reach the data, the tool reports the limitation and stops.

Read [docs/SECURITY.md](docs/SECURITY.md) for the full security model and
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) for what each method can and cannot
capture.

## 🧊 Evidence handling guarantees

> *A penguin does not rearrange the egg it is sitting on.*

These are properties the code enforces and the test suite checks:

- Files under `original/` are never modified, never overwritten and never
  deleted by this tool.
- Every evidence file is created with `create_new`, so an existing file causes a
  failure rather than a silent replacement.
- Bulk data is written to a `.partial` file and renamed into place only after
  the transfer completes cleanly. A file under its final name is always a
  completed transfer.
- Every artifact is hashed with SHA-256 as it is written, and by default re-read
  from disk afterwards to confirm the digest.
- An acquisition that does not complete exits non-zero and records its partial
  output as incomplete. It never reports success.
- Conversions and copies produce new artifacts under `derived/` or `working/`;
  the source is opened read-only.

These are engineering guarantees about this program's behaviour. They are not a
claim about the legal or evidentiary sufficiency of any acquisition, which
depends on authorization, procedure and jurisdiction.

## 🛠️ Installation

Requires a stable Rust toolchain (1.88 or newer; developed and tested against
1.96.0) and the Android SDK platform-tools, which provide `adb`.

```sh
git clone https://github.com/arditore/NootExtract.git
cd NootExtract
cargo build --release
```

The binary is at `target/release/nootextract`.

`adb` must be on `PATH`, or pass `--adb-path /path/to/adb`. See
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for per-platform setup and
[docs/IMAGE_FORMATS.md](docs/IMAGE_FORMATS.md) for the optional libewf
dependency used by E01 conversion.

## 🔌 Device setup

1. Enable Developer options, then USB debugging, on the device.
2. Connect the device and run `nootextract devices`.
3. Accept the USB debugging prompt on the device itself. Until you do, the
   device is reported as `unauthorized` and cannot be acquired. NootExtract does
   not work around this.
4. Keep the device unlocked during a logical acquisition: on a device with
   file-based encryption, locked-profile directories are unreadable.

## 🐟 Quick start

Type the name and nothing else:

```sh
nootextract
```

That starts a guided session: it lists your devices, walks through an
acquisition, shows the plan as a dry run before transferring anything, and
**prints the equivalent command line for every operation**. Nothing done
interactively is unreproducible — the printed command is the one to put in a
script or a case note.

Everything is also available directly:

```sh
# 0. Check the environment before touching a device.
nootextract doctor --output ./evidence/CASE-001

# 1. Discover devices and confirm authorization state.
nootextract devices

# 2. Read identification metadata.
nootextract info FAKEDEVICE01

# 3. See what an acquisition would do, without transferring anything.
nootextract acquire FAKEDEVICE01 \
    --case-id CASE-001 --evidence-id EVIDENCE-001 \
    --output ./evidence/CASE-001 --dry-run

# 4. Acquire.
nootextract acquire FAKEDEVICE01 \
    --case-id CASE-001 --evidence-id EVIDENCE-001 \
    --output ./evidence/CASE-001

# 5. Verify the case against its manifests.
nootextract verify ./evidence/CASE-001

# 6. Unpack the archive into verified, manifested files for analysis.
nootextract extract ./evidence/CASE-001/original/EVIDENCE-001-logical.tar

# 7. Render a report for the case file.
nootextract report ./evidence/CASE-001 --verify > CASE-001-report.md
```

Real output from step 5 on a completed case:

```text
RESULT  PATH                               CLASS     DETAIL
------  ---------------------------------  --------  ------
MATCH   original/EVIDENCE-001-logical.tar  original  -

1 MATCH, 0 MISMATCH, 0 MISSING, 0 EXTRA (1 manifest(s) checked)
```

## 📋 Commands

| Command | Purpose |
|---|---|
| `nootextract devices` | List transports, with authorization state and whether acquisition is permitted |
| `nootextract info <DEVICE_ID>` | Non-invasive identification metadata for one device |
| `nootextract acquire <DEVICE_ID>` | Acquire evidence into a case directory |
| `nootextract hash <PATH>` | Streaming SHA-256 (and optionally SHA-512) of a file |
| `nootextract verify <PATH>` | Verify a case or a single manifest |
| `nootextract manifest <PATH>` | Inspect and validate a manifest, or list a case's manifests |
| `nootextract convert <PATH>` | Produce a derived image in another format |
| `nootextract copy <PATH>` | Produce a verified working copy |
| `nootextract extract <PATH>` | Unpack a logical archive into verified, manifested files |
| `nootextract methods` | List acquisition backends and their requirements |
| `nootextract doctor` | Check the environment: adb, devices, free space, optional tools |
| `nootextract report <PATH>` | Render a Markdown case report for an examiner's file |
| `nootextract` (no arguments) | Start the guided session |

Global options: `--help`, `--version`, `--verbose`, `--quiet`, `--json`,
`--no-progress`, `--adb-path`. Acquisition adds `--output`, `--case-id`,
`--evidence-id`, `--method`, `--source`, `--sha512`, `--examiner`, `--notes`,
`--allow-source-read-errors`, `--no-post-verify` and `--dry-run`.

Exit codes are a stable contract; see [docs/EXIT_CODES.md](docs/EXIT_CODES.md).

## 🎣 Acquisition methods

| Method | Kind | Output | Requires |
|---|---|---|---|
| `adb-logical-tar` (default) | logical | `tar` | Authorized ADB, device unlocked, `tar` on the device |
| `adb-physical-dd` | physical | `raw` | Authorized ADB, an ADB shell **already** running as UID 0, explicit `--source` |

`nootextract methods` prints the same information, including platform notes.
Physical acquisition is unavailable on an ordinary retail device; that is a
property of Android's security model, and NootExtract reports it (exit code 9)
rather than attempting to change it.

## 🗂️ Evidence directory

> *One rookery, one colony, everything in its own nest.*

```text
CASE-001/
    original/    🧊  acquired evidence — never modified, overwritten or deleted
    derived/     🔄  conversions produced from originals
    working/     🐟  verified copies and extracted files, for analysis tools
    manifests/   📜  one immutable manifest per operation
    hashes/      🔐  sha256sum-compatible hash lists
    logs/        📓  structured JSON Lines logs
```

One case directory holds several evidence items. Manifests are append-only: a
conversion writes a *new* manifest referencing the source, so the record of the
original acquisition is never rewritten.

## 🔐 Hashing and verification

SHA-256 is always computed; `--sha512` adds SHA-512. Hashing is fully streaming
over a 1 MiB buffer, so memory use is constant regardless of image size, and the
digest recorded at acquisition is produced by the same code path that later
verifies it.

`verify` reports four outcomes per file — `MATCH`, `MISMATCH`, `MISSING`,
`EXTRA` — and exits 5 if any mismatch, missing artifact, or unaccounted file is
found. `--ignore-extra` downgrades unaccounted files to a reported observation.

The `hashes/*.sha256` side files are coreutils-compatible and can be checked with
an independent tool:

```sh
cd ./evidence/CASE-001 && sha256sum -c hashes/EVIDENCE-001-*.sha256
```

## 🔗 Interoperability

See [docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) for import procedures
and, importantly, for which of them have actually been tested and which have
not. NootExtract does not claim compatibility it has not exercised.

## 📚 Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module layout and the boundaries that matter |
| [docs/MANIFEST_SCHEMA.md](docs/MANIFEST_SCHEMA.md) | Manifest schema 1.0, field by field |
| [docs/EXIT_CODES.md](docs/EXIT_CODES.md) | Exit-code contract |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model and security review |
| [docs/IMAGE_FORMATS.md](docs/IMAGE_FORMATS.md) | Formats, conversion, libewf |
| [docs/INTEROPERABILITY.md](docs/INTEROPERABILITY.md) | Autopsy and other tools |
| [docs/RESUMABILITY.md](docs/RESUMABILITY.md) | Why resumable acquisition is not implemented |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What each method cannot do |
| [docs/TESTING.md](docs/TESTING.md) | Test strategy and verification status |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Toolchain, dependencies, workflow |

## ✅ Verification status

The automated suite runs without a physical device. Device behaviour is supplied
by a scripted ADB stand-in, which exercises the real command paths but is not
evidence that any particular handset or Android version behaves as modelled.

CI runs the suite plus a full end-to-end check on Linux, macOS and Windows, and
compiles the crate on the declared minimum Rust version. All jobs pass.

**No physical Android device, and no Autopsy import, was used in developing this
version.** [docs/TESTING.md](docs/TESTING.md) states precisely what was and was
not verified.

## 📜 License

MIT. See [LICENSE](LICENSE).

---

```text
   .--.
  |o_o |   Evidence in. Evidence unchanged. Evidence out.
  |:_/ |   noot noot.
```
