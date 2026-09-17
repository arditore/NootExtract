# 📜 Manifest schema 1.0

> *Every catch is logged, down to the last fish.*

Every acquisition, conversion and copy writes one JSON manifest to
`manifests/<evidence-id>-<operation-id>.manifest.json`.

Manifests are immutable records. A later operation writes a new manifest that
references the source artifact; it never edits an existing one.

## 🔢 Versioning

`manifest_version` is `MAJOR.MINOR`.

- A **minor** increment adds optional fields. Readers must ignore fields they do
  not recognize and must accept a manifest whose minor version is higher than
  their own, reporting a note rather than an error.
- A **major** increment signals an incompatible change. A reader that does not
  support the major version must refuse the document.

This build emits `1.0` and reads `1.x`. `nootextract manifest <PATH>` validates a
document and reports both errors and non-fatal notes.

## 📋 Top-level fields

| Field | Type | Required | Description |
|---|---|---|---|
| `manifest_version` | string | yes | Schema version, `MAJOR.MINOR` |
| `manifest_id` | string | yes | Identifier of this record, equal to `operation.operation_id` |
| `generated_at` | RFC 3339 | yes | When the manifest was written (UTC) |
| `tool` | object | yes | Tool identification |
| `host` | object | yes | Examination host |
| `case` | object | yes | Case and evidence identification |
| `operation` | object | yes | What was done |
| `device` | object | no | Device identification; absent for operations with no device |
| `artifacts` | array | yes | Files produced |
| `events` | array | no | Chronological event log |
| `errors` | array of string | no | Errors encountered |
| `warnings` | array of string | no | Conditions the operator should know about |

Empty arrays and absent optional fields are omitted from the output.

### `tool`

| Field | Type | Description |
|---|---|---|
| `name` | string | `nootextract` |
| `version` | string | Crate version that produced the record |
| `external_tools` | object | Program path to reported version, for each external tool used (`adb`, `ewfacquire`) |

### `host`

| Field | Type | Description |
|---|---|---|
| `os` | string | `linux`, `windows`, `macos`, … |
| `arch` | string | `x86_64`, `aarch64`, … |
| `family` | string | `unix` or `windows` |

Deliberately coarse. No hostname, user name or network identifier is recorded.

### `case`

| Field | Type | Required | Description |
|---|---|---|---|
| `case_id` | string | yes | Operator-supplied, `[A-Za-z0-9._-]{1,64}` |
| `evidence_id` | string | yes | Operator-supplied, same alphabet |
| `examiner` | string | no | From `--examiner` |
| `notes` | string | no | From `--notes` |

### `operation`

| Field | Type | Required | Description |
|---|---|---|---|
| `operation_id` | string | yes | `<prefix>-<UTC timestamp>`; `acq`, `cnv` or `cpy`. Sorts chronologically |
| `method` | string | yes | Backend or converter identifier, e.g. `adb-logical-tar` |
| `method_description` | string | yes | Human-readable description of what was done |
| `source` | object | yes | See below |
| `started_at` | RFC 3339 | yes | Acquisition start time |
| `completed_at` | RFC 3339 | no | Completion time; absent if the operation never reached an end state |
| `duration_ms` | integer | no | Elapsed milliseconds |
| `status` | enum | yes | See below |
| `parameters` | object | no | Effective parameters, as strings, for reproducibility |

#### `operation.source`

| Field | Type | Description |
|---|---|---|
| `source_id` | string | ADB serial, or the case-relative path of the source artifact for derived operations |
| `source_path` | string | Scope on the device, or the source artifact path |
| `remote_command` | array of string | The exact argument vector executed on the device |
| `reported_size_bytes` | integer | Size the source reported before the transfer, when readable |

`remote_command` is the unquoted argument vector. What was actually sent is that
vector, POSIX-quoted and passed to `adb exec-out` as a single argument.

#### `operation.status`

| Value | Meaning |
|---|---|
| `completed` | Every byte the source offered was written and verified |
| `completed-with-errors` | The transfer finished but the source reported read errors the operator explicitly allowed with `--allow-source-read-errors`. Each error is listed in `errors` |
| `failed` | The transfer stopped before the source was exhausted. Whatever was written is preserved and marked incomplete |
| `cancelled` | The operator interrupted the transfer. Partial data is preserved |

Only `completed` and `completed-with-errors` exit zero.

### `device`

Present when an operation involved a device. Contains `serial` plus the optional
fields `manufacturer`, `brand`, `model`, `product_name`, `device_name`,
`hardware`, `board_platform`, `android_release`, `android_sdk`,
`security_patch`, `build_id`, `build_fingerprint`, `build_type`, `build_tags`,
`crypto_state`, `crypto_type`, `shell_uid`, and `missing_properties` (an array
naming identification properties the device did not report).

All values originate from the device and are treated as untrusted: control
characters are stripped and lengths are capped before storage.

**No telephony, subscriber, account, contact or location identifier is
collected.** The selection is limited to what documents the acquisition.

### `artifacts[]`

| Field | Type | Required | Description |
|---|---|---|---|
| `path` | string | yes | Case-relative, forward slashes, never absolute, never containing `..` |
| `classification` | enum | yes | `original`, `derived` or `working` |
| `role` | enum | yes | `physical-image`, `logical-archive`, `image-segment`, `converted-image`, `working-copy`, `extracted-file` |
| `format` | string | yes | Container format, e.g. `raw`, `tar`, `raw-segmented`, `ewf` |
| `size_bytes` | integer | yes | Size in bytes |
| `hashes.sha256` | string | yes | 64 lower-case hex characters |
| `hashes.sha512` | string | no | 128 lower-case hex characters, when `--sha512` was used |
| `complete` | boolean | yes | False when the transfer did not run to completion |
| `created_at` | RFC 3339 | yes | When the artifact was opened for writing |
| `derived_from` | string | no | Case-relative path of the source artifact |
| `segment_index` | integer | no | Position in a segmented set, starting at 1 |
| `notes` | string | no | Free-text qualification, e.g. why an artifact is incomplete |

An artifact whose `path` ends in `.partial` is by definition incomplete.

### `events[]`

| Field | Type | Required |
|---|---|---|
| `timestamp` | RFC 3339 | yes |
| `event` | string | yes |
| `result` | string | yes |
| `detail` | string | no |

Ordered chronologically. Event names emitted by this version:
`transfer-started`, `artifact-published`, `post-write-verification`,
`partial-data-preserved`, `logical-acquisition`, `physical-acquisition`,
`derived-artifact-created`, `acquisition`, `manifest-generated`.

## ✔️ Validation rules

`nootextract manifest` enforces:

- `manifest_version` parses as `MAJOR.MINOR`, and `MAJOR` equals 1.
- Every `artifacts[].path` is relative and contains no `..`.
- Every `sha256` is 64 hex characters; every `sha512`, when present, is 128.

and reports as non-fatal notes:

- a `MINOR` higher than this build understands,
- an empty `artifacts` array,
- an artifact marked incomplete while the operation status is complete,
- a complete operation with no `completed_at`.

## 🔐 Hash list side file

Each manifest has a companion `hashes/<evidence-id>-<operation-id>.sha256` in
coreutils format — `<sha256><two spaces><case-relative path>` — so an evidence
set can be checked with an independent tool:

```sh
cd ./evidence/CASE-001 && sha256sum -c hashes/EVIDENCE-001-*.sha256
```

## 📄 Example

```json
{
  "manifest_version": "1.0",
  "manifest_id": "acq-20260917T124848.902Z",
  "generated_at": "2026-09-17T12:48:49.113052800Z",
  "tool": {
    "name": "nootextract",
    "version": "0.1.0",
    "external_tools": { "adb": "Android Debug Bridge version 1.0.41" }
  },
  "host": { "os": "windows", "arch": "x86_64", "family": "windows" },
  "case": { "case_id": "CASE-001", "evidence_id": "EVIDENCE-001" },
  "operation": {
    "operation_id": "acq-20260917T124848.902Z",
    "method": "adb-logical-tar",
    "method_description": "Logical acquisition of `/sdcard` as a tar stream via `adb exec-out`",
    "source": {
      "source_id": "FAKEDEVICE01",
      "source_path": "/sdcard",
      "remote_command": ["tar", "-c", "-f", "-", "/sdcard"],
      "reported_size_bytes": 262144
    },
    "started_at": "2026-09-17T12:48:48.902677600Z",
    "completed_at": "2026-09-17T12:48:49.113003800Z",
    "duration_ms": 210,
    "status": "completed",
    "parameters": {
      "allow_source_read_errors": "false",
      "container": "tar",
      "device_state": "authorized",
      "post_write_verify": "true",
      "sha512": "false",
      "source_path": "/sdcard"
    }
  },
  "device": {
    "serial": "FAKEDEVICE01",
    "manufacturer": "FakeVendor",
    "model": "Fake Model X",
    "android_release": "14",
    "android_sdk": "34",
    "security_patch": "2025-01-05",
    "build_id": "FAKE.240101.001",
    "build_type": "user",
    "crypto_state": "encrypted",
    "shell_uid": 2000
  },
  "artifacts": [
    {
      "path": "original/EVIDENCE-001-logical.tar",
      "classification": "original",
      "role": "logical-archive",
      "format": "tar",
      "size_bytes": 262144,
      "hashes": {
        "sha256": "13e83532fdd5f99da72e9b2cfb65a2c397b4ebef18e1d163c51c8939ee451619"
      },
      "complete": true,
      "created_at": "2026-09-17T12:48:49.033397700Z"
    }
  ],
  "events": [
    { "timestamp": "2026-09-17T12:48:49.033406Z", "event": "transfer-started", "result": "ok" },
    { "timestamp": "2026-09-17T12:48:49.107361300Z", "event": "artifact-published", "result": "ok" },
    { "timestamp": "2026-09-17T12:48:49.112989500Z", "event": "post-write-verification", "result": "match" },
    { "timestamp": "2026-09-17T12:48:49.113062Z", "event": "manifest-generated", "result": "completed" }
  ],
  "warnings": [
    "the device reports encrypted userdata; a logical acquisition captures only what the ADB shell can read while the device is unlocked"
  ]
}
```

This example was produced by an actual run against the scripted test device, with
the `adb` path shortened for readability.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
