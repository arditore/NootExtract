# 🛡️ Security model

> *The colony trusts nothing that swims in from open water.*

## 🔑 Authorization stance

NootExtract operates only with access the device has already granted. It does
not attempt to defeat PINs, passwords, biometrics, lock screens, file-based or
metadata encryption, verified boot, secure boot, OEM protections, enterprise
controls, or any other authentication or access-control mechanism, and it
contains no exploit, privilege-escalation or credential-extraction code.

Concretely:

- An `unauthorized` device is never presented as acquirable. Accepting the USB
  debugging prompt is an action taken on the handset by the operator.
- Physical acquisition checks whether the ADB shell **already** runs as UID 0. If
  it does not, the limitation is reported (exit 9). No `su` invocation, no
  `adb root` daemon restart, and no other escalation is attempted.
- A raw image of an encrypted partition contains ciphertext. NootExtract acquires
  and documents those bytes and provides no means of decrypting them.
- If no authorized method can reach the data, that is the reported outcome.

## 🧭 Trust boundaries

Everything reaching the tool from outside is untrusted:

| Source | Treatment |
|---|---|
| Device system properties | Control characters stripped, length-capped, property count capped |
| Device serials | Validated against `[A-Za-z0-9.:_-]{1,64}`, must not start with `-`; entries failing validation are dropped from the device list |
| Device stdout | Streamed to disk without interpretation; never parsed as a command |
| Device stderr | Sanitized, line-capped, stored as manifest errors or warnings |
| Manifests on disk | Schema-validated before use, including artifact-path safety |
| Operator identifiers | Validated against a narrow alphabet before becoming path components |

## 🔍 Review findings and mitigations

### Command injection

**Host side.** No shell is ever involved. Every external program is launched with
`std::process::Command` and an explicit argument vector; no command line is
assembled as a string. An argument containing `;`, `&&`, backticks or quotes
reaches the target program verbatim.

**Device side.** `adb shell` and `adb exec-out` join their arguments and hand the
result to `/system/bin/sh` on the handset, which re-parses it. This is a genuine
injection point. `adb/remote.rs` builds the remote command as a single
fully POSIX-quoted string: safe words pass through, everything else is wrapped in
single quotes with embedded quotes emitted as `'\''`. Remote paths are
additionally validated — absolute, no control characters, no `..`, length-capped
— so malformed input is rejected rather than merely neutralized.

Tested by re-parsing quoted payloads with a POSIX word splitter and asserting
that each yields exactly one word identical to the input, and end to end by
driving the real binary with a path full of shell syntax.

### Path traversal

All evidence paths go through `join_inside`, which rejects absolute paths,
drive-relative and UNC prefixes, and `.` and `..` components. Manifest artifact
paths are re-validated on load, so a hand-edited manifest cannot direct a read or
write outside the case directory. Operator identifiers are validated before they
become path components; Windows reserved device names are rejected.

### Symlink attacks

Before any evidence file is created, every path component below the case root is
checked with `symlink_metadata`; a symlinked component aborts the operation. The
evidence root itself is refused if it is a link. During verification, an artifact
that has become a symlink is reported as `MISMATCH` and not followed — even when
the link target happens to have matching content.

### TOCTOU

The lexical and symlink checks cannot close the race on their own, so every
evidence file is created with `create_new`, where the existence check and the
creation are one syscall. A file appearing between check and open causes a
failure, not an overwrite. The final rename is guarded by a second existence
check, and the acquired data is preserved under its `.partial` name if that check
fires.

### Temporary files

Manifests are written to a uniquely named temporary file in the destination
directory, opened with `create_new`, fsynced, then renamed over the target. No
shared temporary directory is used, so there is no cross-user temp race. The only
file the tool ever deletes is the destination write probe, which it created
itself moments earlier.

### Resource exhaustion

Every device-controlled channel is bounded: 4 MiB for metadata output, 256 KiB
for stderr during a transfer, 4096 system properties, 256 device-list entries,
200 recorded stderr lines. When a cap is hit the capture is truncated, the
truncation is flagged, and the remainder of the pipe is *drained* rather than
abandoned — abandoning it would leave the child blocked on a full pipe and the
acquisition unable to observe its exit status.

Memory use during acquisition, hashing, conversion and copying is a constant
1 MiB per buffer, independent of image size.

### Integer overflow

Byte counters saturate rather than wrap; a wrapped length would be recorded as a
false artifact size. Size parsing uses `checked_mul` and rejects overflow. The
free-space headroom calculation saturates, which is covered by a test using
`u64::MAX`. Segment indices are checked and capped at 999.

### Malformed device responses

`adb devices -l` and `getprop` parsing tolerate arbitrary input: unparsable lines
are skipped, entries with unusable serials are dropped, and multi-word states
such as `no permissions (...)` are handled. Unknown connection states are
preserved verbatim and treated as **not** acquirable.

### Corrupted images

Verification recomputes digests from disk and reports size and content
differences separately. Tests cover single-bit flips at the start, middle and end
of an image, truncation, and zero-length replacement.

### Malicious filenames

Device-derived strings are never used as a path directly. A filename fragment
built from untrusted data is reduced to `[A-Za-z0-9._-]`, has separator runs
collapsed, leading dots and dashes stripped, is length-capped, and is rejected if
it collides with a Windows reserved device name or reduces to nothing.

### Terminal and log injection

Control characters — including ANSI escape sequences and newlines — are removed
from device strings before they reach operator output, the manifest or the JSON
Lines log. A hostile property value cannot forge a log line or repaint the
terminal.

## 🧠 Memory safety

`unsafe_code = "forbid"` is set crate-wide. The crate contains no `unsafe` block,
and none of its direct dependencies required one to be written here. Clippy runs
with `all` and `pedantic` plus `unwrap_used`, `expect_used`, `panic`,
`indexing_slicing` and the numeric-cast lints denied in non-test code.

## ⚠️ Residual risks

- **Host compromise.** NootExtract trusts the host it runs on. A compromised
  examination workstation invalidates every guarantee here.
- **`adb` itself.** The Android platform-tools binary is trusted to relay bytes
  faithfully. Its version is recorded in each manifest.
- **libewf.** When `--format ewf` is used, container construction is delegated to
  `ewfacquire`; the produced segments are hashed and manifested by NootExtract,
  but their internal correctness is libewf's responsibility.
- **Device-side truth.** A device can report whatever properties and bytes it
  chooses. NootExtract records what it was given; it cannot attest that the
  device told the truth.
- **Filesystem-level races outside the case directory.** Protections apply below
  the evidence root. An attacker with write access to that root can still
  interfere with a case; the tool detects tampering after the fact through
  verification rather than preventing it.
- **Logical acquisition scope.** What the ADB shell can read is what is captured.
  See [LIMITATIONS.md](LIMITATIONS.md).

## 📨 Reporting

Report suspected vulnerabilities to the repository owner through the project's
issue tracker or private contact channel, whichever the owner designates.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
