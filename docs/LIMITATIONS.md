# 🚧 Limitations

> *Where the ice shelf ends.*

What this tool does not do, and what each method cannot reach. Stated plainly so
the boundary is visible before an acquisition rather than after it.

## 🚫 Not attempted, by design

NootExtract makes no attempt to defeat PINs, passwords, patterns, biometrics,
lock screens, file-based or metadata encryption, verified boot, secure boot, OEM
protections, enterprise controls, or any authentication or access-control
mechanism. It contains no exploit, privilege-escalation, credential-extraction or
detection-evasion code.

When an authorized method cannot reach data, the tool reports the limitation and
exits 9. That is the intended outcome, not a gap to be closed.

## 🎣 Logical acquisition (`adb-logical-tar`)

Captures a directory subtree as the ADB shell user can read it.

Cannot capture:

- Unallocated space. There is none in a file-level archive.
- Deleted files, file slack, or anything recoverable only through carving.
- Directories the ADB shell (typically UID 2000, `shell`) cannot read — most of
  `/data` on a retail device.
- Content protected by file-based encryption for a locked user or profile. The
  device must be unlocked, and even then, other users' credential-encrypted
  storage stays unreadable.
- Filesystem metadata beyond what tar records.

The device's `tar` is toybox on modern Android. Behaviour on unreadable files,
special files and unusual names is toybox's, not this tool's. `tar` exiting
non-zero fails the acquisition unless `--allow-source-read-errors` is given, in
which case every error is recorded and the status becomes
`completed-with-errors`.

## 💽 Physical acquisition (`adb-physical-dd`)

Requires an ADB shell that **already** runs as UID 0 — an engineering or
userdebug build, or a device whose owner has made a root shell available. On an
ordinary retail device this method is unavailable, and NootExtract reports that
rather than trying to change it.

Further constraints:

- `--source` must name the block device explicitly. The partition is never
  guessed.
- On a device with file-based or metadata encryption, the image contains
  ciphertext. NootExtract acquires and documents those bytes; it does not decrypt
  them and offers no mechanism to.
- The source is a live block device on a running system, so the image is not a
  snapshot of a single instant. See [RESUMABILITY.md](RESUMABILITY.md).
- `--allow-source-read-errors` adds `conv=noerror,sync` to the remote `dd`, which
  substitutes zeroes for unreadable blocks. The image then differs from the
  source media at those offsets. This is recorded in the manifest parameters and
  warned about, and is off by default.

## 📱 Device states

Only a device reporting `device` (authorized) can be acquired. `unauthorized`,
`offline`, `bootloader`, `recovery`, `sideload`, `no permissions` and any
unrecognized state are reported as not acquirable, each with the reason.

Recovery mode is treated as not acquirable even though some recovery images
expose ADB, because whether it does — and with what privileges — depends entirely
on the image installed. Assuming otherwise would be a guess presented as a
capability.

## 💻 Platform differences

The evidence layer, hashing, manifests, verification and conversion behave
identically on Linux, macOS and Windows, and the automated suite runs on all
three by construction. What differs:

| Concern | Note |
|---|---|
| `adb` availability | Supplied by the Android SDK platform-tools on every platform; must be on `PATH` or given with `--adb-path` |
| USB device access on Linux | Requires udev rules. Without them the device reports `no permissions`, which is a host configuration problem, not a device lock |
| USB drivers on Windows | Some vendors require an OEM-specific driver before ADB sees the device |
| Symlink checks | Meaningful on all platforms, but the symlink-specific tests run only on Unix, where creating one needs no elevation |
| libewf | Not bundled anywhere; must be installed separately, and is least readily available on Windows |
| Extracting a tar archive | Android filenames legal on Linux may be invalid on Windows; extract on Linux where possible |

The `adb-logical-tar` and `adb-physical-dd` backends relay bytes through
`adb exec-out`, which is binary-clean on all three hosts. The behaviour that
varies is the *device's*, not the host's.

## 🧊 Format limitations

- EWF and segmented raw cannot be used as conversion *sources*.
- Segmented raw is limited to 999 segments, the range of a three-digit extension.
- The E01 path requires libewf and, in this version, has never been executed. See
  [IMAGE_FORMATS.md](IMAGE_FORMATS.md).

## 🚫 Not claimed

This tool does not make, and should not be read as making, any claim of
"forensic soundness", completeness or evidentiary sufficiency. It implements
specific, documented, testable behaviours — those in the README's guarantees
section. Whether an acquisition is admissible or complete depends on
authorization, procedure, the device, and the jurisdiction, none of which a
program can determine.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
