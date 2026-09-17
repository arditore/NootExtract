# 🚦 Exit-code contract

> *Every way off the ice floe has a number.*

Every failure resolves to exactly one error variant, and every variant maps to
exactly one exit code. The numeric values are part of the public interface and
will not be reassigned; new conditions receive new codes.

| Code | Name | Meaning |
|---|---|---|
| 0 | success | The operation completed and every integrity check passed |
| 1 | failure | Unclassified runtime failure: I/O error, malformed input, unreadable manifest |
| 2 | usage | Command-line usage error, including rejected identifiers and unknown methods |
| 3 | device | Device absent, offline, unauthorized, or otherwise unusable |
| 4 | acquisition | The acquisition started but did not complete |
| 5 | integrity | Verification reported MISMATCH, MISSING or EXTRA, or a digest did not match |
| 6 | destination | Unsafe destination: already occupied, not a directory, not writable, symlinked |
| 7 | insufficient space | The destination filesystem cannot hold the expected image |
| 8 | missing tool | A required external tool (`adb`, `ewfacquire`) was not found |
| 9 | unsupported | The operation is not supported by the available authorized methods |
| 130 | interrupted | The operator interrupted the run (Ctrl-C / SIGINT) |

Code 2 matches clap's own convention, so an argument rejected by the parser and
one rejected by validation are indistinguishable to a caller — which is the
intent.

## 📝 Notes on specific codes

**4 (acquisition)** means a transfer began and stopped early. Partial data is
preserved as a `.partial` file and recorded in a manifest with
`status: "failed"`. A manifest is always written on this path.

**5 (integrity)** is never returned on a success path. A digest mismatch, a
missing artifact, an unaccounted file, a source that no longer matches its
manifest, and a post-write verification failure all produce it.

**6 (destination)** is preferred over 4 even when it surfaces during a transfer.
An occupied destination is a destination problem, not a transfer failure, and the
code reflects that rather than reporting the more generic error.

**6 (destination)** also covers writing into a case directory that already holds
evidence for a different case, which is refused rather than merged.

**9 (unsupported)** is how a limitation is reported. An unprivileged ADB shell
blocking physical acquisition, a device without `tar`, or a path the shell cannot
read all produce it. It never indicates that a protection mechanism should be
worked around.

**130** follows the shell convention of `128 + SIGINT`.

## 💻 Behaviour in scripts

```sh
nootextract verify ./evidence/CASE-001
case $? in
  0) echo "evidence intact" ;;
  5) echo "INTEGRITY FAILURE - investigate before proceeding"; exit 1 ;;
  *) echo "verification could not be completed"; exit 1 ;;
esac
```

With `--json`, results go to stdout and errors go to stderr as
`{"error": {"kind": ..., "message": ..., "exit_code": ...}}`, so a wrapper can
branch on `kind` without parsing prose.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
