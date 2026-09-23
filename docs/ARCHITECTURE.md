# 🏗️ Architecture

> *How the colony is organised, and which walls of ice must not be moved.*

## 🧱 Layers

```text
src/
    main.rs             argument parsing, signal handler, exit-code mapping
    cli.rs              clap definition and the exit-code contract text
    interactive.rs      guided session: a front end over the same commands
    commands/           operator workflows
        device.rs       devices, info, methods
        doctor.rs       environment diagnostics
        report.rs       Markdown case report
        acquire.rs      acquisition orchestration
        evidence.rs     hash, verify, manifest
        derive.rs       convert, copy, extract
    acquisition/        backends that obtain bytes from a source
        backend.rs      the AcquisitionBackend trait and its context types
        adb.rs          shared streaming, status determination, post-write check
        logical.rs      adb-logical-tar
        physical.rs     adb-physical-dd
    evidence/           layout, manifests, verification
        store.rs        EvidenceStore, ArtifactWriter, write discipline
        manifest.rs     schema 1.0
        verify.rs       MATCH / MISMATCH / MISSING / EXTRA
    imaging/            format identification, conversion and extraction
        format.rs       signature-based identification
        archive.rs      safe tar extraction into manifested files
        segmented.rs    raw -> segmented raw
        ewf.rs          raw -> E01 via libewf
    adb/                process execution and ADB protocol handling
        runner.rs       CommandRunner, SystemRunner, bounded capture
        remote.rs       device-side command construction and quoting
        client.rs       typed ADB client, untrusted-output parsing
    device/             connection state, identification metadata, serials
    hashing.rs          streaming SHA-256 / SHA-512
    logging.rs          tracing setup, console and case log
    output.rs           tables, JSON, progress
    util/               path safety, cancellation, byte parsing
```

## 🎛️ The interactive session

`nootextract` with no arguments starts a guided session. It builds the same
argument structures the flags produce and calls the same command functions, so a
guided run cannot reach a state the command line cannot, and cannot skip a check
that only the flag path enforces.

It prints the equivalent command line before every operation. An operation
performed through a menu that leaves no reproducible form behind is not
auditable, and "I chose acquire from a list" is not an answer to how evidence was
produced. The session also refuses to start without a terminal, so a bare
invocation in a pipe or a CI job is a usage error rather than a hang.

The input reader is injected rather than taken from `stdin` directly, so prompt
flows are driven by scripted transcripts in tests.

## 🚧 The boundary that matters

`acquisition` and `evidence` are deliberately separated.

A backend receives an `AcquisitionContext` — which owns an `&EvidenceStore` — and
returns an `AcquisitionOutcome`. It never chooses where bytes land, how files are
named, how digests are computed, or what goes into a manifest. All of that is
`evidence`'s responsibility.

The consequence is that adding an acquisition method cannot weaken evidence
handling: a new backend has no way to overwrite an original, skip a digest, or
write outside the case directory, because it has no API for any of those things.

`evidence` in turn knows nothing about Android or ADB. It handles bytes,
classifications and records.

## ➕ Adding an acquisition backend

1. Implement `AcquisitionBackend` in a new module under `src/acquisition/`.
2. `info()` returns a `BackendInfo` with a stable `id`, its requirements and its
   host-platform caveats. Do not claim platform parity you have not verified.
3. `preflight()` validates that the method can run and describes what it will
   do. It must not transfer evidence. If an authorized path is unavailable,
   return `Error::Unsupported` describing the limitation — never attempt to work
   around it.
4. `acquire()` streams data through `EvidenceStore::create_artifact` and returns
   the real status. Returning `Completed` after a partial transfer is a defect.
5. Add the backend to `available_backends()` in `src/acquisition/mod.rs`.

Nothing else changes. The manifest, hashing, verification and CLI pick it up.

## 🔬 Testability

Two seams make the system testable without hardware.

`CommandRunner` abstracts process execution, so `AdbClient` can be driven by a
scripted implementation in unit tests.

`nootextract-fake-adb` is a small binary, behind the `test-support` feature, that
speaks the ADB command surface NootExtract uses and is steered by environment
variables. The integration suite runs the **real** binary against it, so argument
construction, stream handling, hashing, manifest generation and exit codes are
all exercised end to end.

`ProgressSink` keeps backends independent of any terminal.

## ⚙️ Concurrency and I/O

The tool is synchronous. Its workload is one subprocess pipe feeding one file
write; an async runtime would add a dependency and complexity without improving
throughput, so `tokio` is deliberately not used.

Threads are used in exactly one place: `SystemRunner` drains a child's stderr on
a separate thread, because reading two pipes serially deadlocks as soon as one
fills its kernel buffer.

Memory use is bounded and independent of image size — 1 MiB read, hash and write
buffers, and capped capture of any device-controlled output.

## 🛑 Cancellation

`CancellationToken` is an atomic flag shared by the signal handler, the
acquisition loop and the hashing loops. A Ctrl-C sets the flag; the worker thread
observes it within one buffer, kills the child process, flushes and fsyncs what
was written, finalizes the digest, records the partial artifact in the manifest
and exits 130. Teardown deliberately happens on the worker thread so no partial
artifact is ever left unhashed and unrecorded.

## ⚠️ Error handling

One `Error` enum, one variant per failure class, each mapping to exactly one exit
code. `main` performs the mapping; no command calls `std::process::exit`. I/O
errors carry the operation and the path so the message is actionable.

`unsafe` is forbidden crate-wide (`unsafe_code = "forbid"`); there is none.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
