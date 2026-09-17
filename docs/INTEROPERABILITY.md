# 🔗 Interoperability with analysis tools

> *Handing the catch to a neighbouring colony.*

## ✅ Verification status — read this first

| Claim | Status |
|---|---|
| `hashes/*.sha256` verifies with coreutils `sha256sum -c` | **Tested.** Executed against a NootExtract-produced case; reported `OK` |
| Manifests are valid JSON with the documented schema | **Tested**, automated, plus an independent Python validator |
| Segmented raw output follows the `.001`/`.002` naming convention | **Tested** that the files are produced and reassemble byte for byte |
| Autopsy imports a NootExtract raw image | **Not tested.** No Autopsy installation was used |
| Autopsy imports a NootExtract segmented raw set | **Not tested** |
| Autopsy imports a NootExtract E01 | **Not tested**, and the E01 path itself was never executed — libewf was unavailable |
| The Sleuth Kit reads these images | **Not tested** |
| Any tar archive from a real device opens in any given tool | **Not tested** on real device output |

The procedures below are written from the documented behaviour of those tools.
They are a starting point for your own validation, not a compatibility claim.
**Validate the workflow on non-evidential test data before using it on a case.**

## 🎣 What each acquisition produces

| Method | Output | What it is |
|---|---|---|
| `adb-logical-tar` | `original/<evidence-id>-logical.tar` | POSIX tar archive of a directory subtree, as read through the device's filesystem layer |
| `adb-physical-dd` | `original/<evidence-id>-<partition>.raw` | Bit-stream image of one block device |

This distinction governs what an analysis tool can do with the result.

A **raw physical image** carries a filesystem, so a forensic suite can parse it,
recover unallocated space and carve deleted content.

A **logical tar archive** is a file container, not a filesystem image. Tools that
expect a disk image will not parse it as one. It carries only files the ADB shell
could read, with their POSIX metadata; there is no unallocated space in it and no
deleted content to recover.

## ✅ Verify before importing

Always confirm the evidence is intact before handing it to another tool:

```sh
nootextract verify ./evidence/CASE-001
```

Exit 0 means every recorded artifact matched. Exit 5 means something did not —
investigate before proceeding. An independent check is available too:

```sh
cd ./evidence/CASE-001 && sha256sum -c hashes/EVIDENCE-001-*.sha256
```

## 🐟 Work from a copy

Analysis tools may write to what they open. Produce a working copy first; the
original is never opened for writing by NootExtract, and should not be by
anything else:

```sh
nootextract copy ./evidence/CASE-001/original/EVIDENCE-001-userdata.raw
# -> working/EVIDENCE-001-userdata.raw, digest-checked against the source
```

## 🔬 Autopsy

*Procedure below is from Autopsy's documented behaviour; it has not been executed
against this tool's output.*

### Raw physical image

1. **Case → New Case**, entering the same case number you used for `--case-id`
   so the two records line up.
2. **Add Data Source → Disk Image or VM File**.
3. Select `working/<evidence-id>-<partition>.raw`.
4. Autopsy detects split raw sets automatically when you select the first
   segment (`.001`); the remaining segments must sit in the same directory under
   their sequential names, which is how NootExtract writes them.
5. Configure ingest modules and run.

Autopsy computes its own hash on ingest. Compare it with the `sha256` in the
NootExtract manifest — note that Autopsy's disk-image hashing has historically
been MD5-oriented, so you may need to compare via `nootextract hash` output
rather than in the Autopsy UI.

### Logical tar archive

Autopsy's **Logical Files** data source expects files or folders, not a tar
container. Extract it first, to a working location — never over the original:

```sh
mkdir -p ./evidence/CASE-001/working/EVIDENCE-001-extracted
tar -xf ./evidence/CASE-001/original/EVIDENCE-001-logical.tar \
    -C ./evidence/CASE-001/working/EVIDENCE-001-extracted
```

Then **Add Data Source → Logical Files** and select that directory.

Note two consequences of extraction: the host filesystem may not preserve Android
ownership and permission metadata, and files whose names are legal on Android but
not on the host (particularly on Windows) may fail to extract. Extract on Linux
where possible, and reconcile the extracted file count against the archive
listing.

Extraction produces files NootExtract did not record, so a later `verify` will
report them as `EXTRA`. That is correct — they are unaccounted-for files. Use
`--ignore-extra` once you have confirmed their provenance, or keep extractions
outside the case directory.

### E01

If you produce an E01 (see [IMAGE_FORMATS.md](IMAGE_FORMATS.md)), add it as
**Disk Image or VM File** and select the `.E01`. Autopsy reads the remaining
segments from the same directory. Confirm `ewfverify` succeeded first — and note
that the E01 path in this version has never been executed.

## 🔬 The Sleuth Kit

For a raw physical image:

```sh
mmls working/EVIDENCE-001-userdata.raw     # partition layout, if any
fsstat working/EVIDENCE-001-userdata.raw   # filesystem details
fls -r working/EVIDENCE-001-userdata.raw   # file listing
```

A `userdata` partition image usually has no partition table, so `mmls` will
report nothing and `fsstat`/`fls` should be pointed at the image directly. On a
device with file-based encryption the image contains ciphertext and these tools
will not find a readable filesystem — that is expected, and no part of this tool
changes it.

## 🏢 X-Ways, EnCase, Magnet AXIOM

These accept raw and split-raw images through their standard image-import
dialogs. Segmented raw sets use the `.001` convention NootExtract emits. None of
this has been tested against these products.

## ⛓️ Preserving the chain of custody

Whatever tool you import into, keep together:

- the file under `original/` (or a verified working copy),
- its manifest from `manifests/`,
- its hash list from `hashes/`,
- the run log from `logs/`.

The manifest records the tool version, the acquisition method, the exact command
executed on the device, the device metadata, the start and completion times, and
every warning and error. That is the record of how the evidence came to exist.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
