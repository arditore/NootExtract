# 🧊 Image formats and conversion

> *Reshaping the ice never melts the original.*

## 🧭 Principle

A conversion produces a **new derived artifact**. The source is opened read-only
and is never renamed, truncated or rewritten. Renaming a file's extension is not
a conversion and NootExtract never does it: either this crate restructures the
bytes itself, or the work is delegated to an established library whose output is
then hashed and manifested like any other artifact.

```text
original/EVIDENCE-001-userdata.raw      ← untouched
derived/EVIDENCE-001-userdata.001       ← new artifact, new manifest
derived/EVIDENCE-001-userdata.002
```

## 🔎 Format identification

`ImageFormat` recognizes `raw`, `raw-segmented`, `tar`, `ewf` and `ewf2`.

Identification prefers content over file names, and reports which it used:

| Evidence | Meaning |
|---|---|
| `signature` | A documented signature was found: EWF (`EVF\x09\x0d\x0a\xff\x00`), EWF2 (`EVF2\x0d\x0a\x81\x00`), or POSIX tar (`ustar` at offset 257) |
| `filename` | No signature; inferred from the extension |
| `assumed` | Nothing identified the file; treated as an unstructured image |

A raw image has no signature by definition, so `raw` is the residual case rather
than a positive identification — and the tool says so:

```text
size: 256.00 KiB (262144 bytes), format: raw (no signature found; treated as an unstructured image)
```

A misleading extension does not win: a file named `archive.raw` whose content
carries the tar magic is identified as `tar` by signature.

## 📥 Sources

Conversion reads formats this crate interprets itself:

| Source format | Supported |
|---|---|
| `raw` | yes |
| `tar` | yes |
| `ewf` / `ewf2` | no — reading EWF would mean reimplementing a mature library |
| `raw-segmented` | no — reassembly is not implemented in this version |

## 📤 Targets

### Segmented raw (`--format raw-segmented`)

Splits a raw image into sequentially numbered segments (`.001`, `.002`, …), the
convention understood by Autopsy, The Sleuth Kit and EnCase for split raw
evidence.

```sh
nootextract convert ./evidence/CASE-001/original/EVIDENCE-001-userdata.raw \
    --format raw-segmented --segment-size 2G
```

- `--segment-size` accepts binary units: `512`, `64K`, `2M`, `4G`, `1TiB`.
  Default 2 GiB, which stays below the FAT32 file-size limit for transfer media.
  Minimum 1 MiB; maximum 999 segments.
- The concatenation of the segments is byte-identical to the source. The
  conversion proves this by hashing the source stream as it reads and comparing
  the result against the digest computed before the conversion started; a
  mismatch fails with exit 5.
- Each segment is hashed individually and recorded with its `segment_index`.

This path is implemented in this crate and is covered by tests that concatenate
the produced segments and compare them byte for byte against the source.

### EWF / E01 (`--format ewf`)

EWF is a documented but non-trivial container with its own compression, chunk
checksums and metadata sections. libewf is the mature, widely reviewed
implementation, so NootExtract delegates to it rather than reimplementing it.

```sh
nootextract convert ./evidence/CASE-001/original/EVIDENCE-001-userdata.raw \
    --format ewf --case-id CASE-001 --evidence-id EVIDENCE-001
```

What NootExtract does:

1. Refuses if any `derived/<name>.E*` file already exists.
2. Runs `ewfacquire -u` (unattended) with format `encase6`, the requested segment
   size, and the case metadata, writing into `derived/`.
3. Hashes every produced segment and records it as a derived artifact.
4. Runs `ewfverify` against the container when that tool is available, and
   records the result in the manifest. If `ewfverify` reports failure, the
   conversion fails with exit 5. If `ewfverify` is absent, a warning says so and
   advises running it manually.

libewf is **not bundled**. When `ewfacquire` is missing the conversion exits 8
with installation guidance:

| Platform | Installation |
|---|---|
| Debian / Ubuntu | `apt install ewf-tools` |
| Fedora | `dnf install libewf-tools` |
| macOS | `brew install libewf` |
| Windows | libewf release binaries; then pass `--ewfacquire-path` |

Override the tool locations with `--ewfacquire-path` and `--ewfverify-path`.

## ✅ Verification status

| Path | Status |
|---|---|
| Format identification by signature and by name | Tested, automated |
| raw → segmented raw | Tested, automated, including byte-for-byte reassembly |
| Refusal to convert a source that no longer matches its manifest | Tested, automated |
| Missing-libewf handling | Tested, automated |
| raw → EWF with libewf actually present | **Not tested.** libewf was not available in the development environment, so `ewfacquire` and `ewfverify` were never executed |

Treat the EWF path as implemented but unproven. Before relying on it, run one
conversion on a known image, confirm `ewfverify` reports success, and confirm the
container opens in your analysis tool.

## 🐟 Working copies

`nootextract copy` produces a verified copy under `working/`. The source is
verified against its manifest first, the copy is hashed as it is written, and the
two digests are compared; a difference fails with exit 5. Working copies exist
because analysis tools may modify what they open — the original never is.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
