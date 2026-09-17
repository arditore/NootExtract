# ⏸️ Resumable acquisition

> *Why half a fish is never stitched onto another half.*

**Not implemented, deliberately.** This document records the investigation and
the reasoning, so the decision can be revisited with the analysis in hand rather
than repeated from scratch.

## 📌 The requirement

A resumed acquisition would have to verify the existing data, detect corruption,
record the resume event, preserve what was already acquired, and update the
manifest. Those are implementable. The problem is upstream of all of them.

## 🤔 Why it is unsafe for the current backends

### Logical acquisition (`adb-logical-tar`)

The artifact is a tar stream generated on the fly by the device. There is no
stable mapping from a byte offset in the stream to a position in the source tree:
the stream's content depends on directory iteration order, on file sizes at the
moment each entry is read, and on which files were readable during that run.

Restarting `tar` and skipping N bytes does not resume the same archive. It
produces a *different* archive, spliced onto the first one at an arbitrary
boundary. The result would be a file that looks like a tar archive, carries a
digest, and is internally inconsistent — worse than an honest partial, because it
would pass a structural glance.

### Physical acquisition (`adb-physical-dd`)

Byte offsets are meaningful here: `dd skip=N` resumes at a defined position, and
the segments could be concatenated correctly.

The problem is that the source is a **live block device on a running system**. The
device keeps writing to `userdata` between the interruption and the resume —
journal commits, log rotation, background sync, the transfer's own effect on the
device. The concatenation of a prefix read at T0 and a suffix read at T1 is an
image that never existed at any single moment. Filesystem structures can
reference blocks that were rewritten in the gap, so the image can be internally
inconsistent in ways that only surface during analysis.

An image assembled from two points in time, recorded under one digest as though
it were one acquisition, misrepresents what was acquired. The digest would be
mathematically correct and evidentially misleading.

## 🔄 What NootExtract does instead

An interrupted transfer is treated as a completed *failure*, fully documented:

1. Data already written stays under its `.partial` name. The name reserved for a
   complete image stays free, so a partial can never be mistaken for a whole one.
2. The partial file is flushed, fsynced and hashed. It is a documented,
   verifiable object rather than an unknown quantity.
3. It is recorded in the manifest with `complete: false`, a note explaining why,
   and `status` of `failed` or `cancelled`.
4. The process exits 4 (failed) or 130 (interrupted). Never 0.
5. `nootextract verify` passes on the resulting case, because the partial
   artifact is properly accounted for.

To acquire again, use a new `--evidence-id`. The earlier partial is preserved and
remains documented; the new acquisition is a separate, complete record. Both
attempts stay in the case, which is the accurate account of what happened.

## 🔀 Conditions under which this could change

Resumption could be reconsidered for a backend where:

- the source is genuinely immutable for the duration — a powered-off device
  imaged through a hardware interface, a read-only mount, or a device in a mode
  that guarantees no writes; **and**
- the already-written prefix can be re-verified against the source at the resume
  offset, not merely against itself; **and**
- the manifest records the resume as a distinct event, with the offset, the
  verification result and both time ranges, so a reader can see that the image
  spans two acquisition windows.

The third condition is the important one. If those hold, a resumable backend can
be added without touching the evidence layer, exactly as
[ARCHITECTURE.md](ARCHITECTURE.md) describes. Until they hold, a partial
acquisition that says so is the correct outcome.

---

<sub>🐧 **NootExtract** — *noot noot.* · [Back to the README](../README.md)</sub>
