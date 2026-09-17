#!/usr/bin/env bash
#
# End-to-end workflow check.
#
# Drives the built binary through a complete case — physical acquisition,
# conversion to a segmented set, working copy, verification — against the
# scripted ADB stand-in, then cross-checks the result two independent ways:
# with the Python validator and with coreutils sha256sum.
#
# This script contains no forensic logic. It only invokes the tool and compares
# exit codes; every integrity decision is made by the programs it calls. It
# exists because this exact sequence caught a defect that the unit tests missed.
#
# Usage: scripts/e2e-check.sh

set -euo pipefail

# Git Bash on Windows rewrites arguments that look like Unix paths, which would
# mangle the device-side block device path (`/dev/block/...`) before it reaches
# the tool. Conversion is therefore disabled, and every host path handed to the
# tool is made native below so it needs no conversion in the first place.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Renders a path in a form both the shell and a native binary accept.
# On Windows that means `C:/...`; elsewhere the path is already native.
native_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -m "$1"
    else
        printf '%s' "$1"
    fi
}

exe_suffix=""
case "${OSTYPE:-}" in
    msys* | cygwin* | win32*) exe_suffix=".exe" ;;
esac

nootextract="target/release/nootextract${exe_suffix}"
fake_adb="target/release/nootextract-fake-adb${exe_suffix}"

if [ ! -x "$nootextract" ] || [ ! -x "$fake_adb" ]; then
    echo "building release binaries..."
    cargo build --release --all-features
fi

workspace="$(native_path "$(mktemp -d)")"
trap 'rm -rf "$workspace"' EXIT
case_root="$workspace/CASE-E2E"
nootextract="$(native_path "$repo_root")/$nootextract"
fake_adb="$(native_path "$repo_root")/$fake_adb"

# A device whose ADB shell already runs as UID 0, offering 5 MiB of data.
export FAKE_ADB_SCENARIO=root
export FAKE_ADB_PAYLOAD_BYTES=5242880

common=(--adb-path "$fake_adb" --no-progress --quiet)

echo "==> acquire (physical, sha256 + sha512)"
"$nootextract" acquire FAKEDEVICE01 \
    --case-id CASE-E2E --evidence-id EVIDENCE-001 \
    --output "$case_root" \
    --method adb-physical-dd --source /dev/block/by-name/userdata \
    --sha512 "${common[@]}"

echo "==> convert to a segmented raw set"
"$nootextract" convert "$case_root/original/EVIDENCE-001-userdata.raw" \
    --format raw-segmented --segment-size 2M "${common[@]}"

echo "==> create a working copy"
"$nootextract" copy "$case_root/original/EVIDENCE-001-userdata.raw" "${common[@]}"

echo "==> verify the case"
"$nootextract" verify "$case_root" "${common[@]}"

echo "==> cross-check with the independent Python validator"
# Probe by running the interpreter: on Windows, `python3` may resolve to the
# Microsoft Store stub, which exists on PATH but is not an interpreter.
python_bin=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
        python_bin="$candidate"
        break
    fi
done
if [ -z "$python_bin" ]; then
    echo "FAIL: no working Python interpreter found for the cross-check" >&2
    exit 1
fi
"$python_bin" scripts/validate_evidence.py "$case_root"

echo "==> cross-check the hash lists with coreutils sha256sum"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$case_root" && for list in hashes/*.sha256; do sha256sum -c "$list"; done)
elif command -v shasum >/dev/null 2>&1; then
    (cd "$case_root" && for list in hashes/*.sha256; do shasum -a 256 -c "$list"; done)
else
    echo "no sha256sum or shasum available; skipping this cross-check" >&2
fi

echo "==> confirm segments reassemble into the source byte for byte"
cat "$case_root"/derived/EVIDENCE-001-userdata.00[0-9] > "$workspace/reassembled.raw"
if cmp -s "$workspace/reassembled.raw" "$case_root/original/EVIDENCE-001-userdata.raw"; then
    echo "reassembled image matches the source"
else
    echo "FAIL: reassembled segments differ from the source" >&2
    exit 1
fi

echo "==> confirm tampering is detected"
# Flip one byte in a copy of the case, which must make verification fail.
tampered="$workspace/CASE-TAMPERED"
cp -r "$case_root" "$tampered"
target="$tampered/original/EVIDENCE-001-userdata.raw"
printf 'X' | dd of="$target" bs=1 seek=1024 conv=notrunc status=none

set +e
"$nootextract" verify "$tampered" "${common[@]}" >/dev/null 2>&1
verify_status=$?
set -e
if [ "$verify_status" -ne 5 ]; then
    echo "FAIL: tampered evidence should exit 5, got $verify_status" >&2
    exit 1
fi
echo "tampered evidence correctly reported as an integrity failure (exit 5)"

echo
echo "end-to-end check passed"
