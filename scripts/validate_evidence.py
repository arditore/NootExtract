#!/usr/bin/env python3
"""Independent validator for a NootExtract case directory.

This script exists to cross-check the Rust implementation with a second,
unrelated one. It re-implements the manifest rules and the digest computation
from the documentation alone, using only the Python standard library, and shares
no code with the tool it checks. A bug present in both implementations would have
to be made twice, independently, to go unnoticed.

It is a read-only verifier: it opens files for reading and writes nothing.

Usage:
    python scripts/validate_evidence.py ./evidence/CASE-001
    python scripts/validate_evidence.py ./evidence/CASE-001 --json

Exit codes mirror the tool's own contract where they overlap:
    0   every manifest is valid and every artifact matched
    1   the case could not be read
    5   a schema violation or a digest mismatch was found
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SUPPORTED_MAJOR = 1
READ_BLOCK = 1024 * 1024

HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
HEX128 = re.compile(r"^[0-9a-fA-F]{128}$")
RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")

REQUIRED_TOP_LEVEL = [
    "manifest_version",
    "manifest_id",
    "generated_at",
    "tool",
    "host",
    "case",
    "operation",
    "artifacts",
]
VALID_CLASSIFICATIONS = {"original", "derived", "working"}
VALID_STATUSES = {"completed", "completed-with-errors", "failed", "cancelled"}
EVIDENCE_DIRECTORIES = ("original", "derived", "working")


def sha256_of(path: Path) -> tuple[str, int]:
    """Stream a file through SHA-256, returning the digest and the byte count."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            block = handle.read(READ_BLOCK)
            if not block:
                break
            digest.update(block)
            total += len(block)
    return digest.hexdigest(), total


def sha512_of(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        while True:
            block = handle.read(READ_BLOCK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def check_schema(manifest: dict, name: str, problems: list[str]) -> None:
    """Apply the rules documented in docs/MANIFEST_SCHEMA.md."""
    for field in REQUIRED_TOP_LEVEL:
        if field not in manifest:
            problems.append(f"{name}: missing required field `{field}`")

    version = str(manifest.get("manifest_version", ""))
    if not re.fullmatch(r"\d+\.\d+", version):
        problems.append(f"{name}: manifest_version `{version}` is not MAJOR.MINOR")
    elif int(version.split(".")[0]) != SUPPORTED_MAJOR:
        problems.append(
            f"{name}: manifest_version `{version}` has an unsupported major version"
        )

    generated = manifest.get("generated_at", "")
    if not RFC3339.match(str(generated)):
        problems.append(f"{name}: generated_at `{generated}` is not RFC 3339")

    operation = manifest.get("operation", {})
    status = operation.get("status")
    if status not in VALID_STATUSES:
        problems.append(f"{name}: unknown operation status `{status}`")
    for field in ("operation_id", "method", "method_description", "source", "started_at"):
        if field not in operation:
            problems.append(f"{name}: operation is missing `{field}`")

    case = manifest.get("case", {})
    for field in ("case_id", "evidence_id"):
        value = case.get(field)
        if not value or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(value)):
            problems.append(f"{name}: case.{field} `{value}` is not a valid identifier")

    for artifact in manifest.get("artifacts", []):
        path = str(artifact.get("path", ""))
        label = f"{name}: artifact `{path}`"
        if not path:
            problems.append(f"{name}: an artifact has no path")
            continue
        if path.startswith("/") or ".." in path.split("/") or "\\" in path:
            problems.append(f"{label} is not a safe case-relative path")
        if artifact.get("classification") not in VALID_CLASSIFICATIONS:
            problems.append(
                f"{label} has unknown classification `{artifact.get('classification')}`"
            )
        if not isinstance(artifact.get("size_bytes"), int) or artifact["size_bytes"] < 0:
            problems.append(f"{label} has a non-integer size")
        hashes = artifact.get("hashes", {})
        if not HEX64.match(str(hashes.get("sha256", ""))):
            problems.append(f"{label} has a malformed SHA-256 digest")
        if "sha512" in hashes and not HEX128.match(str(hashes["sha512"])):
            problems.append(f"{label} has a malformed SHA-512 digest")
        if not isinstance(artifact.get("complete"), bool):
            problems.append(f"{label} has no boolean `complete` flag")

    events = manifest.get("events", [])
    timestamps = [event.get("timestamp", "") for event in events]
    if timestamps != sorted(timestamps):
        problems.append(f"{name}: the event log is not in chronological order")


def validate(case_root: Path) -> dict:
    """Validate every manifest and re-verify every artifact."""
    manifests_dir = case_root / "manifests"
    if not manifests_dir.is_dir():
        raise FileNotFoundError(f"`{case_root}` has no manifests/ directory")

    problems: list[str] = []
    results = []
    accounted: set[str] = set()

    manifest_paths = sorted(manifests_dir.glob("*.manifest.json"))
    if not manifest_paths:
        problems.append("the case contains no manifests")

    for manifest_path in manifest_paths:
        name = manifest_path.name
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            problems.append(f"{name}: not readable as JSON: {error}")
            continue
        if not isinstance(manifest, dict):
            problems.append(f"{name}: top level is not a JSON object")
            continue

        check_schema(manifest, name, problems)

        for artifact in manifest.get("artifacts", []):
            relative = str(artifact.get("path", ""))
            if not relative or relative in accounted:
                continue
            accounted.add(relative)

            target = case_root / relative
            if target.is_symlink():
                results.append({"path": relative, "outcome": "MISMATCH",
                                "detail": "artifact is a symbolic link"})
                continue
            if not target.is_file():
                results.append({"path": relative, "outcome": "MISSING", "detail": None})
                continue

            digest, size = sha256_of(target)
            expected = artifact.get("hashes", {})
            detail = None
            if size != artifact.get("size_bytes"):
                outcome = "MISMATCH"
                detail = f"size {size} != recorded {artifact.get('size_bytes')}"
            elif digest.lower() != str(expected.get("sha256", "")).lower():
                outcome = "MISMATCH"
                detail = "sha256 differs"
            elif "sha512" in expected and sha512_of(target).lower() != str(
                expected["sha512"]
            ).lower():
                outcome = "MISMATCH"
                detail = "sha512 differs"
            else:
                outcome = "MATCH"
            results.append({"path": relative, "outcome": outcome, "detail": detail})

    # Files present in an evidence directory that no manifest accounts for.
    for directory in EVIDENCE_DIRECTORIES:
        base = case_root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(case_root).as_posix()
            if relative not in accounted:
                results.append({"path": relative, "outcome": "EXTRA", "detail": None})

    # The coreutils-format side files must agree with the manifests.
    for hash_list in sorted((case_root / "hashes").glob("*.sha256")):
        for number, line in enumerate(
            hash_list.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not line.strip():
                continue
            if "  " not in line:
                problems.append(f"{hash_list.name}:{number}: not in sha256sum format")
                continue
            digest, relative = line.split("  ", 1)
            if not HEX64.match(digest):
                problems.append(f"{hash_list.name}:{number}: malformed digest")
                continue
            target = case_root / relative
            if not target.is_file():
                problems.append(f"{hash_list.name}:{number}: `{relative}` is missing")
                continue
            if sha256_of(target)[0].lower() != digest.lower():
                problems.append(f"{hash_list.name}:{number}: `{relative}` does not match")

    counts = {outcome: 0 for outcome in ("MATCH", "MISMATCH", "MISSING", "EXTRA")}
    for result in results:
        counts[result["outcome"]] += 1

    return {
        "case_root": str(case_root),
        "manifests_checked": [path.name for path in manifest_paths],
        "results": results,
        "counts": counts,
        "problems": problems,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently validate a NootExtract case directory."
    )
    parser.add_argument("case_root", type=Path, help="path to the case directory")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--ignore-extra",
        action="store_true",
        help="report unaccounted files without failing",
    )
    args = parser.parse_args()

    try:
        report = validate(args.case_root)
    except (OSError, FileNotFoundError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    failed = (
        report["counts"]["MISMATCH"] > 0
        or report["counts"]["MISSING"] > 0
        or bool(report["problems"])
        or (report["counts"]["EXTRA"] > 0 and not args.ignore_extra)
    )

    if args.json:
        report["passed"] = not failed
        print(json.dumps(report, indent=2))
    else:
        for result in report["results"]:
            detail = f"  ({result['detail']})" if result["detail"] else ""
            print(f"{result['outcome']:<9}{result['path']}{detail}")
        for problem in report["problems"]:
            print(f"PROBLEM  {problem}")
        counts = report["counts"]
        print(
            f"\n{counts['MATCH']} MATCH, {counts['MISMATCH']} MISMATCH, "
            f"{counts['MISSING']} MISSING, {counts['EXTRA']} EXTRA "
            f"({len(report['manifests_checked'])} manifest(s) checked)"
        )
        print("FAILED" if failed else "PASSED")

    return 5 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
