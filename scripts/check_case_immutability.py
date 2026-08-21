#!/usr/bin/env python3
"""Reject rewrites of case bytes already present at a pull request's base."""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


OVERRIDE_ENV = "AEB_CASE_IMMUTABILITY_REPAIR"
OVERRIDE_TOKEN = "I_UNDERSTAND_CASE_IMMUTABILITY_REPAIR"
OVERRIDE_REASON_ENV = "AEB_CASE_IMMUTABILITY_REASON"
REPAIR_RECORD_DIR = Path("governance/case-repairs")


def fail(message):
    raise ValueError(message)


def git(root, *args):
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git {' '.join(args)} failed: {detail or 'no diagnostic'}")
    return result.stdout


def resolve_base(root, base):
    if not isinstance(base, str) or not base.strip():
        fail("base revision is required and must be non-empty")
    resolved = git(root, "rev-parse", "--verify", f"{base}^{{commit}}").decode("ascii").strip()
    if not resolved:
        fail("base revision resolved to an empty value")
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", resolved, "HEAD"],
        check=False,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        fail(f"base revision is not an ancestor of HEAD: {resolved}")
    return resolved


def base_tree_files(root, base):
    raw = git(root, "ls-tree", "-r", "-z", "--long", base, "--", "cases")
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            metadata, relative = record.split(b"\t", 1)
            _mode, kind, object_id, _size = metadata.split()
        except ValueError as exc:
            fail(f"cannot parse base tree record: {record!r}: {exc}")
        if kind != b"blob":
            continue
        entries.append((relative.decode("utf-8", errors="surrogateescape"), object_id))
    return entries


def read_base_blobs(root, entries):
    if not entries:
        return {}
    requested = b"".join(object_id + b"\n" for _relative, object_id in entries)
    result = subprocess.run(
        ["git", "-C", str(root), "cat-file", "--batch"],
        check=False,
        capture_output=True,
        input=requested,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"git cat-file --batch failed: {detail or 'no diagnostic'}")

    blobs = {}
    offset = 0
    for relative, object_id in entries:
        line_end = result.stdout.find(b"\n", offset)
        if line_end < 0:
            fail(f"git cat-file --batch returned no header for {relative}")
        header = result.stdout[offset:line_end].split()
        offset = line_end + 1
        if len(header) != 3 or header[0] != object_id or header[1] != b"blob":
            fail(f"git cat-file --batch returned an invalid blob header for {relative}")
        try:
            size = int(header[2])
        except ValueError as exc:
            fail(f"git cat-file --batch returned an invalid blob size for {relative}: {exc}")
        end = offset + size
        if len(result.stdout) < end + 1 or result.stdout[end:end + 1] != b"\n":
            fail(f"git cat-file --batch returned truncated blob data for {relative}")
        blobs[relative] = result.stdout[offset:end]
        offset = end + 1
    if offset != len(result.stdout):
        fail("git cat-file --batch returned unexpected trailing data")
    return blobs


def base_case_inventory(root, base):
    entries = base_tree_files(root, base)
    if not entries:
        fail(f"base revision {base} contains no files under cases/")
    raw_by_path = read_base_blobs(root, entries)

    cases = {}
    drift_dirs = {}
    for relative, _object_id in entries:
        parts = Path(relative).parts
        if len(parts) >= 4 and parts[:2] == ("cases", "mcp-drift"):
            case_id = parts[2]
            drift_dirs.setdefault(case_id, set()).add(relative)
            continue
        if len(parts) != 3 or parts[0] != "cases" or not relative.endswith(".json"):
            continue
        raw = raw_by_path[relative]
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            fail(f"base case is not valid JSON: {relative}: {exc}")
        case_id = document.get("id") if isinstance(document, dict) else None
        if not isinstance(case_id, str) or not case_id:
            fail(f"base case has no non-empty id: {relative}")
        if case_id in cases or case_id in drift_dirs:
            fail(f"duplicate base case id: {case_id}")
        cases[case_id] = {relative: raw}

    for case_id, drift_paths in drift_dirs.items():
        if not case_id:
            fail("MCP-drift case directory has an empty id")
        if case_id in cases:
            fail(f"duplicate base case id: {case_id}")
        if not any(path.endswith("/case.yaml") for path in drift_paths):
            fail(f"base MCP-drift case {case_id} has no case.yaml")
        cases[case_id] = {path: raw_by_path[path] for path in drift_paths}

    if not cases:
        fail(f"base revision {base} contains no discoverable cases")
    return cases, set(drift_dirs)


def current_drift_paths(root, case_id):
    directory = root / "cases" / "mcp-drift" / case_id
    if not directory.is_dir() or directory.is_symlink():
        return None
    paths = set()
    for path in directory.rglob("*"):
        if path.is_symlink():
            fail(f"current MCP-drift case contains a symlink: {path.relative_to(root)}")
        if path.is_file():
            paths.add(path.relative_to(root).as_posix())
    return paths


def current_regular_paths(root, case_id):
    """Discover every current single-file case carrying one existing case ID."""
    cases_dir = root / "cases"
    paths = set()
    for path in sorted(cases_dir.rglob("*.json")):
        relative = path.relative_to(root)
        if "mcp-drift" in relative.parts:
            continue
        if path.is_symlink() or not path.is_file():
            fail(f"current single-file case is not a regular file: {relative}")
        try:
            document = json.loads(path.read_bytes())
        except json.JSONDecodeError as exc:
            fail(f"current case is not valid JSON: {relative}: {exc}")
        if isinstance(document, dict) and document.get("id") == case_id:
            paths.add(relative.as_posix())
    return paths


def changed_base_cases(root, base, cases, drift_ids):
    changed = []
    for case_id, expected_files in sorted(cases.items()):
        expected_paths = set(expected_files)
        if case_id in drift_ids:
            actual_paths = current_drift_paths(root, case_id)
            if actual_paths is None:
                changed.append(f"{case_id}: MCP-drift case directory was removed")
                continue
            if actual_paths != expected_paths:
                changed.append(
                    f"{case_id}: file inventory changed "
                    f"(missing={sorted(expected_paths - actual_paths)}, added={sorted(actual_paths - expected_paths)})"
                )
                continue
        else:
            actual_paths = current_regular_paths(root, case_id)
            if actual_paths != expected_paths:
                changed.append(
                    f"{case_id}: file inventory changed "
                    f"(missing={sorted(expected_paths - actual_paths)}, added={sorted(actual_paths - expected_paths)})"
                )
                continue
        for relative, expected in sorted(expected_files.items()):
            path = root / relative
            if path.is_symlink() or not path.is_file():
                changed.append(f"{case_id}: missing case file {relative}")
                continue
            actual = path.read_bytes()
            if actual != expected:
                changed.append(f"{case_id}: bytes changed in {relative}")
    return changed


def sha256(raw):
    """Return the lowercase SHA-256 digest for exact case bytes."""
    return hashlib.sha256(raw).hexdigest()


def current_case_files(root, case_id, expected_files, drift_ids):
    """Read the complete current file inventory for one existing case."""
    if case_id in drift_ids:
        actual_paths = current_drift_paths(root, case_id)
        if actual_paths is None:
            fail(f"repair records cannot authorize removing case {case_id}")
    else:
        actual_paths = current_regular_paths(root, case_id)
    files = {}
    for relative in sorted(actual_paths):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            fail(f"repair record for {case_id} cannot authorize missing file {relative}")
        files[relative] = path.read_bytes()
    return files


def path_exists_at_revision(root, revision, relative):
    """Report whether a repository-relative path exists at a Git revision."""
    found = git(root, "ls-tree", "--name-only", revision, "--", relative)
    return found.decode("utf-8", errors="surrogateescape").strip() == relative


def validate_repair_record(root, base, case_id, expected_files, drift_ids):
    """Validate one new repair record against exact base and working-tree bytes."""
    records = []
    directory = root / REPAIR_RECORD_DIR
    if directory.is_dir() and not directory.is_symlink():
        for path in sorted(directory.glob(f"{case_id}-*.repair.json")):
            relative = path.relative_to(root).as_posix()
            if not path_exists_at_revision(root, base, relative):
                records.append(path)
    if not records:
        return None
    if len(records) != 1:
        fail(f"case {case_id} has multiple new repair records")

    record_path = records[0]
    if record_path.is_symlink() or not record_path.is_file():
        fail(f"repair record must be a regular file: {record_path.relative_to(root)}")
    try:
        record = json.loads(record_path.read_bytes())
    except json.JSONDecodeError as exc:
        fail(f"repair record is not valid JSON: {record_path.relative_to(root)}: {exc}")
    required = {"schema_version", "case_id", "reason", "files"}
    if not isinstance(record, dict) or set(record) != required:
        fail(f"repair record for {case_id} must contain exactly {sorted(required)}")
    if record["schema_version"] != 1 or record["case_id"] != case_id:
        fail(f"repair record identity does not match case {case_id}")
    reason = record["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 240 or "\n" in reason or "\r" in reason:
        fail(f"repair record reason for {case_id} must be one visible line of at most 240 characters")

    current_files = current_case_files(root, case_id, expected_files, drift_ids)
    files = record["files"]
    if not isinstance(files, list) or not files:
        fail(f"repair record for {case_id} must contain a non-empty files list")
    recorded = {}
    for item in files:
        keys = {"path", "base_sha256", "repaired_sha256"}
        if not isinstance(item, dict) or set(item) != keys:
            fail(f"repair record file entries for {case_id} must contain exactly {sorted(keys)}")
        relative = item["path"]
        if not isinstance(relative, str) or relative in recorded:
            fail(f"repair record for {case_id} contains an invalid or duplicate path")
        recorded[relative] = (item["base_sha256"], item["repaired_sha256"])

    all_paths = set(expected_files) | set(current_files)
    if set(recorded) != all_paths:
        fail(f"repair record file inventory does not match case {case_id}")
    for relative in sorted(all_paths):
        base_raw = expected_files.get(relative)
        repaired_raw = current_files.get(relative)
        if base_raw is None or repaired_raw is None:
            fail(f"repair record for {case_id} cannot authorize adding or removing files")
        if recorded[relative] != (sha256(base_raw), sha256(repaired_raw)):
            fail(f"repair record hashes do not match {relative}")
    return reason.strip()


def override_from_environment():
    value = os.environ.get(OVERRIDE_ENV, "")
    if not value:
        return None
    if value != OVERRIDE_TOKEN:
        fail(
            f"{OVERRIDE_ENV} is set but does not contain the required acknowledgement token "
            f"{OVERRIDE_TOKEN!r}"
        )
    reason = os.environ.get(OVERRIDE_REASON_ENV, "").strip()
    if not reason:
        fail(f"{OVERRIDE_REASON_ENV} must name the documented repair when {OVERRIDE_ENV} is active")
    if len(reason) > 240 or "\n" in reason or "\r" in reason:
        fail(f"{OVERRIDE_REASON_ENV} must be one visible line of at most 240 characters")
    return reason


def check(root, base, override_reason=None):
    resolved_base = resolve_base(root, base)
    cases, drift_ids = base_case_inventory(root, resolved_base)
    changed = changed_base_cases(root, resolved_base, cases, drift_ids)
    if changed and not override_reason:
        changed_ids = {item.split(":", 1)[0] for item in changed}
        missing = []
        for case_id in sorted(changed_ids):
            if validate_repair_record(root, resolved_base, case_id, cases[case_id], drift_ids) is None:
                missing.append(case_id)
        if missing:
            fail(
                "immutable case bytes changed since base "
                f"{resolved_base}:\n  " + "\n  ".join(changed)
            )
    return resolved_base, len(cases), changed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    try:
        override_reason = override_from_environment()
        base, count, changed = check(root, args.base, override_reason)
    except (OSError, ValueError) as exc:
        print(f"check-case-immutability: FAIL - {exc}", file=sys.stderr)
        return 1
    if changed and override_reason:
        print(
            "check-case-immutability: OVERRIDE ACTIVE "
            f"(base {base}, {len(changed)} changed existing cases, reason: {override_reason})"
        )
    elif changed:
        print(
            "check-case-immutability: REPAIR RECORD ACTIVE "
            f"(base {base}, {len(changed)} changed existing cases)"
        )
    else:
        print(f"check-case-immutability: OK ({count} base cases unchanged from {base})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
