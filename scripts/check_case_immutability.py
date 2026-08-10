#!/usr/bin/env python3
"""Reject rewrites of case bytes already present at a pull request's base."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


OVERRIDE_ENV = "AEB_CASE_IMMUTABILITY_REPAIR"
OVERRIDE_TOKEN = "I_UNDERSTAND_CASE_IMMUTABILITY_REPAIR"
OVERRIDE_REASON_ENV = "AEB_CASE_IMMUTABILITY_REASON"


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


def base_case_inventory(root, base):
    paths = git(root, "ls-tree", "-r", "--name-only", base, "--", "cases").decode("utf-8").splitlines()
    if not paths:
        fail(f"base revision {base} contains no files under cases/")

    cases = {}
    drift_dirs = {}
    for relative in paths:
        parts = Path(relative).parts
        if len(parts) >= 4 and parts[:2] == ("cases", "mcp-drift"):
            case_id = parts[2]
            drift_dirs.setdefault(case_id, set()).add(relative)
            continue
        if len(parts) != 3 or parts[0] != "cases" or not relative.endswith(".json"):
            continue
        raw = git(root, "show", f"{base}:{relative}")
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
        cases[case_id] = {path: git(root, "show", f"{base}:{path}") for path in drift_paths}

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
        for relative, expected in sorted(expected_files.items()):
            path = root / relative
            if path.is_symlink() or not path.is_file():
                changed.append(f"{case_id}: missing case file {relative}")
                continue
            actual = path.read_bytes()
            if actual != expected:
                changed.append(f"{case_id}: bytes changed in {relative}")
    return changed


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
    if changed:
        print(
            "check-case-immutability: OVERRIDE ACTIVE "
            f"(base {base}, {len(changed)} changed existing cases, reason: {override_reason})"
        )
    else:
        print(f"check-case-immutability: OK ({count} base cases unchanged from {base})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
