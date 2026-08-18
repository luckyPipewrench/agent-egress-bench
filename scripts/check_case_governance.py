#!/usr/bin/env python3
"""Fail when a case governance decision record is absent or inconsistent."""

import argparse
import sys
from pathlib import Path

import artifact_schema
import case_governance


SCHEMA_PATH = Path("schemas/case-governance-decision-v1.schema.json")


def fail(message):
    raise ValueError(message)


def require_directory(root, relative):
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            fail(f"decision-record directory contains a symlink: {current.relative_to(root)}")
        if not current.is_dir():
            fail(f"missing decision-record directory: {current.relative_to(root)}")
    return current


def record_paths(root):
    directory = require_directory(root, case_governance.DECISION_DIRECTORY)
    paths = []
    for path in sorted(directory.iterdir()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            fail(f"decision record is a symlink: {relative}")
        if not path.is_file():
            fail(f"decision-record directory contains a non-file entry: {relative}")
        if not path.name.endswith(case_governance.DECISION_SUFFIX):
            fail(f"decision-record directory contains an unexpected file: {relative}")
        paths.append(path)
    return paths


def check(root):
    root = Path(root).resolve()
    cases = case_governance.load_cases(root)
    schema = artifact_schema.load_schema(root / SCHEMA_PATH)
    records = {}
    for path in record_paths(root):
        relative = path.relative_to(root).as_posix()
        record = case_governance.load_json_object(path, "decision record")
        artifact_schema.validate(record, schema, relative)
        case_id = record["case_id"]
        expected_name = f"{case_id}{case_governance.DECISION_SUFFIX}"
        if path.name != expected_name:
            fail(f"{relative}: filename must be {expected_name}")
        if case_id in records:
            fail(f"duplicate decision record for case {case_id}: {relative}")
        case = cases.get(case_id)
        if case is None:
            fail(f"{relative}: record points at unknown case ID {case_id}")
        expected = case_governance.record_for_case(case)
        if record != expected:
            mismatches = sorted(
                field
                for field in sorted(set(record) | set(expected))
                if record.get(field) != expected.get(field)
            )
            fail(f"{relative}: record is inconsistent with case {case_id}: {mismatches}")
        records[case_id] = path
    missing = sorted(set(cases) - set(records))
    if missing:
        fail(f"missing decision records for case IDs: {missing}")
    # A supersedes value that merely LOOKS like a case ID is not an audit trail. Verify the target
    # exists and that nothing supersedes itself, so governance history cannot record a relationship
    # that never existed.
    supersedes = {}
    for case_id in sorted(cases):
        target = case_governance.record_for_case(cases[case_id]).get("supersedes")
        if target is None:
            continue
        if target == case_id:
            fail(f"case {case_id} supersedes itself")
        if target not in cases:
            fail(f"case {case_id} supersedes unknown case {target}")
        supersedes[case_id] = target
    # A cycle is an impossible predecessor history that every individual record validates against, so
    # rejecting self-reference alone leaves the audit trail claiming something that cannot be true.
    for start in sorted(supersedes):
        seen = [start]
        current = supersedes[start]
        while current in supersedes:
            if current in seen:
                cycle = " -> ".join(seen[seen.index(current):] + [current])
                fail(f"supersession cycle: {cycle}")
            seen.append(current)
            current = supersedes[current]
        if current in seen and current != seen[-1]:
            fail(f"supersession cycle involving {current}")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        count = check(args.repo_root)
    except (OSError, ValueError) as exc:
        print(f"check-case-governance: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-case-governance: OK ({count} logical cases have matching decision records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
