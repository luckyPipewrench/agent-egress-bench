#!/usr/bin/env python3
"""Require the G2 CEE v0 schema copies to match their root sources."""

import sys
from pathlib import Path


COPIED_SCHEMA_NAMES = {
    "control-evidence-clock-evidence.schema.json",
    "control-evidence-dsse.schema.json",
    "control-evidence-manifest.schema.json",
    "control-evidence-observer-evidence.schema.json",
    "control-evidence-requirement.schema.json",
    "control-evidence-run-envelope.schema.json",
}


def fail(message):
    raise ValueError(message)


def checked_bytes(path, label):
    if path.is_symlink():
        fail(f"{label} must be a regular file, not a symlink: {path}")
    if not path.is_file():
        fail(f"missing {label}: {path}")
    data = path.read_bytes()
    if not data:
        fail(f"empty {label}: {path}")
    return data


def check(root):
    source_dir = root / "schemas"
    copy_dir = root / "control-evidence" / "g2" / "authentication" / "schemas" / "cee-v0"
    if not source_dir.is_dir() or not copy_dir.is_dir():
        fail("schema source or CEE v0 copy directory is missing")
    actual = {path.name for path in copy_dir.iterdir() if path.is_file() or path.is_symlink()}
    if actual != COPIED_SCHEMA_NAMES:
        fail(
            "CEE v0 schema inventory differs from the six governed copies; "
            f"missing={sorted(COPIED_SCHEMA_NAMES - actual)}, extra={sorted(actual - COPIED_SCHEMA_NAMES)}"
        )
    for name in sorted(COPIED_SCHEMA_NAMES):
        source = checked_bytes(source_dir / name, "root schema")
        copied = checked_bytes(copy_dir / name, "CEE v0 schema copy")
        if source != copied:
            fail(f"CEE v0 schema copy differs from root source: {name}")
    return len(COPIED_SCHEMA_NAMES)


def main():
    root = Path(__file__).resolve().parents[1]
    try:
        count = check(root)
    except (OSError, ValueError) as exc:
        print(f"check-schema-copies: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-schema-copies: OK ({count} byte-identical CEE v0 schemas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
