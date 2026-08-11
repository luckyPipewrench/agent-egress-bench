#!/usr/bin/env python3
"""Require embedded Control Evidence schemas to match their root sources."""

import sys
from pathlib import Path


G2_V0_SCHEMA_NAMES = {
    "control-evidence-clock-evidence-v0.schema.json",
    "control-evidence-dsse-v0.schema.json",
    "control-evidence-manifest-v0.schema.json",
    "control-evidence-observer-evidence-v0.schema.json",
    "control-evidence-requirement-v0.schema.json",
    "control-evidence-run-envelope-v0.schema.json",
}

VERIFIER_V1_SCHEMA_NAMES = {
    "control-evidence-buyer-reproduction-statement-v1.schema.json",
    "control-evidence-buyer-reproduction-transcript-v1.schema.json",
    "control-evidence-buyer-reproduction-v1.schema.json",
    "control-evidence-clock-evidence-v1.schema.json",
    "control-evidence-context-v1.schema.json",
    "control-evidence-dsse-v1.schema.json",
    "control-evidence-health-control-material-v1.schema.json",
    "control-evidence-manifest-v1.schema.json",
    "control-evidence-observer-evidence-v1.schema.json",
    "control-evidence-outcomes-v1.schema.json",
    "control-evidence-requirement-v1.schema.json",
    "control-evidence-run-envelope-v1.schema.json",
    "control-evidence-token-material-v1.schema.json",
    "tool-profile-v1.schema.json",
    "tool-profile-v4.schema.json",
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
    if not source_dir.is_dir():
        fail("root schema directory is missing")
    groups = [
        (
            "CEE v0",
            root / "control-evidence" / "g2" / "authentication" / "schemas" / "cee-v0",
            G2_V0_SCHEMA_NAMES,
            True,
        ),
        (
            "CEE v1 verifier",
            root / "control-evidence" / "v1" / "verifier" / "schemas",
            VERIFIER_V1_SCHEMA_NAMES,
            True,
        ),
    ]
    checked = 0
    for label, copy_dir, names, exact_inventory in groups:
        if not copy_dir.is_dir():
            fail(f"{label} schema copy directory is missing")
        actual = {path.name for path in copy_dir.iterdir() if path.is_file() or path.is_symlink()}
        missing = names - actual
        extra = actual - names if exact_inventory else set()
        if missing or extra:
            fail(f"{label} schema inventory differs; missing={sorted(missing)}, extra={sorted(extra)}")
        for name in sorted(names):
            source = checked_bytes(source_dir / name, "root schema")
            copied = checked_bytes(copy_dir / name, f"{label} schema copy")
            if source != copied:
                fail(f"{label} schema copy differs from root source: {name}")
            checked += 1
    return checked


def main():
    root = Path(__file__).resolve().parents[1]
    try:
        count = check(root)
    except (OSError, ValueError) as exc:
        print(f"check-schema-copies: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-schema-copies: OK ({count} byte-identical governed schemas)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
