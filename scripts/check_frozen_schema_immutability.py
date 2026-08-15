#!/usr/bin/env python3
"""Keep frozen schema bytes immutable across commits.

The sole allowed historical transition changes the former non-resolving GitHub
browser URL to the raw-document endpoint. It may not change any other byte.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from schema_catalog import PUBLIC_SCHEMA_ID_PREFIX


LEGACY_SCHEMA_ID_PREFIX = "https://github.com/luckyPipewrench/agent-egress-bench/schemas/"


def load_object(data, label):
    try:
        value = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def frozen_schema_paths(manifest):
    paths = set()
    for family in manifest.get("artifact_families", []):
        for schema in family.get("schemas", []):
            if schema.get("status") == "frozen" and isinstance(schema.get("path"), str):
                paths.add(schema["path"])
    for asset in manifest.get("retained_schema_assets", []):
        if isinstance(asset.get("path"), str):
            paths.add(asset["path"])
    if not paths:
        raise ValueError("base manifest names no frozen schema assets")
    return paths


def is_identifier_only_migration(path, before, after):
    """Accept only the one legacy identifier rewrite for a frozen schema."""
    before_object = load_object(before, f"base schema {path}")
    after_object = load_object(after, f"current schema {path}")
    filename = Path(path).name
    if before_object.get("$id") != LEGACY_SCHEMA_ID_PREFIX + filename:
        return False
    if after_object.get("$id") != PUBLIC_SCHEMA_ID_PREFIX + filename:
        return False
    before_object.pop("$id")
    after_object.pop("$id")
    return before_object == after_object


def git_show(root, revision, path):
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"cannot read {path} at {revision}: {result.stderr.strip()}")
    return result.stdout


def changed_paths(root, base):
    result = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", base, "--", "schemas"],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"cannot inspect schema changes from {base}: {result.stderr.strip()}")
    return {line for line in result.stdout.splitlines() if line}


def check(root, base):
    manifest = load_object(git_show(root, base, "contracts/artifacts.json"), "base compatibility manifest")
    frozen = frozen_schema_paths(manifest)
    changed = changed_paths(root, base)
    protected_changes = sorted(changed & frozen)
    for path in protected_changes:
        current = root / path
        if not current.is_file():
            raise ValueError(f"frozen schema was removed: {path}")
        if not is_identifier_only_migration(path, git_show(root, base, path), current.read_text(encoding="utf-8")):
            raise ValueError(f"frozen schema bytes changed: {path}")
    return len(frozen), len(protected_changes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        frozen, changed = check(root, args.base)
    except (OSError, ValueError) as exc:
        print(f"check-frozen-schema-immutability: FAIL - {exc}", file=sys.stderr)
        return 1
    print(
        "check-frozen-schema-immutability: OK "
        f"({frozen} frozen schemas, {changed} permitted identifier migrations)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
