#!/usr/bin/env python3
"""Keep frozen schema bytes immutable across commits.

A frozen schema's bytes are the contract. Comparison is byte-for-byte against
the base revision, with no permitted transformation: parsed-JSON equality would
accept a reformat, a key reorder, or an escaping change, and a consumer pinning
a digest sees all of those as a different document.

Deliberately no repair exception. An evergreen exception here is a standing
authorization to edit exactly the files this exists to protect, and it is the
one an author reaches for when their change is blocked. The supported route for
changing a frozen contract is a new version. A genuine historical repair is a
governance decision that should arrive as its own reviewed change, visible in
the diff, rather than as a code path that quietly permits the class forever.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path


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


def git_show_bytes(root, revision, path):
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        capture_output=True,
    )
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise ValueError(f"cannot read {path} at {revision}: {message}")
    return result.stdout


def changed_paths(root, base):
    # Diff the whole tree, not a `schemas` pathspec. Frozen assets also live
    # under control-evidence/**, and a pathspec that omitted them would report
    # a clean run while a retained verifier schema was edited: a gate that
    # passes by not looking.
    result = subprocess.run(
        ["git", "-C", str(root), "diff", "--name-only", base],
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise ValueError(f"cannot inspect changes from {base}: {result.stderr.strip()}")
    return {line for line in result.stdout.splitlines() if line}


def check(root, base):
    manifest = load_object(
        git_show_bytes(root, base, "contracts/artifacts.json").decode("utf-8"),
        "base compatibility manifest",
    )
    frozen = frozen_schema_paths(manifest)
    changed = changed_paths(root, base)
    protected_changes = sorted(changed & frozen)
    for path in protected_changes:
        current = root / path
        if not current.is_file():
            raise ValueError(f"frozen schema was removed: {path}")
        if current.read_bytes() != git_show_bytes(root, base, path):
            raise ValueError(f"frozen schema bytes changed: {path}")
    return len(frozen), len(protected_changes)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        frozen, touched = check(root, args.base)
    except (OSError, ValueError) as exc:
        print(f"check-frozen-schema-immutability: FAIL - {exc}", file=sys.stderr)
        return 1
    print(
        "check-frozen-schema-immutability: OK "
        f"({frozen} frozen schemas, {touched} touched and byte-identical)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
