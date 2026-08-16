#!/usr/bin/env python3
"""Resolve governed artifact schema versions and paths from the public manifest."""

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "contracts" / "artifacts.json"


def families(manifest_path=MANIFEST):
    document = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    entries = document.get("artifact_families")
    if not isinstance(entries, list):
        raise ValueError("artifact contract manifest has no artifact_families array")
    resolved = {}
    for entry in entries:
        name = entry.get("family") if isinstance(entry, dict) else None
        if not isinstance(name, str) or not name or name in resolved:
            raise ValueError(f"artifact contract manifest has an invalid family: {name!r}")
        resolved[name] = entry
    return resolved


def family(name, manifest_path=MANIFEST):
    try:
        return families(manifest_path)[name]
    except KeyError as exc:
        raise ValueError(f"unknown artifact family: {name}") from exc


def active_version(name, manifest_path=MANIFEST):
    version = family(name, manifest_path).get("active_writer_version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"artifact family {name} has no valid active writer version")
    return version


def schema_paths(name, manifest_path=MANIFEST, root=ROOT):
    entries = family(name, manifest_path).get("schemas")
    if not isinstance(entries, list):
        raise ValueError(f"artifact family {name} has no schemas array")
    paths = {}
    for entry in entries:
        version = entry.get("version") if isinstance(entry, dict) else None
        relative = entry.get("path") if isinstance(entry, dict) else None
        if isinstance(version, bool) or not isinstance(version, int) or not isinstance(relative, str):
            raise ValueError(f"artifact family {name} has an invalid schema entry")
        if version in paths:
            raise ValueError(f"artifact family {name} repeats schema version {version}")
        path = Path(root) / relative
        if not path.is_file():
            raise ValueError(f"artifact family {name} schema does not exist: {relative}")
        paths[version] = path
    return paths


def canonical_schema_path(name, manifest_path=MANIFEST, root=ROOT):
    relative = family(name, manifest_path).get("canonical_schema_path")
    if not isinstance(relative, str) or not relative:
        raise ValueError(f"artifact family {name} has no canonical schema path")
    path = Path(root) / relative
    if not path.is_file():
        raise ValueError(f"artifact family {name} canonical schema does not exist: {relative}")
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("active-version", "canonical-schema"))
    parser.add_argument("family")
    args = parser.parse_args()
    if args.command == "active-version":
        print(active_version(args.family))
    else:
        print(canonical_schema_path(args.family))


if __name__ == "__main__":
    main()
