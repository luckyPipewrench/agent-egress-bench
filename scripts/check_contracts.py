#!/usr/bin/env python3
"""Check the artifact compatibility manifest against repository contracts."""

import argparse
import json
import re
import sys
from pathlib import Path


REQUIRED_CONSTANTS = {
    ("runner/case.go", "activeSchemaVersion"),
    ("validate/main.go", "activeCaseSchemaVersion"),
    ("runner/summary.go", "activeSummarySchemaVersion"),
}
REQUIRED_RETAINED_RECORD_PATHS = {
    "ci/gauntlet-baseline.json",
    "gauntlet-site",
}


def fail(message):
    raise ValueError(message)


def load_object(path, label):
    if not path.is_file():
        fail(f"missing {label}: {path}")
    if path.stat().st_size == 0:
        fail(f"empty {label}: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label} {path}: {exc}")
    if not isinstance(value, dict) or not value:
        fail(f"{label} must be a non-empty JSON object: {path}")
    return value


def require_int(value, label):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        fail(f"{label} must be a positive integer")
    return value


def require_int_list(value, label):
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    result = [require_int(item, f"{label} entry") for item in value]
    if len(result) != len(set(result)):
        fail(f"{label} contains duplicate versions")
    return result


def require_path_list(root, value, label, allow_glob=False):
    if not isinstance(value, list) or not value:
        fail(f"{label} must be a non-empty array")
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            fail(f"{label} entries must be non-empty strings")
        if allow_glob and "*" in entry:
            if not list(root.glob(entry)):
                fail(f"{label} glob matches nothing: {entry}")
        elif not (root / entry).exists():
            fail(f"{label} path does not exist: {entry}")


def read_go_constant(root, source):
    relative = source.get("path")
    symbol = source.get("symbol")
    if not isinstance(relative, str) or not isinstance(symbol, str):
        fail("source_versions entries require path and symbol strings")
    path = root / relative
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"governing source is missing or empty: {relative}")
    match = re.search(
        rf"\bconst\s+{re.escape(symbol)}\s*=\s*([0-9]+)\b",
        path.read_text(encoding="utf-8"),
    )
    if match is None:
        fail(f"cannot find integer constant {symbol} in {relative}")
    return int(match.group(1))


def versioned_schema_inventory(root):
    inventory = set()
    schema_dir = root / "schemas"
    if not schema_dir.is_dir():
        fail("missing schemas directory")
    for path in sorted(schema_dir.glob("*.json")):
        document = load_object(path, "schema")
        version = document.get("properties", {}).get("schema_version", {}).get("const")
        if version is not None:
            require_int(version, f"{path.relative_to(root)} schema_version const")
            inventory.add(path.relative_to(root).as_posix())
    if not inventory:
        fail("no versioned schemas discovered")
    return inventory


def walk_schema_versions(value, label, found):
    if isinstance(value, dict):
        for key, child in value.items():
            child_label = f"{label}.{key}"
            if key == "schema_version":
                found.add(require_int(child, child_label))
            walk_schema_versions(child, child_label, found)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk_schema_versions(child, f"{label}[{index}]", found)


def retained_record_versions(root, paths):
    if not isinstance(paths, list) or not paths:
        fail("retained_public_records.paths must be a non-empty array")
    if any(not isinstance(path, str) or not path for path in paths):
        fail("retained public record paths must be non-empty strings")
    if len(paths) != len(set(paths)):
        fail("retained public record paths contain duplicates")
    if set(paths) != REQUIRED_RETAINED_RECORD_PATHS:
        fail(
            "retained public record roots must remain complete; "
            f"missing={sorted(REQUIRED_RETAINED_RECORD_PATHS - set(paths))}, "
            f"extra={sorted(set(paths) - REQUIRED_RETAINED_RECORD_PATHS)}"
        )
    files = []
    for relative in paths:
        path = root / relative
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
        else:
            fail(f"retained public record path does not exist: {relative}")
    if not files:
        fail("retained public record scan found no JSON files")
    found = set()
    for path in files:
        if path.stat().st_size == 0:
            fail(f"retained public record is empty: {path.relative_to(root)}")
        document = load_object(path, "retained public record")
        walk_schema_versions(document, path.relative_to(root).as_posix(), found)
    if not found:
        fail("retained public record scan found no schema_version values")
    return found, len(files)


def check(root, manifest_path):
    manifest = load_object(manifest_path, "compatibility manifest")
    if manifest.get("manifest_version") != 1:
        fail("compatibility manifest_version must be 1")
    families = manifest.get("artifact_families")
    if not isinstance(families, list) or not families:
        fail("artifact_families must be a non-empty array")

    names = set()
    listed_schemas = set()
    listed_constants = set()
    constant_values = {}
    for family in families:
        if not isinstance(family, dict):
            fail("artifact family entries must be objects")
        name = family.get("family")
        if not isinstance(name, str) or not name:
            fail("artifact family requires a non-empty family name")
        if name in names:
            fail(f"duplicate artifact family: {name}")
        names.add(name)

        active = require_int(family.get("active_writer_version"), f"{name}.active_writer_version")
        accepted = require_int_list(family.get("accepted_reader_versions"), f"{name}.accepted_reader_versions")
        frozen = require_int_list(family.get("frozen_versions"), f"{name}.frozen_versions")
        if active not in accepted:
            fail(f"{name}: active writer version {active} is not accepted by a reader")
        if not set(frozen).issubset(accepted):
            fail(f"{name}: frozen versions must be accepted by a reader")
        require_path_list(root, family.get("writer"), f"{name}.writer", allow_glob=True)
        require_path_list(root, family.get("reader"), f"{name}.reader")
        if family.get("gate") != "make check-contracts":
            fail(f"{name}: gate must be 'make check-contracts'")

        schemas = family.get("schemas")
        if not isinstance(schemas, list):
            fail(f"{name}.schemas must be an array")
        active_schema_paths = []
        for schema in schemas:
            if not isinstance(schema, dict):
                fail(f"{name}: schema entries must be objects")
            version = require_int(schema.get("version"), f"{name} schema version")
            status = schema.get("status")
            expected_status = "frozen" if version in frozen else "active" if version == active else None
            if expected_status is None or status != expected_status:
                fail(f"{name}: schema v{version} has status {status!r}, expected {expected_status!r}")
            relative = schema.get("path")
            expected_id = schema.get("$id")
            if not isinstance(relative, str) or not relative:
                fail(f"{name}: schema path must be a non-empty string")
            if relative in listed_schemas:
                fail(f"schema is listed more than once: {relative}")
            listed_schemas.add(relative)
            document = load_object(root / relative, "schema")
            if document.get("$id") != expected_id:
                fail(f"{relative}: $id does not match compatibility manifest")
            declared = document.get("properties", {}).get("schema_version", {}).get("const")
            if declared != version:
                fail(f"{relative}: declares schema_version {declared!r}, manifest says {version}")
            if status == "active":
                active_schema_paths.append(relative)

        canonical = family.get("canonical_schema_path")
        if canonical is None:
            if active_schema_paths:
                fail(f"{name}: active schema exists but canonical_schema_path is null")
        elif not isinstance(canonical, str) or canonical not in active_schema_paths:
            fail(f"{name}: canonical_schema_path must name its active schema")

        sources = family.get("source_versions")
        if not isinstance(sources, list):
            fail(f"{name}.source_versions must be an array")
        for source in sources:
            coordinate = (source.get("path"), source.get("symbol"))
            value = read_go_constant(root, source)
            listed_constants.add(coordinate)
            constant_values[coordinate] = value
            if value != active:
                fail(f"{name}: {coordinate[0]} {coordinate[1]} is {value}, active writer is {active}")

    discovered_schemas = versioned_schema_inventory(root)
    if listed_schemas != discovered_schemas:
        missing = sorted(discovered_schemas - listed_schemas)
        extra = sorted(listed_schemas - discovered_schemas)
        fail(f"versioned schema inventory mismatch; unlisted={missing}, nonexistent={extra}")
    if not REQUIRED_CONSTANTS.issubset(listed_constants):
        fail(f"governing constants missing from manifest: {sorted(REQUIRED_CONSTANTS - listed_constants)}")
    case_runner = constant_values[("runner/case.go", "activeSchemaVersion")]
    case_validator = constant_values[("validate/main.go", "activeCaseSchemaVersion")]
    if case_runner != case_validator:
        fail(f"runner and validator case schema versions differ: {case_runner} != {case_validator}")

    records = manifest.get("retained_public_records")
    if not isinstance(records, dict):
        fail("retained_public_records must be an object")
    readers = records.get("frozen_readers")
    if not isinstance(readers, list) or not readers:
        fail("retained_public_records.frozen_readers must be a non-empty array")
    frozen_readers = {}
    for entry in readers:
        if not isinstance(entry, dict):
            fail("frozen reader entries must be objects")
        version = require_int(entry.get("version"), "frozen reader version")
        if version in frozen_readers:
            fail(f"duplicate frozen public-record reader for version {version}")
        require_path_list(root, entry.get("reader"), f"frozen v{version} reader")
        frozen_readers[version] = entry["reader"]
    found_versions, file_count = retained_record_versions(root, records.get("paths"))
    unlisted = found_versions - set(frozen_readers)
    if unlisted:
        fail(f"retained public records contain versions without frozen readers: {sorted(unlisted)}")
    return len(families), len(discovered_schemas), file_count, sorted(found_versions)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    manifest_path = args.manifest.resolve() if args.manifest else root / "contracts" / "artifacts.json"
    try:
        families, schemas, records, versions = check(root, manifest_path)
    except ValueError as exc:
        print(f"check-contracts: FAIL - {exc}", file=sys.stderr)
        return 1
    print(
        "check-contracts: OK "
        f"({families} families, {schemas} schemas, {records} retained JSON files, "
        f"frozen record versions {versions})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
