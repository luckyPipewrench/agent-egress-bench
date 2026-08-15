#!/usr/bin/env python3
"""Check the artifact compatibility manifest against repository contracts."""

import argparse
import ast
import hashlib
import json
import re
import sys
from pathlib import Path


REQUIRED_SOURCE_VERSIONS = {
    ("runner/case.go", "activeCaseSchemaVersion"),
    ("runner/case.go", "activeMultiFileCaseSchemaVersion"),
    ("runner/case.go", "activeResultSchemaVersion"),
    ("runner/case.go", "activeToolProfileSchemaVersion"),
    ("runner/case.go", "activeReceiptProfileSchemaVersion"),
    ("validate/main.go", "activeCaseSchemaVersion"),
    ("validate/main.go", "activeMultiFileCaseSchemaVersion"),
    ("validate/main.go", "activeResultSchemaVersion"),
    ("validate/main.go", "activeToolProfileSchemaVersion"),
    ("runner/summary.go", "activeSummarySchemaVersion"),
    ("scripts/build_gauntlet_provenance.py", "ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION"),
}
REQUIRED_RETAINED_RECORD_PATHS = {
    "ci/gauntlet-baseline.json",
    "gauntlet-site",
}
# Frozen schema assets the manifest must keep listing. Pinned here as well as in
# the manifest so shrinking the inventory takes two deliberate edits: the v0
# Control Evidence format is published with immutable conformance vectors, so
# deleting one of these files or editing its $id would invalidate evidence that
# cannot be regenerated.
REQUIRED_RETAINED_SCHEMA_ASSETS = {
    "schemas/control-evidence-buyer-reproduction-statement-v0.schema.json",
    "schemas/control-evidence-buyer-reproduction-statement-v1.schema.json",
    "schemas/control-evidence-buyer-reproduction-transcript-v0.schema.json",
    "schemas/control-evidence-buyer-reproduction-transcript-v1.schema.json",
    "schemas/control-evidence-buyer-reproduction-v0.schema.json",
    "schemas/control-evidence-buyer-reproduction-v1.schema.json",
    "schemas/control-evidence-clock-evidence-v0.schema.json",
    "schemas/control-evidence-clock-evidence-v1.schema.json",
    "schemas/control-evidence-context-v0.schema.json",
    "schemas/control-evidence-context-v1.schema.json",
    "schemas/control-evidence-dsse-v0.schema.json",
    "schemas/control-evidence-dsse-v1.schema.json",
    "schemas/control-evidence-health-control-material-v0.schema.json",
    "schemas/control-evidence-health-control-material-v1.schema.json",
    "schemas/control-evidence-manifest-v0.schema.json",
    "schemas/control-evidence-manifest-v1.schema.json",
    "schemas/control-evidence-observer-evidence-v0.schema.json",
    "schemas/control-evidence-observer-evidence-v1.schema.json",
    "schemas/control-evidence-outcomes-v0.schema.json",
    "schemas/control-evidence-outcomes-v1.schema.json",
    "schemas/control-evidence-requirement-v0.schema.json",
    "schemas/control-evidence-requirement-v1.schema.json",
    "schemas/control-evidence-run-envelope-v0.schema.json",
    "schemas/control-evidence-run-envelope-v1.schema.json",
    "schemas/control-evidence-token-material-v0.schema.json",
    "schemas/control-evidence-token-material-v1.schema.json",
    "schemas/control-evidence-trust-policy-dsse-v1.schema.json",
}
PUBLIC_SCHEMA_ID_PREFIX = "https://github.com/luckyPipewrench/agent-egress-bench/schemas/"
VERSIONED_SCHEMA_FILENAME = re.compile(r"^.+-v([0-9]+)\.schema\.json$")
TITLE_VERSION = re.compile(r"\bv([0-9]+)\b", re.IGNORECASE)


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


def sha256_file(path, label):
    if not path.is_file():
        fail(f"missing {label}: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_sha256(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
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


def strip_go_comments_and_strings(text):
    """Blank out Go comments and string bodies before matching a declaration.

    Matching raw source let a commented-out or quoted declaration satisfy this
    gate, so deleting the real constant and leaving `// const x = 4` behind would
    keep the check green while it protected nothing. Comment and string spans are
    replaced with spaces rather than removed so that reported positions and line
    structure survive.

    This is a lexical pass, not a Go parser. It handles line comments, block
    comments, interpreted strings, raw strings, and runes, which covers the ways
    a declaration can hide in this repository's sources. A Go-side assertion that
    the constant equals its manifest value would remove the class outright, since
    the compiler would then have to agree the constant exists.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out.append(" ")
                i += 1
        elif ch == "/" and nxt == "*":
            while i < n and not (text[i] == "*" and i + 1 < n and text[i + 1] == "/"):
                out.append("\n" if text[i] == "\n" else " ")
                i += 1
            out.append("  ")
            i += 2
        elif ch in "\"'`":
            quote = ch
            out.append(" ")
            i += 1
            while i < n and text[i] != quote:
                if quote != "`" and text[i] == "\\":
                    out.append(" ")
                    i += 1
                if i < n:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
            if i < n:
                out.append(" ")
                i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def go_const_blocks(text):
    """Yield the body of each `const (...)` block in comment-stripped Go source.

    Parenthesis depth is tracked rather than matched with a regex, because a
    grouped constant can carry a parenthesised expression and a non-greedy match
    would stop at the first inner close paren and truncate the block.
    """
    for match in re.finditer(r"\bconst\s*\(", text):
        depth = 1
        start = match.end()
        i = start
        while i < len(text) and depth:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
            i += 1
        if depth == 0:
            yield text[start : i - 1]


def read_go_constant(root, source):
    relative = source.get("path")
    symbol = source.get("symbol")
    if not isinstance(relative, str) or not isinstance(symbol, str):
        fail("source_versions entries require path and symbol strings")
    path = root / relative
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"governing source is missing or empty: {relative}")
    text = strip_go_comments_and_strings(path.read_text(encoding="utf-8"))
    # Go declares a constant either on its own (`const name = 4`) or inside a
    # grouped block. Matching only the first form made this gate reject a legal
    # refactor into a group, which is the failure direction that gets a gate
    # switched off rather than fixed.
    #
    # The grouped form is searched only inside `const (...)` spans. Matching it
    # against the whole file accepted any line shaped `name = 4`, so removing the
    # constant and leaving a `var` declaration or an assignment in `init` behind
    # still satisfied the gate. The value has to come from a constant, or this
    # check does not establish what the writer emits.
    optional_type = r"(?:\s+[A-Za-z_][A-Za-z0-9_.]*)?"
    single = rf"\bconst\s+{re.escape(symbol)}{optional_type}\s*=\s*([0-9]+)\b"
    grouped = rf"(?m)^\s*{re.escape(symbol)}{optional_type}\s*=\s*([0-9]+)\s*$"
    matches = [m.group(1) for m in re.finditer(single, text)]
    for block in go_const_blocks(text):
        matches.extend(m.group(1) for m in re.finditer(grouped, block))
    if not matches:
        fail(f"cannot find integer constant {symbol} in {relative}")
    # A second, differing declaration means the governing value is ambiguous, so
    # refuse rather than silently taking whichever one matched first.
    if len(set(matches)) > 1:
        fail(f"{symbol} in {relative} has conflicting values: {sorted(set(matches))}")
    return int(matches[0])


def read_python_constant(root, source):
    relative = source.get("path")
    symbol = source.get("symbol")
    if not isinstance(relative, str) or not isinstance(symbol, str):
        fail("source_versions entries require path and symbol strings")
    path = root / relative
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"governing source is missing or empty: {relative}")
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except (OSError, SyntaxError) as exc:
        fail(f"cannot parse governing source {relative}: {exc}")

    values = []
    for statement in tree.body:
        value = None
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == symbol for target in statement.targets
        ):
            value = statement.value
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == symbol
        ):
            value = statement.value
        if value is not None:
            if (
                not isinstance(value, ast.Constant)
                or isinstance(value.value, bool)
                or not isinstance(value.value, int)
            ):
                fail(f"{symbol} in {relative} must be an integer literal")
            values.append(value.value)
    if not values:
        fail(f"cannot find integer constant {symbol} in {relative}")
    if len(set(values)) > 1:
        fail(f"{symbol} in {relative} has conflicting values: {sorted(set(values))}")
    return values[0]


def read_source_version(root, source):
    relative = source.get("path")
    if isinstance(relative, str) and relative.endswith(".go"):
        return read_go_constant(root, source)
    if isinstance(relative, str) and relative.endswith(".py"):
        return read_python_constant(root, source)
    fail(f"unsupported governing source type: {relative!r}")


def declared_schema_version(document, label):
    """Return a schema's declared `schema_version` const, or None if it declares none.

    Walking `properties.schema_version.const` with chained `.get` calls assumed
    every level is an object. A schema whose `properties` is a string raised
    AttributeError, which `main` does not catch, so a malformed input produced a
    traceback instead of the `check-contracts: FAIL - ...` line every other bad
    input produces. A gate that crashes reports nothing an operator can act on.
    """
    properties = document.get("properties", {})
    if not isinstance(properties, dict):
        fail(f"{label}: properties must be an object")
    declared = properties.get("schema_version", {})
    if not isinstance(declared, dict):
        fail(f"{label}: properties.schema_version must be an object")
    return declared.get("const")


def resolve_local_schema_ref(document, reference):
    """Resolve one local JSON Pointer, returning None when it is unusable."""
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return None
    current = document
    for raw_token in reference[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current


def schema_accepts_null(schema, document, resolving=()):
    """Return whether a JSON Schema permits null, conservatively on ambiguity."""
    if schema is True:
        return True
    if schema is False:
        return False
    if not isinstance(schema, dict):
        return True

    accepts = True
    if "$ref" in schema:
        reference = schema["$ref"]
        if reference in resolving:
            return True
        target = resolve_local_schema_ref(document, reference)
        accepts = accepts and (
            True
            if target is None
            else schema_accepts_null(target, document, resolving + (reference,))
        )

    if "type" in schema:
        declared_type = schema["type"]
        accepts = accepts and (
            declared_type == "null"
            or (isinstance(declared_type, list) and "null" in declared_type)
        )
    if "enum" in schema:
        accepts = accepts and isinstance(schema["enum"], list) and None in schema["enum"]
    if "const" in schema:
        accepts = accepts and schema["const"] is None
    if "allOf" in schema and isinstance(schema["allOf"], list):
        accepts = accepts and all(
            schema_accepts_null(branch, document, resolving) for branch in schema["allOf"]
        )
    if "anyOf" in schema and isinstance(schema["anyOf"], list):
        accepts = accepts and any(
            schema_accepts_null(branch, document, resolving) for branch in schema["anyOf"]
        )
    if "oneOf" in schema and isinstance(schema["oneOf"], list):
        accepts = accepts and sum(
            schema_accepts_null(branch, document, resolving) for branch in schema["oneOf"]
        ) == 1
    if "not" in schema:
        accepts = accepts and not schema_accepts_null(schema["not"], document, resolving)
    if "if" in schema:
        branch = "then" if schema_accepts_null(schema["if"], document, resolving) else "else"
        if branch in schema:
            accepts = accepts and schema_accepts_null(schema[branch], document, resolving)
    return accepts


def require_top_level_required_properties(document, label):
    """Require every top-level required name to have an explicit schema.

    JSON Schema permits a name in ``required`` without a matching entry in
    ``properties``. With an open object that means the field must exist but may
    contain any JSON value, including null. Active interchange contracts must
    define the shape they require instead of relying on that permissive default.
    """
    required = document.get("required", [])
    if not isinstance(required, list):
        fail(f"{label}: required must be an array")
    if any(not isinstance(field, str) or not field for field in required):
        fail(f"{label}: required entries must be non-empty strings")
    if len(required) != len(set(required)):
        fail(f"{label}: required contains duplicate field names")
    properties = document.get("properties", {})
    if not isinstance(properties, dict):
        fail(f"{label}: properties must be an object")
    missing = sorted(set(required) - set(properties))
    if missing:
        fail(f"{label}: required fields lack property definitions: {missing}")
    nullable_required = document.get("x-aeb-nullable-required", [])
    if not isinstance(nullable_required, list) or any(
        not isinstance(field, str) or field not in required for field in nullable_required
    ):
        fail(f"{label}: x-aeb-nullable-required must name required fields")
    null_permissive = sorted(
        field
        for field in required
        if field not in nullable_required and schema_accepts_null(properties[field], document)
    )
    if null_permissive:
        fail(f"{label}: required field definitions accept null: {null_permissive}")


def versioned_schema_inventory(root):
    inventory = set()
    schema_dir = root / "schemas"
    if not schema_dir.is_dir():
        fail("missing schemas directory")
    for path in sorted(schema_dir.glob("*.json")):
        document = load_object(path, "schema")
        declared = declared_schema_version(document, str(path.relative_to(root)))
        versions = set()
        if declared is not None:
            versions.add(require_int(declared, f"{path.relative_to(root)} schema_version const"))
        title = document.get("title", "")
        if not isinstance(title, str):
            fail(f"{path.relative_to(root)} schema title must be a string")
        versions.update(int(match.group(1)) for match in TITLE_VERSION.finditer(title))
        if versions:
            if len(versions) != 1:
                fail(f"{path.relative_to(root)} has conflicting declared schema versions: {sorted(versions)}")
            version = versions.pop()
            filename_match = VERSIONED_SCHEMA_FILENAME.fullmatch(path.name)
            if filename_match is None or int(filename_match.group(1)) != version:
                fail(
                    f"{path.relative_to(root)} is a versioned schema but its filename does not "
                    f"declare v{version}"
                )
            expected_id = f"{PUBLIC_SCHEMA_ID_PREFIX}{path.name}"
            if document.get("$id") != expected_id:
                fail(f"{path.relative_to(root)}: $id must be {expected_id!r}")
        if declared is not None:
            inventory.add(path.relative_to(root).as_posix())
    if not inventory:
        fail("no versioned schemas discovered")
    return inventory


def retained_schema_assets(root, assets):
    if not isinstance(assets, list) or not assets:
        fail("retained_schema_assets must be a non-empty array")
    by_path = {}
    for asset in assets:
        if not isinstance(asset, dict):
            fail("retained schema assets must be objects")
        relative = asset.get("path")
        expected_id = asset.get("$id")
        rationale = asset.get("rationale")
        if not isinstance(relative, str) or not relative:
            fail("retained schema asset path must be a non-empty string")
        if relative in by_path:
            fail(f"duplicate retained schema asset: {relative}")
        if not isinstance(expected_id, str) or not expected_id:
            fail(f"{relative}: retained schema asset $id must be a non-empty string")
        if not isinstance(rationale, str) or not rationale.strip():
            fail(f"{relative}: retained schema asset rationale must be a non-empty string")
        document = load_object(root / relative, "retained schema asset")
        if document.get("$id") != expected_id:
            fail(f"{relative}: $id does not match retained schema asset manifest entry")
        expected_sha256 = require_sha256(asset.get("sha256"), f"{relative}: retained schema asset sha256")
        if sha256_file(root / relative, "retained schema asset") != expected_sha256:
            fail(f"{relative}: bytes do not match retained schema asset digest")
        by_path[relative] = asset
    actual_paths = set(by_path)
    if actual_paths != REQUIRED_RETAINED_SCHEMA_ASSETS:
        fail(
            "retained schema asset inventory differs from the required set; "
            f"missing={sorted(REQUIRED_RETAINED_SCHEMA_ASSETS - actual_paths)}, "
            f"extra={sorted(actual_paths - REQUIRED_RETAINED_SCHEMA_ASSETS)}"
        )
    return len(by_path)


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
    source_owners = {}
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
        schema_versions = set()
        for schema in schemas:
            if not isinstance(schema, dict):
                fail(f"{name}: schema entries must be objects")
            version = require_int(schema.get("version"), f"{name} schema version")
            if version in schema_versions:
                fail(f"{name}: schema version {version} is listed more than once")
            schema_versions.add(version)
            status = schema.get("status")
            # The writer's own version is active even when it also appears in
            # frozen_versions, which is a real state: a family can still emit v1
            # while published records pin v1. Resolving frozen first made that
            # combination unsatisfiable, because the family's only schema would
            # have to be declared frozen and no schema could be active.
            # Immutability for that version is carried by frozen_versions; this
            # field records what the writer emits.
            expected_status = "active" if version == active else "frozen" if version in frozen else None
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
            if status == "frozen":
                expected_sha256 = require_sha256(schema.get("sha256"), f"{relative}: frozen schema sha256")
                if sha256_file(root / relative, "schema") != expected_sha256:
                    fail(f"{relative}: bytes do not match frozen schema digest")
            elif "sha256" in schema:
                fail(f"{relative}: active schema must not pin a frozen schema digest")
            declared = declared_schema_version(document, relative)
            if declared != version:
                fail(f"{relative}: declares schema_version {declared!r}, manifest says {version}")
            if status == "active":
                require_top_level_required_properties(document, relative)
                active_schema_paths.append(relative)

        if schemas and schema_versions != set(accepted):
            missing = sorted(set(accepted) - schema_versions)
            extra = sorted(schema_versions - set(accepted))
            fail(f"{name}: schemas do not cover accepted reader versions; missing={missing}, extra={extra}")

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
            if not isinstance(source, dict):
                fail(f"{name}.source_versions entries must be objects")
            coordinate = (source.get("path"), source.get("symbol"))
            previous_owner = source_owners.get(coordinate)
            if previous_owner is not None and previous_owner != name:
                fail(
                    f"source version {coordinate[0]}:{coordinate[1]} is shared by families "
                    f"{previous_owner} and {name}"
                )
            source_owners[coordinate] = name
            value = read_source_version(root, source)
            listed_constants.add(coordinate)
            constant_values[coordinate] = value
            if value != active:
                fail(f"{name}: {coordinate[0]} {coordinate[1]} is {value}, active writer is {active}")

    discovered_schemas = versioned_schema_inventory(root)
    if listed_schemas != discovered_schemas:
        missing = sorted(discovered_schemas - listed_schemas)
        extra = sorted(listed_schemas - discovered_schemas)
        fail(f"versioned schema inventory mismatch; unlisted={missing}, nonexistent={extra}")
    if not REQUIRED_SOURCE_VERSIONS.issubset(listed_constants):
        fail(
            "governing source versions missing from manifest: "
            f"{sorted(REQUIRED_SOURCE_VERSIONS - listed_constants)}"
        )
    # Every source constant a family declares must equal that family's active
    # writer version. Checked generically rather than as named pairs: the
    # per-family split was landed three times because each round only bound the
    # coordinates someone remembered, so a newly split constant could drift
    # while the manifest, the runner, and the Go contract test all still agreed.
    # Whatever the manifest declares is what gets verified.
    for family in manifest.get("artifact_families", []):
        name = family.get("family")
        active = family.get("active_writer_version")
        if not isinstance(active, int):
            continue
        for source in family.get("source_versions", []) or []:
            coordinate = (source.get("path"), source.get("symbol"))
            if coordinate not in constant_values:
                continue
            found = constant_values[coordinate]
            if found != active:
                fail(
                    f"family {name}: {coordinate[0]}:{coordinate[1]} is {found}, "
                    f"but active_writer_version is {active}; move both together or neither"
                )

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
    asset_count = retained_schema_assets(root, manifest.get("retained_schema_assets"))
    return len(families), len(discovered_schemas), file_count, sorted(found_versions), asset_count


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    manifest_path = args.manifest.resolve() if args.manifest else root / "contracts" / "artifacts.json"
    try:
        families, schemas, records, versions, assets = check(root, manifest_path)
    except (OSError, ValueError) as exc:
        print(f"check-contracts: FAIL - {exc}", file=sys.stderr)
        return 1
    print(
        "check-contracts: OK "
        f"({families} families, {schemas} schemas, {records} retained JSON files, "
        f"frozen record versions {versions}, {assets} retained schema assets)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
