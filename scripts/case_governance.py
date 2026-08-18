#!/usr/bin/env python3
"""Load immutable cases and render their governance-decision records."""

import hashlib
import json
import re
from pathlib import Path


ACTIVE_CASE_GOVERNANCE_DECISION_SCHEMA_VERSION = 1
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
EXPECTED_VERDICTS = {"block", "allow", "warn"}
FALSE_POSITIVE_RISKS = {"low", "medium", "high"}
DECISION_DIRECTORY = Path("governance/case-decisions")
DECISION_SUFFIX = ".decision.json"
_YAML_FIELD = re.compile(r"^([a-z_]+):(?:[ \t]*(.*))?$")


def fail(message):
    raise ValueError(message)


def _reject_json_constant(value):
    fail(f"non-finite JSON constant is not allowed: {value}")


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_json_object(path, label):
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        fail(f"cannot read {label} {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object: {path}")
    return value


def _decode_scalar(value, path, key):
    value = value.strip()
    if not value:
        fail(f"{path}: {key} must have a scalar value")
    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except json.JSONDecodeError as exc:
            fail(f"{path}: {key} has an invalid quoted scalar: {exc}")
        if not isinstance(decoded, str):
            fail(f"{path}: {key} must decode to a string")
        return decoded
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            fail(f"{path}: {key} has an unterminated quoted scalar")
        return value[1:-1].replace("''", "'")
    return value


def _decode_block(lines, start, style, path, key):
    body = []
    index = start
    while index < len(lines):
        line = lines[index]
        if line and not line[0].isspace() and _YAML_FIELD.match(line.rstrip("\n\r")):
            break
        body.append(line.rstrip("\n\r"))
        index += 1
    nonempty = [line for line in body if line.strip()]
    if not nonempty:
        fail(f"{path}: {key} block scalar is empty")
    indentation = min(len(line) - len(line.lstrip(" ")) for line in nonempty)
    if indentation == 0:
        fail(f"{path}: {key} block scalar is not indented")
    normalized = [line[indentation:] if line.strip() else "" for line in body]
    if style.startswith(">"):
        value = " ".join(line for line in normalized if line)
    else:
        value = "\n".join(normalized)
    if style != "|-":
        value += "\n"
    return value, index


def load_multifile_metadata(path):
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError) as exc:
        fail(f"cannot read multi-file case metadata {path}: {exc}")
    fields = {}
    index = 0
    required = {
        "id",
        "description",
        "expected_verdict",
        "why_expected",
        "source",
        "false_positive_risk",
    }
    # supersedes is optional, but it must be PARSED, or a multifile case that declares one silently
    # produces a record claiming it supersedes nothing.
    optional = {"supersedes"}
    wanted = required | optional
    while index < len(lines):
        line = lines[index]
        if line and not line[0].isspace():
            match = _YAML_FIELD.match(line.rstrip("\n\r"))
            if match is not None and match.group(1) in wanted:
                key, raw = match.groups()
                if key in fields:
                    fail(f"{path}: duplicate {key} field")
                raw = raw or ""
                if raw.startswith("|") or raw.startswith(">"):
                    value, index = _decode_block(lines, index + 1, raw, path, key)
                    fields[key] = value
                    continue
                fields[key] = _decode_scalar(raw, path, key)
        index += 1
    missing = sorted(required - set(fields))
    if missing:
        fail(f"{path}: missing required governance metadata: {missing}")
    return fields


def _require_case_metadata(metadata, label):
    case_id = metadata.get("id")
    if not isinstance(case_id, str) or not CASE_ID.fullmatch(case_id):
        fail(f"{label}: id must match {CASE_ID.pattern!r}")
    for key in ("description", "why_expected", "source"):
        value = metadata.get(key)
        if not isinstance(value, str) or not value.strip():
            fail(f"{label}: {key} must be a non-empty string")
    verdict = metadata.get("expected_verdict")
    if verdict not in EXPECTED_VERDICTS:
        fail(f"{label}: expected_verdict must be one of {sorted(EXPECTED_VERDICTS)}")
    risk = metadata.get("false_positive_risk")
    if risk not in FALSE_POSITIVE_RISKS:
        fail(f"{label}: false_positive_risk must be one of {sorted(FALSE_POSITIVE_RISKS)}")
    supersedes = metadata.get("supersedes")
    if supersedes is not None and (not isinstance(supersedes, str) or not CASE_ID.fullmatch(supersedes)):
        fail(f"{label}: supersedes must be a case ID when present")


def _case_digest(root, paths):
    digest = hashlib.sha256()
    digest.update(b"agent-egress-bench/case-governance-decision-v1\x00")
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or not path.is_file():
            fail(f"case source is not a regular file: {path}")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        try:
            content = path.read_bytes()
        except OSError as exc:
            fail(f"cannot read case source {path}: {exc}")
        digest.update(relative)
        digest.update(b"\x00")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\x00")
        digest.update(content)
        digest.update(b"\x00")
    return digest.hexdigest()


def _single_file_cases(root, cases_dir):
    found = []
    for path in sorted(cases_dir.rglob("*.json")):
        if "mcp-drift" in path.relative_to(cases_dir).parts:
            continue
        if path.is_symlink():
            fail(f"single-file case is a symlink: {path.relative_to(root)}")
        metadata = load_json_object(path, "single-file case")
        _require_case_metadata(metadata, path.relative_to(root).as_posix())
        found.append((metadata, [path]))
    return found


def _multifile_cases(root, cases_dir):
    family = cases_dir / "mcp-drift"
    if not family.exists():
        return []
    if family.is_symlink() or not family.is_dir():
        fail(f"multi-file case family is not a directory: {family.relative_to(root)}")
    found = []
    for case_dir in sorted(family.iterdir()):
        if not case_dir.is_dir():
            continue
        if case_dir.is_symlink():
            fail(f"multi-file case is a symlink: {case_dir.relative_to(root)}")
        metadata = load_multifile_metadata(case_dir / "case.yaml")
        _require_case_metadata(metadata, (case_dir / "case.yaml").relative_to(root).as_posix())
        paths = []
        for path in sorted(case_dir.rglob("*")):
            if path.is_symlink():
                fail(f"multi-file case contains a symlink: {path.relative_to(root)}")
            if path.is_file():
                paths.append(path)
        if not paths:
            fail(f"multi-file case has no source files: {case_dir.relative_to(root)}")
        found.append((metadata, paths))
    return found


def load_cases(root):
    root = Path(root).resolve()
    cases_dir = root / "cases"
    if cases_dir.is_symlink() or not cases_dir.is_dir():
        fail(f"cases directory is not a directory: {cases_dir}")
    cases = {}
    for metadata, paths in _single_file_cases(root, cases_dir) + _multifile_cases(root, cases_dir):
        case_id = metadata["id"]
        if case_id in cases:
            fail(f"duplicate logical case ID: {case_id}")
        cases[case_id] = {
            "metadata": metadata,
            "paths": paths,
            "case_sha256": _case_digest(root, paths),
        }
    if not cases:
        fail("no logical cases found")
    return cases


def record_for_case(case):
    metadata = case["metadata"]
    return {
        "schema_version": ACTIVE_CASE_GOVERNANCE_DECISION_SCHEMA_VERSION,
        "case_id": metadata["id"],
        "case_sha256": case["case_sha256"],
        "case_description": metadata["description"],
        "expected_verdict": metadata["expected_verdict"],
        "why_expected": metadata["why_expected"],
        "source": metadata["source"],
        "false_positive_risk": metadata["false_positive_risk"],
        "supersedes": metadata.get("supersedes"),
    }


def rendered_record(record):
    return (json.dumps(record, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
