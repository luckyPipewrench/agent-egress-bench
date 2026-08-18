#!/usr/bin/env python3
"""Load immutable cases and render their governance-decision records."""

import hashlib
import json
import yaml
import stat
import os
import re
from pathlib import Path


ACTIVE_CASE_GOVERNANCE_DECISION_SCHEMA_VERSION = 1
CASE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,127}$")
EXPECTED_VERDICTS = {"block", "allow", "warn"}
FALSE_POSITIVE_RISKS = {"low", "medium", "high"}
DECISION_DIRECTORY = Path("governance/case-decisions")
DECISION_SUFFIX = ".decision.json"
_YAML_FIELD = re.compile(r"^([a-z_]+):(?:[ \t]*(.*))?$")


class _StrictSafeLoader(yaml.SafeLoader):
    """A safe loader that refuses duplicate mapping keys.

    yaml.safe_load keeps the last value for a duplicated key, so a case declaring a field twice would
    be read one way here and possibly another way by a different parser, while the record claims to
    bind the case's metadata exactly. The JSON path already refuses duplicates; this matches it.
    """


def _no_duplicate_keys(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark, f"duplicate key {key!r}", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicate_keys)


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


MAX_METADATA_BYTES = 1 << 20
# Unix-only open flags. Windows has no equivalent, so fall back to a plain read-only open there and
# rely on the descriptor check below. The symlink refusal is weaker on that platform; the reader is
# still the thing being validated, not the name.
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
# Case sources are repository files, but an unbounded read is an unbounded read.
MAX_CASE_SOURCE_BYTES = 1 << 24


def _read_regular_file(path, label):
    """Read a file only after proving the object opened is a regular file.

    Checking a path and then opening it are two operations. A symlink to a FIFO blocks the read
    forever, and a device supplies unbounded input, so open with no-follow first and then ask the
    descriptor itself what it is.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    except OSError as exc:
        fail(f"cannot read {label} {path}: {exc}")
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            fail(f"{label} is not a regular file: {path}")
        if status.st_size > MAX_METADATA_BYTES:
            fail(f"{label} is larger than {MAX_METADATA_BYTES} bytes: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_METADATA_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_METADATA_BYTES:
        fail(f"{label} is larger than {MAX_METADATA_BYTES} bytes: {path}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label} is not valid UTF-8: {path} ({exc})")


def _read_regular_file_bytes(path, label):
    """Return file bytes, proving through the descriptor that a regular file was read."""
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW | _NONBLOCK)
    except OSError as exc:
        fail(f"cannot read {label} {path}: {exc}")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            fail(f"{label} is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_CASE_SOURCE_BYTES + 1)
        if len(raw) > MAX_CASE_SOURCE_BYTES:
            fail(f"{label} is larger than {MAX_CASE_SOURCE_BYTES} bytes: {path}")
        return raw
    finally:
        os.close(descriptor)


def load_multifile_metadata(path):
    """Parse case.yaml with the same safe YAML parser the multifile case consumer uses.

    A hand-written line parser is not YAML. It keeps a trailing comment inside a plain scalar, it
    handles folded and chomped block scalars differently, and it ends a block on recognised field
    names rather than on indentation. A record built from it can therefore bind a value that differs
    from the case metadata it claims to describe, which is the single thing these records exist to
    prevent.
    """
    text = _read_regular_file(path, "multi-file case metadata")
    # yaml.load with a SafeLoader SUBCLASS, which constructs no arbitrary Python. It is not
    # yaml.load with the default loader, and it is not unsafe_load.
    try:
        document = yaml.load(text, Loader=_StrictSafeLoader)
    except yaml.YAMLError as exc:
        fail(f"cannot parse multi-file case metadata {path}: {exc}")
    if not isinstance(document, dict):
        fail(f"multi-file case metadata must be a mapping: {path}")
    required = {
        "id",
        "description",
        "expected_verdict",
        "why_expected",
        "source",
        "false_positive_risk",
    }
    # supersedes is optional, but it must be READ, or a multifile case that declares one silently
    # produces a record claiming it supersedes nothing.
    optional = {"supersedes"}
    fields = {}
    for key in sorted((required | optional) & set(document)):
        value = document[key]
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            fail(f"{path}: {key} must be a string scalar")
        fields[key] = value if isinstance(value, str) else str(value)
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
        relative = path.relative_to(root).as_posix().encode("utf-8")
        # Verify and read through ONE descriptor. Checking the path and then reading it separately
        # lets a replacement in between bind this record to bytes nothing ever checked, which is the
        # exact claim the record is supposed to make trustworthy.
        content = _read_regular_file_bytes(path, "case source")
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
