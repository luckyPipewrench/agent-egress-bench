#!/usr/bin/env python3
"""Validate Gauntlet scope artifacts against an explicit corpus authority."""

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import subprocess
import sys
import urllib.parse
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

try:
    import artifact_schema
except ModuleNotFoundError:
    _artifact_schema_spec = importlib.util.spec_from_file_location(
        "artifact_schema", Path(__file__).with_name("artifact_schema.py")
    )
    artifact_schema = importlib.util.module_from_spec(_artifact_schema_spec)
    _artifact_schema_spec.loader.exec_module(artifact_schema)
try:
    from scripts import artifact_contracts
except ModuleNotFoundError:
    import artifact_contracts


V1_REQUIRED_SCOPE_PATHS = (
    ("schema_version",),
    ("artifact_id",),
    ("corpus_manifest_sha256",),
    ("logical_case_count",),
    ("runner_version",),
    ("scoring_version",),
    ("case_count", "applicable"),
    ("case_count", "total"),
    ("case_count", "not_applicable"),
    ("case_count", "not_applicable_reasons"),
    ("scores", "applicable", "containment"),
    ("scores", "applicable", "false_positive_rate"),
    ("metric_counts", "applicable", "containment", "numerator"),
    ("metric_counts", "applicable", "containment", "denominator"),
    ("metric_counts", "applicable", "false_positive_rate", "numerator"),
    ("metric_counts", "applicable", "false_positive_rate", "denominator"),
    ("canonical_url",),
)
V2_REQUIRED_SCOPE_PATHS = (
    ("schema_version",),
    ("artifact_id",),
    ("corpus_manifest_sha256",),
    ("case_index_sha256",),
    ("logical_case_count",),
    ("runner_version",),
    ("scoring_version",),
    ("case_count", "applicable"),
    ("case_count", "total"),
    ("case_count", "not_applicable"),
    ("case_count", "not_applicable_reasons"),
    ("case_count", "errors"),
    ("canonical_url",),
)
METRICS = ("containment", "false_positive_rate", "detection", "evidence")
OUTCOME_METRICS = ("containment", "false_positive_rate")
PRESENCE_DIAGNOSTICS = (
    "classification_present_rate",
    "structured_evidence_present_rate",
)
SCOPES = ("applicable", "full")

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA1_HEX = re.compile(r"^[0-9a-f]{40}$")

REPO_ROOT = Path(__file__).resolve().parents[1]
PROVENANCE_SCHEMAS = artifact_contracts.schema_paths("provenance_candidate")
PROMOTED_RECORD_SCHEMAS = artifact_contracts.schema_paths("promoted_record")
MANIFEST_PATH = REPO_ROOT / "cases" / "MANIFEST.txt"
CORPUS_VERSION_PATH = Path("cases") / "CORPUS_VERSION"
ACTIVE_SET_DIRECTORY = Path("corpora") / "active-sets" / "v1"
CORPUS_VERSIONS_PATH = Path("ci") / "corpus-versions.json"
ARCHIVE_RECORD_MANIFEST = "record-manifest.json"
ARCHIVE_CANDIDATE = "continuous-gauntlet-pipelock.json"
ARCHIVE_CORPUS_MANIFEST = "corpus-manifest.txt"


def path_value(document, path):
    current = document
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError("missing required scope field: " + ".".join(path))
        current = current[key]
    return current


def non_negative_integer(document, path):
    value = path_value(document, path)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("scope field must be a non-negative integer: " + ".".join(path))
    return value


def optional_non_negative_integer(document, path, default=0):
    current = document
    for key in path[:-1]:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    if not isinstance(current, dict) or path[-1] not in current:
        return default
    value = current[path[-1]]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("scope field must be a non-negative integer: " + ".".join(path))
    return value


def finite_fraction(document, path, allow_null=False):
    value = path_value(document, path)
    if value is None and allow_null:
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        suffix = " or null" if allow_null else ""
        raise ValueError("scope field must be a number" + suffix + ": " + ".".join(path))
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError("scope field must be between 0 and 1: " + ".".join(path))
    return value


def non_empty_string(document, path):
    value = path_value(document, path)
    if not isinstance(value, str) or not value.strip():
        raise ValueError("scope field must be a non-empty string: " + ".".join(path))
    return value


def corpus_manifest_authority(raw, label="corpus manifest"):
    """Return one manifest identity and ID set from the same supplied bytes."""
    try:
        logical_ids = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    if not logical_ids:
        raise ValueError(f"{label} has no logical case IDs")
    if len(logical_ids) != len(set(logical_ids)):
        raise ValueError(f"{label} contains duplicate logical case IDs")
    return hashlib.sha256(raw).hexdigest(), len(logical_ids), set(logical_ids)


def corpus_manifest_identity(manifest_path, label="corpus manifest"):
    """Return one manifest identity using the runner's non-empty/unique ID rules."""
    try:
        raw = manifest_path.read_bytes()
    except OSError as exc:
        raise ValueError(f"read {label} {manifest_path}: {exc}") from exc
    digest, count, _ = corpus_manifest_authority(raw, label)
    return digest, count


@dataclass(frozen=True)
class CorpusAuthority:
    source_digest: str
    source_count: int
    logical_count: int
    source_label: str
    logical_label: str


def read_repo_regular_bytes(repo_root, relative_path, label):
    """Read a repository-relative authority file without following symlinks."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError(f"cannot safely open {label}: O_NOFOLLOW is unavailable")
    relative_path = Path(relative_path)
    if relative_path.is_absolute() or not relative_path.parts or any(
        part in {"", ".", ".."} for part in relative_path.parts
    ):
        raise ValueError(f"invalid repository-relative path for {label}")
    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = (
        os.O_RDONLY | close_on_exec | getattr(os, "O_DIRECTORY", 0) | os.O_NOFOLLOW
    )
    try:
        directory = os.open(repo_root, directory_flags)
    except OSError as exc:
        raise ValueError(f"cannot anchor repository path for {label}: {exc}") from exc
    try:
        for component in relative_path.parts[:-1]:
            try:
                child = os.open(component, directory_flags, dir_fd=directory)
            except OSError as exc:
                raise ValueError(f"parent path for {label} must contain only directories") from exc
            os.close(directory)
            directory = child
        try:
            descriptor = os.open(
                relative_path.name,
                os.O_RDONLY | close_on_exec | os.O_NOFOLLOW,
                dir_fd=directory,
            )
        except OSError as exc:
            raise ValueError(f"{label} must be a regular file") from exc
    finally:
        os.close(directory)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def checked_out_active_set_count(source_digest, source_ids, corpus_version):
    """Authenticate the current version's selected subset of the source catalog."""
    active_set_path = ACTIVE_SET_DIRECTORY / f"{corpus_version}.json"
    try:
        active_set_bytes = read_repo_regular_bytes(REPO_ROOT, active_set_path, "active set")
        active_set = json.loads(active_set_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse active set {active_set_path}: {exc}") from exc

    required_keys = {
        "schema_version",
        "corpus_version",
        "source_manifest_sha256",
        "excluded_case_ids",
        "case_count",
    }
    if not isinstance(active_set, dict) or set(active_set) != required_keys:
        raise ValueError("active set must contain exactly the versioned selection fields")
    if (
        isinstance(active_set["schema_version"], bool)
        or active_set["schema_version"] != 1
        or active_set["corpus_version"] != corpus_version
        or active_set["source_manifest_sha256"] != source_digest
    ):
        raise ValueError("active set does not bind the checked-out corpus version and source manifest")
    excluded = active_set["excluded_case_ids"]
    if (
        not isinstance(excluded, list)
        or any(not isinstance(case_id, str) or not case_id for case_id in excluded)
        or len(excluded) != len(set(excluded))
    ):
        raise ValueError("active set excluded_case_ids must be a unique string array")
    unknown = sorted(set(excluded) - source_ids)
    if unknown:
        raise ValueError(f"active set excludes unknown case IDs: {unknown!r}")
    selected_count = len(source_ids - set(excluded))
    if (
        isinstance(active_set["case_count"], bool)
        or not isinstance(active_set["case_count"], int)
        or active_set["case_count"] < 1
        or active_set["case_count"] != selected_count
    ):
        raise ValueError("active set case_count does not match its selected source cases")
    try:
        ledger = json.loads(
            read_repo_regular_bytes(REPO_ROOT, CORPUS_VERSIONS_PATH, "corpus version ledger")
        )
    except json.JSONDecodeError as exc:
        raise ValueError(f"parse corpus version ledger {CORPUS_VERSIONS_PATH}: {exc}") from exc
    versions = ledger.get("versions") if isinstance(ledger, dict) else None
    matches = [
        entry
        for entry in versions or []
        if isinstance(entry, dict) and entry.get("corpus_version") == corpus_version
    ]
    if not isinstance(versions, list) or len(matches) != 1 or versions[-1] is not matches[0]:
        raise ValueError("active corpus version must appear once as the final ledger entry")
    ledger_entry = matches[0]
    if ledger_entry.get("active_set_sha256") != hashlib.sha256(active_set_bytes).hexdigest():
        raise ValueError("corpus version ledger does not bind the active set bytes")
    if (
        isinstance(ledger_entry.get("case_count"), bool)
        or not isinstance(ledger_entry.get("case_count"), int)
        or ledger_entry.get("case_count") != selected_count
    ):
        raise ValueError("corpus version ledger case_count does not match the active set")
    return selected_count


def checked_out_corpus_authority(document, expected_manifest=MANIFEST_PATH):
    """Return source and logical corpus identities for candidate validation."""
    if expected_manifest == MANIFEST_PATH:
        source_label = "checked-out cases/MANIFEST.txt"
        manifest_bytes = read_repo_regular_bytes(
            REPO_ROOT, Path("cases") / "MANIFEST.txt", source_label
        )
    else:
        source_label = "explicit expected corpus manifest"
        try:
            manifest_bytes = expected_manifest.read_bytes()
        except OSError as exc:
            raise ValueError(f"read {source_label} {expected_manifest}: {exc}") from exc
    source_digest, source_count, source_ids = corpus_manifest_authority(
        manifest_bytes, source_label
    )
    logical_count = source_count
    logical_label = source_label

    # Historical artifacts and explicit manifest pairs retain their original
    # source-manifest semantics. The current checked-out corpus instead has a
    # declared active set whose count is the executed scoring denominator.
    if expected_manifest == MANIFEST_PATH and document.get("corpus_version"):
        try:
            current_version = read_repo_regular_bytes(
                REPO_ROOT, CORPUS_VERSION_PATH, "checked-out corpus version"
            ).decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("checked-out corpus version is not valid UTF-8") from exc
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", current_version):
            raise ValueError("checked-out corpus version must be a v-prefixed semantic version")
        if document["corpus_version"] != current_version:
            raise ValueError("artifact corpus_version does not match the checked-out corpus version")
        logical_count = checked_out_active_set_count(source_digest, source_ids, current_version)
        logical_label = f"checked-out active set {current_version}"
    return CorpusAuthority(source_digest, source_count, logical_count, source_label, logical_label)


def require_sha256(value, label):
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be 64 lower-case hex characters")
    return value


def render_version_options(versions):
    rendered = [str(version) for version in sorted(versions)]
    if not rendered:
        return "no accepted versions"
    if len(rendered) == 1:
        return rendered[0]
    if len(rendered) == 2:
        return " or ".join(rendered)
    return ", ".join(rendered[:-1]) + f", or {rendered[-1]}"


def archive_manifest_identity(artifact_path, record_dir, expected_record_manifest_sha256):
    """Verify a retained manifest against a caller-authenticated immutable record."""
    record_dir = record_dir.resolve()
    artifact_path = artifact_path.resolve()
    expected_record_manifest_sha256 = require_sha256(
        expected_record_manifest_sha256, "expected record manifest SHA-256"
    )
    if artifact_path != record_dir / ARCHIVE_CANDIDATE:
        raise ValueError(
            "archive artifact must be the record's " + ARCHIVE_CANDIDATE
        )
    if not record_dir.is_dir() or record_dir.is_symlink():
        raise ValueError("archive record must be a real directory")

    manifest_path = record_dir / ARCHIVE_RECORD_MANIFEST
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ValueError("archive record manifest is absent or unreadable")
    manifest_bytes = manifest_path.read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_record_manifest_sha256:
        raise ValueError("archive record manifest does not match the trusted expected digest")
    try:
        record_manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("archive record manifest is malformed") from exc
    if not isinstance(record_manifest, dict):
        raise ValueError("archive record manifest must be an object")
    record_schema_version = record_manifest.get("schema_version")
    if record_schema_version not in PROMOTED_RECORD_SCHEMAS:
        rendered = render_version_options(PROMOTED_RECORD_SCHEMAS)
        raise ValueError(f"archive record manifest schema_version must be {rendered}")
    artifact_schema.validate_file(
        record_manifest,
        PROMOTED_RECORD_SCHEMAS[record_schema_version],
        "archive record manifest",
    )
    files = record_manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("archive record manifest files must be a non-empty object")

    expected_names = set(files) | {ARCHIVE_RECORD_MANIFEST}
    actual_entries = list(record_dir.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in actual_entries):
        raise ValueError("archive record contains a non-regular entry")
    if {path.name for path in actual_entries} != expected_names:
        raise ValueError("archive record file set does not match its manifest")
    for name, expected_digest in files.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError("archive record manifest has an unsafe file name")
        require_sha256(expected_digest, f"archive record files.{name}")
        if hashlib.sha256((record_dir / name).read_bytes()).hexdigest() != expected_digest:
            raise ValueError(f"archive record file changed: {name}")

    if ARCHIVE_CANDIDATE not in files or ARCHIVE_CORPUS_MANIFEST not in files:
        raise ValueError("archive record does not bind its candidate and corpus manifest")
    candidate_digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if record_dir.name != candidate_digest:
        raise ValueError("archive record directory name does not bind its candidate")
    if record_manifest.get("candidate_sha256") != candidate_digest:
        raise ValueError("archive record manifest does not bind its candidate")

    with artifact_path.open(encoding="utf-8") as artifact_file:
        artifact = json.load(artifact_file)
    corpus_git_sha = artifact.get("corpus_git_sha") if isinstance(artifact, dict) else None
    if not isinstance(corpus_git_sha, str) or not GIT_SHA1_HEX.fullmatch(corpus_git_sha):
        raise ValueError("archive artifact corpus_git_sha must be 40 lower-case hex characters")
    retained_manifest_path = record_dir / ARCHIVE_CORPUS_MANIFEST
    manifest_at_revision = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{corpus_git_sha}:cases/MANIFEST.txt"],
        check=False,
        capture_output=True,
    )
    if manifest_at_revision.returncode != 0:
        raise ValueError("archive artifact corpus_git_sha is not a retained repository commit")
    if manifest_at_revision.stdout != retained_manifest_path.read_bytes():
        raise ValueError("archive retained corpus manifest differs from corpus_git_sha")
    return corpus_manifest_identity(retained_manifest_path, "authenticated archive corpus manifest")


def validate_metric_fraction(document, scope, metric):
    """Bind a score to its explicit numerator/denominator."""
    score_path = ("scores", scope, metric)
    count_path = ("metric_counts", scope, metric)
    numerator = non_negative_integer(document, count_path + ("numerator",))
    denominator = non_negative_integer(document, count_path + ("denominator",))
    if numerator > denominator:
        raise ValueError("metric numerator cannot exceed denominator: " + ".".join(count_path))

    score = finite_fraction(document, score_path, allow_null=True)
    if denominator == 0:
        if score is not None:
            raise ValueError("score must be null when metric denominator is zero: " + ".".join(score_path))
        return numerator, denominator
    if score is None:
        raise ValueError("score must be a number when metric denominator is non-zero: " + ".".join(score_path))
    if score != numerator / denominator:
        raise ValueError("score must equal metric numerator/denominator: " + ".".join(score_path))
    return numerator, denominator


def validate_diagnostic_fraction(document, scope, diagnostic):
    """Bind a non-scoring diagnostic to its explicit numerator/denominator."""
    rate_path = ("diagnostics", scope, diagnostic)
    count_path = ("diagnostic_counts", scope, diagnostic)
    numerator = non_negative_integer(document, count_path + ("numerator",))
    denominator = non_negative_integer(document, count_path + ("denominator",))
    if numerator > denominator:
        raise ValueError("diagnostic numerator cannot exceed denominator: " + ".".join(count_path))

    rate = finite_fraction(document, rate_path, allow_null=True)
    if denominator == 0:
        if rate is not None:
            raise ValueError("diagnostic must be null when denominator is zero: " + ".".join(rate_path))
        return numerator, denominator
    if rate is None:
        raise ValueError("diagnostic must be a number when denominator is non-zero: " + ".".join(rate_path))
    if rate != numerator / denominator:
        raise ValueError("diagnostic must equal numerator/denominator: " + ".".join(rate_path))
    return numerator, denominator


def require_exact_keys(document, path, expected):
    value = path_value(document, path)
    if not isinstance(value, dict):
        raise ValueError("scope field must be an object: " + ".".join(path))
    actual = set(value)
    expected = set(expected)
    if actual != expected:
        raise ValueError(
            "scope field has unexpected keys: "
            + ".".join(path)
            + f" (got {sorted(actual)!r}, want {sorted(expected)!r})"
        )
    return value


def validate_canonical_url(document):
    """Require an absolute HTTPS canonical artifact URL."""
    canonical_url = path_value(document, ("canonical_url",))
    if not isinstance(canonical_url, str) or not canonical_url:
        raise ValueError("canonical_url must be a non-empty string")
    parsed_url = urllib.parse.urlparse(canonical_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError("canonical_url must be an absolute https URL")


def validate_scope(document, corpus_authority):
    """Dispatch provenance validation by the explicit artifact schema version."""
    if not isinstance(document, dict):
        raise ValueError("artifact must be a JSON object")
    version = path_value(document, ("schema_version",))
    if version == 1:
        validate_scope_v1(document, corpus_authority)
    elif version == 2:
        validate_scope_v2(document, corpus_authority)
    elif version == 4:
        validate_scope_v4(document, corpus_authority)
    elif version == 5:
        validate_scope_v5(document, corpus_authority)
    elif version == 6:
        validate_scope_v5(document, corpus_authority, expected_version=6)
    else:
        raise ValueError(f"unsupported schema_version: {version!r}")
    return artifact_schema.validate_file(
        document, PROVENANCE_SCHEMAS[version], f"provenance candidate v{version}"
    )


def validate_scope_v1(document, corpus_authority):
    """Validate the original applicable-only provenance contract."""
    for path in V1_REQUIRED_SCOPE_PATHS:
        path_value(document, path)
    if document["schema_version"] != 1:
        raise ValueError("schema_version must be 1 for a v1 artifact")

    non_empty_string(document, ("artifact_id",))
    non_empty_string(document, ("runner_version",))
    non_empty_string(document, ("scoring_version",))
    manifest_digest = non_empty_string(document, ("corpus_manifest_sha256",))
    if not SHA256_HEX.fullmatch(manifest_digest):
        raise ValueError("corpus_manifest_sha256 must be 64 lower-case hex characters")
    manifest_count = non_negative_integer(document, ("logical_case_count",))
    if manifest_digest != corpus_authority.source_digest:
        raise ValueError(f"corpus_manifest_sha256 does not match {corpus_authority.source_label}")
    if manifest_count != corpus_authority.logical_count:
        raise ValueError(f"logical_case_count does not match {corpus_authority.logical_label}")

    applicable = non_negative_integer(document, ("case_count", "applicable"))
    total = non_negative_integer(document, ("case_count", "total"))
    # Explicit unreachable coverage was added after frozen v2 artifacts were
    # published. Missing stays zero for those immutable readers; a present row
    # is outside score denominators but still part of the logical corpus.
    unreachable = optional_non_negative_integer(document, ("case_count", "unreachable"))
    not_applicable = non_negative_integer(document, ("case_count", "not_applicable"))
    if total == 0 or total != corpus_authority.logical_count:
        raise ValueError(f"case_count.total does not match {corpus_authority.logical_label} logical corpus count")
    if applicable + unreachable + not_applicable != total:
        raise ValueError("case_count.applicable, unreachable, and not_applicable must equal case_count.total")
    reasons = path_value(document, ("case_count", "not_applicable_reasons"))
    if not isinstance(reasons, dict):
        raise ValueError("scope field must be an object: case_count.not_applicable_reasons")
    if any(
        not isinstance(reason, str)
        or not reason
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for reason, count in reasons.items()
    ):
        raise ValueError("not_applicable_reasons must map strings to non-negative integers")
    if sum(reasons.values()) != not_applicable:
        raise ValueError("not_applicable_reasons must sum to case_count.not_applicable")

    containment = path_value(document, ("scores", "applicable", "containment"))
    _, containment_denominator = validate_metric_fraction(document, "applicable", "containment")
    _, false_positive_denominator = validate_metric_fraction(
        document, "applicable", "false_positive_rate"
    )
    if containment_denominator > applicable or false_positive_denominator > applicable:
        raise ValueError("metric denominator cannot exceed case_count.applicable")
    if applicable == 0 and (containment is not None or containment_denominator != 0):
        raise ValueError("scores.applicable.containment must be null when case_count.applicable is zero")
    if applicable > 0 and containment_denominator == 0:
        raise ValueError("containment must have a denominator when case_count.applicable is non-zero")
    validate_canonical_url(document)


def validate_scope_v2(document, corpus_authority):
    """Validate the full/applicable, case-index-bound provenance contract."""
    if document.get("schema_version") != 2:
        raise ValueError("schema_version must be 2 for a v2 artifact")

    for path in V2_REQUIRED_SCOPE_PATHS:
        path_value(document, path)

    non_empty_string(document, ("artifact_id",))
    non_empty_string(document, ("runner_version",))
    non_empty_string(document, ("scoring_version",))

    manifest_digest = non_empty_string(document, ("corpus_manifest_sha256",))
    if not SHA256_HEX.fullmatch(manifest_digest):
        raise ValueError("corpus_manifest_sha256 must be 64 lower-case hex characters")
    case_index_digest = non_empty_string(document, ("case_index_sha256",))
    if not SHA256_HEX.fullmatch(case_index_digest):
        raise ValueError("case_index_sha256 must be 64 lower-case hex characters")
    manifest_count = non_negative_integer(document, ("logical_case_count",))
    if manifest_digest != corpus_authority.source_digest:
        raise ValueError(f"corpus_manifest_sha256 does not match {corpus_authority.source_label}")
    if manifest_count != corpus_authority.logical_count:
        raise ValueError(f"logical_case_count does not match {corpus_authority.logical_label}")

    applicable = non_negative_integer(document, ("case_count", "applicable"))
    total = non_negative_integer(document, ("case_count", "total"))
    unreachable = optional_non_negative_integer(document, ("case_count", "unreachable"))
    not_applicable = non_negative_integer(document, ("case_count", "not_applicable"))
    errors = non_negative_integer(document, ("case_count", "errors"))
    if total == 0:
        raise ValueError("case_count.total must be greater than zero")
    if total != corpus_authority.logical_count:
        raise ValueError(f"case_count.total does not match {corpus_authority.logical_label} logical corpus count")
    if applicable > total:
        raise ValueError("case_count.applicable cannot exceed case_count.total")
    if applicable + unreachable + not_applicable != total:
        raise ValueError(
            "case_count.applicable, unreachable, and not_applicable must equal case_count.total"
        )
    if errors > applicable:
        raise ValueError("case_count.errors cannot exceed case_count.applicable")

    reasons = path_value(document, ("case_count", "not_applicable_reasons"))
    if not isinstance(reasons, dict):
        raise ValueError("scope field must be an object: case_count.not_applicable_reasons")
    reason_total = 0
    for reason, count in reasons.items():
        if not isinstance(reason, str) or not reason:
            raise ValueError("not_applicable_reasons keys must be non-empty strings")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("not_applicable_reasons values must be non-negative integers")
        reason_total += count
    if reason_total != not_applicable:
        raise ValueError("not_applicable_reasons must sum to case_count.not_applicable")

    # Containment has no denominator when every case is N/A. In exactly that
    # state it must be null rather than a made-up score; otherwise it must be a
    # finite fraction because scope-render.js publishes it as the headline.
    containment = path_value(document, ("scores", "applicable", "containment"))
    counts = {
        scope: {
            metric: validate_metric_fraction(document, scope, metric)
            for metric in METRICS
        }
        for scope in SCOPES
    }
    containment_numerator, containment_denominator = counts["applicable"]["containment"]
    _, false_positive_denominator = counts["applicable"]["false_positive_rate"]
    if containment_denominator > applicable or false_positive_denominator > applicable:
        raise ValueError("metric denominator cannot exceed case_count.applicable")
    if applicable == 0:
        if containment is not None or containment_denominator != 0:
            raise ValueError("scores.applicable.containment must be null when case_count.applicable is zero")
    else:
        if containment_denominator == 0:
            raise ValueError("containment must have a denominator when case_count.applicable is non-zero")
    if applicable == 0 and false_positive_denominator != 0:
        raise ValueError("false_positive_rate must have a zero denominator when case_count.applicable is zero")
    if containment_denominator + false_positive_denominator != applicable:
        raise ValueError("applicable metric denominators must partition case_count.applicable")
    if counts["full"]["containment"][1] + counts["full"]["false_positive_rate"][1] != total - unreachable:
        raise ValueError("full metric denominators must partition scoreable cases")
    for metric in METRICS:
        if counts["full"][metric][0] != counts["applicable"][metric][0]:
            raise ValueError(
                f"metric_counts.full.{metric}.numerator must equal applicable numerator"
            )
    for scope in SCOPES:
        for metric in ("detection", "evidence"):
            if counts[scope][metric][1] != containment_numerator:
                raise ValueError(
                    f"metric_counts.{scope}.{metric}.denominator must equal blocked malicious count"
                )

    validate_canonical_url(document)


def validate_scope_v4(document, corpus_authority):
    """Validate an active registry-bound artifact without reusing a v2 claim."""
    copied = dict(document)
    copied["schema_version"] = 2
    validate_scope_v2(copied, corpus_authority)
    reference = document.get("capability_registry")
    if not isinstance(reference, dict) or set(reference) != {"id", "format", "revision", "sha256"}:
        raise ValueError("capability_registry must be an exact registry reference")
    if not isinstance(reference["id"], str) or not reference["id"]:
        raise ValueError("capability_registry.id must be non-empty")
    for key in ("format", "revision"):
        if isinstance(reference[key], bool) or not isinstance(reference[key], int) or reference[key] < 1:
            raise ValueError(f"capability_registry.{key} must be a positive integer")
    if not isinstance(reference["sha256"], str) or not SHA256_HEX.fullmatch(reference["sha256"]):
        raise ValueError("capability_registry.sha256 must be 64 lower-case hex characters")


def validate_scope_v5(document, corpus_authority, expected_version=5):
    """Validate the active outcome-score plus presence-diagnostics contract."""
    if document.get("schema_version") != expected_version:
        raise ValueError(
            f"schema_version must be {expected_version} for a v{expected_version} artifact"
        )

    # Reuse the v2 arithmetic and partition checks with an internal projection.
    # V5 deliberately moved the old field-presence values out of scores, so the
    # projection is validation machinery only and never changes the artifact.
    projected = deepcopy(document)
    projected["schema_version"] = 2
    projected["scores"] = {}
    projected["metric_counts"] = {}
    require_exact_keys(document, ("scores",), SCOPES)
    require_exact_keys(document, ("diagnostics",), SCOPES)
    require_exact_keys(document, ("metric_counts",), SCOPES)
    require_exact_keys(document, ("diagnostic_counts",), SCOPES)
    for scope in SCOPES:
        scores = require_exact_keys(document, ("scores", scope), OUTCOME_METRICS)
        diagnostics = require_exact_keys(
            document, ("diagnostics", scope), PRESENCE_DIAGNOSTICS
        )
        metric_counts = require_exact_keys(
            document, ("metric_counts", scope), OUTCOME_METRICS
        )
        diagnostic_counts = require_exact_keys(
            document, ("diagnostic_counts", scope), PRESENCE_DIAGNOSTICS
        )
        projected["scores"][scope] = {
            **scores,
            "detection": diagnostics["classification_present_rate"],
            "evidence": diagnostics["structured_evidence_present_rate"],
        }
        projected["metric_counts"][scope] = {
            **metric_counts,
            "detection": diagnostic_counts["classification_present_rate"],
            "evidence": diagnostic_counts["structured_evidence_present_rate"],
        }

    validate_scope_v2(projected, corpus_authority)
    validate_scope_v4(
        {**projected, "capability_registry": document.get("capability_registry")},
        corpus_authority,
    )

    counts = {
        scope: {
            diagnostic: validate_diagnostic_fraction(document, scope, diagnostic)
            for diagnostic in PRESENCE_DIAGNOSTICS
        }
        for scope in SCOPES
    }
    for diagnostic in PRESENCE_DIAGNOSTICS:
        if counts["full"][diagnostic][0] != counts["applicable"][diagnostic][0]:
            raise ValueError(
                f"diagnostic_counts.full.{diagnostic}.numerator must equal applicable numerator"
            )
        for scope in SCOPES:
            containment_numerator = non_negative_integer(
                document, ("metric_counts", scope, "containment", "numerator")
            )
            if counts[scope][diagnostic][1] != containment_numerator:
                raise ValueError(
                    f"diagnostic_counts.{scope}.{diagnostic}.denominator must equal blocked malicious count"
                )


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Validate a Gauntlet scope artifact against a trusted corpus authority."
    )
    parser.add_argument(
        "--expected-manifest",
        type=Path,
        help="trusted expected corpus manifest for candidate validation (default: checked-out cases/MANIFEST.txt)",
    )
    parser.add_argument(
        "--archive-record",
        type=Path,
        help="immutable record directory for historical archive validation",
    )
    parser.add_argument(
        "--expected-record-manifest-sha256",
        help="trusted SHA-256 of --archive-record/record-manifest.json",
    )
    parser.add_argument("artifact", type=Path, metavar="ARTIFACT.json")
    args = parser.parse_args(argv[1:])
    if args.archive_record is None:
        if args.expected_record_manifest_sha256 is not None:
            parser.error("--expected-record-manifest-sha256 requires --archive-record")
    else:
        if args.expected_manifest is not None:
            parser.error("--expected-manifest cannot be combined with --archive-record")
        if args.expected_record_manifest_sha256 is None:
            parser.error("--archive-record requires --expected-record-manifest-sha256")
    return args


def main(argv):
    args = parse_args(argv)
    try:
        with args.artifact.open(encoding="utf-8") as artifact_file:
            artifact = json.load(artifact_file)
        if args.archive_record is not None:
            source_digest, source_count = archive_manifest_identity(
                args.artifact,
                args.archive_record,
                args.expected_record_manifest_sha256,
            )
            corpus_authority = CorpusAuthority(
                source_digest,
                source_count,
                source_count,
                "authenticated archive corpus manifest",
                "authenticated archive corpus manifest",
            )
        else:
            corpus_authority = checked_out_corpus_authority(
                artifact, args.expected_manifest or MANIFEST_PATH
            )
        validate_scope(artifact, corpus_authority)
    except (OSError, json.JSONDecodeError, ValueError, subprocess.SubprocessError) as exc:
        print(f"scope validation: FAIL: {exc}", file=sys.stderr)
        return 1
    print("scope validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
