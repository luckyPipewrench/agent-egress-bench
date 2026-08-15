#!/usr/bin/env python3
"""Build and finalize hash-bound continuous Gauntlet evidence."""

import argparse
import hashlib
import json
import math
import os
import re
import shlex
import sys
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse


# Scoring versions belonging to retained, frozen published records. Those
# summaries predate schema_version and keep their original byte shape, so they
# are read by the frozen reader and never normalized. Everything else is active
# output and must carry its schema marker. Add a version here only when a record
# scored under it has actually been published and frozen.
FROZEN_SCORING_VERSIONS = frozenset({"2.4"})

RAW_EVIDENCE = {
    "raw_summary": "raw-summary.json",
    "results": "results.jsonl",
    "runner_stderr": "runner.stderr",
    "command": "command.txt",
    "stats": "make-stats.txt",
    "case_index": "case-index.json",
    "entrypoint_command": "entrypoint-command.txt",
    "run_metadata": "run-metadata.json",
    "pipelock_release": "pipelock-release.json",
    "release_checksums": "checksums.txt",
    "pipelock_version_output": "pipelock-version.txt",
    "corpus_manifest": "corpus-manifest.txt",
}
V4_RAW_EVIDENCE = {
    "tool_profile": "tool-profile.json",
    "capability_registry": "capability-registry.json",
    "receipt_profile": "receipt-profile.json",
}
ACTIVE_SUMMARY_SCHEMA_VERSIONS = frozenset({4, 5})
ACTIVE_SUMMARY_SCHEMA_VERSION = 5
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
V5_SCOPES = frozenset({"full", "applicable"})
V5_OUTCOME_SCORE_FIELDS = frozenset({"containment", "false_positive_rate"})
V5_DIAGNOSTIC_FIELDS = frozenset(
    {"classification_present_rate", "structured_evidence_present_rate"}
)


def load_budget_timing_case_ids(repo_root):
    case_ids = set()
    for path in (repo_root / "cases").rglob("*.json"):
        if "mcp-drift" in path.relative_to(repo_root / "cases").parts:
            continue
        try:
            case = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read canonical case metadata from {path}: {exc}") from exc
        if not isinstance(case, dict) or case.get("expected_verdict") != "block":
            continue
        payload = case.get("payload")
        if isinstance(payload, dict) and "budget_limit_calls" in payload:
            case_id = case.get("id")
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"canonical budget case has no valid id: {path}")
            if case_id in case_ids:
                raise ValueError(f"duplicate canonical budget case id: {case_id}")
            case_ids.add(case_id)
    return case_ids


def active_result_score(expected, actual, evidence, budget_timing_required):
    if actual == "not_applicable":
        return "not_applicable"
    if actual in {"unreachable", "error"}:
        return "error"
    if budget_timing_required and expected == "block" and actual == "block":
        timing = evidence.get("budget_block_timing")
        if timing == "at_over_budget":
            return "pass"
        if timing in {"before_over_budget", "after_over_budget"}:
            return "fail"
        raise ValueError("budget block result requires a valid budget_block_timing")
    if "budget_block_timing" in evidence:
        raise ValueError("non-budget result carries budget_block_timing")
    return "pass" if actual == expected else "fail"


def result_reader_contract(repo_root):
    manifest = load_object(repo_root / "contracts" / "artifacts.json")
    families = manifest.get("artifact_families")
    if not isinstance(families, list):
        raise ValueError("artifact manifest families must be an array")
    result_family = next(
        (family for family in families if isinstance(family, dict) and family.get("family") == "result_row"),
        None,
    )
    if result_family is None:
        raise ValueError("artifact manifest has no result_row family")
    active_version = result_family.get("active_writer_version")
    accepted_versions = result_family.get("accepted_reader_versions")
    if isinstance(active_version, bool) or not isinstance(active_version, int):
        raise ValueError("result_row active_writer_version must be an integer")
    if not isinstance(accepted_versions, list) or any(
        isinstance(version, bool) or not isinstance(version, int) for version in accepted_versions
    ):
        raise ValueError("result_row accepted_reader_versions must be an integer array")
    if active_version not in accepted_versions:
        raise ValueError("result_row active writer is not accepted by its reader")

    contract = load_object(repo_root / "contracts" / f"result-states-v{active_version}.json")
    if contract.get("result_schema_version") != active_version:
        raise ValueError("active result-state contract version differs from the artifact manifest")
    states = contract.get("evidence_result_states")
    if not isinstance(states, dict) or not states or any(not isinstance(state, str) for state in states):
        raise ValueError("active result-state contract has no valid evidence_result_states")
    return active_version, frozenset(accepted_versions), frozenset(states)


def validate_result_row_contract(row, row_number, active_version, accepted_versions, result_states):
    schema_version = row.get("schema_version")
    if schema_version not in accepted_versions:
        raise ValueError(
            f"runner JSONL row {row_number} schema_version must be one of {sorted(accepted_versions)}"
        )
    if schema_version != active_version:
        return

    evidence = row.get("evidence")
    state = evidence.get("result_state") if isinstance(evidence, dict) else None
    if not isinstance(state, str) or state not in result_states:
        raise ValueError(f"runner JSONL row {row_number} has invalid or missing evidence.result_state")
    actual = row.get("actual_verdict")
    score = row.get("score")
    if state == "observed" and (actual not in {"allow", "block"} or score not in {"pass", "fail"}):
        raise ValueError(f"runner JSONL row {row_number} observed result is not a measurement")
    if state == "unreachable" and (actual != "unreachable" or score != "error"):
        raise ValueError(f"runner JSONL row {row_number} unreachable result is inconsistent")
    if state not in {"observed", "unreachable"} and (actual != "error" or score != "error"):
        raise ValueError(f"runner JSONL row {row_number} unobserved failure result is inconsistent")


def raw_evidence_for_summary(summary):
    """Return the immutable evidence members for this artifact generation.

    V2 evidence is frozen and did not retain registry bytes. Active v4/v5 is a
    different contract: its raw profile, snapshot, and receipt profile are
    first-class evidence rather than a reconstructed view of current files.
    """
    if summary.get("schema_version") in ACTIVE_SUMMARY_SCHEMA_VERSIONS:
        return {**RAW_EVIDENCE, **V4_RAW_EVIDENCE}
    return RAW_EVIDENCE


def atomic_json_write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def load_object(path):
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_hashes(run_dir, require_all, evidence_spec=RAW_EVIDENCE):
    hashes = {}
    for label, relative_path in evidence_spec.items():
        path = run_dir / relative_path
        if not path.is_file():
            if require_all:
                raise ValueError(f"required evidence is missing: {label} ({relative_path})")
            hashes[label] = None
            continue
        hashes[label] = file_sha256(path)
    return hashes


def registry_reference(value, label):
    if not isinstance(value, dict) or set(value) != {"id", "format", "revision", "sha256"}:
        raise ValueError(f"{label} must be an exact capability registry reference")
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier or "/" in identifier or ".." in identifier:
        raise ValueError(f"{label}.id is invalid")
    for key in ("format", "revision"):
        if isinstance(value.get(key), bool) or not isinstance(value.get(key), int) or value[key] < 1:
            raise ValueError(f"{label}.{key} must be a positive integer")
    if not isinstance(value.get("sha256"), str) or not SHA256_HEX.fullmatch(value["sha256"]):
        raise ValueError(f"{label}.sha256 must be 64 lower-case hex characters")
    return value


def validate_v4_registry_binding(run_dir, summary, results):
    """Bind active publication data to one exact raw snapshot, never today's registry."""
    profile_bytes = (run_dir / V4_RAW_EVIDENCE["tool_profile"]).read_bytes()
    snapshot_bytes = (run_dir / V4_RAW_EVIDENCE["capability_registry"]).read_bytes()
    receipt = load_object(run_dir / V4_RAW_EVIDENCE["receipt_profile"])
    try:
        profile = json.loads(profile_bytes)
        snapshot = json.loads(snapshot_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"active registry evidence is not valid JSON: {exc}") from exc
    if not isinstance(profile, dict) or not isinstance(snapshot, dict):
        raise ValueError("active registry evidence must be JSON objects")
    reference = registry_reference(summary.get("capability_registry"), "summary capability_registry")
    if hashlib.sha256(snapshot_bytes).hexdigest() != reference["sha256"]:
        raise ValueError("capability registry raw snapshot digest does not match summary")
    for label, value in (("profile", profile), ("receipt profile", receipt)):
        if registry_reference(value.get("capability_registry"), f"{label} capability_registry") != reference:
            raise ValueError(f"{label} capability registry does not match summary")
    if snapshot.get("id") != reference["id"] or snapshot.get("format") != reference["format"] or snapshot.get("revision") != reference["revision"]:
        raise ValueError("capability registry snapshot identity does not match summary")
    entries = snapshot.get("entries")
    if not isinstance(entries, list):
        raise ValueError("capability registry snapshot entries must be an array")
    active = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or entry.get("status") != "active":
            raise ValueError("capability registry snapshot has an invalid entry")
        if entry["id"] in active:
            raise ValueError("capability registry snapshot has duplicate IDs")
        active.add(entry["id"])
    for label, values in (
        ("profile claims", profile.get("claims")),
        ("summary reported_claims", summary.get("reported_claims")),
        ("summary exercised capability_tags", summary.get("exercised", {}).get("capability_tags")),
    ):
        if not isinstance(values, list) or any(not isinstance(value, str) or value not in active for value in values):
            raise ValueError(f"{label} are not active IDs in the pinned capability registry")
    for row_number, row in enumerate(results, 1):
        if registry_reference(row.get("capability_registry"), f"runner JSONL row {row_number} capability_registry") != reference:
            raise ValueError(f"runner JSONL row {row_number} capability registry does not match summary")
    return reference


def require_non_empty_string(document, key, label=None):
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label or key} must be a non-empty string")
    return value


def claims_synthetic(row):
    """Report whether a result row claims synthetic calibration evidence.

    An explicit boolean false is an honest negative and is honored. Every other
    present value counts as a claim, including a non-boolean such as
    "synthetic": "calibration". Requiring the boolean true would let a malformed
    marker be the reason a run reads as measured and publishes, which inverts the
    gate. Mirrors hasSyntheticEvidence in runner/summary.go; the two must agree
    because each cross-checks the other's measurement_status.
    """
    evidence = row.get("evidence")
    if not isinstance(evidence, dict) or "synthetic" not in evidence:
        return False
    return evidence["synthetic"] is not False


def require_sha256(document, key, allow_null=False):
    value = document.get(key)
    if value is None and allow_null:
        return value
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise ValueError(f"{key} must be 64 lower-case hex characters")
    return value


def read_results(path):
    results = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid runner JSONL at line {line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"runner JSONL row {line_number} is not an object")
            results.append(row)
    return results


def load_manifest(repo_root, run_dir):
    manifest_path = run_dir / RAW_EVIDENCE["corpus_manifest"]
    manifest = manifest_path.read_bytes()
    checked_out_manifest = (repo_root / "cases" / "MANIFEST.txt").read_bytes()
    if manifest != checked_out_manifest:
        raise ValueError("retained corpus manifest does not match the checked-out corpus manifest")
    id_list = [line.strip() for line in manifest.decode("utf-8").splitlines() if line.strip()]
    ids = set(id_list)
    if not id_list:
        raise ValueError("refusing provenance bundle: cases/MANIFEST.txt has no logical case IDs")
    if len(ids) != len(id_list):
        raise ValueError("refusing provenance bundle: cases/MANIFEST.txt contains duplicate IDs")
    return manifest, ids


def load_case_index(path, manifest_ids, require_categories=False):
    case_index_bytes = path.read_bytes()
    case_index = json.loads(case_index_bytes)
    if not isinstance(case_index, dict) or case_index.get("schema_version") != 1:
        raise ValueError("loader case index must be a schema_version 1 object")
    rows = case_index.get("cases")
    if not isinstance(rows, list):
        raise ValueError("loader case index cases must be an array")
    expected_by_id = {}
    category_by_id = {}
    for row_number, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"loader case index row {row_number} is not an object")
        case_id = row.get("case_id")
        expected = row.get("expected_verdict")
        category = row.get("category")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"loader case index row {row_number} has no case_id")
        if case_id in expected_by_id:
            raise ValueError(f"loader case index contains duplicate case ID {case_id!r}")
        if expected not in {"block", "allow"}:
            raise ValueError(
                f"loader case index row {row_number} has invalid normalized expected_verdict {expected!r}"
            )
        if require_categories and (not isinstance(category, str) or not category):
            raise ValueError(f"loader case index row {row_number} has no category")
        expected_by_id[case_id] = expected
        if isinstance(category, str) and category:
            category_by_id[case_id] = category
    if set(expected_by_id) != manifest_ids:
        raise ValueError("loader case index IDs do not match cases/MANIFEST.txt")
    return case_index_bytes, expected_by_id, category_by_id


def count_stat(make_stats, name):
    match = re.search(rf"(?m)^{re.escape(name)}: ([0-9]+)$", make_stats)
    if match is None:
        raise ValueError(f"make stats output is missing {name!r}")
    return int(match.group(1))


def has_classification(evidence):
    if not isinstance(evidence, dict):
        return False
    for key in ("kind", "scanner", "block_reason"):
        if evidence.get(key) is not None:
            return True
    return isinstance(evidence.get("error_message"), str) and bool(evidence["error_message"])


def has_structured_evidence(evidence):
    if not isinstance(evidence, dict):
        return False
    return any(
        key in evidence and evidence[key] is not None
        for key in ("kind", "scanner", "block_reason", "error_message", "decision", "findings")
    )


def expected_fraction(numerator, denominator):
    return numerator / denominator if denominator else None


def require_exact_keys(value, label, expected):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        raise ValueError(f"{label} is missing fields: {missing!r}")
    if unexpected:
        raise ValueError(f"{label} has unexpected fields: {unexpected!r}")
    return value


def require_rate_or_null(value, label):
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError(f"{label} must be a finite rate or null")
    return value


def validate_v5_summary_metric_contract(summary):
    """Reject fields a v5 bundle must neither retain nor promote."""
    scores = require_exact_keys(summary.get("scores"), "runner summary scores", V5_SCOPES)
    diagnostics = require_exact_keys(
        summary.get("diagnostics"), "runner summary diagnostics", V5_SCOPES
    )
    for scope in V5_SCOPES:
        scope_scores = require_exact_keys(
            scores[scope], f"runner summary scores.{scope}", V5_OUTCOME_SCORE_FIELDS
        )
        scope_diagnostics = require_exact_keys(
            diagnostics[scope], f"runner summary diagnostics.{scope}", V5_DIAGNOSTIC_FIELDS
        )
        for metric, value in scope_scores.items():
            require_rate_or_null(value, f"runner summary scores.{scope}.{metric}")
        for diagnostic, value in scope_diagnostics.items():
            require_rate_or_null(value, f"runner summary diagnostics.{scope}.{diagnostic}")
    per_category = summary.get("per_category")
    if not isinstance(per_category, dict):
        raise ValueError("runner summary per_category must be an object")
    category_fields = frozenset({"applicable", "containment", "false_positive_rate", "diagnostics"})
    for category, category_summary in per_category.items():
        if not isinstance(category, str) or not category:
            raise ValueError("runner summary per_category has an invalid category")
        values = require_exact_keys(
            category_summary, f"runner summary per_category.{category}", category_fields
        )
        if isinstance(values["applicable"], bool) or not isinstance(values["applicable"], int) or values["applicable"] < 0:
            raise ValueError(f"runner summary per_category.{category}.applicable must be a non-negative integer")
        require_rate_or_null(values["containment"], f"runner summary per_category.{category}.containment")
        require_rate_or_null(values["false_positive_rate"], f"runner summary per_category.{category}.false_positive_rate")
        category_diagnostics = require_exact_keys(
            values["diagnostics"], f"runner summary per_category.{category}.diagnostics", V5_DIAGNOSTIC_FIELDS
        )
        for diagnostic, value in category_diagnostics.items():
            require_rate_or_null(value, f"runner summary per_category.{category}.diagnostics.{diagnostic}")


def verify_score(summary, scope, metric, numerator, denominator):
    try:
        actual = summary["scores"][scope][metric]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"runner summary is missing scores.{scope}.{metric}") from exc
    expected = expected_fraction(numerator, denominator)
    if actual != expected:
        raise ValueError(
            f"runner summary scores.{scope}.{metric} does not match bound metric counts: "
            f"{actual!r} != {expected!r}"
        )


def verify_diagnostic(summary, scope, diagnostic, numerator, denominator):
    try:
        actual = summary["diagnostics"][scope][diagnostic]
    except (KeyError, TypeError) as exc:
        raise ValueError(f"runner summary is missing diagnostics.{scope}.{diagnostic}") from exc
    expected = expected_fraction(numerator, denominator)
    if actual != expected:
        raise ValueError(
            f"runner summary diagnostics.{scope}.{diagnostic} does not match bound diagnostic counts: "
            f"{actual!r} != {expected!r}"
        )


def measurements(repo_root, run_dir):
    summary = load_object(run_dir / RAW_EVIDENCE["raw_summary"])
    # Active summaries always serialize the explicit unreachable counter.
    # The retained v2.4 summary predates that field and carries no
    # schema_version, so it keeps its original byte shape. Any scoring version
    # that is not a retained frozen one is active output and cannot borrow that
    # frozen representation by omitting its schema marker.
    #
    # This is deliberately expressed as "not frozen" rather than as a list of
    # active versions. Keying on a single active literal meant the next scoring
    # bump silently reopened the hole it was written to close, because a summary
    # carrying the new version matched neither branch.
    summary_schema_version = summary.get("schema_version")
    if summary_schema_version in ACTIVE_SUMMARY_SCHEMA_VERSIONS:
        active_case_count = summary.get("case_count")
        if not isinstance(active_case_count, dict) or "unreachable" not in active_case_count:
            raise ValueError("active runner summary missing case_count.unreachable")
        active_unreachable = active_case_count["unreachable"]
        if (
            isinstance(active_unreachable, bool)
            or not isinstance(active_unreachable, int)
            or active_unreachable < 0
        ):
            raise ValueError("active runner summary case_count.unreachable must be a non-negative integer")
    elif summary_schema_version is not None:
        raise ValueError("runner summary schema_version must be frozen v2 or active v4/v5")
    elif summary.get("scoring_version") not in FROZEN_SCORING_VERSIONS:
        # Both guards are load-bearing and neither replaces the other. The
        # first rejects a summary carrying an unrecognised schema_version. This
        # one rejects a summary carrying no schema_version at all while
        # claiming a scoring version that is not a retained frozen one, which
        # is how an active run would otherwise borrow the frozen byte shape.
        #
        # It asks whether a version is FROZEN rather than naming an active one.
        # The literal it replaced named a single active version, so the next
        # scoring bump silently reopened the hole this closes: a summary
        # carrying the new version matched neither branch.
        raise ValueError("active runner summary missing schema_version")
    if summary_schema_version == ACTIVE_SUMMARY_SCHEMA_VERSION:
        validate_v5_summary_metric_contract(summary)
    for key in (
        "gauntlet_version",
        "scoring_version",
        "runner_version",
        "tool",
        "corpus_version",
    ):
        require_non_empty_string(summary, key, f"runner summary {key}")
    for key in ("corpus_sha256", "tool_profile_sha256"):
        require_sha256(summary, key)
    # v5 is the active summary contract that introduced the framed corpus
    # identity. Frozen v4 records must remain readable without a field that did
    # not exist when they were emitted.
    if summary_schema_version == ACTIVE_SUMMARY_SCHEMA_VERSION:
        require_sha256(summary, "benchmark_manifest_sha256")
    command = (run_dir / RAW_EVIDENCE["command"]).read_text(encoding="utf-8").strip()
    make_stats = (run_dir / RAW_EVIDENCE["stats"]).read_text(encoding="utf-8")
    stderr = (run_dir / RAW_EVIDENCE["runner_stderr"]).read_text(encoding="utf-8")
    results = read_results(run_dir / RAW_EVIDENCE["results"])
    result_contract = None
    if summary_schema_version in ACTIVE_SUMMARY_SCHEMA_VERSIONS:
        result_contract = result_reader_contract(repo_root)
    # An active artifact is uninterpretable without the exact raw registry
    # snapshot it names. Frozen v2 evidence has no such bytes and remains on the
    # historical reader path above.
    registry = None
    if summary_schema_version in ACTIVE_SUMMARY_SCHEMA_VERSIONS:
        registry = validate_v4_registry_binding(run_dir, summary, results)
    manifest, manifest_ids = load_manifest(repo_root, run_dir)
    case_index_bytes, expected_by_id, category_by_id = load_case_index(
        run_dir / RAW_EVIDENCE["case_index"],
        manifest_ids,
        require_categories=summary_schema_version == 5,
    )
    budget_timing_case_ids = load_budget_timing_case_ids(repo_root)

    try:
        command_argv = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"recorded runner command is not valid shell syntax: {exc}") from exc
    if "--fixtures" not in command_argv:
        raise ValueError("recorded runner command does not include --fixtures")
    if not re.search(r"(?m)^Fixtures: HTTP=.* TLS=.* WS=.* DNS=.* MCP_HTTP=", stderr):
        raise ValueError("runner stderr does not prove fixture startup")

    result_ids = []
    for row_number, row in enumerate(results, 1):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"runner JSONL row {row_number} has no case_id")
        result_ids.append(case_id)
    duplicate_ids = sorted(case_id for case_id, count in Counter(result_ids).items() if count > 1)
    if duplicate_ids:
        raise ValueError(f"runner JSONL contains duplicate case IDs: {duplicate_ids!r}")
    result_id_set = set(result_ids)
    if result_id_set != manifest_ids:
        missing = sorted(manifest_ids - result_id_set)
        unknown = sorted(result_id_set - manifest_ids)
        raise ValueError(
            "runner JSONL case IDs do not match cases/MANIFEST.txt: "
            f"missing={missing!r} unknown={unknown!r}"
        )
    for row_number, row in enumerate(results, 1):
        expected = expected_by_id[row["case_id"]]
        if row.get("expected_verdict") != expected:
            raise ValueError(
                f"runner JSONL row {row_number} expected_verdict for {row['case_id']!r} "
                f"does not match loader case index: {row.get('expected_verdict')!r} != {expected!r}"
            )
        actual = row.get("actual_verdict")
        score = row.get("score")
        evidence = row.get("evidence")
        if actual not in {"block", "allow", "not_applicable", "unreachable", "error"}:
            raise ValueError(f"runner JSONL row {row_number} has invalid actual_verdict {actual!r}")
        if score not in {"pass", "fail", "not_applicable", "error"}:
            raise ValueError(f"runner JSONL row {row_number} has invalid score {score!r}")
        if not isinstance(evidence, dict):
            raise ValueError(f"runner JSONL row {row_number} evidence must be an object")
        if result_contract is not None:
            validate_result_row_contract(row, row_number, *result_contract)
        if not isinstance(row.get("notes"), str):
            raise ValueError(f"runner JSONL row {row_number} notes must be a string")
        if row.get("tool") != summary.get("tool") or row.get("tool_version") != summary.get(
            "tool_version"
        ):
            raise ValueError(f"runner JSONL row {row_number} tool identity does not match summary")
        try:
            expected_score = active_result_score(
                expected,
                actual,
                evidence,
                row["case_id"] in budget_timing_case_ids,
            )
        except ValueError as exc:
            raise ValueError(f"runner JSONL row {row_number}: {exc}") from exc
        if score != expected_score:
            raise ValueError(
                f"runner JSONL row {row_number} score {score!r} does not match its verdicts"
            )

    # An unreachable route has no measurement. It is deliberately neither a
    # historical N/A nor a scoreable adapter error: retain it as explicit
    # coverage evidence, but leave it out of score denominators.
    unreachable_results = [row for row in results if row.get("actual_verdict") == "unreachable"]
    applicable_results = [
        row
        for row in results
        if row.get("actual_verdict") not in {"not_applicable", "unreachable"}
    ]
    applicable_malicious = [
        row for row in applicable_results if row.get("expected_verdict") == "block"
    ]
    applicable_benign = [
        row for row in applicable_results if row.get("expected_verdict") == "allow"
    ]
    blocked_malicious = [
        row for row in applicable_malicious if row.get("actual_verdict") == "block"
    ]
    correctly_blocked_malicious = [row for row in blocked_malicious if row.get("score") == "pass"]
    blocked_benign = [
        row for row in applicable_benign if row.get("actual_verdict") == "block"
    ]
    classified = sum(has_classification(row.get("evidence")) for row in correctly_blocked_malicious)
    evidence_emitted = sum(
        has_structured_evidence(row.get("evidence")) for row in correctly_blocked_malicious
    )
    full_malicious = sum(
        row.get("expected_verdict") == "block"
        for row in results
        if row.get("actual_verdict") != "unreachable"
    )
    full_benign = sum(
        row.get("expected_verdict") in {"allow", "warn"}
        for row in results
        if row.get("actual_verdict") != "unreachable"
    )
    outcome_metric_counts = {
        "applicable": {
            "containment": {
                "numerator": len(blocked_malicious),
                "denominator": len(applicable_malicious),
            },
            "false_positive_rate": {
                "numerator": len(blocked_benign),
                "denominator": len(applicable_benign),
            },
        },
        "full": {
            "containment": {
                "numerator": len(blocked_malicious),
                "denominator": full_malicious,
            },
            "false_positive_rate": {
                "numerator": len(blocked_benign),
                "denominator": full_benign,
            },
        },
    }
    diagnostic_counts = {
        scope: {
            "classification_present_rate": {
                "numerator": classified,
                "denominator": len(correctly_blocked_malicious),
            },
            "structured_evidence_present_rate": {
                "numerator": evidence_emitted,
                "denominator": len(correctly_blocked_malicious),
            },
        }
        for scope in ("applicable", "full")
    }
    if summary_schema_version != 5:
        # Frozen and active-v4 records keep the former score names and definition.
        metric_counts = {
            scope: {
                **outcome_metric_counts[scope],
                "detection": diagnostic_counts[scope]["classification_present_rate"],
                "evidence": diagnostic_counts[scope]["structured_evidence_present_rate"],
            }
            for scope in ("applicable", "full")
        }
    else:
        metric_counts = outcome_metric_counts

    logical_case_count = len(manifest_ids)
    case_count = summary.get("case_count")
    if not isinstance(case_count, dict):
        raise ValueError("runner summary case_count must be an object")
    if case_count.get("total") != logical_case_count:
        raise ValueError(
            "runner summary total does not match the pinned manifest: "
            f"{case_count.get('total')!r} != {logical_case_count}"
        )
    if len(results) != logical_case_count:
        raise ValueError(
            "runner JSONL row count does not match the logical corpus: "
            f"{len(results)} != {logical_case_count}"
        )
    if count_stat(make_stats, "block") + count_stat(make_stats, "allow") + count_stat(make_stats, "warn") != logical_case_count:
        raise ValueError("make stats verdict counts do not match the logical corpus")
    if case_count.get("applicable") != len(applicable_results):
        raise ValueError("runner summary applicable count does not match runner JSONL")
    unreachable_count = len(unreachable_results)
    if case_count.get("unreachable", 0) != unreachable_count:
        raise ValueError("runner summary unreachable count does not match runner JSONL")
    not_applicable_count = logical_case_count - len(applicable_results) - unreachable_count
    if case_count.get("not_applicable") != not_applicable_count:
        raise ValueError("runner summary not_applicable count does not match runner JSONL")
    not_applicable_reasons = case_count.get("not_applicable_reasons")
    if not isinstance(not_applicable_reasons, dict) or any(
        not isinstance(reason, str)
        or not reason
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for reason, count in not_applicable_reasons.items()
    ):
        raise ValueError("runner summary not_applicable_reasons is invalid")
    if sum(not_applicable_reasons.values()) != not_applicable_count:
        raise ValueError("runner summary not_applicable reasons do not sum to the N/A count")
    jsonl_errors = sum(row.get("actual_verdict") == "error" for row in applicable_results)
    if case_count.get("errors") != jsonl_errors:
        raise ValueError("runner summary error count does not match runner JSONL")
    if jsonl_errors != 0:
        raise ValueError(f"runner produced {jsonl_errors} error result(s)")
    # A synthetic row is asserted rather than observed, so a run carrying one
    # anywhere is not a measurement and cannot publish. This is deliberately a
    # standalone rejection over EVERY row rather than an input to the
    # measurement_status comparison below: the Go runner builds that status from
    # the applicable rows it is given and never sees a not_applicable row, so
    # folding a broader scan into the comparison would make the two sides
    # disagree on a run neither considers publishable.
    synthetic_rows = sum(claims_synthetic(row) for row in results)
    if synthetic_rows != 0:
        raise ValueError(f"runner produced {synthetic_rows} synthetic result(s)")
    if full_malicious + full_benign + unreachable_count != logical_case_count:
        raise ValueError("runner JSONL scoreable and unreachable rows do not match the logical corpus")
    for scope, metrics in metric_counts.items():
        for metric, counts in metrics.items():
            verify_score(summary, scope, metric, counts["numerator"], counts["denominator"])
    if summary_schema_version == 5:
        for scope, diagnostics in diagnostic_counts.items():
            for diagnostic, counts in diagnostics.items():
                verify_diagnostic(
                    summary, scope, diagnostic, counts["numerator"], counts["denominator"]
                )
        rows_by_category = {}
        for row in applicable_results:
            rows_by_category.setdefault(category_by_id[row["case_id"]], []).append(row)
        if set(summary["per_category"]) != set(rows_by_category):
            raise ValueError("runner summary per_category keys do not match bound result categories")
        for category, category_rows in rows_by_category.items():
            category_summary = summary["per_category"][category]
            malicious = [row for row in category_rows if row["expected_verdict"] == "block"]
            benign = [row for row in category_rows if row["expected_verdict"] == "allow"]
            blocked = [row for row in malicious if row["actual_verdict"] == "block"]
            correct_blocks = [row for row in blocked if row["score"] == "pass"]
            expected_category = {
                "applicable": len(category_rows),
                "containment": expected_fraction(len(blocked), len(malicious)),
                "false_positive_rate": expected_fraction(
                    sum(row["actual_verdict"] == "block" for row in benign), len(benign)
                ),
                "diagnostics": {
                    "classification_present_rate": expected_fraction(
                        sum(has_classification(row["evidence"]) for row in correct_blocks), len(correct_blocks)
                    ),
                    "structured_evidence_present_rate": expected_fraction(
                        sum(has_structured_evidence(row["evidence"]) for row in correct_blocks), len(correct_blocks)
                    ),
                },
            }
            if category_summary != expected_category:
                raise ValueError(f"runner summary per_category.{category} does not match bound result rows")
    if summary_schema_version in ACTIVE_SUMMARY_SCHEMA_VERSIONS:
        # Scoped to the applicable rows so this mirrors exactly what the Go
        # runner can observe when it derives the same field. Synthetic rows
        # outside that scope are rejected outright above.
        has_synthetic = any(claims_synthetic(row) for row in applicable_results)
        expected_measurement_status = (
            "measured"
            if unreachable_count == 0 and jsonl_errors == 0 and not has_synthetic
            else "incomplete"
        )
        if summary.get("measurement_status") != expected_measurement_status:
            raise ValueError(
                "runner summary measurement_status does not match observed result coverage"
            )
    else:
        # Frozen v2.4 evidence retains the historical field and containment
        # threshold. This compatibility branch cannot be used by active output.
        full_containment = expected_fraction(
            metric_counts["full"]["containment"]["numerator"],
            metric_counts["full"]["containment"]["denominator"],
        )
        expected_sufficient = unreachable_count == 0 and (
            full_containment is None or full_containment >= 0.80
        )
        if summary.get("sufficient") is not expected_sufficient:
            raise ValueError(
                "frozen runner summary sufficient flag does not match its historical containment gate"
            )

    return {
        "summary": summary,
        "command": command,
        "make_stats": make_stats,
        "metric_counts": metric_counts,
        "diagnostic_counts": diagnostic_counts if summary_schema_version == 5 else None,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "case_index_sha256": hashlib.sha256(case_index_bytes).hexdigest(),
        "logical_case_count": logical_case_count,
        "capability_registry": registry,
    }


def validate_metadata(metadata):
    if metadata.get("schema_version") != 1:
        raise ValueError("run metadata schema_version must be 1")
    for key in (
        "local_run_id",
        "generated_at",
        "corpus_repository",
        "corpus_ref_kind",
        "corpus_git_sha",
    ):
        require_non_empty_string(metadata, key, f"run metadata {key}")
    if not isinstance(metadata.get("dirty"), bool):
        raise ValueError("run metadata dirty must be boolean")
    if not isinstance(metadata.get("canonical_execution"), bool):
        raise ValueError("run metadata canonical_execution must be boolean")
    reasons = metadata.get("noncanonical_reasons")
    if not isinstance(reasons, list) or any(not isinstance(item, str) or not item for item in reasons):
        raise ValueError("run metadata noncanonical_reasons must be an array of strings")
    if metadata["canonical_execution"] and (metadata["dirty"] or reasons):
        raise ValueError("canonical execution cannot be dirty or have noncanonical reasons")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["corpus_git_sha"]):
        raise ValueError("run metadata corpus_git_sha must be 40 lower-case hex characters")
    if metadata["corpus_ref_kind"] not in {"origin/main", "tag", "development"}:
        raise ValueError("run metadata corpus_ref_kind is invalid")
    if metadata["canonical_execution"]:
        if metadata["corpus_ref_kind"] not in {"origin/main", "tag"}:
            raise ValueError("canonical execution requires origin/main or a tag")
        if metadata["corpus_repository"] != "luckyPipewrench/agent-egress-bench":
            raise ValueError("canonical execution names an unexpected corpus repository")


def validate_release(release, metadata, run_dir):
    if release.get("schema_version") != 1:
        raise ValueError("Pipelock release metadata schema_version must be 1")
    for key in ("repository", "tag", "version", "asset", "binary_sha256", "version_output"):
        require_non_empty_string(release, key, f"Pipelock release {key}")
    require_sha256(release, "binary_sha256")
    require_sha256(release, "asset_sha256", allow_null=not release.get("released_binary", False))
    if not isinstance(release.get("released_binary"), bool):
        raise ValueError("Pipelock release released_binary must be boolean")
    if metadata["canonical_execution"] and not release["released_binary"]:
        raise ValueError("canonical execution requires a released Pipelock binary")
    if metadata["canonical_execution"] and release["repository"] != "luckyPipewrench/pipelock":
        raise ValueError("canonical execution names an unexpected Pipelock repository")
    if release["tag"] != "v" + release["version"]:
        raise ValueError("Pipelock release tag and version do not match")
    expected_version_line = f"pipelock version {release['version']}"
    if expected_version_line not in release["version_output"].splitlines():
        raise ValueError("Pipelock release version_output does not report the pinned version")
    retained_version = (run_dir / RAW_EVIDENCE["pipelock_version_output"]).read_text(
        encoding="utf-8"
    ).strip()
    if retained_version != release["version_output"].strip():
        raise ValueError("retained Pipelock version output does not match release metadata")
    if release["released_binary"]:
        expected_asset = re.escape(f"pipelock_{release['version']}_linux_")
        if not re.fullmatch(expected_asset + r"(?:amd64|arm64)\.tar\.gz", release["asset"]):
            raise ValueError("Pipelock release asset name does not match the pinned Linux version")
        matches = []
        checksums = (run_dir / RAW_EVIDENCE["release_checksums"]).read_text(encoding="utf-8")
        for line in checksums.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].lstrip("*") == release["asset"]:
                matches.append(fields[0])
        if matches != [release["asset_sha256"]]:
            raise ValueError("release checksums do not bind the recorded Pipelock asset digest")


def build_complete_bundle(repo_root, run_dir):
    metadata = load_object(run_dir / RAW_EVIDENCE["run_metadata"])
    release = load_object(run_dir / RAW_EVIDENCE["pipelock_release"])
    validate_metadata(metadata)
    validate_release(release, metadata, run_dir)
    if not (run_dir / RAW_EVIDENCE["entrypoint_command"]).read_text(encoding="utf-8").strip():
        raise ValueError("entrypoint command evidence is empty")
    measured = measurements(repo_root, run_dir)
    summary = measured["summary"]
    if summary.get("tool_version") != release["version"]:
        raise ValueError(
            "runner summary tool_version does not match the executed Pipelock release: "
            f"{summary.get('tool_version')!r} != {release['version']!r}"
        )
    evidence_spec = raw_evidence_for_summary(summary)
    hashes = evidence_hashes(run_dir, require_all=True, evidence_spec=evidence_spec)
    candidate_case_count = {
        "total": summary["case_count"]["total"],
        "applicable": summary["case_count"]["applicable"],
        "not_applicable": summary["case_count"]["not_applicable"],
        "not_applicable_reasons": summary["case_count"]["not_applicable_reasons"],
        "errors": summary["case_count"]["errors"],
    }
    # Frozen evidence predates the explicit unreachable state. Preserve its
    # serialized shape exactly: readers default a missing field to zero, while
    # new runner summaries carry the field and retain it in their provenance.
    if "unreachable" in summary["case_count"]:
        candidate_case_count["unreachable"] = summary["case_count"]["unreachable"]

    candidate_scope = {
        "schema_version": (
            summary.get("schema_version")
            if summary.get("schema_version") in ACTIVE_SUMMARY_SCHEMA_VERSIONS
            else 2
        ),
        "local_run_id": metadata["local_run_id"],
        "generated_at": metadata["generated_at"],
        "corpus_ref_kind": metadata["corpus_ref_kind"],
        "corpus_git_sha": metadata["corpus_git_sha"],
        "corpus_commit_url": (
            f"https://github.com/{metadata['corpus_repository']}/commit/{metadata['corpus_git_sha']}"
        ),
        "dirty": metadata["dirty"],
        "pipelock_tag": release["tag"],
        "pipelock_version": release["version"],
        "pipelock_asset": release["asset"],
        "pipelock_asset_sha256": release.get("asset_sha256"),
        "pipelock_binary_sha256": release["binary_sha256"],
        "pipelock_release_url": f"https://github.com/{release['repository']}/releases/tag/{release['tag']}",
        "gauntlet_version": summary["gauntlet_version"],
        "scoring_version": summary["scoring_version"],
        "runner_version": summary["runner_version"],
        "tool": summary["tool"],
        "tool_version": summary["tool_version"],
        "corpus_version": summary["corpus_version"],
        "corpus_sha256": summary["corpus_sha256"],
        "corpus_manifest_sha256": measured["manifest_sha256"],
        "case_index_sha256": measured["case_index_sha256"],
        "logical_case_count": measured["logical_case_count"],
        "tool_profile_sha256": summary["tool_profile_sha256"],
        "case_count": candidate_case_count,
        "scores": summary["scores"],
        "metric_counts": measured["metric_counts"],
        "fixtures": True,
        "multifile_cases": True,
        "command": measured["command"],
        "make_stats": measured["make_stats"],
        "evidence_sha256": hashes,
    }
    if summary.get("schema_version") == 4:
        candidate_scope["measurement_status"] = summary["measurement_status"]
    elif summary.get("schema_version") == 5:
        candidate_scope["measurement_status"] = summary["measurement_status"]
        candidate_scope["benchmark_manifest_sha256"] = summary["benchmark_manifest_sha256"]
        candidate_scope["diagnostics"] = summary["diagnostics"]
        candidate_scope["diagnostic_counts"] = measured["diagnostic_counts"]
    else:
        candidate_scope["sufficient"] = summary["sufficient"]
    if measured["capability_registry"] is not None:
        candidate_scope["capability_registry"] = measured["capability_registry"]
        candidate_scope["reported_claims"] = summary["reported_claims"]
        candidate_scope["exercised"] = summary["exercised"]
    return {
        "schema_version": 1,
        "bundle_status": "complete",
        "local_run_id": metadata["local_run_id"],
        "publication_eligible": metadata["canonical_execution"] and release["released_binary"],
        "noncanonical_reasons": metadata["noncanonical_reasons"],
        "evidence_sha256": hashes,
        "candidate_scope": candidate_scope,
    }


def build_partial_bundle(run_dir, failure):
    metadata_path = run_dir / RAW_EVIDENCE["run_metadata"]
    metadata = load_object(metadata_path) if metadata_path.is_file() else {}
    return {
        "schema_version": 1,
        "bundle_status": "partial",
        "local_run_id": metadata.get("local_run_id"),
        "publication_eligible": False,
        "noncanonical_reasons": metadata.get("noncanonical_reasons", []),
        "evidence_sha256": evidence_hashes(run_dir, require_all=False),
        "failure": failure,
    }


def bundle_command(args):
    run_dir = args.run_dir.resolve()
    output_path = run_dir / "run-bundle.json"
    decision_path = run_dir / "execution-decision.json"
    if args.failure:
        bundle = build_partial_bundle(run_dir, args.failure)
        decision = {
            "schema_version": 1,
            "local_run_id": bundle.get("local_run_id"),
            "blocked": True,
            "execution_status": "blocked",
            "publication_eligible": False,
            "failures": [args.failure],
            "evidence_sha256": bundle["evidence_sha256"],
        }
    else:
        bundle = build_complete_bundle(args.repo_root.resolve(), run_dir)
        decision = {
            "schema_version": 1,
            "local_run_id": bundle["local_run_id"],
            "blocked": False,
            "execution_status": "complete",
            "publication_eligible": bundle["publication_eligible"],
            "failures": [],
            "review_notes": bundle["noncanonical_reasons"],
            "evidence_sha256": bundle["evidence_sha256"],
        }
    atomic_json_write(output_path, bundle)
    atomic_json_write(decision_path, decision)


def finalize_command(args):
    bundle_path = args.bundle.resolve()
    run_dir = bundle_path.parent
    output_path = args.output.resolve()
    bundle = load_object(bundle_path)
    if bundle.get("schema_version") != 1 or bundle.get("bundle_status") != "complete":
        raise ValueError("portable run bundle is not complete")
    if bundle.get("publication_eligible") is not True:
        raise ValueError("portable run bundle is noncanonical and cannot be finalized")
    recorded_hashes = bundle.get("evidence_sha256")
    evidence_spec = {**RAW_EVIDENCE, **V4_RAW_EVIDENCE} if isinstance(recorded_hashes, dict) and set(V4_RAW_EVIDENCE).issubset(recorded_hashes) else RAW_EVIDENCE
    protected_paths = {
        (run_dir / relative_path).resolve() for relative_path in evidence_spec.values()
    }
    protected_paths.update(
        {
            bundle_path,
            (run_dir / "execution-decision.json").resolve(),
            (run_dir / "promotion-decision.json").resolve(),
        }
    )
    if output_path in protected_paths:
        raise ValueError("candidate output cannot overwrite retained evidence or a decision")
    if output_path.exists():
        raise ValueError("candidate output must not already exist")
    if not isinstance(recorded_hashes, dict) or set(recorded_hashes) != set(evidence_spec):
        raise ValueError("portable run bundle evidence set is incomplete")
    current_hashes = evidence_hashes(run_dir, require_all=True, evidence_spec=evidence_spec)
    for label in sorted(evidence_spec):
        if recorded_hashes.get(label) != current_hashes[label]:
            raise ValueError(f"evidence {label} changed after the portable bundle was created")
    recomputed_bundle = build_complete_bundle(args.repo_root.resolve(), run_dir)
    if bundle != recomputed_bundle:
        raise ValueError("portable run bundle does not match a fresh reconstruction from evidence")

    artifact_id = args.artifact_id.strip()
    if not artifact_id:
        raise ValueError("artifact_id must be non-empty")
    canonical_url = args.canonical_url.strip()
    parsed = urlparse(canonical_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("canonical_url must be an absolute https URL")
    candidate_scope = bundle.get("candidate_scope")
    if not isinstance(candidate_scope, dict):
        raise ValueError("portable run bundle candidate_scope must be an object")
    candidate = dict(candidate_scope)
    candidate.update(
        {
            "artifact_id": artifact_id,
            "canonical_url": canonical_url,
            "portable_bundle_sha256": file_sha256(bundle_path),
        }
    )
    atomic_json_write(output_path, candidate)


def start_command(args):
    metadata = {
        "schema_version": 1,
        "local_run_id": args.local_run_id,
        "generated_at": args.generated_at,
        "corpus_repository": args.corpus_repository,
        "corpus_ref_kind": args.corpus_ref_kind,
        "corpus_git_sha": args.corpus_git_sha,
        "dirty": args.dirty,
        "canonical_execution": args.canonical_execution,
        "noncanonical_reasons": args.noncanonical_reason,
    }
    validate_metadata(metadata)
    atomic_json_write(args.output, metadata)


def release_command(args):
    release = {
        "schema_version": 1,
        "repository": args.repository,
        "tag": args.tag,
        "version": args.version,
        "asset": args.asset,
        "asset_sha256": args.asset_sha256,
        "binary_sha256": args.binary_sha256,
        "version_output": args.version_output,
        "released_binary": args.released_binary,
    }
    atomic_json_write(args.output, release)


def bool_value(value):
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    raise argparse.ArgumentTypeError("want true or false")


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    start = subparsers.add_parser("start")
    start.add_argument("--output", type=Path, required=True)
    start.add_argument("--local-run-id", required=True)
    start.add_argument("--generated-at", required=True)
    start.add_argument("--corpus-repository", required=True)
    start.add_argument("--corpus-ref-kind", required=True)
    start.add_argument("--corpus-git-sha", required=True)
    start.add_argument("--dirty", type=bool_value, required=True)
    start.add_argument("--canonical-execution", type=bool_value, required=True)
    start.add_argument("--noncanonical-reason", action="append", default=[])

    release = subparsers.add_parser("release")
    release.add_argument("--output", type=Path, required=True)
    release.add_argument("--repository", required=True)
    release.add_argument("--tag", required=True)
    release.add_argument("--version", required=True)
    release.add_argument("--asset", required=True)
    release.add_argument("--asset-sha256")
    release.add_argument("--binary-sha256", required=True)
    release.add_argument("--version-output", required=True)
    release.add_argument("--released-binary", type=bool_value, required=True)

    bundle = subparsers.add_parser("bundle")
    bundle.add_argument("--repo-root", type=Path, required=True)
    bundle.add_argument("--run-dir", type=Path, required=True)
    bundle.add_argument("--failure")

    finalize = subparsers.add_parser("finalize")
    finalize.add_argument(
        "--repo-root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    finalize.add_argument("--bundle", type=Path, required=True)
    finalize.add_argument("--artifact-id", required=True)
    finalize.add_argument("--canonical-url", required=True)
    finalize.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.command == "start":
            start_command(args)
        elif args.command == "release":
            release_command(args)
        elif args.command == "bundle":
            bundle_command(args)
        else:
            finalize_command(args)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"provenance: BLOCKED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
