#!/usr/bin/env python3
"""Evaluate a continuous-gauntlet candidate without publishing it."""

import argparse
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path


LEGACY_REQUIRED_FLOORS = {
    "full": {"containment"},
    "applicable": {"containment", "detection", "evidence"},
}
ACTIVE_V5_REQUIRED_FLOORS = {
    "full": {"containment"},
    "applicable": {"containment"},
}
LEGACY_REQUIRED_CEILINGS = {"applicable": {"false_positive_rate"}}
ACTIVE_V5_REQUIRED_CEILINGS = {"applicable": {"false_positive_rate"}}
REQUIRED_COUNT_KEYS = ("total", "applicable", "not_applicable", "not_applicable_reasons")
REQUIRED_IDENTITIES = (
    "corpus_git_sha",
    "corpus_sha256",
    "corpus_version",
    "scoring_version",
    "runner_version",
)
SCOPE_IDENTITIES = {"corpus_sha256", "corpus_version", "scoring_version", "runner_version"}
SHA256_HEX = set("0123456789abcdef")
V5_SCOPES = frozenset({"full", "applicable"})
V5_OUTCOME_SCORE_FIELDS = frozenset({"containment", "false_positive_rate"})
V5_DIAGNOSTIC_FIELDS = frozenset(
    {"classification_present_rate", "structured_evidence_present_rate"}
)


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


def finite_number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    return float(value)


def fraction(value, label):
    number = finite_number(value, label)
    if not 0 <= number <= 1:
        raise ValueError(f"{label} must be between 0 and 1")
    return number


def rate_or_null(value, label):
    if value is None:
        return None
    return fraction(value, label)


def nested_value(document, path):
    current = document
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError("missing field: " + ".".join(path))
        current = current[key]
    return current


def require_capability_registry(candidate):
    reference = candidate.get("capability_registry")
    if not isinstance(reference, dict) or set(reference) != {"id", "format", "revision", "sha256"}:
        raise ValueError("candidate capability_registry must be an exact reference")
    if not isinstance(reference["id"], str) or not reference["id"]:
        raise ValueError("candidate capability_registry.id must be non-empty")
    if any(isinstance(reference[key], bool) or not isinstance(reference[key], int) or reference[key] < 1 for key in ("format", "revision")):
        raise ValueError("candidate capability_registry format and revision must be positive integers")
    if not isinstance(reference["sha256"], str) or len(reference["sha256"]) != 64 or any(character not in SHA256_HEX for character in reference["sha256"]):
        raise ValueError("candidate capability_registry.sha256 must be lower-case SHA-256")
    return reference


def metric_contract_for(schema_version):
    if schema_version == 5:
        return ACTIVE_V5_REQUIRED_FLOORS, ACTIVE_V5_REQUIRED_CEILINGS
    return LEGACY_REQUIRED_FLOORS, LEGACY_REQUIRED_CEILINGS


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


def validate_v5_candidate_metric_contract(candidate):
    """Require the same v5 score surface used when a bundle was built."""
    scores = require_exact_keys(candidate.get("scores"), "candidate scores", V5_SCOPES)
    diagnostics = require_exact_keys(
        candidate.get("diagnostics"), "candidate diagnostics", V5_SCOPES
    )
    for scope in V5_SCOPES:
        scope_scores = require_exact_keys(
            scores[scope], f"candidate scores.{scope}", V5_OUTCOME_SCORE_FIELDS
        )
        scope_diagnostics = require_exact_keys(
            diagnostics[scope], f"candidate diagnostics.{scope}", V5_DIAGNOSTIC_FIELDS
        )
        for metric, value in scope_scores.items():
            rate_or_null(value, f"candidate scores.{scope}.{metric}")
        for diagnostic, value in scope_diagnostics.items():
            rate_or_null(value, f"candidate diagnostics.{scope}.{diagnostic}")


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


def evaluate(candidate_path, baseline_path, evidence_paths=None):
    evidence_paths = evidence_paths or {}
    decision = {
        "schema_version": 1,
        "candidate_sha256": None,
        "baseline_sha256": None,
        "evidence_sha256": {},
        "blocked": True,
        "promotion_status": "under_review",
        "failures": [],
        "review_notes": [],
    }

    for label, path in sorted(evidence_paths.items()):
        try:
            decision["evidence_sha256"][label] = file_sha256(path)
        except OSError as exc:
            decision["evidence_sha256"][label] = None
            decision["failures"].append(f"cannot hash evidence {label}: {exc}")

    try:
        decision["candidate_sha256"] = file_sha256(candidate_path)
        decision["baseline_sha256"] = file_sha256(baseline_path)
        candidate = load_object(candidate_path)
        baseline = load_object(baseline_path)

        candidate_schema_version = candidate.get("schema_version")
        if candidate_schema_version not in {2, 4, 5}:
            raise ValueError("candidate schema_version must be 2, 4, or 5")
        if candidate_schema_version in {4, 5}:
            require_capability_registry(candidate)
        if candidate_schema_version == 5:
            validate_v5_candidate_metric_contract(candidate)

        decision["artifact_id"] = nested_value(candidate, ("artifact_id",))
        decision["canonical_url"] = nested_value(candidate, ("canonical_url",))
        for candidate_key, evidence_label in (
            ("case_index_sha256", "case_index"),
            ("portable_bundle_sha256", "run_bundle"),
        ):
            advertised_digest = candidate.get(candidate_key)
            evidence_digest = decision["evidence_sha256"].get(evidence_label)
            if (
                not isinstance(advertised_digest, str)
                or len(advertised_digest) != 64
                or any(character not in "0123456789abcdef" for character in advertised_digest)
            ):
                decision["failures"].append(
                    f"candidate {candidate_key} must be 64 lower-case hex characters"
                )
            elif not isinstance(evidence_digest, str):
                decision["failures"].append(f"{evidence_label} evidence is required")
            elif advertised_digest != evidence_digest:
                decision["failures"].append(
                    f"candidate {candidate_key} does not match {evidence_label} evidence"
                )

        if candidate_schema_version in {4, 5}:
            if candidate.get("measurement_status") != "measured":
                decision["failures"].append(
                    "measurement_status="
                    f"{candidate.get('measurement_status')!r}, want 'measured'"
                )
        elif candidate.get("sufficient") is not True:
            decision["failures"].append(
                f"legacy sufficient={candidate.get('sufficient')!r}, want true"
            )
        # case_count must be an object before any field is read. A null or a
        # list raises inside the comparison below, and that exception escapes
        # this handler, so the evaluator exits WITHOUT writing a blocked
        # decision. A malformed candidate must be refused, not crash the gate.
        case_count = candidate.get("case_count")
        if not isinstance(case_count, dict):
            decision["failures"].append(
                f"case_count={case_count!r}, want an object"
            )
            case_count = {}
        # A boolean is rejected explicitly: Python compares False == 0, so
        # "errors": false would otherwise satisfy a want-zero check while
        # describing nothing.
        errors = case_count.get("errors")
        if isinstance(errors, bool) or not isinstance(errors, int) or errors != 0:
            decision["failures"].append(f"case_count.errors={errors!r}, want 0")
        unreachable = case_count.get("unreachable", 0)
        if isinstance(unreachable, bool) or not isinstance(unreachable, int) or unreachable != 0:
            decision["failures"].append(
                f"case_count.unreachable={unreachable!r}, want 0"
            )

        expected_version = baseline.get("pipelock_version")
        actual_version = candidate.get("pipelock_version")
        if not isinstance(expected_version, str) or not expected_version:
            raise ValueError("baseline pipelock_version must be a non-empty string")
        if actual_version != expected_version:
            decision["failures"].append(
                f"pipelock_version={actual_version!r}, baseline is {expected_version!r}"
            )

        required_floors, required_ceilings = metric_contract_for(candidate_schema_version)
        if candidate_schema_version == 5 and baseline.get("summary_schema_version") != 5:
            raise ValueError(
                "v5 candidate requires a reviewed baseline with summary_schema_version=5"
            )

        floors = baseline.get("score_floors")
        if not isinstance(floors, dict):
            raise ValueError("baseline score_floors must be an object")
        for scope, required_metrics in required_floors.items():
            metrics = floors.get(scope)
            if not isinstance(metrics, dict):
                raise ValueError(f"baseline score_floors.{scope} must be an object")
            missing = required_metrics - metrics.keys()
            if missing:
                raise ValueError(
                    f"baseline score_floors.{scope} missing required metrics: {sorted(missing)!r}"
                )
        for scope, metrics in floors.items():
            if not isinstance(metrics, dict):
                raise ValueError(f"baseline score_floors.{scope} must be an object")
            allowed = required_floors.get(scope, set())
            unexpected = set(metrics) - allowed
            if unexpected:
                raise ValueError(
                    f"baseline score_floors.{scope} has unsupported metrics for candidate schema "
                    f"v{candidate_schema_version}: {sorted(unexpected)!r}"
                )
            for metric, raw_floor in metrics.items():
                floor = fraction(raw_floor, f"baseline score_floors.{scope}.{metric}")
                actual = fraction(
                    nested_value(candidate, ("scores", scope, metric)),
                    f"candidate scores.{scope}.{metric}",
                )
                if actual < floor - 1e-12:
                    decision["failures"].append(
                        f"scores.{scope}.{metric}={actual}, below baseline floor {floor}"
                    )
                elif actual > floor + 1e-12:
                    decision["review_notes"].append(
                        f"scores.{scope}.{metric}={actual} is above baseline floor {floor}"
                    )

        ceilings = baseline.get("score_ceilings")
        if not isinstance(ceilings, dict):
            raise ValueError("baseline score_ceilings must be an object")
        for scope, required_metrics in required_ceilings.items():
            metrics = ceilings.get(scope)
            if not isinstance(metrics, dict):
                raise ValueError(f"baseline score_ceilings.{scope} must be an object")
            missing = required_metrics - metrics.keys()
            if missing:
                raise ValueError(
                    f"baseline score_ceilings.{scope} missing required metrics: {sorted(missing)!r}"
                )
        for scope, metrics in ceilings.items():
            if not isinstance(metrics, dict):
                raise ValueError(f"baseline score_ceilings.{scope} must be an object")
            allowed = required_ceilings.get(scope, set())
            unexpected = set(metrics) - allowed
            if unexpected:
                raise ValueError(
                    f"baseline score_ceilings.{scope} has unsupported metrics for candidate schema "
                    f"v{candidate_schema_version}: {sorted(unexpected)!r}"
                )
            for metric, raw_ceiling in metrics.items():
                ceiling = fraction(raw_ceiling, f"baseline score_ceilings.{scope}.{metric}")
                actual = fraction(
                    nested_value(candidate, ("scores", scope, metric)),
                    f"candidate scores.{scope}.{metric}",
                )
                if actual > ceiling + 1e-12:
                    decision["failures"].append(
                        f"scores.{scope}.{metric}={actual}, above baseline ceiling {ceiling}"
                    )
                elif actual < ceiling - 1e-12:
                    decision["review_notes"].append(
                        f"scores.{scope}.{metric}={actual} is below baseline ceiling {ceiling}"
                    )

        if baseline.get("schema_version") != 1:
            raise ValueError("baseline schema_version must be 1")
        observed = baseline.get("observed_case_count", {})
        if not isinstance(observed, dict):
            raise ValueError("baseline observed_case_count must be an object")
        missing_count_keys = [key for key in REQUIRED_COUNT_KEYS if key not in observed]
        if missing_count_keys:
            raise ValueError(
                f"baseline observed_case_count missing required keys: {missing_count_keys!r}"
            )
        observed_unreachable = observed.get("unreachable", 0)
        if isinstance(observed_unreachable, bool) or not isinstance(observed_unreachable, int) or observed_unreachable < 0:
            raise ValueError("baseline observed_case_count.unreachable must be a non-negative integer")
        for key in ("total", "applicable", "not_applicable"):
            value = observed[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"baseline observed_case_count.{key} must be a non-negative integer")
        reasons = observed["not_applicable_reasons"]
        if not isinstance(reasons, dict):
            raise ValueError("baseline observed_case_count.not_applicable_reasons must be an object")
        if any(
            not isinstance(reason, str)
            or not reason
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for reason, count in reasons.items()
        ):
            raise ValueError(
                "baseline observed_case_count.not_applicable_reasons must map non-empty strings to non-negative integers"
            )
        if observed["applicable"] + observed_unreachable + observed["not_applicable"] != observed["total"]:
            raise ValueError("baseline observed case counts must partition total")
        if sum(reasons.values()) != observed["not_applicable"]:
            raise ValueError("baseline not_applicable reasons must sum to not_applicable")

        candidate_counts = candidate.get("case_count")
        if not isinstance(candidate_counts, dict):
            raise ValueError("candidate case_count must be an object")
        for key in ("total", "applicable", "not_applicable"):
            value = candidate_counts.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"candidate case_count.{key} must be a non-negative integer")
        candidate_unreachable = candidate_counts.get("unreachable", 0)
        if (
            isinstance(candidate_unreachable, bool)
            or not isinstance(candidate_unreachable, int)
            or candidate_unreachable < 0
        ):
            raise ValueError("candidate case_count.unreachable must be a non-negative integer")
        candidate_reasons = candidate_counts.get("not_applicable_reasons")
        if not isinstance(candidate_reasons, dict):
            raise ValueError("candidate case_count.not_applicable_reasons must be an object")
        if any(
            not isinstance(reason, str)
            or not reason
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 0
            for reason, count in candidate_reasons.items()
        ):
            raise ValueError(
                "candidate case_count.not_applicable_reasons must map non-empty strings to non-negative integers"
            )
        if candidate_counts["applicable"] + candidate_unreachable + candidate_counts["not_applicable"] != candidate_counts["total"]:
            raise ValueError("candidate case counts must partition total")
        if sum(candidate_reasons.values()) != candidate_counts["not_applicable"]:
            raise ValueError("candidate not_applicable reasons must sum to not_applicable")

        scope_changed = False
        for key in ("total", "applicable", "unreachable", "not_applicable"):
            previous = observed.get(key, 0)
            current = candidate_counts.get(key, 0)
            if previous is not None and current != previous:
                scope_changed = True
                decision["review_notes"].append(
                    f"case_count.{key} moved {previous!r} -> {current!r}"
                )
        previous_reasons = observed.get("not_applicable_reasons")
        current_reasons = candidate_reasons
        if previous_reasons is not None and current_reasons != previous_reasons:
            scope_changed = True
            decision["review_notes"].append(
                "case_count.not_applicable_reasons changed from the reviewed baseline"
            )

        for identity_key in REQUIRED_IDENTITIES:
            previous = baseline.get(identity_key)
            if not isinstance(previous, str) or not previous:
                raise ValueError(f"baseline {identity_key} must be a non-empty string")
            current = candidate.get(identity_key)
            if current != previous:
                if identity_key in SCOPE_IDENTITIES:
                    scope_changed = True
                decision["review_notes"].append(
                    f"{identity_key} moved {previous!r} -> {current!r}"
                )

        if not decision["failures"] and scope_changed:
            decision["promotion_status"] = "scope_changed_requires_review"
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        decision["failures"].append(str(exc))

    decision["blocked"] = bool(decision["failures"])
    if decision["blocked"]:
        decision["promotion_status"] = "blocked"
    return decision


def enforcement_result(decision_path, candidate_path, baseline_path, verdict, promotion_status, failures):
    result = {
        "schema_version": 1,
        "verdict": verdict,
        "promotion_status": promotion_status,
        "failures": failures,
        "decision_sha256": None,
        "candidate_sha256": None,
        "baseline_sha256": None,
    }
    for field, path in (
        ("decision_sha256", decision_path),
        ("candidate_sha256", candidate_path),
        ("baseline_sha256", baseline_path),
    ):
        try:
            result[field] = file_sha256(path)
        except OSError:
            pass
    return result


def write_enforcement_result(result_path, result):
    try:
        atomic_json_write(result_path, result)
    except OSError as exc:
        print(f"::error::cannot write enforcement result: {exc}")
        return False
    return True


def enforce(decision_path, candidate_path, baseline_path, result_path, evidence_paths=None):
    evidence_paths = evidence_paths or {}
    try:
        decision = load_object(decision_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        failure = f"cannot read candidate decision: {exc}"
        write_enforcement_result(
            result_path,
            enforcement_result(
                decision_path, candidate_path, baseline_path, "blocked", "blocked", [failure]
            ),
        )
        print(f"candidate decision: BLOCKED: {failure}")
        return 1
    integrity_failures = []
    recomputed = evaluate(candidate_path, baseline_path, evidence_paths)
    if decision != recomputed:
        integrity_failures.append("stored decision does not match a fresh evaluation")
    for label, path, digest_key in (
        ("candidate", candidate_path, "candidate_sha256"),
        ("baseline", baseline_path, "baseline_sha256"),
    ):
        try:
            current_digest = file_sha256(path)
        except OSError as exc:
            integrity_failures.append(f"cannot hash {label}: {exc}")
            continue
        if current_digest != decision.get(digest_key):
            integrity_failures.append(f"{label} changed after its promotion decision was created")
    recorded_evidence = decision.get("evidence_sha256")
    if not isinstance(recorded_evidence, dict):
        integrity_failures.append("decision evidence_sha256 is not an object")
        recorded_evidence = {}
    if set(recorded_evidence) != set(evidence_paths):
        integrity_failures.append("decision evidence set does not match the required evidence set")
    for label, path in sorted(evidence_paths.items()):
        try:
            current_digest = file_sha256(path)
        except OSError as exc:
            integrity_failures.append(f"cannot hash evidence {label}: {exc}")
            continue
        if current_digest != recorded_evidence.get(label):
            integrity_failures.append(f"evidence {label} changed after the decision was created")

    if decision.get("blocked") is not False or integrity_failures:
        failures = decision.get("failures")
        if not isinstance(failures, list):
            failures = []
        if decision.get("blocked") is not False and not failures:
            failures = ["decision is blocked without a recorded reason"]
        failures = [*failures, *integrity_failures]
        for failure in failures:
            print(f"::error::{failure}")
        result = enforcement_result(
            decision_path, candidate_path, baseline_path, "blocked", "blocked", failures
        )
        if not write_enforcement_result(result_path, result):
            return 1
        print(f"candidate decision: BLOCKED ({len(failures)} failure(s))")
        return 1
    if decision.get("promotion_status") == "scope_changed_requires_review":
        result = enforcement_result(
            decision_path,
            candidate_path,
            baseline_path,
            "review_required",
            "scope_changed_requires_review",
            [],
        )
        if not write_enforcement_result(result_path, result):
            return 1
        print("::warning::candidate scope changed and requires owner review; public record unchanged")
        print("candidate decision: REVIEW REQUIRED (not published)")
        return 2
    if decision.get("promotion_status") != "under_review":
        failure = "candidate decision has an unrecognized promotion status"
        write_enforcement_result(
            result_path,
            enforcement_result(
                decision_path, candidate_path, baseline_path, "blocked", "blocked", [failure]
            ),
        )
        print(f"::error::{failure}")
        return 1
    result = enforcement_result(
        decision_path, candidate_path, baseline_path, "pass", "under_review", []
    )
    if not write_enforcement_result(result_path, result):
        return 1
    print("candidate decision: PASS (no action required; not published)")
    return 0


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser("evaluate")
    evaluate_parser.add_argument("--candidate", type=Path, required=True)
    evaluate_parser.add_argument("--baseline", type=Path, required=True)
    evaluate_parser.add_argument("--decision", type=Path, required=True)
    evaluate_parser.add_argument("--evidence", action="append", default=[], metavar="NAME=PATH")

    enforce_parser = subparsers.add_parser("enforce")
    enforce_parser.add_argument("decision", type=Path)
    enforce_parser.add_argument("--candidate", type=Path, required=True)
    enforce_parser.add_argument("--baseline", type=Path, required=True)
    enforce_parser.add_argument("--result", type=Path, required=True)
    enforce_parser.add_argument("--evidence", action="append", default=[], metavar="NAME=PATH")
    return parser.parse_args()


def parse_evidence(values):
    evidence = {}
    for value in values:
        label, separator, raw_path = value.partition("=")
        if not separator or not label or not raw_path:
            raise ValueError(f"invalid --evidence value {value!r}; want NAME=PATH")
        if label in evidence:
            raise ValueError(f"duplicate evidence label: {label}")
        evidence[label] = Path(raw_path)
    return evidence


def main():
    args = parse_args()
    try:
        evidence_paths = parse_evidence(args.evidence)
    except ValueError as exc:
        print(f"candidate decision: BLOCKED: {exc}")
        return 1
    if args.command == "enforce":
        return enforce(args.decision, args.candidate, args.baseline, args.result, evidence_paths)

    decision = evaluate(args.candidate, args.baseline, evidence_paths)
    atomic_json_write(args.decision, decision)
    for note in decision["review_notes"]:
        print(f"::notice::{note}")
    for failure in decision["failures"]:
        print(f"::error::{failure}")
    print(f"candidate decision written to {args.decision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
