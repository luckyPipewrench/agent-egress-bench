#!/usr/bin/env python3
"""Evaluate a continuous-gauntlet candidate without publishing it."""

import argparse
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path


REQUIRED_FLOORS = {
    "full": {"containment"},
    "applicable": {"containment", "detection", "evidence"},
}
REQUIRED_CEILINGS = {"applicable": {"false_positive_rate"}}
REQUIRED_COUNT_KEYS = ("total", "applicable", "not_applicable", "not_applicable_reasons")
REQUIRED_IDENTITIES = (
    "corpus_git_sha",
    "corpus_sha256",
    "corpus_version",
    "scoring_version",
    "runner_version",
)
SCOPE_IDENTITIES = {"corpus_sha256", "corpus_version", "scoring_version", "runner_version"}


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


def nested_value(document, path):
    current = document
    for key in path:
        if not isinstance(current, dict) or key not in current:
            raise ValueError("missing field: " + ".".join(path))
        current = current[key]
    return current


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

        if candidate.get("schema_version") != 2:
            raise ValueError("candidate schema_version must be 2")

        decision["artifact_id"] = nested_value(candidate, ("artifact_id",))
        decision["canonical_url"] = nested_value(candidate, ("canonical_url",))

        if candidate.get("sufficient") is not True:
            decision["failures"].append(f"sufficient={candidate.get('sufficient')!r}, want true")
        errors = nested_value(candidate, ("case_count", "errors"))
        if errors != 0:
            decision["failures"].append(f"case_count.errors={errors!r}, want 0")

        expected_version = baseline.get("pipelock_version")
        actual_version = candidate.get("pipelock_version")
        if not isinstance(expected_version, str) or not expected_version:
            raise ValueError("baseline pipelock_version must be a non-empty string")
        if actual_version != expected_version:
            decision["failures"].append(
                f"pipelock_version={actual_version!r}, baseline is {expected_version!r}"
            )

        floors = baseline.get("score_floors")
        if not isinstance(floors, dict):
            raise ValueError("baseline score_floors must be an object")
        for scope, required_metrics in REQUIRED_FLOORS.items():
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
        for scope, required_metrics in REQUIRED_CEILINGS.items():
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
        if observed["applicable"] + observed["not_applicable"] != observed["total"]:
            raise ValueError("baseline observed case counts must partition total")
        if sum(reasons.values()) != observed["not_applicable"]:
            raise ValueError("baseline not_applicable reasons must sum to not_applicable")
        scope_changed = False
        for key in ("total", "applicable", "not_applicable"):
            previous = observed.get(key)
            current = nested_value(candidate, ("case_count", key))
            if previous is not None and current != previous:
                scope_changed = True
                decision["review_notes"].append(
                    f"case_count.{key} moved {previous!r} -> {current!r}"
                )
        previous_reasons = observed.get("not_applicable_reasons")
        current_reasons = nested_value(candidate, ("case_count", "not_applicable_reasons"))
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


def enforce(decision_path, candidate_path, baseline_path, evidence_paths=None):
    evidence_paths = evidence_paths or {}
    try:
        decision = load_object(decision_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"candidate decision: BLOCKED: {exc}")
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
        if not isinstance(failures, list) or not failures:
            failures = ["decision is blocked without a recorded reason"]
        failures = [*failures, *integrity_failures]
        for failure in failures:
            print(f"::error::{failure}")
        print(f"candidate decision: BLOCKED ({len(failures)} failure(s))")
        return 1
    print("candidate decision: ACCEPTED FOR HUMAN REVIEW (not published)")
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
        return enforce(args.decision, args.candidate, args.baseline, evidence_paths)

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
