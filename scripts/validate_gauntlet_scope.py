#!/usr/bin/env python3
"""Refuse incomplete provenance artifacts before scope-aware publication."""

import json
import math
import sys
from pathlib import Path


REQUIRED_SCOPE_PATHS = (
    ("case_count", "applicable"),
    ("case_count", "total"),
    ("case_count", "not_applicable"),
    ("case_count", "not_applicable_reasons"),
    ("scores", "applicable", "containment"),
    ("scores", "applicable", "false_positive_rate"),
    ("canonical_url",),
)


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


def validate_scope(document):
    """Raise ValueError unless an artifact can render an honest scope block."""
    if not isinstance(document, dict):
        raise ValueError("artifact must be a JSON object")

    for path in REQUIRED_SCOPE_PATHS:
        path_value(document, path)

    applicable = non_negative_integer(document, ("case_count", "applicable"))
    total = non_negative_integer(document, ("case_count", "total"))
    not_applicable = non_negative_integer(document, ("case_count", "not_applicable"))
    if applicable > total:
        raise ValueError("case_count.applicable cannot exceed case_count.total")
    if applicable + not_applicable != total:
        raise ValueError("case_count.applicable plus not_applicable must equal case_count.total")

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

    false_positive_rate = path_value(document, ("scores", "applicable", "false_positive_rate"))
    if false_positive_rate is not None:
        if isinstance(false_positive_rate, bool) or not isinstance(false_positive_rate, (int, float)):
            raise ValueError("scores.applicable.false_positive_rate must be a number or null")
        if not math.isfinite(false_positive_rate) or not 0 <= false_positive_rate <= 1:
            raise ValueError("scores.applicable.false_positive_rate must be between 0 and 1")

    # containment is the published headline score in scope-render.js, so it is
    # required and must be a real fraction. Unlike false_positive_rate it is NOT
    # nullable: a missing, non-numeric, or out-of-range containment must fail the
    # gate rather than render as a misleading headline.
    containment = path_value(document, ("scores", "applicable", "containment"))
    if isinstance(containment, bool) or not isinstance(containment, (int, float)):
        raise ValueError("scores.applicable.containment must be a number")
    if not math.isfinite(containment) or not 0 <= containment <= 1:
        raise ValueError("scores.applicable.containment must be between 0 and 1")

    canonical_url = path_value(document, ("canonical_url",))
    if not isinstance(canonical_url, str) or not canonical_url:
        raise ValueError("canonical_url must be a non-empty string")


def main(argv):
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} ARTIFACT.json", file=sys.stderr)
        return 2
    try:
        with open(argv[1], encoding="utf-8") as artifact_file:
            artifact = json.load(artifact_file)
        validate_scope(artifact)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"scope validation: FAIL: {exc}", file=sys.stderr)
        return 1
    print("scope validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
