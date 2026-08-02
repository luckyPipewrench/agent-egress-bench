#!/usr/bin/env python3
"""Validate scope-artifact fields against the checked-out corpus manifest."""

import hashlib
import json
import math
import re
import sys
import urllib.parse
from pathlib import Path


REQUIRED_SCOPE_PATHS = (
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

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "cases" / "MANIFEST.txt"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


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


def checked_out_corpus_identity():
    """Return the manifest identity asserted by runner/corpus_manifest_test.go."""
    try:
        raw = MANIFEST_PATH.read_bytes()
    except OSError as exc:
        raise ValueError(f"read corpus manifest {MANIFEST_PATH}: {exc}") from exc

    # The runner test treats non-empty IDs as a set when comparing the manifest
    # to loadable cases. It separately rejects duplicate IDs, so this is the
    # same logical count once the runner's corpus pin is green.
    logical_ids = {line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()}
    if not logical_ids:
        raise ValueError("checked-out corpus manifest has no logical case IDs")
    return hashlib.sha256(raw).hexdigest(), len(logical_ids)


def validate_metric_fraction(document, metric):
    """Bind an applicable-view score to its explicit numerator/denominator."""
    score_path = ("scores", "applicable", metric)
    count_path = ("metric_counts", "applicable", metric)
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


def validate_scope(document):
    """Raise ValueError unless an artifact can render an honest scope block."""
    if not isinstance(document, dict):
        raise ValueError("artifact must be a JSON object")

    for path in REQUIRED_SCOPE_PATHS:
        path_value(document, path)

    non_empty_string(document, ("artifact_id",))
    non_empty_string(document, ("runner_version",))
    non_empty_string(document, ("scoring_version",))

    manifest_digest = non_empty_string(document, ("corpus_manifest_sha256",))
    if not SHA256_HEX.fullmatch(manifest_digest):
        raise ValueError("corpus_manifest_sha256 must be 64 lower-case hex characters")
    manifest_count = non_negative_integer(document, ("logical_case_count",))
    checked_out_digest, checked_out_count = checked_out_corpus_identity()
    if manifest_digest != checked_out_digest:
        raise ValueError("corpus_manifest_sha256 does not match checked-out cases/MANIFEST.txt")
    if manifest_count != checked_out_count:
        raise ValueError("logical_case_count does not match checked-out cases/MANIFEST.txt")

    applicable = non_negative_integer(document, ("case_count", "applicable"))
    total = non_negative_integer(document, ("case_count", "total"))
    not_applicable = non_negative_integer(document, ("case_count", "not_applicable"))
    if total == 0:
        raise ValueError("case_count.total must be greater than zero")
    if total != checked_out_count:
        raise ValueError("case_count.total does not match checked-out logical corpus count")
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

    # Containment has no denominator when every case is N/A. In exactly that
    # state it must be null rather than a made-up score; otherwise it must be a
    # finite fraction because scope-render.js publishes it as the headline.
    containment = path_value(document, ("scores", "applicable", "containment"))
    _, containment_denominator = validate_metric_fraction(document, "containment")
    _, false_positive_denominator = validate_metric_fraction(document, "false_positive_rate")
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

    canonical_url = path_value(document, ("canonical_url",))
    if not isinstance(canonical_url, str) or not canonical_url:
        raise ValueError("canonical_url must be a non-empty string")
    parsed_url = urllib.parse.urlparse(canonical_url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ValueError("canonical_url must be an absolute https URL")


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
