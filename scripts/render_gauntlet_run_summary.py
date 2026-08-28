#!/usr/bin/env python3
"""Render a fail-closed, owner-facing Continuous Gauntlet summary."""

import argparse
import hashlib
import html
import json
import math
import re
from pathlib import Path


REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
RUN_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REVIEW_STATUS = "scope_changed_requires_review"
PASS_STATUS = "under_review"


def markdown_text(value):
    """Render untrusted values as literal, one-line Markdown text."""
    if not isinstance(value, str):
        return "(unavailable)"
    escaped = value.replace("\\", "\\\\").replace("`", "\\`").replace("\r", " ").replace("\n", " ")
    for character in ("[", "]", "(", ")"):
        escaped = escaped.replace(character, "\\" + character)
    return html.escape(escaped, quote=False)


def code_text(value):
    """Render a literal one-line value inside a Markdown code span."""
    if not isinstance(value, str):
        return "(unavailable)"
    return html.escape(value.replace("`", "'").replace("\r", " ").replace("\n", " "), quote=False)


def load_object(path, label, failures):
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        failures.append(f"cannot read {label}: {exc}")
        return None
    if not isinstance(value, dict):
        failures.append(f"{label} must be a JSON object")
        return None
    return value


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def required_string(document, path, failures):
    value = document
    for key in path:
        if not isinstance(value, dict):
            failures.append("missing field: " + ".".join(path))
            return None
        value = value.get(key)
    if not isinstance(value, str) or not value:
        failures.append("invalid field: " + ".".join(path))
        return None
    return value


def count(document, key, failures):
    value = document.get("case_count", {}).get(key) if isinstance(document.get("case_count"), dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        failures.append(f"invalid field: case_count.{key}")
        return None
    return value


def optional_count(document, key, failures, default=0):
    case_count = document.get("case_count")
    if not isinstance(case_count, dict) or key not in case_count:
        return default
    return count(document, key, failures)


def score(document, scope, metric, failures):
    scores = document.get("scores")
    value = scores.get(scope, {}).get(metric) if isinstance(scores, dict) and isinstance(scores.get(scope), dict) else None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 1:
        failures.append(f"invalid field: scores.{scope}.{metric}")
        return None
    return float(value)


def percent(value):
    return f"{value * 100:.1f}%"


def append_failure(failures, message):
    if message not in failures:
        failures.append(message)


def verify_enforcement_digests(enforcement, paths, failures):
    for field, (label, path) in paths.items():
        recorded = enforcement.get(field)
        if not isinstance(recorded, str) or not SHA256_RE.fullmatch(recorded):
            append_failure(failures, f"enforcement result {field} is invalid")
            continue
        try:
            current = file_sha256(path)
        except OSError as exc:
            append_failure(failures, f"cannot hash {label}: {exc}")
            continue
        if current != recorded:
            append_failure(failures, f"{label} changed after enforcement")


def build_summary(candidate_path, decision_path, baseline_path, enforcement_path, repository, run_url):
    failures = []
    repository_valid = bool(REPOSITORY_RE.fullmatch(repository))
    run_url_valid = bool(RUN_URL_RE.fullmatch(run_url))
    if not repository_valid:
        failures.append("repository context is invalid")
    if not run_url_valid:
        failures.append("current run URL is invalid")

    candidate = load_object(candidate_path, "candidate", failures)
    decision = load_object(decision_path, "decision", failures)
    baseline = load_object(baseline_path, "approved baseline", failures)
    enforcement = load_object(enforcement_path, "enforcement result", failures)

    verdict = None
    enforced_status = None
    enforcement_failures = []
    if enforcement is not None:
        if enforcement.get("schema_version") != 1:
            failures.append("enforcement result schema_version must be 1")
        verdict = enforcement.get("verdict")
        enforced_status = enforcement.get("promotion_status")
        if verdict not in {"pass", "review_required", "blocked"}:
            failures.append("enforcement result verdict is invalid")
        values = enforcement.get("failures")
        if not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values):
            failures.append("enforcement result failures must be non-empty strings")
        else:
            enforcement_failures.extend(values)
        verify_enforcement_digests(
            enforcement,
            {
                "decision_sha256": ("decision", decision_path),
                "candidate_sha256": ("candidate", candidate_path),
                "baseline_sha256": ("approved baseline", baseline_path),
            },
            failures,
        )

    details = {}
    if candidate is not None:
        if candidate.get("schema_version") not in {2, 4, 5, 6}:
            failures.append("candidate schema_version must be 2, 4, 5, or 6")
        elif candidate.get("schema_version") in {4, 5, 6}:
            try:
                import evaluate_gauntlet_candidate as evaluator
                evaluator.require_capability_registry(candidate)
            except ValueError as exc:
                failures.append(str(exc))
        for key in ("pipelock_version", "generated_at", "corpus_version", "corpus_git_sha"):
            details[key] = required_string(candidate, (key,), failures)
        for key in ("total", "applicable", "not_applicable", "errors"):
            details[key] = count(candidate, key, failures)
        details["unreachable"] = optional_count(candidate, "unreachable", failures)
        if candidate.get("schema_version") in {4, 5, 6}:
            if candidate.get("measurement_status") != "measured":
                failures.append("candidate measurement_status must be 'measured'")
        elif candidate.get("sufficient") is not True:
            failures.append("legacy candidate sufficient must be true")
        if details["errors"] not in (None, 0):
            failures.append("candidate case_count.errors must be 0")
        if details["unreachable"] not in (None, 0):
            failures.append("candidate case_count.unreachable must be 0")
        reasons = candidate.get("case_count", {}).get("not_applicable_reasons") if isinstance(candidate.get("case_count"), dict) else None
        if not isinstance(reasons, dict) or any(not isinstance(reason, str) or not reason or isinstance(value, bool) or not isinstance(value, int) or value < 0 for reason, value in reasons.items()):
            failures.append("invalid field: case_count.not_applicable_reasons")
        elif details["not_applicable"] is not None and sum(reasons.values()) != details["not_applicable"]:
            failures.append("candidate N/A reasons do not match case_count.not_applicable")
        if all(details[key] is not None for key in ("total", "applicable", "unreachable", "not_applicable")) and details["applicable"] + details["unreachable"] + details["not_applicable"] != details["total"]:
            failures.append("candidate case counts do not partition total")
        details["applicable_containment"] = score(candidate, "applicable", "containment", failures)
        details["full_containment"] = score(candidate, "full", "containment", failures)
        details["false_positive_rate"] = score(candidate, "applicable", "false_positive_rate", failures)

    decision_failures = []
    review_notes = []
    status = None
    if decision is not None:
        if decision.get("schema_version") != 1:
            failures.append("decision schema_version must be 1")
        if not isinstance(decision.get("blocked"), bool):
            failures.append("decision blocked must be a boolean")
        status = decision.get("promotion_status")
        if not isinstance(status, str) or not status:
            failures.append("decision promotion_status is invalid")
        for source, destination in (("failures", decision_failures), ("review_notes", review_notes)):
            values = decision.get(source)
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                failures.append(f"decision {source} must be a list of strings")
            else:
                destination.extend(values)

    if baseline is not None:
        if baseline.get("schema_version") != 1:
            failures.append("approved baseline schema_version must be 1")
        for key in ("pipelock_version", "corpus_version", "corpus_git_sha"):
            required_string(baseline, (key,), failures)

    for failure in decision_failures:
        append_failure(failures, "decision: " + failure)
    for failure in enforcement_failures:
        append_failure(failures, "enforcement: " + failure)

    if verdict == "blocked":
        if not enforcement_failures:
            append_failure(failures, "enforcement blocked without a recorded reason")
        state = "BLOCKED — ACTION REQUIRED"
    elif (
        not failures
        and verdict == "review_required"
        and enforced_status == REVIEW_STATUS
        and status == REVIEW_STATUS
        and decision is not None
        and decision.get("blocked") is False
    ):
        state = "REVIEW REQUIRED — PUBLIC RECORD UNCHANGED"
    elif (
        not failures
        and verdict == "pass"
        and enforced_status == PASS_STATUS
        and status == PASS_STATUS
        and decision is not None
        and decision.get("blocked") is False
    ):
        state = "PASS — NO ACTION REQUIRED"
    else:
        if not failures:
            failures.append(
                "decision status disagrees with enforcement result: "
                f"promotion_status={status!r}, verdict={verdict!r}, "
                f"enforced_status={enforced_status!r}"
            )
        state = "BLOCKED — ACTION REQUIRED"

    latest_url = f"https://github.com/{repository}/blob/main/gauntlet-site/latest-verified.json" if repository_valid else None
    lines = [f"## Continuous Gauntlet: {state}", ""]
    if state == "PASS — NO ACTION REQUIRED":
        lines.extend(["The candidate is complete and matches the approved scope. No PR was created; permanent publication was not requested.", ""])
    elif state.startswith("REVIEW REQUIRED"):
        lines.extend(["The candidate is complete, but its approved scope changed. The archived record in this repository is unchanged. Review and publish new Pipelock results from the product-owned lane.", ""])
    else:
        lines.extend(["The candidate, decision, or enforcement result is incomplete, blocked, or malformed. The archived record in this repository is unchanged. Fix or inspect the failures before publishing the run elsewhere.", ""])

    lines.extend(["### Run details", ""])
    if candidate is not None:
        lines.append(f"- Pipelock: `{code_text(details.get('pipelock_version'))}`")
        lines.append(f"- Generated: `{code_text(details.get('generated_at'))}`")
        if all(details.get(key) is not None for key in ("total", "applicable", "unreachable", "not_applicable", "errors")):
            lines.append(f"- Cases: {details['total']} total; {details['applicable']} routed; {details['unreachable']} unreachable; {details['not_applicable']} N/A; {details['errors']} errors")
        if details.get("applicable_containment") is not None:
            lines.append(f"- Applicable containment: {percent(details['applicable_containment'])}")
        if details.get("full_containment") is not None:
            lines.append(f"- Full containment: {percent(details['full_containment'])}")
        if details.get("false_positive_rate") is not None:
            lines.append(f"- Applicable false-positive rate: {percent(details['false_positive_rate'])}")
        sha = details.get("corpus_git_sha")
        short_sha = sha[:12] if isinstance(sha, str) else "(unavailable)"
        lines.append(f"- Corpus: `{code_text(details.get('corpus_version'))}` at `{code_text(short_sha)}`")
        if state == "PASS — NO ACTION REQUIRED":
            lines.append("- Approved scope: unchanged")
    else:
        lines.append("- Candidate details are unavailable.")

    if review_notes:
        lines.extend(["", "### Review notes", ""])
        lines.extend(f"- {markdown_text(note)}" for note in review_notes)
    if failures:
        lines.extend(["", "### Failures", ""])
        lines.extend(f"- {markdown_text(failure)}" for failure in failures)
    lines.extend(["", "### Links", ""])
    lines.append(f"- [Current workflow run]({run_url})" if run_url_valid else "- Current workflow run: (unavailable)")
    lines.append(f"- [Current verified pointer]({latest_url})" if latest_url else "- Current verified pointer: (unavailable)")
    lines.append("")
    return "\n".join(lines), state


def render(candidate_path, decision_path, baseline_path, enforcement_path, repository, run_url):
    return build_summary(
        candidate_path, decision_path, baseline_path, enforcement_path, repository, run_url
    )[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--enforcement-result", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()
    output, state = build_summary(
        args.candidate,
        args.decision,
        args.baseline,
        args.enforcement_result,
        args.repository,
        args.run_url,
    )
    print(output)
    return 1 if state == "BLOCKED — ACTION REQUIRED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
