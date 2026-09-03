#!/usr/bin/env python3
"""Prepare an append-only Gauntlet result and latest-verified pointer."""

import argparse
import importlib.util
import hashlib
import json
import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import build_gauntlet_provenance as provenance
import evaluate_gauntlet_candidate as evaluator
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


CANDIDATE_FILENAME = "continuous-gauntlet-pipelock.json"
SOURCE_DECISION_FILENAME = "promotion-decision.json"
EXECUTION_DECISION_FILENAME = "execution-decision.json"
RUN_BUNDLE_FILENAME = "run-bundle.json"
PUBLISHED_DECISION_FILENAME = "reviewed-promotion-decision.json"
BASELINE_SNAPSHOT_FILENAME = "reviewed-baseline.json"
SOURCE_BASELINE_FILENAME = "source-baseline.json"
SOURCE_BASELINE_ORIGIN_FILENAME = "source-baseline-origin.json"
RECORD_MANIFEST_FILENAME = "record-manifest.json"
LATEST_POINTER_FILENAME = "latest-verified.json"
FIRST_PARTY_ASSURANCES = ["self-run", "artifact-validated"]
SOURCE_PROMOTION_DECISION_FILENAME = "source-promotion-decision.json"
DESTINATION_BASELINE_FILENAME = "destination-baseline.json"
DESTINATION_PROMOTION_DECISION_FILENAME = "destination-promotion-decision.json"
DEFAULT_ARTIFACT_PREFIX = "github-actions:luckyPipewrench/agent-egress-bench:"
DEFAULT_URL_PREFIX = "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
ACTIVE_PROMOTED_RECORD_SCHEMA_VERSION = artifact_contracts.active_version("promoted_record")
ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION = artifact_contracts.active_version(
    "provenance_candidate"
)
PROMOTED_RECORD_SCHEMAS = artifact_contracts.schema_paths("promoted_record")
PROMOTION_BASELINE_SCHEMA = artifact_contracts.canonical_schema_path("promotion_baseline")
REVIEWABLE_SCORE_FAILURE = re.compile(
    r"^scores\.(?:full|applicable)\.[a-z_]+=.+, "
    r"(?:below baseline floor|above baseline ceiling) .+$"
)

EVIDENCE_FILES = {
    **provenance.RAW_EVIDENCE,
    "execution_decision": EXECUTION_DECISION_FILENAME,
    "run_bundle": RUN_BUNDLE_FILENAME,
}


def require_object(path):
    return evaluator.load_object(path)


def require_non_empty_string(document, key):
    value = document.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def require_sha256(value, label):
    if not isinstance(value, str) or not SHA256_HEX.fullmatch(value):
        raise ValueError(f"{label} must be 64 lower-case hex characters")
    return value


def parse_timestamp(value, label):
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} must be an ISO-8601 timestamp with a timezone") from exc
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise ValueError(f"{label} must be an ISO-8601 timestamp with a timezone")
    return timestamp


def evidence_files_for(candidate):
    files = dict(EVIDENCE_FILES)
    if candidate.get("schema_version") in {4, 5, 6}:
        files.update(provenance.V4_RAW_EVIDENCE)
    return files


def evidence_paths(artifact_dir, candidate=None):
    candidate = candidate or {}
    paths = {}
    for label, filename in evidence_files_for(candidate).items():
        path = artifact_dir / filename
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required evidence is missing: {label} ({filename})")
        paths[label] = path
    return paths


def validate_execution_decision(path):
    decision = require_object(path)
    if decision.get("execution_status") != "complete":
        raise ValueError("execution decision is not complete")
    if decision.get("blocked") is not False:
        raise ValueError("execution decision is blocked")
    if decision.get("publication_eligible") is not True:
        raise ValueError("execution decision is not publication eligible")
    failures = decision.get("failures")
    if failures != []:
        raise ValueError("execution decision failures must be an empty array")


def validate_candidate_origin(
    candidate, artifact_prefix, url_prefix, expected_run_id, expected_run_attempt
):
    artifact_id = require_non_empty_string(candidate, "artifact_id")
    canonical_url = require_non_empty_string(candidate, "canonical_url")
    if not artifact_id.startswith(artifact_prefix):
        raise ValueError(f"artifact_id must start with {artifact_prefix!r}")
    if not canonical_url.startswith(url_prefix):
        raise ValueError(f"canonical_url must start with {url_prefix!r}")
    parsed = urlparse(canonical_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("canonical_url must be an absolute HTTPS URL")
    identity_parts = artifact_id.removeprefix(artifact_prefix).split(":")
    if len(identity_parts) not in {1, 2}:
        raise ValueError("artifact_id must end in a run ID and optional run attempt")
    run_id = identity_parts[0]
    run_attempt = identity_parts[1] if len(identity_parts) == 2 else None
    if not run_id.isascii() or not run_id.isdigit() or run_id.startswith("0"):
        raise ValueError("artifact_id must end in a positive decimal run ID")
    if run_attempt is not None and (
        not run_attempt.isascii()
        or not run_attempt.isdigit()
        or run_attempt.startswith("0")
    ):
        raise ValueError("artifact_id run attempt must be a positive decimal integer")
    expected_urls = {url_prefix + run_id}
    if run_attempt is not None:
        expected_urls.add(f"{url_prefix}{run_id}/attempts/{run_attempt}")
    if canonical_url not in expected_urls:
        raise ValueError("artifact_id and canonical_url run IDs do not match")
    if expected_run_id is not None and run_id != expected_run_id:
        raise ValueError("candidate run ID does not match the requested source run")
    if expected_run_attempt is not None and run_attempt != expected_run_attempt:
        raise ValueError("candidate run attempt does not match the requested source attempt")


def validate_reference_candidate(candidate):
    if candidate.get("schema_version") not in {2, 4, 5, 6}:
        raise ValueError("candidate schema_version must be 2, 4, 5, or 6")
    if candidate.get("schema_version") in {4, 5, 6}:
        evaluator.require_capability_registry(candidate)
    if candidate.get("schema_version") in {5, 6}:
        evaluator.validate_v5_candidate_contract(candidate)
    if candidate.get("schema_version") == 6:
        for field in (
            "method_repository",
            "method_commit",
            "adapter_id",
            "adapter_owner",
            "target_config_ref",
        ):
            require_non_empty_string(candidate, field)
        require_sha256(candidate.get("target_config_sha256"), "target_config_sha256")
        candidate = artifact_schema.validate_file(
            candidate,
            evaluator.PROVENANCE_SCHEMAS[6],
            "provenance candidate v6",
        )
    if candidate.get("tool") != "pipelock":
        raise ValueError("reference promotion candidate tool must be pipelock")
    parse_timestamp(require_non_empty_string(candidate, "generated_at"), "generated_at")
    tool_version = require_non_empty_string(candidate, "tool_version")
    if tool_version != require_non_empty_string(candidate, "pipelock_version"):
        raise ValueError("candidate tool_version and pipelock_version must match")
    return candidate


def validate_new_candidate_evidence(candidate, paths):
    if candidate.get("schema_version") != ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION:
        raise ValueError(
            "new promotions require active provenance candidate schema_version "
            f"{ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION}"
        )
    summary = require_object(paths["raw_summary"])
    if summary.get("schema_version") != provenance.ACTIVE_SUMMARY_SCHEMA_VERSION:
        raise ValueError(
            f"provenance candidate v{ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION} requires retained "
            f"summary schema_version {provenance.ACTIVE_SUMMARY_SCHEMA_VERSION}"
        )
    metadata = require_object(paths["run_metadata"])
    command = paths["command"].read_text(encoding="utf-8").strip()
    bound = provenance.publication_provenance(summary, metadata, command)
    for field, expected in bound.items():
        if candidate.get(field) != expected:
            raise ValueError(f"candidate {field} does not match retained run evidence")

    advertised = candidate.get("evidence_sha256")
    expected_labels = set(provenance.raw_evidence_for_summary(summary))
    if not isinstance(advertised, dict) or set(advertised) != expected_labels:
        raise ValueError("candidate evidence_sha256 does not name the complete retained evidence set")
    for label in sorted(expected_labels):
        if evaluator.file_sha256(paths[label]) != advertised.get(label):
            raise ValueError(f"candidate evidence_sha256.{label} does not match retained evidence")

    bundle = require_object(paths["run_bundle"])
    if bundle.get("schema_version") != 1 or bundle.get("bundle_status") != "complete":
        raise ValueError("retained run bundle is not complete")
    scope = bundle.get("candidate_scope")
    if not isinstance(scope, dict):
        raise ValueError("retained run bundle candidate_scope must be an object")
    for field, expected in bound.items():
        if scope.get(field) != expected:
            raise ValueError(f"run bundle {field} does not match retained run evidence")


def reviewable_policy_failure(failure):
    if not isinstance(failure, str):
        return False
    if REVIEWABLE_SCORE_FAILURE.fullmatch(failure):
        return True
    if failure == "v5 candidate requires a reviewed baseline with summary_schema_version=5":
        return True
    if failure == "v6 candidate requires a reviewed baseline with summary_schema_version=5":
        return True
    return failure.startswith("pipelock_version=") and ", baseline is " in failure


def proposed_baseline(candidate, candidate_sha256):
    generated_at = require_non_empty_string(candidate, "generated_at")
    recorded_on = parse_timestamp(generated_at, "generated_at").date().isoformat()

    counts = candidate.get("case_count")
    scores = candidate.get("scores")
    if not isinstance(counts, dict) or not isinstance(scores, dict):
        raise ValueError("candidate case_count and scores must be objects")
    applicable_scores = scores.get("applicable")
    full_scores = scores.get("full")
    if not isinstance(applicable_scores, dict) or not isinstance(full_scores, dict):
        raise ValueError("candidate full and applicable scores must be objects")

    baseline = {
        "_comment": (
            "Reviewed baseline for the continuous Gauntlet lane. Exact candidate scores become "
            "the next run's floors and ceiling only through a promotion PR. Public records remain "
            "append-only and the latest-verified pointer moves only with that reviewed commit."
        ),
        "schema_version": 1,
        "recorded_on": recorded_on,
        "verified_candidate_sha256": candidate_sha256,
        "verified_artifact_id": require_non_empty_string(candidate, "artifact_id"),
        "pipelock_version": require_non_empty_string(candidate, "pipelock_version"),
        "corpus_git_sha": require_non_empty_string(candidate, "corpus_git_sha"),
        "corpus_sha256": require_non_empty_string(candidate, "corpus_sha256"),
        "corpus_version": require_non_empty_string(candidate, "corpus_version"),
        "scoring_version": require_non_empty_string(candidate, "scoring_version"),
        "runner_version": require_non_empty_string(candidate, "runner_version"),
        "observed_case_count": {
            "total": counts.get("total"),
            "applicable": counts.get("applicable"),
            "unreachable": counts.get("unreachable", 0),
            "not_applicable": counts.get("not_applicable"),
            "not_applicable_reasons": counts.get("not_applicable_reasons"),
        },
        "score_floors": {
            "full": {"containment": full_scores.get("containment")},
            "applicable": {"containment": applicable_scores.get("containment")},
        },
        "score_ceilings": {
            "applicable": {"false_positive_rate": applicable_scores.get("false_positive_rate")}
        },
    }
    if candidate.get("schema_version") in {5, 6}:
        baseline["summary_schema_version"] = 5
        baseline["benchmark_manifest_sha256"] = require_sha256(
            candidate.get("benchmark_manifest_sha256"), "benchmark_manifest_sha256"
        )
    else:
        baseline["score_floors"]["applicable"].update(
            {
                "detection": applicable_scores.get("detection"),
                "evidence": applicable_scores.get("evidence"),
            }
        )
    baseline = artifact_schema.validate_file(
        baseline, PROMOTION_BASELINE_SCHEMA, "proposed baseline"
    )
    return baseline


SOURCE_BASELINE_ORIGIN_KEYS = {"schema_version", "repository", "commit", "path", "sha256"}


def load_source_baseline_origin(path, source_baseline_bytes):
    """Read the origin record and bind it to the baseline bytes it describes.

    WHAT THIS PROVES, AND WHAT IT DOES NOT. The record already proves its
    decision was computed from the retained baseline. It cannot say whose
    policy that was or where it lived, so this document supplies that locator
    and is only accepted when its digest matches the bytes actually used.

    It is a LOCATOR, not an origin proof. This repository has no network and
    should not acquire one, so nothing here resolves the named repository,
    commit and path to confirm those bytes were ever published there. A forged
    locator whose digest matches a forged policy is accepted by this function.
    The producer is what makes it meaningful: the site promotion fetches the
    policy from the named repository at the run's own commit and writes the
    locator from what it fetched, so it is a true audit pointer at write time
    and an unresolved claim at archive-validation time.

    Closing that gap needs a product-signed acceptance artifact rather than a
    stricter check here, because no check over self-authored data can establish
    origin.
    """
    document = require_object(Path(path))
    if set(document) != SOURCE_BASELINE_ORIGIN_KEYS:
        raise ValueError(
            "source baseline origin must contain exactly "
            f"{sorted(SOURCE_BASELINE_ORIGIN_KEYS)!r}"
        )
    if document["schema_version"] != 1:
        raise ValueError("source baseline origin schema_version must be 1")
    for key in ("repository", "path"):
        value = document[key]
        if not isinstance(value, str) or not value or value.strip() != value:
            raise ValueError(f"source baseline origin {key} must be a trimmed non-empty string")
    commit = document["commit"]
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise ValueError("source baseline origin commit must be a lower-case 40-character Git SHA")
    require_sha256(document["sha256"], "source baseline origin sha256")
    actual = hashlib.sha256(source_baseline_bytes).hexdigest()
    if document["sha256"] != actual:
        raise ValueError(
            "source baseline origin does not describe the retained source baseline"
        )
    return document


def atomic_copy(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=destination.name + ".", dir=destination.parent)
    try:
        with os.fdopen(descriptor, "wb") as target, source.open("rb") as current:
            shutil.copyfileobj(current, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def manifest_for(
    record_dir,
    candidate,
    previous_candidate_sha256,
    previous_record_manifest_sha256,
):
    files = {}
    for path in sorted(record_dir.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"record contains a non-regular entry: {path.name}")
        if path.name != RECORD_MANIFEST_FILENAME:
            files[path.name] = evaluator.file_sha256(path)
    return {
        "schema_version": ACTIVE_PROMOTED_RECORD_SCHEMA_VERSION,
        "tool": require_non_empty_string(candidate, "tool"),
        "tool_version": require_non_empty_string(candidate, "tool_version"),
        "artifact_id": require_non_empty_string(candidate, "artifact_id"),
        "canonical_url": require_non_empty_string(candidate, "canonical_url"),
        "generated_at": require_non_empty_string(candidate, "generated_at"),
        "candidate_sha256": files[CANDIDATE_FILENAME],
        "previous_candidate_sha256": previous_candidate_sha256,
        "previous_record_manifest_sha256": previous_record_manifest_sha256,
        "files": files,
    }


def validate_record(record_dir, candidate_sha256):
    manifest_path = record_dir / RECORD_MANIFEST_FILENAME
    manifest = require_object(manifest_path)
    schema_version = manifest.get("schema_version")
    if schema_version not in PROMOTED_RECORD_SCHEMAS:
        raise ValueError("record manifest schema_version is unsupported")
    manifest = artifact_schema.validate_file(
        manifest, PROMOTED_RECORD_SCHEMAS[schema_version], "record manifest"
    )
    require_sha256(manifest.get("candidate_sha256"), "record candidate_sha256")
    if manifest["candidate_sha256"] != candidate_sha256:
        raise ValueError("existing record candidate digest does not match its directory")
    previous_candidate = manifest.get("previous_candidate_sha256")
    previous_manifest = manifest.get("previous_record_manifest_sha256")
    if previous_candidate is None:
        if previous_manifest is not None:
            raise ValueError("first record cannot name a previous record manifest")
    else:
        require_sha256(previous_candidate, "record previous_candidate_sha256")
        require_sha256(previous_manifest, "record previous_record_manifest_sha256")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("record manifest files must be a non-empty object")
    if files.get(CANDIDATE_FILENAME) != manifest["candidate_sha256"]:
        raise ValueError("record candidate_sha256 must match the candidate file digest")
    entries = list(record_dir.iterdir())
    if any(path.is_symlink() or not path.is_file() for path in entries):
        raise ValueError("existing record contains a non-regular entry")
    expected_names = set(files) | {RECORD_MANIFEST_FILENAME}
    actual_names = {path.name for path in entries}
    if actual_names != expected_names:
        raise ValueError("existing record file set does not match its manifest")
    for filename, expected in files.items():
        require_sha256(expected, f"record files.{filename}")
        if evaluator.file_sha256(record_dir / filename) != expected:
            raise ValueError(f"existing record file changed: {filename}")
    candidate = require_object(record_dir / CANDIDATE_FILENAME)
    for field in ("tool", "tool_version", "artifact_id", "canonical_url", "generated_at"):
        if manifest.get(field) != candidate.get(field):
            raise ValueError(f"record manifest and candidate disagree on {field}")
    return manifest


def canonical_pointer_paths(latest_path, candidate_sha256):
    site_root = latest_path.resolve().parent
    record_root = site_root / "results" / "pipelock" / candidate_sha256
    base = "./" + record_root.relative_to(site_root).as_posix()
    return (
        f"{base}/{CANDIDATE_FILENAME}",
        f"{base}/{RECORD_MANIFEST_FILENAME}",
    )


def validate_site_layout(store_root, latest_path):
    expected_store_root = latest_path.resolve().parent / "results"
    if store_root.resolve() != expected_store_root:
        raise ValueError("store root must be the results directory beside latest-verified")


def validate_pointer(pointer, latest_path):
    if pointer.get("schema_version") != 1 or pointer.get("status") != "verified":
        raise ValueError("latest pointer must be a schema-v1 verified pointer")
    candidate_sha256 = require_sha256(pointer.get("candidate_sha256"), "pointer candidate_sha256")
    expected_record, expected_manifest = canonical_pointer_paths(latest_path, candidate_sha256)
    if pointer.get("record_path") != expected_record:
        raise ValueError("latest pointer record_path is not canonical")
    if pointer.get("record_manifest_path") != expected_manifest:
        raise ValueError("latest pointer record_manifest_path is not canonical")
    require_sha256(pointer.get("record_manifest_sha256"), "pointer record_manifest_sha256")
    assurances = pointer.get("assurances")
    if assurances is not None and assurances != FIRST_PARTY_ASSURANCES:
        raise ValueError("latest pointer assurances must name the first-party execution and artifact checks")
    previous_candidate = pointer.get("previous_candidate_sha256")
    previous_manifest = pointer.get("previous_record_manifest_sha256")
    if previous_candidate is None:
        if previous_manifest is not None:
            raise ValueError("first latest pointer cannot name a previous record manifest")
    else:
        require_sha256(previous_candidate, "pointer previous_candidate_sha256")
        require_sha256(previous_manifest, "pointer previous_record_manifest_sha256")
    generated_at = require_non_empty_string(pointer, "generated_at")
    parse_timestamp(generated_at, f"{latest_path} generated_at")
    return pointer


def existing_promotion_is_complete(latest_path, record_dir, candidate_sha256):
    if not latest_path.is_file() or not record_dir.is_dir():
        return False
    pointer = validate_pointer(require_object(latest_path), latest_path)
    if pointer["candidate_sha256"] != candidate_sha256:
        return False
    manifest = validate_record(record_dir, candidate_sha256)
    candidate = require_object(record_dir / CANDIDATE_FILENAME)
    for field in ("tool", "tool_version", "artifact_id", "canonical_url", "generated_at"):
        if pointer.get(field) != candidate.get(field):
            raise ValueError(f"latest pointer and record candidate disagree on {field}")
    if evaluator.file_sha256(record_dir / RECORD_MANIFEST_FILENAME) != pointer["record_manifest_sha256"]:
        raise ValueError("latest pointer record manifest digest does not match the record")
    if manifest["candidate_sha256"] != candidate_sha256:
        raise ValueError("latest pointer and record candidate digests differ")
    for field in ("previous_candidate_sha256", "previous_record_manifest_sha256"):
        if manifest.get(field) != pointer.get(field):
            raise ValueError(f"latest pointer and record manifest disagree on {field}")
    return True


def markdown_code(value):
    return str(value).replace("`", "'").replace("\r", " ").replace("\n", " ")


def nonpassing_case_lines(results_path):
    lines = []
    with results_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"results JSONL line {line_number} is invalid") from exc
            if not isinstance(row, dict):
                raise ValueError(f"results JSONL line {line_number} must be an object")
            if row.get("score") not in {"fail", "error"}:
                continue
            evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
            detail = evidence.get("error_message") or evidence.get("reason") or row.get("notes") or ""
            timing = evidence.get("budget_block_timing")
            suffix = f"; {timing}" if timing else ""
            if detail:
                suffix += f"; {detail}"
            lines.append(
                "- `{}`: expected `{}`, observed `{}`, score `{}`{}".format(
                    markdown_code(row.get("case_id", "unknown")),
                    markdown_code(row.get("expected_verdict", "unknown")),
                    markdown_code(row.get("actual_verdict", "unknown")),
                    markdown_code(row.get("score", "unknown")),
                    markdown_code(suffix),
                )
            )
    return lines


def write_summary(
    path, candidate, candidate_sha256, destination_decision, policy_change, results_path
):
    counts = candidate["case_count"]
    applicable_scores = candidate["scores"]["applicable"]
    full_scores = candidate["scores"]["full"]
    lines = [
        "## What changed",
        "",
        (
            "This promotion adds the immutable evidence record for the source run, updates the "
            "reviewed baseline, and advances `latest-verified` without replacing or deleting earlier records."
        ),
        "",
        (
            f"- Source run: [{markdown_code(candidate['artifact_id'])}]"
            f"({candidate['canonical_url']})"
        ),
        f"- Candidate SHA-256: `{candidate_sha256}`",
        f"- Pipelock: `{markdown_code(candidate['pipelock_version'])}`",
        (
            f"- Corpus: `{markdown_code(candidate['corpus_version'])}` at "
            f"`{markdown_code(candidate['corpus_git_sha'])}`"
        ),
        (
            f"- Scope: `{counts['applicable']} / {counts['total']}` routed, "
            f"`{counts.get('unreachable', 0)}` unreachable, "
            f"`{counts['not_applicable']}` N/A, `{counts['errors']}` errors"
        ),
        f"- Applicable containment: `{applicable_scores['containment']}`",
        f"- Full-corpus containment: `{full_scores['containment']}`",
        f"- Applicable false-positive rate: `{applicable_scores['false_positive_rate']}`",
        f"- Reviewed policy change proposed: `{'yes' if policy_change else 'no'}`",
    ]
    failures = destination_decision.get("failures", [])
    notes = destination_decision.get("review_notes", [])
    if failures or notes:
        lines.extend(["", "### Current-site baseline comparison"])
        lines.extend(f"- Failure: {markdown_code(value)}" for value in failures)
        lines.extend(f"- Review: {markdown_code(value)}" for value in notes)
    case_lines = nonpassing_case_lines(results_path)
    if case_lines:
        lines.extend(["", "### Non-passing routed cases", *case_lines])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def promote(args):
    artifact_dir = args.artifact_dir.resolve()
    candidate_path = artifact_dir / CANDIDATE_FILENAME
    source_decision_path = artifact_dir / SOURCE_DECISION_FILENAME
    if (
        not candidate_path.is_file()
        or candidate_path.is_symlink()
        or not source_decision_path.is_file()
        or source_decision_path.is_symlink()
    ):
        raise ValueError("artifact directory is missing the candidate or source decision")

    candidate = require_object(candidate_path)
    candidate = validate_reference_candidate(candidate)
    validate_candidate_origin(
        candidate,
        args.artifact_prefix,
        args.url_prefix,
        args.expected_run_id,
        args.expected_run_attempt,
    )
    candidate_sha256 = evaluator.file_sha256(candidate_path)
    validate_site_layout(args.store_root, args.latest)
    tool_root = args.store_root.resolve() / "pipelock"
    record_dir = tool_root / candidate_sha256
    latest_path = args.latest.resolve()
    previous_candidate_sha256 = None
    previous_record_manifest_sha256 = None

    if existing_promotion_is_complete(latest_path, record_dir, candidate_sha256):
        baseline_snapshot = record_dir / BASELINE_SNAPSHOT_FILENAME
        if evaluator.file_sha256(args.baseline.resolve()) != evaluator.file_sha256(baseline_snapshot):
            raise ValueError("latest-verified record and reviewed baseline are out of sync")
        if args.summary is not None:
            stored_candidate = require_object(record_dir / CANDIDATE_FILENAME)
            destination_decision_path = record_dir / DESTINATION_PROMOTION_DECISION_FILENAME
            if not destination_decision_path.is_file():
                destination_decision_path = record_dir / SOURCE_PROMOTION_DECISION_FILENAME
            stored_destination_decision = require_object(destination_decision_path)
            write_summary(
                args.summary.resolve(),
                stored_candidate,
                candidate_sha256,
                stored_destination_decision,
                bool(stored_destination_decision.get("failures"))
                or stored_destination_decision.get("promotion_status")
                == "scope_changed_requires_review",
                record_dir / provenance.RAW_EVIDENCE["results"],
            )
        print(f"promotion already complete for {candidate_sha256}")
        return record_dir

    if candidate.get("schema_version") != ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION:
        raise ValueError(
            "new promotions require active provenance candidate schema_version "
            f"{ACTIVE_PROVENANCE_CANDIDATE_SCHEMA_VERSION}"
        )

    if latest_path.is_file():
        previous = validate_pointer(require_object(latest_path), latest_path)
        previous_candidate_sha256 = previous["candidate_sha256"]
        previous_record_manifest_sha256 = previous["record_manifest_sha256"]
        previous_record = tool_root / previous["candidate_sha256"]
        validate_record(previous_record, previous["candidate_sha256"])
        if (
            evaluator.file_sha256(previous_record / RECORD_MANIFEST_FILENAME)
            != previous["record_manifest_sha256"]
        ):
            raise ValueError("existing latest pointer does not match its append-only record")
        previous_time = parse_timestamp(previous["generated_at"], "previous generated_at")
        current_time = parse_timestamp(candidate.get("generated_at"), "candidate generated_at")
        if current_time <= previous_time:
            raise ValueError("refusing to move latest-verified backward or sideways in time")

    paths = evidence_paths(artifact_dir, candidate)
    validate_execution_decision(paths["execution_decision"])
    validate_new_candidate_evidence(candidate, paths)

    source_baseline = (getattr(args, "source_baseline", None) or args.baseline).resolve()
    destination_baseline = args.baseline.resolve()
    source_baseline_bytes = source_baseline.read_bytes()
    source_baseline_origin_path = getattr(args, "source_baseline_origin", None)
    if source_baseline_origin_path is None:
        raise ValueError("--source-baseline-origin is required: a record must state whose policy judged it")
    source_baseline_origin_path = Path(source_baseline_origin_path).resolve()
    load_source_baseline_origin(source_baseline_origin_path, source_baseline_bytes)
    source_baseline_origin_bytes = source_baseline_origin_path.read_bytes()
    destination_baseline_bytes = destination_baseline.read_bytes()
    source_decision_bytes = source_decision_path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="gauntlet-baseline-snapshots-") as temporary:
        snapshot_root = Path(temporary)
        source_baseline_snapshot = snapshot_root / SOURCE_BASELINE_FILENAME
        destination_baseline_snapshot = snapshot_root / DESTINATION_BASELINE_FILENAME
        source_decision_snapshot = snapshot_root / SOURCE_PROMOTION_DECISION_FILENAME
        source_baseline_snapshot.write_bytes(source_baseline_bytes)
        destination_baseline_snapshot.write_bytes(destination_baseline_bytes)
        source_decision_snapshot.write_bytes(source_decision_bytes)
        source_decision = require_object(source_decision_snapshot)
        fresh_source_decision = evaluator.evaluate(
            candidate_path, source_baseline_snapshot, paths
        )
        destination_decision = evaluator.evaluate(
            candidate_path, destination_baseline_snapshot, paths
        )
    if source_decision != fresh_source_decision:
        raise ValueError("source decision does not match a fresh evaluation against the source baseline")
    failures = destination_decision.get("failures")
    if not isinstance(failures, list):
        raise ValueError("destination decision failures must be an array")
    scope_change = destination_decision.get("promotion_status") == "scope_changed_requires_review"
    source_blocked = fresh_source_decision.get("blocked") is not False
    policy_change = bool(failures) or scope_change or source_blocked
    if policy_change and not args.accept_policy_change:
        raise ValueError(
            "candidate requires an explicit reviewed policy-change proposal"
        )
    if failures:
        unreviewable = [failure for failure in failures if not reviewable_policy_failure(failure)]
        if unreviewable:
            raise ValueError("candidate has non-reviewable failures: " + "; ".join(unreviewable))

    baseline = proposed_baseline(candidate, candidate_sha256)
    with tempfile.TemporaryDirectory(prefix="gauntlet-promotion-") as temporary:
        proposed_baseline_path = Path(temporary) / BASELINE_SNAPSHOT_FILENAME
        evaluator.atomic_json_write(proposed_baseline_path, baseline)
        reviewed_decision = evaluator.evaluate(candidate_path, proposed_baseline_path, paths)
        if reviewed_decision.get("blocked") is not False:
            raise ValueError(
                "candidate remains blocked against its proposed baseline: "
                + "; ".join(reviewed_decision.get("failures", []))
            )

        tool_root.mkdir(parents=True, exist_ok=True)
        temporary_record = Path(tempfile.mkdtemp(prefix=f".{candidate_sha256}.", dir=tool_root))
        try:
            atomic_copy(candidate_path, temporary_record / CANDIDATE_FILENAME)
            (temporary_record / SOURCE_PROMOTION_DECISION_FILENAME).write_bytes(
                source_decision_bytes
            )
            (temporary_record / SOURCE_BASELINE_FILENAME).write_bytes(source_baseline_bytes)
            (temporary_record / SOURCE_BASELINE_ORIGIN_FILENAME).write_bytes(
                source_baseline_origin_bytes
            )
            (temporary_record / DESTINATION_BASELINE_FILENAME).write_bytes(
                destination_baseline_bytes
            )
            evaluator.atomic_json_write(
                temporary_record / DESTINATION_PROMOTION_DECISION_FILENAME,
                destination_decision,
            )
            for path in paths.values():
                atomic_copy(path, temporary_record / path.name)
            evaluator.atomic_json_write(
                temporary_record / PUBLISHED_DECISION_FILENAME, reviewed_decision
            )
            atomic_copy(proposed_baseline_path, temporary_record / BASELINE_SNAPSHOT_FILENAME)
            record_manifest = manifest_for(
                temporary_record,
                candidate,
                previous_candidate_sha256,
                previous_record_manifest_sha256,
            )
            if record_manifest["candidate_sha256"] != candidate_sha256:
                raise ValueError("candidate changed while preparing the append-only record")
            record_manifest = artifact_schema.validate_file(
                record_manifest,
                PROMOTED_RECORD_SCHEMAS[ACTIVE_PROMOTED_RECORD_SCHEMA_VERSION],
                "record manifest",
            )
            evaluator.atomic_json_write(
                temporary_record / RECORD_MANIFEST_FILENAME, record_manifest
            )
            if record_dir.exists():
                validate_record(record_dir, candidate_sha256)
                raise ValueError("append-only record already exists without a matching latest pointer")
            os.replace(temporary_record, record_dir)
        finally:
            if temporary_record.exists():
                shutil.rmtree(temporary_record)

    manifest_sha256 = evaluator.file_sha256(record_dir / RECORD_MANIFEST_FILENAME)
    record_path, record_manifest_path = canonical_pointer_paths(latest_path, candidate_sha256)
    pointer = {
        "schema_version": 1,
        "status": "verified",
        "assurances": FIRST_PARTY_ASSURANCES,
        "tool": "pipelock",
        "tool_version": require_non_empty_string(candidate, "tool_version"),
        "generated_at": require_non_empty_string(candidate, "generated_at"),
        "artifact_id": require_non_empty_string(candidate, "artifact_id"),
        "canonical_url": require_non_empty_string(candidate, "canonical_url"),
        "candidate_sha256": candidate_sha256,
        "record_manifest_sha256": manifest_sha256,
        "previous_candidate_sha256": previous_candidate_sha256,
        "previous_record_manifest_sha256": previous_record_manifest_sha256,
        "record_path": record_path,
        "record_manifest_path": record_manifest_path,
    }
    evaluator.atomic_json_write(args.baseline.resolve(), baseline)
    evaluator.atomic_json_write(latest_path, pointer)
    if args.summary is not None:
        write_summary(
            args.summary.resolve(),
            candidate,
            candidate_sha256,
            destination_decision,
            policy_change,
            paths["results"],
        )
    print(f"prepared append-only record {record_dir}")
    print(f"advanced latest-verified to {candidate_sha256}")
    return record_dir


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument(
        "--source-baseline",
        type=Path,
        help="baseline used by the producer to create promotion-decision.json; defaults to --baseline",
    )
    parser.add_argument(
        "--source-baseline-origin",
        type=Path,
        required=True,
        help="JSON document naming the repository, commit, path and digest of the source baseline",
    )
    parser.add_argument("--store-root", type=Path, default=Path("gauntlet-site/results"))
    parser.add_argument("--latest", type=Path, default=Path("gauntlet-site") / LATEST_POINTER_FILENAME)
    parser.add_argument("--summary", type=Path)
    parser.add_argument(
        "--artifact-prefix",
        default=DEFAULT_ARTIFACT_PREFIX,
    )
    parser.add_argument(
        "--url-prefix",
        default=DEFAULT_URL_PREFIX,
    )
    parser.add_argument("--expected-run-id")
    parser.add_argument("--expected-run-attempt")
    parser.add_argument("--accept-policy-change", action="store_true")
    return parser.parse_args()


def main():
    try:
        promote(parse_args())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"promotion: BLOCKED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
