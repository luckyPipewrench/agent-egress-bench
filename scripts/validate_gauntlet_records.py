#!/usr/bin/env python3
"""Validate every retained Gauntlet record and the latest-verified pointer."""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import build_gauntlet_provenance as provenance
import evaluate_gauntlet_candidate as evaluator
import promote_gauntlet_candidate as promotion


RESULTS_PATH = Path("gauntlet-site/results/pipelock")


def reconstruct_candidate(record_dir, candidate, repo_root):
    corpus_git_sha = promotion.require_non_empty_string(candidate, "corpus_git_sha")
    if len(corpus_git_sha) != 40 or any(char not in "0123456789abcdef" for char in corpus_git_sha):
        raise ValueError(f"{record_dir}: corpus_git_sha must be 40 lower-case hex characters")
    manifest_at_commit = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{corpus_git_sha}:cases/MANIFEST.txt"],
        check=False,
        capture_output=True,
    )
    if manifest_at_commit.returncode != 0:
        raise ValueError(f"{record_dir}: corpus_git_sha is not a retained repository commit")
    retained_manifest = record_dir / provenance.RAW_EVIDENCE["corpus_manifest"]
    if manifest_at_commit.stdout != retained_manifest.read_bytes():
        raise ValueError(f"{record_dir}: retained corpus manifest differs from corpus_git_sha")
    with tempfile.TemporaryDirectory(prefix="gauntlet-record-validation-") as temporary:
        root = Path(temporary)
        (root / "cases").mkdir()
        shutil.copyfile(
            record_dir / provenance.RAW_EVIDENCE["corpus_manifest"],
            root / "cases" / "MANIFEST.txt",
        )
        rebuilt = root / promotion.CANDIDATE_FILENAME
        provenance.finalize_command(
            SimpleNamespace(
                repo_root=root,
                bundle=record_dir / promotion.RUN_BUNDLE_FILENAME,
                artifact_id=candidate["artifact_id"],
                canonical_url=candidate["canonical_url"],
                output=rebuilt,
            )
        )
        if rebuilt.read_bytes() != (record_dir / promotion.CANDIDATE_FILENAME).read_bytes():
            raise ValueError(f"{record_dir}: candidate does not match a fresh evidence reconstruction")


def validate_decision(record_dir, candidate_path, baseline_filename, decision_filename):
    baseline_path = record_dir / baseline_filename
    decision_path = record_dir / decision_filename
    candidate = evaluator.load_object(candidate_path)
    paths = {
        label: record_dir / filename
        for label, filename in promotion.evidence_files_for(candidate).items()
    }
    expected = evaluator.evaluate(candidate_path, baseline_path, paths)
    actual = evaluator.load_object(decision_path)
    if actual != expected:
        raise ValueError(f"{record_dir}: {decision_filename} does not match a fresh evaluation")
    return actual


def validate_record(record_dir, repo_root):
    digest = promotion.require_sha256(record_dir.name, "record directory name")
    manifest = promotion.validate_record(record_dir, digest)
    candidate_path = record_dir / promotion.CANDIDATE_FILENAME
    candidate = evaluator.load_object(candidate_path)
    if evaluator.file_sha256(candidate_path) != digest:
        raise ValueError(f"{record_dir}: candidate digest does not match its directory")
    promotion.validate_reference_candidate(candidate)
    promotion.validate_candidate_origin(
        candidate,
        promotion.DEFAULT_ARTIFACT_PREFIX,
        promotion.DEFAULT_URL_PREFIX,
        None,
    )
    promotion.validate_execution_decision(record_dir / promotion.EXECUTION_DECISION_FILENAME)
    reconstruct_candidate(record_dir, candidate, repo_root)
    validate_decision(
        record_dir,
        candidate_path,
        promotion.SOURCE_BASELINE_FILENAME,
        promotion.SOURCE_PROMOTION_DECISION_FILENAME,
    )
    reviewed = validate_decision(
        record_dir,
        candidate_path,
        promotion.BASELINE_SNAPSHOT_FILENAME,
        promotion.PUBLISHED_DECISION_FILENAME,
    )
    if reviewed.get("blocked") is not False:
        raise ValueError(f"{record_dir}: reviewed promotion decision is blocked")
    return candidate, manifest


def require_predecessor_older(predecessor, successor):
    predecessor_time = promotion.parse_timestamp(
        predecessor["generated_at"], "predecessor generated_at"
    )
    successor_time = promotion.parse_timestamp(
        successor["generated_at"], "successor generated_at"
    )
    if predecessor_time >= successor_time:
        raise ValueError("append-only record chain is not strictly chronological")


def validate_immutable_history(repo_root, base_ref):
    ancestor = subprocess.run(
        ["git", "-C", str(repo_root), "merge-base", "--is-ancestor", base_ref, "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    if ancestor.returncode != 0:
        raise ValueError(f"immutable base is not an ancestor of HEAD: {base_ref}")
    listing = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            base_ref,
            "--",
            RESULTS_PATH.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if listing.returncode != 0:
        raise ValueError(f"cannot inspect append-only records at immutable base: {base_ref}")
    for raw_path in listing.stdout.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        current = repo_root / relative
        if current.is_symlink() or not current.is_file():
            raise ValueError(f"append-only history deleted a retained file: {relative}")
        original = subprocess.run(
            ["git", "-C", str(repo_root), "show", f"{base_ref}:{relative.as_posix()}"],
            check=False,
            capture_output=True,
        )
        if original.returncode != 0 or original.stdout != current.read_bytes():
            raise ValueError(f"append-only history modified a retained file: {relative}")


def validate(site_root, baseline_path, repo_root):
    results_root = site_root / "results" / "pipelock"
    latest_path = site_root / promotion.LATEST_POINTER_FILENAME
    if not results_root.exists():
        if latest_path.exists():
            raise ValueError("latest-verified exists without an append-only result store")
        print("Gauntlet record validation: OK (no promoted records yet)")
        return
    if results_root.is_symlink() or not results_root.is_dir():
        raise ValueError("Pipelock result store must be a real directory")

    records = {}
    for entry in sorted(results_root.iterdir(), key=lambda item: item.name):
        if entry.is_symlink() or not entry.is_dir():
            raise ValueError(f"unexpected non-directory result-store entry: {entry}")
        candidate, manifest = validate_record(entry, repo_root)
        records[entry.name] = (entry, candidate, manifest)
    if not records:
        raise ValueError("Pipelock result store is empty")
    if not latest_path.is_file() or latest_path.is_symlink():
        raise ValueError("append-only records exist without latest-verified")

    pointer = promotion.validate_pointer(evaluator.load_object(latest_path), latest_path)
    digest = pointer["candidate_sha256"]
    if digest not in records:
        raise ValueError("latest-verified points outside the retained result set")
    record_dir, candidate, manifest = records[digest]
    if evaluator.file_sha256(record_dir / promotion.RECORD_MANIFEST_FILENAME) != pointer[
        "record_manifest_sha256"
    ]:
        raise ValueError("latest-verified record manifest digest is wrong")
    for field in ("artifact_id", "canonical_url", "tool", "tool_version", "generated_at"):
        if pointer.get(field) != candidate.get(field):
            raise ValueError(f"latest-verified and selected candidate disagree on {field}")
    newest_digest = max(
        records,
        key=lambda value: promotion.parse_timestamp(
            records[value][1]["generated_at"], f"{value} generated_at"
        ),
    )
    if digest != newest_digest:
        raise ValueError("latest-verified does not select the newest retained record")
    if evaluator.file_sha256(baseline_path) != evaluator.file_sha256(
        record_dir / promotion.BASELINE_SNAPSHOT_FILENAME
    ):
        raise ValueError("reviewed baseline does not match latest-verified")
    if manifest["candidate_sha256"] != digest:
        raise ValueError("selected record manifest and pointer candidate digests differ")
    for field in ("previous_candidate_sha256", "previous_record_manifest_sha256"):
        if pointer.get(field) != manifest.get(field):
            raise ValueError(f"latest-verified and selected manifest disagree on {field}")

    visited = set()
    current_digest = digest
    expected_manifest_digest = pointer["record_manifest_sha256"]
    successor_candidate = None
    while current_digest is not None:
        if current_digest in visited:
            raise ValueError("append-only record chain contains a cycle")
        if current_digest not in records:
            raise ValueError("append-only record chain is missing a predecessor")
        visited.add(current_digest)
        current_dir, current_candidate, current_manifest = records[current_digest]
        if successor_candidate is not None:
            require_predecessor_older(current_candidate, successor_candidate)
        successor_candidate = current_candidate
        actual_manifest_digest = evaluator.file_sha256(
            current_dir / promotion.RECORD_MANIFEST_FILENAME
        )
        if actual_manifest_digest != expected_manifest_digest:
            raise ValueError("append-only record chain manifest digest is wrong")
        current_digest = current_manifest.get("previous_candidate_sha256")
        expected_manifest_digest = current_manifest.get("previous_record_manifest_sha256")
    if visited != set(records):
        raise ValueError("result store contains records outside the append-only chain")
    print(f"Gauntlet record validation: OK ({len(records)} append-only record(s))")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--site-root", type=Path, default=Path("gauntlet-site"))
    parser.add_argument("--baseline", type=Path, default=Path("ci/gauntlet-baseline.json"))
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--immutable-base")
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        if args.immutable_base is not None:
            validate_immutable_history(args.repo_root.resolve(), args.immutable_base)
        validate(args.site_root.resolve(), args.baseline.resolve(), args.repo_root.resolve())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"Gauntlet record validation: BLOCKED: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
