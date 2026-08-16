#!/usr/bin/env python3
"""Tests for retained Gauntlet record and pointer validation."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


provenance = load_module("build_gauntlet_provenance")
evaluator = load_module("evaluate_gauntlet_candidate")
promotion = load_module("promote_gauntlet_candidate")
validator = load_module("validate_gauntlet_records")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ValidRecordFixture:
    def __init__(self, root):
        self.root = root
        self.artifact_dir = root / "artifact"
        self.artifact_dir.mkdir()
        self.corpus_root = root / "corpus"
        (self.corpus_root / "cases").mkdir(parents=True)
        manifest = "attack-a\nattack-b\nbenign-a\n"
        (self.corpus_root / "cases" / "MANIFEST.txt").write_text(manifest, encoding="utf-8")
        (self.corpus_root / "contracts").mkdir()
        shutil.copy2(REPO_ROOT / "contracts" / "artifacts.json", self.corpus_root / "contracts")
        shutil.copy2(REPO_ROOT / "contracts" / "result-states-v5.json", self.corpus_root / "contracts")
        (self.artifact_dir / "corpus-manifest.txt").write_text(manifest, encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.corpus_root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "config", "user.name", "Gauntlet Test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "config", "user.email", "test@vendor.example"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "config", "commit.gpgsign", "false"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "config", "core.hooksPath", "/dev/null"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "add", "."], check=True
        )
        subprocess.run(
            ["git", "-C", str(self.corpus_root), "commit", "-q", "-m", "fixture"],
            check=True,
        )
        corpus_git_sha = subprocess.check_output(
            ["git", "-C", str(self.corpus_root), "rev-parse", "HEAD"], text=True
        ).strip()

        capability_snapshot = json.dumps(
            {
                "id": "aeb.test-capabilities",
                "format": 1,
                "revision": 1,
                "entries": [{"id": "test", "status": "active"}],
            },
            sort_keys=True,
        ).encode()
        capability_registry = {
            "id": "aeb.test-capabilities",
            "format": 1,
            "revision": 1,
            "sha256": hashlib.sha256(capability_snapshot).hexdigest(),
        }
        tool_profile = json.dumps(
            {"capability_registry": capability_registry, "claims": ["test"]},
            sort_keys=True,
        ).encode()
        (self.artifact_dir / "capability-registry.json").write_bytes(capability_snapshot)
        (self.artifact_dir / "tool-profile.json").write_bytes(tool_profile)
        write_json(
            self.artifact_dir / "receipt-profile.json",
            {"capability_registry": capability_registry},
        )

        rows = [
            {
                "schema_version": 5,
                "case_id": case_id,
                "tool": "pipelock",
                "tool_version": "3.3.0",
                "expected_verdict": expected,
                "actual_verdict": actual,
                "score": "pass",
                "evidence": {**evidence, "result_state": "observed"},
                "notes": "",
                "capability_registry": capability_registry,
            }
            for case_id, expected, actual, evidence in (
                ("attack-a", "block", "block", {"scanner": "dlp", "pattern": "a"}),
                ("attack-b", "block", "block", {"scanner": "dlp", "pattern": "b"}),
                ("benign-a", "allow", "allow", {}),
            )
        ]
        (self.artifact_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        summary = {
            "schema_version": 5,
            "gauntlet_version": "1.0",
            "scoring_version": "2.8",
            "runner_version": "0.4.3",
            "tool": "pipelock",
            "tool_version": "3.3.0",
            "corpus_version": "v-test",
            "corpus_sha256": "a" * 64,
            "tool_profile_sha256": hashlib.sha256(tool_profile).hexdigest(),
            "case_count": {
                "total": 3,
                "applicable": 3,
                "unreachable": 0,
                "not_applicable": 0,
                "not_applicable_reasons": {},
                "errors": 0,
            },
            "scores": {
                scope: {
                    "containment": 1.0,
                    "false_positive_rate": 0.0,
                }
                for scope in ("full", "applicable")
            },
            "measurement_status": "measured",
            "benchmark_manifest_sha256": "c" * 64,
            "diagnostics": {
                scope: {
                    "classification_present_rate": 1.0,
                    "structured_evidence_present_rate": 1.0,
                }
                for scope in ("full", "applicable")
            },
            "per_category": {
                "test": {
                    "applicable": 3,
                    "containment": 1.0,
                    "false_positive_rate": 0.0,
                    "diagnostics": {
                        "classification_present_rate": 1.0,
                        "structured_evidence_present_rate": 1.0,
                    },
                }
            },
            "capability_registry": capability_registry,
            "reported_claims": ["test"],
            "exercised": {
                "transports": ["http"],
                "categories": ["test"],
                "capability_tags": ["test"],
            },
            "method_repository": "luckyPipewrench/agent-egress-bench",
            "method_commit": corpus_git_sha,
            "adapter_id": "proxy",
            "adapter_owner": "Example Maintainers",
            "target_config_ref": "examples/pipelock/pipelock-benchmark.yaml",
            "target_config_sha256": "f" * 64,
        }
        write_json(self.artifact_dir / "raw-summary.json", summary)
        (self.artifact_dir / "runner.stderr").write_text(
            "Fixtures: HTTP=x TLS=x WS=x DNS=x MCP_HTTP=x\n", encoding="utf-8"
        )
        (self.artifact_dir / "command.txt").write_text(
            "timeout --signal=TERM --kill-after=30s 10s aeb-gauntlet "
            "--adapter proxy --fixtures "
            "--method-repository luckyPipewrench/agent-egress-bench "
            f"--method-commit {corpus_git_sha} "
            "--adapter-owner 'Example Maintainers' "
            "--target-config examples/pipelock/pipelock-benchmark.yaml\n",
            encoding="utf-8",
        )
        (self.artifact_dir / "make-stats.txt").write_text(
            "block: 2\nallow: 1\nwarn: 0\n", encoding="utf-8"
        )
        write_json(
            self.artifact_dir / "case-index.json",
            {
                "schema_version": 2,
                "cases": {
                    "attack-a": {"category": "test", "expected_verdict": "block"},
                    "attack-b": {"category": "test", "expected_verdict": "block"},
                    "benign-a": {"category": "test", "expected_verdict": "allow"},
                },
            },
        )
        (self.artifact_dir / "entrypoint-command.txt").write_text(
            "./scripts/run-pipelock-gauntlet.sh\n", encoding="utf-8"
        )
        write_json(
            self.artifact_dir / "run-metadata.json",
            {
                "schema_version": 1,
                "local_run_id": "local:test:1",
                "generated_at": "2026-08-05T00:10:08Z",
                "corpus_repository": "luckyPipewrench/agent-egress-bench",
                "corpus_ref_kind": "origin/main",
                "corpus_git_sha": corpus_git_sha,
                "dirty": False,
                "canonical_execution": True,
                "noncanonical_reasons": [],
            },
        )
        write_json(
            self.artifact_dir / "pipelock-release.json",
            {
                "schema_version": 1,
                "repository": "luckyPipewrench/pipelock",
                "tag": "v3.3.0",
                "version": "3.3.0",
                "asset": "pipelock_3.3.0_linux_amd64.tar.gz",
                "asset_sha256": "d" * 64,
                "binary_sha256": "e" * 64,
                "version_output": "pipelock version 3.3.0",
                "released_binary": True,
            },
        )
        (self.artifact_dir / "checksums.txt").write_text(
            "d" * 64 + "  pipelock_3.3.0_linux_amd64.tar.gz\n", encoding="utf-8"
        )
        (self.artifact_dir / "pipelock-version.txt").write_text(
            "pipelock version 3.3.0\n", encoding="utf-8"
        )

        bundle = provenance.build_complete_bundle(self.corpus_root, self.artifact_dir)
        write_json(self.artifact_dir / promotion.RUN_BUNDLE_FILENAME, bundle)
        write_json(
            self.artifact_dir / promotion.EXECUTION_DECISION_FILENAME,
            {
                "schema_version": 1,
                "local_run_id": bundle["local_run_id"],
                "blocked": False,
                "execution_status": "complete",
                "publication_eligible": True,
                "failures": [],
                "review_notes": [],
                "evidence_sha256": bundle["evidence_sha256"],
            },
        )
        candidate = dict(bundle["candidate_scope"])
        candidate.update(
            {
                "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
                "canonical_url": (
                    "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123"
                ),
                "portable_bundle_sha256": evaluator.file_sha256(
                    self.artifact_dir / promotion.RUN_BUNDLE_FILENAME
                ),
            }
        )
        self.candidate_path = self.artifact_dir / promotion.CANDIDATE_FILENAME
        write_json(self.candidate_path, candidate)
        candidate_digest = evaluator.file_sha256(self.candidate_path)
        self.baseline = root / "baseline.json"
        write_json(self.baseline, promotion.proposed_baseline(candidate, candidate_digest))
        evidence = {
            label: self.artifact_dir / filename
            for label, filename in promotion.evidence_files_for(candidate).items()
        }
        write_json(
            self.artifact_dir / promotion.SOURCE_DECISION_FILENAME,
            evaluator.evaluate(self.candidate_path, self.baseline, evidence),
        )
        self.site = root / "site"
        promotion.promote(
            SimpleNamespace(
                artifact_dir=self.artifact_dir,
                baseline=self.baseline,
                store_root=self.site / "results",
                latest=self.site / promotion.LATEST_POINTER_FILENAME,
                summary=None,
                artifact_prefix="github-actions:luckyPipewrench/agent-egress-bench:",
                url_prefix=(
                    "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/"
                ),
                expected_run_id="123",
                expected_run_attempt=None,
                accept_policy_change=False,
            )
        )

    def promote_newer(self):
        run_metadata_path = self.artifact_dir / "run-metadata.json"
        run_metadata = evaluator.load_object(run_metadata_path)
        run_metadata["local_run_id"] = "local:test:2"
        run_metadata["generated_at"] = "2026-08-06T00:10:08Z"
        write_json(run_metadata_path, run_metadata)

        bundle = provenance.build_complete_bundle(self.corpus_root, self.artifact_dir)
        write_json(self.artifact_dir / promotion.RUN_BUNDLE_FILENAME, bundle)
        write_json(
            self.artifact_dir / promotion.EXECUTION_DECISION_FILENAME,
            {
                "schema_version": 1,
                "local_run_id": bundle["local_run_id"],
                "blocked": False,
                "execution_status": "complete",
                "publication_eligible": True,
                "failures": [],
                "review_notes": [],
                "evidence_sha256": bundle["evidence_sha256"],
            },
        )
        candidate = dict(bundle["candidate_scope"])
        candidate.update(
            {
                "artifact_id": promotion.DEFAULT_ARTIFACT_PREFIX + "124",
                "canonical_url": promotion.DEFAULT_URL_PREFIX + "124",
                "portable_bundle_sha256": evaluator.file_sha256(
                    self.artifact_dir / promotion.RUN_BUNDLE_FILENAME
                ),
            }
        )
        write_json(self.candidate_path, candidate)
        evidence = {
            label: self.artifact_dir / filename
            for label, filename in promotion.evidence_files_for(candidate).items()
        }
        write_json(
            self.artifact_dir / promotion.SOURCE_DECISION_FILENAME,
            evaluator.evaluate(self.candidate_path, self.baseline, evidence),
        )
        promotion.promote(
            SimpleNamespace(
                artifact_dir=self.artifact_dir,
                baseline=self.baseline,
                store_root=self.site / "results",
                latest=self.site / promotion.LATEST_POINTER_FILENAME,
                summary=None,
                artifact_prefix=promotion.DEFAULT_ARTIFACT_PREFIX,
                url_prefix=promotion.DEFAULT_URL_PREFIX,
                expected_run_id="124",
                expected_run_attempt=None,
                accept_policy_change=False,
            )
        )


class ValidateGauntletRecordsTest(unittest.TestCase):
    def root(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def immutable_repo(self):
        root = self.root()
        retained = root / validator.RESULTS_PATH / "record-a" / "evidence.json"
        retained.parent.mkdir(parents=True)
        retained.write_text('{"value":"original"}\n', encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for key, value in (
            ("user.name", "Gauntlet Test"),
            ("user.email", "test@vendor.example"),
            ("commit.gpgsign", "false"),
            ("core.hooksPath", "/dev/null"),
        ):
            subprocess.run(
                ["git", "-C", str(root), "config", key, value], check=True
            )
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-q", "-m", "fixture"], check=True
        )
        base = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
        ).strip()
        return root, base, retained

    def test_no_promoted_records_is_valid_before_first_publication(self):
        root = self.root()
        baseline = root / "baseline.json"
        baseline.write_text("{}\n", encoding="utf-8")
        validator.validate(root / "site", baseline, REPO_ROOT)

    def test_immutable_history_allows_new_records(self):
        root, base, _ = self.immutable_repo()
        added = root / validator.RESULTS_PATH / "record-b" / "evidence.json"
        added.parent.mkdir(parents=True)
        added.write_text('{"value":"new"}\n', encoding="utf-8")
        validator.validate_immutable_history(root, base)

    def test_immutable_history_rejects_modified_or_deleted_files(self):
        for action in ("modified", "deleted"):
            with self.subTest(action=action):
                root, base, retained = self.immutable_repo()
                if action == "modified":
                    retained.write_text('{"value":"changed"}\n', encoding="utf-8")
                else:
                    retained.unlink()
                with self.assertRaisesRegex(ValueError, f"{action} a retained file"):
                    validator.validate_immutable_history(root, base)

    def test_complete_promoted_record_reconstructs_from_retained_evidence(self):
        fixture = ValidRecordFixture(self.root())
        validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_evidence_tamper_fails_even_if_record_manifest_is_rewritten(self):
        fixture = ValidRecordFixture(self.root())
        pointer_path = fixture.site / promotion.LATEST_POINTER_FILENAME
        pointer = evaluator.load_object(pointer_path)
        record = fixture.site / "results" / "pipelock" / pointer["candidate_sha256"]
        (record / "results.jsonl").write_text("tampered\n", encoding="utf-8")
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["files"]["results.jsonl"] = evaluator.file_sha256(record / "results.jsonl")
        write_json(manifest_path, manifest)
        pointer["record_manifest_sha256"] = evaluator.file_sha256(manifest_path)
        write_json(pointer_path, pointer)
        with self.assertRaisesRegex(ValueError, "evidence results changed"):
            validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_root_baseline_must_match_selected_record(self):
        fixture = ValidRecordFixture(self.root())
        fixture.baseline.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "reviewed baseline does not match"):
            validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_missing_predecessor_breaks_append_only_chain(self):
        fixture = ValidRecordFixture(self.root())
        pointer_path = fixture.site / promotion.LATEST_POINTER_FILENAME
        pointer = evaluator.load_object(pointer_path)
        record = fixture.site / "results" / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["previous_candidate_sha256"] = "f" * 64
        manifest["previous_record_manifest_sha256"] = "e" * 64
        write_json(manifest_path, manifest)
        pointer["previous_candidate_sha256"] = "f" * 64
        pointer["previous_record_manifest_sha256"] = "e" * 64
        pointer["record_manifest_sha256"] = evaluator.file_sha256(manifest_path)
        write_json(pointer_path, pointer)
        with self.assertRaisesRegex(ValueError, "missing a predecessor"):
            validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_record_outside_append_only_chain_is_rejected(self):
        fixture = ValidRecordFixture(self.root())
        fixture.promote_newer()
        pointer_path = fixture.site / promotion.LATEST_POINTER_FILENAME
        pointer = evaluator.load_object(pointer_path)
        newest = fixture.site / "results" / "pipelock" / pointer["candidate_sha256"]
        manifest_path = newest / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["previous_candidate_sha256"] = None
        manifest["previous_record_manifest_sha256"] = None
        write_json(manifest_path, manifest)
        pointer["previous_candidate_sha256"] = None
        pointer["previous_record_manifest_sha256"] = None
        pointer["record_manifest_sha256"] = evaluator.file_sha256(manifest_path)
        write_json(pointer_path, pointer)
        with self.assertRaisesRegex(ValueError, "outside the append-only chain"):
            validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_latest_pointer_must_select_newest_record(self):
        fixture = ValidRecordFixture(self.root())
        first_pointer = evaluator.load_object(
            fixture.site / promotion.LATEST_POINTER_FILENAME
        )
        first_record = (
            fixture.site / "results" / "pipelock" / first_pointer["candidate_sha256"]
        )
        first_candidate = evaluator.load_object(first_record / promotion.CANDIDATE_FILENAME)
        fixture.promote_newer()

        pointer = {
            **first_pointer,
            **{
                field: first_candidate[field]
                for field in ("artifact_id", "canonical_url", "tool", "tool_version", "generated_at")
            },
        }
        write_json(fixture.site / promotion.LATEST_POINTER_FILENAME, pointer)
        (fixture.baseline).write_bytes(
            (first_record / promotion.BASELINE_SNAPSHOT_FILENAME).read_bytes()
        )
        with self.assertRaisesRegex(ValueError, "does not select the newest"):
            validator.validate(fixture.site, fixture.baseline, fixture.corpus_root)

    def test_append_only_chain_timestamps_must_strictly_decrease(self):
        with self.assertRaisesRegex(ValueError, "not strictly chronological"):
            validator.require_predecessor_older(
                {"generated_at": "2026-08-06T00:10:08Z"},
                {"generated_at": "2026-08-06T00:10:08Z"},
            )


if __name__ == "__main__":
    unittest.main()
