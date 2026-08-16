#!/usr/bin/env python3
"""Tests for reviewed append-only Gauntlet result promotion."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "promote_gauntlet_candidate.py"


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


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def baseline():
    return {
        "_comment": "Reviewed baseline for the continuous Gauntlet lane.",
        "schema_version": 1,
        "recorded_on": "2026-08-01",
        "verified_candidate_sha256": "a" * 64,
        "verified_artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:122",
        "pipelock_version": "3.3.0",
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "corpus_version": "v2.3.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
        "observed_case_count": {
            "total": 213,
            "applicable": 212,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
        },
        "score_floors": {
            "full": {"containment": 0.99},
            "applicable": {"containment": 1.0, "detection": 1.0, "evidence": 1.0},
        },
        "score_ceilings": {"applicable": {"false_positive_rate": 0.0}},
    }


def candidate(run_id="123", run_attempt=None, generated_at="2026-08-05T00:10:08Z"):
    artifact_suffix = run_id if run_attempt is None else f"{run_id}:{run_attempt}"
    return {
        "schema_version": 2,
        "artifact_id": f"github-actions:luckyPipewrench/agent-egress-bench:{artifact_suffix}",
        "canonical_url": (
            "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/" + run_id
        ),
        "generated_at": generated_at,
        "tool": "pipelock",
        "tool_version": "3.3.0",
        "pipelock_version": "3.3.0",
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "corpus_manifest_sha256": "d" * 64,
        "corpus_version": "v2.3.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
        "logical_case_count": 213,
        "case_count": {
            "total": 213,
            "applicable": 212,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
            "errors": 0,
        },
        "metric_counts": {
            "full": {
                "containment": {"numerator": 157, "denominator": 158},
                "detection": {"numerator": 157, "denominator": 157},
                "evidence": {"numerator": 157, "denominator": 157},
                "false_positive_rate": {"numerator": 0, "denominator": 55},
            },
            "applicable": {
                "containment": {"numerator": 158, "denominator": 158},
                "detection": {"numerator": 157, "denominator": 157},
                "evidence": {"numerator": 157, "denominator": 157},
                "false_positive_rate": {"numerator": 0, "denominator": 54},
            },
        },
        "scores": {
            "full": {
                "containment": 157 / 158,
                "detection": 1.0,
                "evidence": 1.0,
                "false_positive_rate": 0.0,
            },
            "applicable": {
                "containment": 1.0,
                "detection": 1.0,
                "evidence": 1.0,
                "false_positive_rate": 0.0,
            },
        },
        "sufficient": True,
    }


class PromotionFixture:
    def __init__(self, root, candidate_value=None, baseline_value=None):
        self.root = root
        self.artifact_dir = root / "artifact"
        self.artifact_dir.mkdir(parents=True)
        self.store_root = root / "site" / "results"
        self.latest = root / "site" / "latest-verified.json"
        self.baseline_path = root / "baseline.json"
        self.summary = root / "promotion-summary.md"
        write_json(self.baseline_path, baseline_value or baseline())

        self.evidence = {}
        for label, filename in promotion.EVIDENCE_FILES.items():
            path = self.artifact_dir / filename
            if label == "execution_decision":
                write_json(
                    path,
                    {
                        "schema_version": 1,
                        "execution_status": "complete",
                        "blocked": False,
                        "publication_eligible": True,
                        "failures": [],
                    },
                )
            elif label == "results":
                path.write_text(
                    json.dumps(
                        {
                            "case_id": "case-1",
                            "expected_verdict": "block",
                            "actual_verdict": "block",
                            "score": "pass",
                            "evidence": {},
                            "notes": "",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
            else:
                path.write_text(f"{label}\n", encoding="utf-8")
            self.evidence[label] = path

        value = candidate_value or candidate()
        value["case_index_sha256"] = hashlib.sha256(
            self.evidence["case_index"].read_bytes()
        ).hexdigest()
        value["portable_bundle_sha256"] = hashlib.sha256(
            self.evidence["run_bundle"].read_bytes()
        ).hexdigest()
        self.candidate_value = value
        self.candidate_path = self.artifact_dir / promotion.CANDIDATE_FILENAME
        write_json(self.candidate_path, value)
        self.write_source_decision()

    def write_source_decision(self):
        decision = evaluator.evaluate(self.candidate_path, self.baseline_path, self.evidence)
        write_json(self.artifact_dir / promotion.SOURCE_DECISION_FILENAME, decision)

    def command(self, accept_policy_change=False):
        command = [
            sys.executable,
            str(SCRIPT),
            "--artifact-dir",
            str(self.artifact_dir),
            "--baseline",
            str(self.baseline_path),
            "--store-root",
            str(self.store_root),
            "--latest",
            str(self.latest),
            "--summary",
            str(self.summary),
            "--expected-run-id",
            self.candidate_value["canonical_url"].rsplit("/", 1)[1],
        ]
        artifact_parts = self.candidate_value["artifact_id"].split(":")
        if len(artifact_parts) == 4:
            command.extend(["--expected-run-attempt", artifact_parts[-1]])
        if accept_policy_change:
            command.append("--accept-policy-change")
        return command

    def run(self, accept_policy_change=False):
        return subprocess.run(
            self.command(accept_policy_change),
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


class PromoteGauntletCandidateTest(unittest.TestCase):
    def fixture(self, candidate_value=None, baseline_value=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return PromotionFixture(Path(temporary.name), candidate_value, baseline_value)

    def test_v5_baseline_contract_change_requires_explicit_review(self):
        self.assertTrue(
            promotion.reviewable_policy_failure(
                "v5 candidate requires a reviewed baseline with summary_schema_version=5"
            )
        )

    def test_legacy_candidate_baseline_round_trips_through_evaluation(self):
        fixture = self.fixture()
        generated = promotion.proposed_baseline(
            fixture.candidate_value, evaluator.file_sha256(fixture.candidate_path)
        )
        generated_path = fixture.root / "generated-legacy-baseline.json"
        write_json(generated_path, generated)

        decision = evaluator.evaluate(fixture.candidate_path, generated_path, fixture.evidence)

        self.assertNotIn("summary_schema_version", generated)
        self.assertEqual(
            set(generated["score_floors"]["applicable"]),
            {"containment", "detection", "evidence"},
        )
        self.assertFalse(decision["blocked"], decision["failures"])

    def test_v5_baseline_retains_framed_manifest_identity(self):
        value = candidate()
        value["schema_version"] = 5
        value["benchmark_manifest_sha256"] = "e" * 64

        generated = promotion.proposed_baseline(value, "f" * 64)

        self.assertEqual(generated["summary_schema_version"], 5)
        self.assertEqual(generated["benchmark_manifest_sha256"], "e" * 64)

    def test_clean_candidate_creates_append_only_record_pointer_and_baseline(self):
        fixture = self.fixture()
        original_candidate = fixture.candidate_path.read_bytes()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        pointer = evaluator.load_object(fixture.latest)
        digest = pointer["candidate_sha256"]
        record = fixture.store_root / "pipelock" / digest
        self.assertEqual((record / promotion.CANDIDATE_FILENAME).read_bytes(), original_candidate)
        self.assertEqual(
            evaluator.file_sha256(record / promotion.RECORD_MANIFEST_FILENAME),
            pointer["record_manifest_sha256"],
        )
        promoted_baseline = evaluator.load_object(fixture.baseline_path)
        self.assertEqual(promoted_baseline["verified_candidate_sha256"], digest)
        reviewed = evaluator.load_object(record / promotion.PUBLISHED_DECISION_FILENAME)
        self.assertFalse(reviewed["blocked"])
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("Scope: `212 / 213` routed", summary)
        self.assertIn("Reviewed policy change proposed: `no`", summary)

    def test_same_promotion_is_idempotent(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        fixture.summary.unlink()
        second = fixture.run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("already complete", second.stdout)
        self.assertTrue(fixture.summary.is_file())

    def test_score_regression_needs_explicit_policy_change(self):
        value = candidate()
        value["scores"]["full"]["containment"] = 0.98
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual(
            evaluator.load_object(fixture.baseline_path)["score_floors"]["full"]["containment"],
            0.98,
        )

    def test_false_positive_regression_needs_explicit_policy_change(self):
        value = candidate()
        value["metric_counts"]["applicable"]["false_positive_rate"]["numerator"] = 1
        value["scores"]["applicable"]["false_positive_rate"] = 1 / 54
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("above baseline ceiling", fixture.summary.read_text(encoding="utf-8"))

    def test_pinned_version_move_needs_explicit_policy_change(self):
        value = candidate()
        value["pipelock_version"] = "3.4.0"
        value["tool_version"] = "3.4.0"
        fixture = self.fixture(value)
        self.assertNotEqual(fixture.run().returncode, 0)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual(
            evaluator.load_object(fixture.baseline_path)["pipelock_version"], "3.4.0"
        )

    def test_scope_identity_move_needs_explicit_policy_change(self):
        value = candidate()
        value["corpus_sha256"] = "a" * 64
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("Reviewed policy change proposed: `yes`", summary)

    def test_summary_names_nonpassing_case_and_boundary_timing(self):
        fixture = self.fixture()
        fixture.evidence["results"].write_text(
            json.dumps(
                {
                    "case_id": "budget-boundary-1",
                    "expected_verdict": "block",
                    "actual_verdict": "allow",
                    "score": "fail",
                    "evidence": {
                        "budget_block_timing": "before_over_budget",
                        "error_message": "blocked at 4/3",
                    },
                    "notes": "",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        fixture.write_source_decision()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("`budget-boundary-1`:", summary)
        self.assertIn("before_over_budget; blocked at 4/3", summary)

    def test_structural_failure_cannot_be_overridden(self):
        value = candidate()
        value["sufficient"] = False
        fixture = self.fixture(value)
        result = fixture.run(accept_policy_change=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-reviewable failures", result.stdout)
        self.assertFalse(fixture.latest.exists())

    def test_evidence_changed_after_source_decision_is_rejected(self):
        fixture = self.fixture()
        fixture.evidence["results"].write_text("tampered\n", encoding="utf-8")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source decision does not match", result.stdout)

    def test_record_mutation_breaks_idempotent_promotion(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record_candidate = (
            fixture.store_root
            / "pipelock"
            / pointer["candidate_sha256"]
            / promotion.CANDIDATE_FILENAME
        )
        record_candidate.write_text("{}\n", encoding="utf-8")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing record file changed", result.stdout)

    def test_record_manifest_identity_must_match_candidate(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["tool_version"] = "9.9.9"
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(
            ValueError, "record manifest and candidate disagree on tool_version"
        ):
            promotion.validate_record(record, pointer["candidate_sha256"])

    def test_record_manifest_schema_is_enforced(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["schema_version"] = 2
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "manifest schema_version must be 1"):
            promotion.validate_record(record, pointer["candidate_sha256"])

    def test_missing_latest_pointer_cannot_recreate_existing_record(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        fixture.latest.unlink()
        fixture.write_source_decision()
        second = fixture.run()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(
            "append-only record already exists without a matching latest pointer",
            second.stdout,
        )

    def test_latest_pointer_identity_must_match_candidate(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        pointer["artifact_id"] = promotion.DEFAULT_ARTIFACT_PREFIX + "999"
        write_json(fixture.latest, pointer)
        second = fixture.run()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("latest pointer and record candidate disagree on artifact_id", second.stdout)

    def test_unsafe_artifact_origin_is_rejected(self):
        value = candidate()
        value["canonical_url"] = "https://attacker.example/run/123"
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical_url must start", result.stdout)

    def test_non_reference_tool_is_rejected(self):
        value = candidate()
        value["tool"] = "other-tool"
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate tool must be pipelock", result.stdout)

    def test_unicode_run_id_is_rejected(self):
        value = candidate(run_id="١٢٣")
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive decimal run ID", result.stdout)

    def test_store_root_must_be_beside_latest_pointer(self):
        fixture = self.fixture()
        fixture.store_root = fixture.root / "elsewhere" / "results"
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("results directory beside latest-verified", result.stdout)

    def test_cross_run_candidate_substitution_is_rejected(self):
        fixture = self.fixture()
        command = fixture.command()
        command[command.index("--expected-run-id") + 1] = "999"
        result = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the requested source run", result.stdout)

    def test_run_attempt_is_bound_when_present(self):
        fixture = self.fixture(candidate(run_attempt="2"))
        accepted = fixture.run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        command = fixture.command()
        command[command.index("--expected-run-attempt") + 1] = "3"
        rejected = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match the requested source attempt", rejected.stdout)

    def test_legacy_run_id_only_candidate_is_accepted_without_expected_attempt(self):
        fixture = self.fixture(candidate())
        accepted = fixture.run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_legacy_run_id_only_candidate_is_rejected_by_attempt_bound_promotion(self):
        fixture = self.fixture(candidate())
        command = fixture.command()
        command.extend(["--expected-run-attempt", "1"])
        rejected = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match the requested source attempt", rejected.stdout)

    def test_timezone_free_candidate_time_is_rejected(self):
        fixture = self.fixture(candidate(generated_at="2026-08-05T00:10:08"))
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timestamp with a timezone", result.stdout)

    def test_missing_evidence_is_rejected(self):
        fixture = self.fixture()
        fixture.evidence["runner_stderr"].unlink()
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required evidence is missing", result.stdout)

    def test_symlinked_evidence_is_rejected(self):
        fixture = self.fixture()
        target = fixture.root / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        fixture.evidence["runner_stderr"].unlink()
        fixture.evidence["runner_stderr"].symlink_to(target)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required evidence is missing", result.stdout)

    def test_latest_pointer_cannot_move_backward(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        older = candidate(run_id="124", generated_at="2026-08-04T00:10:08Z")
        second_artifact = fixture.root / "older-artifact"
        second_artifact.mkdir()
        for path in fixture.artifact_dir.iterdir():
            if path.is_file():
                (second_artifact / path.name).write_bytes(path.read_bytes())
        older["case_index_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["case_index"]).read_bytes()
        ).hexdigest()
        older["portable_bundle_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["run_bundle"]).read_bytes()
        ).hexdigest()
        write_json(second_artifact / promotion.CANDIDATE_FILENAME, older)
        second_paths = {
            label: second_artifact / filename
            for label, filename in promotion.EVIDENCE_FILES.items()
        }
        source = evaluator.evaluate(
            second_artifact / promotion.CANDIDATE_FILENAME,
            fixture.baseline_path,
            second_paths,
        )
        write_json(second_artifact / promotion.SOURCE_DECISION_FILENAME, source)
        fixture.artifact_dir = second_artifact
        fixture.candidate_value = older
        records_before = sorted((fixture.store_root / "pipelock").iterdir())
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("backward or sideways", result.stdout)
        self.assertEqual(sorted((fixture.store_root / "pipelock").iterdir()), records_before)

    def test_newer_candidate_appends_hash_linked_record_and_advances_pointer(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        first_pointer = evaluator.load_object(fixture.latest)
        first_record = fixture.store_root / "pipelock" / first_pointer["candidate_sha256"]
        first_manifest_path = first_record / promotion.RECORD_MANIFEST_FILENAME
        first_manifest_digest = evaluator.file_sha256(first_manifest_path)

        newer = candidate(run_id="124", generated_at="2026-08-06T00:10:08Z")
        second_artifact = fixture.root / "newer-artifact"
        second_artifact.mkdir()
        for path in fixture.artifact_dir.iterdir():
            if path.is_file():
                (second_artifact / path.name).write_bytes(path.read_bytes())
        newer["case_index_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["case_index"]).read_bytes()
        ).hexdigest()
        newer["portable_bundle_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["run_bundle"]).read_bytes()
        ).hexdigest()
        write_json(second_artifact / promotion.CANDIDATE_FILENAME, newer)
        second_paths = {
            label: second_artifact / filename
            for label, filename in promotion.EVIDENCE_FILES.items()
        }
        write_json(
            second_artifact / promotion.SOURCE_DECISION_FILENAME,
            evaluator.evaluate(
                second_artifact / promotion.CANDIDATE_FILENAME,
                fixture.baseline_path,
                second_paths,
            ),
        )
        fixture.artifact_dir = second_artifact
        fixture.candidate_value = newer
        second = fixture.run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)

        pointer = evaluator.load_object(fixture.latest)
        self.assertEqual(pointer["previous_candidate_sha256"], first_pointer["candidate_sha256"])
        self.assertEqual(
            pointer["previous_record_manifest_sha256"],
            first_pointer["record_manifest_sha256"],
        )
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest = evaluator.load_object(record / promotion.RECORD_MANIFEST_FILENAME)
        self.assertEqual(
            manifest["previous_candidate_sha256"], first_pointer["candidate_sha256"]
        )
        self.assertEqual(evaluator.file_sha256(first_manifest_path), first_manifest_digest)
        self.assertEqual(len(list((fixture.store_root / "pipelock").iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
