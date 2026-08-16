#!/usr/bin/env python3
"""Tests for fail-safe continuous-gauntlet candidate evaluation."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import evaluate_gauntlet_candidate as evaluator


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "evaluate_gauntlet_candidate.py"
def v5_raw_evidence():
    cases = {}
    rows = []
    for index in range(158):
        case_id = f"malicious-{index:03d}"
        cases[case_id] = {"category": "test", "expected_verdict": "block"}
        actual = "not_applicable" if index == 157 else "block"
        rows.append({
            "case_id": case_id,
            "expected_verdict": "block",
            "actual_verdict": actual,
            "score": "not_applicable" if actual == "not_applicable" else "pass",
            "evidence": {} if actual == "not_applicable" else {"kind": "policy"},
        })
    for index in range(55):
        case_id = f"benign-{index:03d}"
        cases[case_id] = {"category": "test", "expected_verdict": "allow"}
        rows.append({
            "case_id": case_id,
            "expected_verdict": "allow",
            "actual_verdict": "allow",
            "score": "pass",
            "evidence": {},
        })
    case_index = (json.dumps({"schema_version": 2, "cases": cases}, sort_keys=True) + "\n").encode()
    results = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    return case_index, results


CASE_INDEX_BYTES, V5_RESULTS_BYTES = v5_raw_evidence()
RUN_BUNDLE_BYTES = b'{"schema_version":1,"bundle_status":"complete"}\n'


def pinned_pipelock_version():
    pin = REPO_ROOT / "examples" / "pipelock" / "release.env"
    for line in pin.read_text(encoding="utf-8").splitlines():
        if line.startswith("PIPELOCK_VERSION="):
            return line.split("=", 1)[1]
    raise AssertionError("release.env does not define PIPELOCK_VERSION")


PIPELOCK_VERSION = pinned_pipelock_version()


def candidate():
    return {
        "schema_version": 2,
        "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "pipelock_version": PIPELOCK_VERSION,
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "corpus_manifest_sha256": "f" * 64,
        "case_index_sha256": hashlib.sha256(CASE_INDEX_BYTES).hexdigest(),
        "portable_bundle_sha256": hashlib.sha256(RUN_BUNDLE_BYTES).hexdigest(),
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
        "scores": {
            "full": {"containment": 0.99},
            "applicable": {
                "containment": 1.0,
                "detection": 1.0,
                "evidence": 1.0,
                "false_positive_rate": 0.0,
            },
        },
        "metric_counts": {},
        "sufficient": True,
    }


def active_candidate():
    value = candidate()
    value["schema_version"] = 4
    value.pop("sufficient")
    value["measurement_status"] = "measured"
    value["capability_registry"] = {
        "id": "aeb.core-capabilities",
        "format": 1,
        "revision": 1,
        "sha256": "d" * 64,
    }
    return value


def v5_candidate():
    value = active_candidate()
    value["schema_version"] = 5
    value["benchmark_manifest_sha256"] = "e" * 64
    value["scoring_version"] = "2.8"
    value["runner_version"] = "0.4.3"
    value["case_count"]["unreachable"] = 0
    for scope in ("full", "applicable"):
        value["scores"][scope].pop("detection", None)
        value["scores"][scope].pop("evidence", None)
    value["scores"]["full"]["false_positive_rate"] = 0.0
    value["scores"]["full"]["containment"] = 157 / 158
    value["diagnostics"] = {
        "full": {
            "classification_present_rate": 1.0,
            "structured_evidence_present_rate": 1.0,
        },
        "applicable": {
            "classification_present_rate": 1.0,
            "structured_evidence_present_rate": 1.0,
        },
    }
    value["metric_counts"] = {
        "full": {
            "containment": {"numerator": 157, "denominator": 158},
            "false_positive_rate": {"numerator": 0, "denominator": 55},
        },
        "applicable": {
            "containment": {"numerator": 157, "denominator": 157},
            "false_positive_rate": {"numerator": 0, "denominator": 55},
        },
    }
    value["diagnostic_counts"] = {
        scope: {
            "classification_present_rate": {"numerator": 157, "denominator": 157},
            "structured_evidence_present_rate": {"numerator": 157, "denominator": 157},
        }
        for scope in ("full", "applicable")
    }
    value.update(
        {
            "local_run_id": "run-123",
            "generated_at": "2026-08-05T10:33:23Z",
            "corpus_ref_kind": "origin/main",
            "corpus_commit_url": "https://github.com/luckyPipewrench/agent-egress-bench/commit/" + "b" * 40,
            "dirty": False,
            "pipelock_tag": "v" + PIPELOCK_VERSION,
            "pipelock_asset": "pipelock.tar.gz",
            "pipelock_asset_sha256": "a" * 64,
            "pipelock_binary_sha256": "a" * 64,
            "pipelock_release_url": "https://github.com/luckyPipewrench/pipelock/releases/tag/v" + PIPELOCK_VERSION,
            "gauntlet_version": "0.4.3",
            "tool": "pipelock",
            "tool_version": PIPELOCK_VERSION,
            "tool_profile_sha256": "a" * 64,
            "fixtures": True,
            "multifile_cases": True,
            "command": "aeb-gauntlet",
            "make_stats": "Total logical cases: 213",
            "evidence_sha256": {label: "a" * 64 for label in (
                "capability_registry", "case_index", "command", "corpus_manifest",
                "entrypoint_command", "pipelock_release", "pipelock_version_output",
                "raw_summary", "receipt_profile", "release_checksums", "results",
                "run_metadata", "runner_stderr", "stats", "tool_profile",
            )},
            "reported_claims": [],
            "exercised": {"transports": ["stdio"], "categories": ["prompt-injection"], "capability_tags": []},
        }
    )
    return value


def baseline():
    return {
        "_comment": "Reviewed baseline for the continuous Gauntlet lane.",
        "schema_version": 1,
        "recorded_on": "2026-08-01",
        "verified_candidate_sha256": "a" * 64,
        "verified_artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:122",
        "pipelock_version": PIPELOCK_VERSION,
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


def v5_baseline():
    value = baseline()
    value["summary_schema_version"] = 5
    value["benchmark_manifest_sha256"] = "e" * 64
    value["scoring_version"] = "2.8"
    value["runner_version"] = "0.4.3"
    del value["score_floors"]["applicable"]["detection"]
    del value["score_floors"]["applicable"]["evidence"]
    return value


class CandidateEvaluationTest(unittest.TestCase):
    def run_evaluate(
        self,
        candidate_value=None,
        baseline_value=None,
        raw_candidate=None,
        missing_candidate=False,
        include_case_index_evidence=True,
        include_run_bundle_evidence=True,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        baseline_path = root / "baseline.json"
        decision_path = root / "decision.json"
        if missing_candidate:
            pass
        elif raw_candidate is None:
            candidate_path.write_text(json.dumps(candidate_value or candidate()), encoding="utf-8")
        else:
            candidate_path.write_text(raw_candidate, encoding="utf-8")
        baseline_path.write_text(json.dumps(baseline_value or baseline()), encoding="utf-8")
        evidence_path = root / "results.jsonl"
        if (candidate_value or {}).get("schema_version") == 5:
            evidence_path.write_bytes(V5_RESULTS_BYTES)
        else:
            evidence_path.write_text('{"id":"case-1"}\n', encoding="utf-8")
        case_index_path = root / "case-index.json"
        case_index_path.write_bytes(CASE_INDEX_BYTES)
        run_bundle_path = root / "run-bundle.json"
        run_bundle_path.write_bytes(RUN_BUNDLE_BYTES)

        evidence_args = ["--evidence", f"results={evidence_path}"]
        if include_run_bundle_evidence:
            evidence_args.extend(["--evidence", f"run_bundle={run_bundle_path}"])
        if include_case_index_evidence:
            evidence_args.extend(["--evidence", f"case_index={case_index_path}"])
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "evaluate",
                "--candidate",
                str(candidate_path),
                "--baseline",
                str(baseline_path),
                *evidence_args,
                "--decision",
                str(decision_path),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(decision_path.is_file())
        return (
            json.loads(decision_path.read_text(encoding="utf-8")),
            decision_path,
            candidate_path,
            baseline_path,
            evidence_path,
        )

    def run_enforce(self, decision_path, candidate_path, baseline_path, evidence_path=None):
        evidence_args = []
        if evidence_path is not None:
            evidence_args = [
                "--evidence",
                f"results={evidence_path}",
                "--evidence",
                f"case_index={evidence_path.parent / 'case-index.json'}",
                "--evidence",
                f"run_bundle={evidence_path.parent / 'run-bundle.json'}",
            ]
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "enforce",
                str(decision_path),
                "--candidate",
                str(candidate_path),
                "--baseline",
                str(baseline_path),
                "--result",
                str(decision_path.parent / "enforcement-result.json"),
                *evidence_args,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_clean_candidate_is_preserved_for_human_review(self):
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        self.assertFalse(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "under_review")
        self.assertRegex(decision["candidate_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(decision["evidence_sha256"]["results"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

    def test_v5_candidate_cannot_silently_use_a_legacy_detection_baseline(self):
        decision, *_ = self.run_evaluate(v5_candidate(), baseline())

        self.assertTrue(decision["blocked"])
        self.assertIn("summary_schema_version=5", decision["failures"][-1])

    def test_v5_candidate_uses_only_reviewed_outcome_metric_contract(self):
        decision, *_ = self.run_evaluate(v5_candidate(), v5_baseline())

        self.assertFalse(decision["blocked"], decision["failures"])

    def test_v5_self_consistent_lie_is_rejected_by_raw_results(self):
        value = v5_candidate()
        for scope in ("full", "applicable"):
            value["scores"][scope]["containment"] = 1.0
            value["metric_counts"][scope]["containment"] = {
                "numerator": 1,
                "denominator": 1,
            }

        evaluator.validate_v5_candidate_contract(value)
        decision, *_ = self.run_evaluate(value, v5_baseline())

        self.assertTrue(decision["blocked"])
        self.assertIn(
            "candidate metric_counts does not match the case index and raw results",
            decision["failures"],
        )

    def test_v5_candidate_requires_framed_manifest_identity(self):
        missing_candidate_digest = v5_candidate()
        del missing_candidate_digest["benchmark_manifest_sha256"]
        decision, *_ = self.run_evaluate(missing_candidate_digest, v5_baseline())
        self.assertTrue(decision["blocked"])
        self.assertIn(
            "candidate benchmark_manifest_sha256 must be 64 lower-case hex characters",
            decision["failures"],
        )

        missing_baseline_digest = v5_baseline()
        del missing_baseline_digest["benchmark_manifest_sha256"]
        decision, *_ = self.run_evaluate(v5_candidate(), missing_baseline_digest)
        self.assertTrue(decision["blocked"])
        self.assertIn(
            "baseline benchmark_manifest_sha256 must be a non-empty string",
            decision["failures"],
        )

    def test_v5_null_ceiling_rate_requires_zero_denominator(self):
        value = v5_candidate()
        value["scores"]["applicable"]["false_positive_rate"] = None
        value["metric_counts"]["applicable"]["false_positive_rate"] = {
            "numerator": 0,
            "denominator": 0,
        }

        evaluator.validate_v5_candidate_contract(value)

        value["metric_counts"]["applicable"]["false_positive_rate"]["denominator"] = 1
        with self.assertRaisesRegex(ValueError, "does not match its numerator and denominator"):
            evaluator.validate_v5_candidate_contract(value)

    def test_v5_candidate_rejects_inconsistent_counts_and_rates(self):
        mutations = (
            ("numerator above denominator", lambda value: value["metric_counts"]["full"]["containment"].__setitem__("numerator", 159), "numerator cannot exceed denominator"),
            ("rate disagrees with counts", lambda value: value["scores"]["full"].__setitem__("containment", 1), "does not match its numerator and denominator"),
            ("total disagrees with logical count", lambda value: value["case_count"].__setitem__("total", 214), "must equal logical_case_count"),
            ("case counts do not sum", lambda value: value["case_count"].__setitem__("applicable", 211), "case counts must sum to total"),
            ("reason counts do not sum", lambda value: value["case_count"]["not_applicable_reasons"].__setitem__("missing_requires", 2), "reasons must sum to not_applicable"),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                value = v5_candidate()
                mutate(value)
                decision, *_ = self.run_evaluate(value, v5_baseline())
                self.assertTrue(decision["blocked"])
                self.assertTrue(any(message in failure for failure in decision["failures"]))

    def test_v5_cross_field_guards_are_individually_exercised(self):
        mutations = (
            (lambda value: value["metric_counts"]["full"]["containment"].__setitem__("numerator", 159), "numerator cannot exceed denominator"),
            (lambda value: value["scores"]["full"].__setitem__("containment", 1), "does not match its numerator and denominator"),
            (lambda value: value["case_count"].__setitem__("total", 214), "must equal logical_case_count"),
            (lambda value: value["case_count"].__setitem__("applicable", 211), "case counts must sum to total"),
            (lambda value: value["case_count"]["not_applicable_reasons"].__setitem__("missing_requires", 2), "reasons must sum to not_applicable"),
            (lambda value: value["case_count"].__setitem__("errors", 213), "errors cannot exceed applicable"),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                value = v5_candidate()
                mutate(value)
                with self.assertRaisesRegex(ValueError, message):
                    evaluator.validate_v5_candidate_contract(value)

    def test_v5_candidate_rejects_retired_or_malformed_metric_fields(self):
        mutations = (
            (
                "retired score",
                lambda value: value["scores"]["applicable"].__setitem__("detection", 1.0),
                "candidate scores.applicable has unexpected fields: ['detection']",
            ),
            (
                "unknown score scope",
                lambda value: value["scores"].__setitem__(
                    "legacy", {"containment": 1.0, "false_positive_rate": 0.0}
                ),
                "candidate scores has unexpected fields: ['legacy']",
            ),
            (
                "retired diagnostic",
                lambda value: value["diagnostics"]["full"].__setitem__("evidence", 1.0),
                "candidate diagnostics.full has unexpected fields: ['evidence']",
            ),
            (
                "boolean rate",
                lambda value: value["scores"]["applicable"].__setitem__(
                    "containment", True
                ),
                "candidate scores.applicable.containment must be a finite number",
            ),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                value = v5_candidate()
                mutate(value)

                decision, *_ = self.run_evaluate(value, v5_baseline())

                self.assertTrue(decision["blocked"])
                self.assertIn(message, decision["failures"])

    def test_measured_candidate_below_historical_floor_reaches_publication_gate(self):
        value = active_candidate()
        value["scores"]["full"]["containment"] = 0.5
        value["scores"]["applicable"]["containment"] = 0.5
        policy = baseline()
        policy["score_floors"]["full"]["containment"] = 0.0
        policy["score_floors"]["applicable"]["containment"] = 0.0

        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(
            value, policy
        )

        self.assertFalse(decision["blocked"], decision["failures"])
        self.assertEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

    def test_active_measurement_status_fails_closed(self):
        for name, status in (("missing", None), ("unknown", "complete"), ("incomplete", "incomplete")):
            with self.subTest(name=name):
                value = active_candidate()
                if status is None:
                    value.pop("measurement_status")
                else:
                    value["measurement_status"] = status
                decision, _, _, _, _ = self.run_evaluate(value)
                self.assertTrue(decision["blocked"])
                self.assertTrue(any("measurement_status" in item for item in decision["failures"]))

    def test_active_error_and_unreachable_each_block_publication(self):
        for name, mutate in (
            ("error", lambda value: value["case_count"].__setitem__("errors", 1)),
            ("unreachable", lambda value: (
                value["case_count"].__setitem__("applicable", 211),
                value["case_count"].__setitem__("unreachable", 1),
            )),
        ):
            with self.subTest(name=name):
                value = active_candidate()
                mutate(value)
                decision, _, _, _, _ = self.run_evaluate(value)
                self.assertTrue(decision["blocked"])
                self.assertTrue(any(f"case_count.{name}" in item for item in decision["failures"]))

    def test_each_regression_direction_blocks_after_decision_is_written(self):
        mutations = {
            "containment drop": lambda value: value["scores"]["applicable"].__setitem__("containment", 0.9),
            "false positive increase": lambda value: value["scores"]["applicable"].__setitem__(
                "false_positive_rate", 0.1
            ),
            "runner error": lambda value: value["case_count"].__setitem__("errors", 1),
            "insufficient": lambda value: value.__setitem__("sufficient", False),
            "wrong release": lambda value: value.__setitem__("pipelock_version", "0.0.0"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                value = candidate()
                mutate(value)
                decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(value)
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["promotion_status"], "blocked")
                self.assertTrue(decision["failures"])
                self.assertNotEqual(
                    self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode, 0
                )

    def test_scope_change_returns_distinct_owner_review_status(self):
        value = candidate()
        value["case_count"] = {
            "total": 214,
            "applicable": 213,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
            "errors": 0,
        }
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(value)
        self.assertFalse(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "scope_changed_requires_review")
        self.assertTrue(any("case_count.total moved" in note for note in decision["review_notes"]))
        enforced = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)
        self.assertEqual(enforced.returncode, 2)
        self.assertIn("REVIEW REQUIRED", enforced.stdout)
        result = json.loads(
            (decision_path.parent / "enforcement-result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(result["verdict"], "review_required")
        self.assertEqual(result["promotion_status"], "scope_changed_requires_review")

    def test_malformed_candidate_counts_are_blocked_not_scope_changed(self):
        for name, mutate in (
            ("partition", lambda value: value["case_count"].__setitem__("total", 214)),
            (
                "not-applicable reasons",
                lambda value: value["case_count"]["not_applicable_reasons"].__setitem__(
                    "missing_requires", 0
                ),
            ),
        ):
            with self.subTest(name=name):
                value = candidate()
                mutate(value)
                decision, _, _, _, _ = self.run_evaluate(value)
                self.assertTrue(decision["blocked"])
                self.assertEqual(decision["promotion_status"], "blocked")
                self.assertTrue(
                    any("candidate case counts must partition total" in failure or "candidate not_applicable reasons must sum" in failure for failure in decision["failures"])
                )

    def test_unreachable_coverage_gap_is_preserved_and_blocks_promotion(self):
        value = candidate()
        value["case_count"]["applicable"] -= 1
        value["case_count"]["unreachable"] = 1
        value["sufficient"] = False

        decision, _, _, _, _ = self.run_evaluate(value)

        self.assertTrue(decision["blocked"])
        self.assertTrue(any("case_count.unreachable moved" in note for note in decision["review_notes"]))
        self.assertTrue(any("sufficient=False" in failure for failure in decision["failures"]))

    def test_malformed_candidate_still_produces_a_blocked_decision(self):
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(raw_candidate="{")
        self.assertTrue(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "blocked")
        self.assertTrue(decision["failures"])
        self.assertNotEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode, 0
        )

    def test_missing_candidate_still_produces_a_blocked_decision(self):
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(
            missing_candidate=True
        )
        self.assertTrue(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "blocked")
        self.assertTrue(decision["failures"])
        self.assertNotEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode, 0
        )

    def test_missing_decision_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = self.run_enforce(root / "missing.json", root / "candidate.json", root / "baseline.json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BLOCKED", result.stdout)

    def test_candidate_substitution_after_decision_fails_closed(self):
        _, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        candidate_path.write_text(json.dumps({"substituted": True}), encoding="utf-8")
        result = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate changed", result.stdout)

    def test_stored_decision_cannot_be_forged(self):
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        decision["review_notes"].append("forged")
        decision_path.write_text(json.dumps(decision), encoding="utf-8")
        result = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fresh evaluation", result.stdout)

    def test_required_baseline_metric_cannot_be_deleted(self):
        baseline_value = baseline()
        del baseline_value["score_floors"]["applicable"]["containment"]
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(
            baseline_value=baseline_value
        )
        self.assertTrue(decision["blocked"])
        self.assertIn("missing required metrics", decision["failures"][0])
        self.assertNotEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode, 0
        )

    def test_supporting_evidence_substitution_fails_closed(self):
        _, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        evidence_path.write_text('{"substituted":true}\n', encoding="utf-8")
        result = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence results changed", result.stdout)
        enforcement = json.loads(
            (decision_path.parent / "enforcement-result.json").read_text(encoding="utf-8")
        )
        self.assertEqual(enforcement["verdict"], "blocked")
        self.assertTrue(any("evidence results changed" in failure for failure in enforcement["failures"]))
        self.assertFalse(any("without a recorded reason" in failure for failure in enforcement["failures"]))

    def test_case_index_substitution_fails_closed(self):
        _, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        (evidence_path.parent / "case-index.json").write_bytes(b'{"substituted":true}\n')

        result = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence case_index changed", result.stdout)

    def test_candidate_case_index_digest_must_match_uploaded_evidence(self):
        value = candidate()
        value["case_index_sha256"] = "0" * 64

        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(value)

        self.assertTrue(decision["blocked"])
        self.assertTrue(
            any("case_index_sha256 does not match" in failure for failure in decision["failures"])
        )
        self.assertNotEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

    def test_candidate_portable_bundle_digest_must_match_uploaded_evidence(self):
        value = candidate()
        value["portable_bundle_sha256"] = "0" * 64

        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(value)

        self.assertTrue(decision["blocked"])
        self.assertTrue(
            any("portable_bundle_sha256 does not match" in failure for failure in decision["failures"])
        )
        self.assertNotEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

    def test_portable_bundle_substitution_fails_closed(self):
        _, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        (evidence_path.parent / "run-bundle.json").write_bytes(b'{"substituted":true}\n')

        result = self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence run_bundle changed", result.stdout)

    def test_missing_candidate_digest_and_case_index_evidence_fail_closed(self):
        value = candidate()
        del value["case_index_sha256"]

        decision, _, _, _, _ = self.run_evaluate(
            value, include_case_index_evidence=False
        )

        self.assertTrue(decision["blocked"])
        self.assertTrue(any("case_index_sha256" in failure for failure in decision["failures"]))

    def test_missing_portable_bundle_digest_and_evidence_fail_closed(self):
        value = candidate()
        del value["portable_bundle_sha256"]

        decision, _, _, _, _ = self.run_evaluate(
            value, include_run_bundle_evidence=False
        )

        self.assertTrue(decision["blocked"])
        self.assertTrue(
            any("portable_bundle_sha256" in failure for failure in decision["failures"])
        )

    def test_supporting_evidence_set_mismatch_fails_closed(self):
        _, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate()
        result = self.run_enforce(decision_path, candidate_path, baseline_path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence set does not match", result.stdout)

    def test_required_baseline_identity_cannot_be_deleted(self):
        for identity in (
            "corpus_git_sha",
            "corpus_sha256",
            "corpus_version",
            "scoring_version",
            "runner_version",
        ):
            with self.subTest(identity=identity):
                baseline_value = baseline()
                del baseline_value[identity]
                decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(
                    baseline_value=baseline_value
                )
                self.assertTrue(decision["blocked"])
                self.assertIn(f"baseline {identity}", decision["failures"][-1])
                self.assertNotEqual(
                    self.run_enforce(
                        decision_path, candidate_path, baseline_path, evidence_path
                    ).returncode,
                    0,
                )

    def test_git_commit_drift_is_informational_not_a_scope_change(self):
        value = candidate()
        value["corpus_git_sha"] = "d" * 40
        decision, decision_path, candidate_path, baseline_path, evidence_path = self.run_evaluate(value)
        self.assertFalse(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "under_review")
        self.assertTrue(any("corpus_git_sha moved" in note for note in decision["review_notes"]))
        self.assertEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

    def test_corpus_content_drift_requires_scope_review(self):
        value = candidate()
        value["corpus_sha256"] = "d" * 64
        decision, _, _, _, _ = self.run_evaluate(value)
        self.assertFalse(decision["blocked"])
        self.assertEqual(decision["promotion_status"], "scope_changed_requires_review")

    def test_malformed_case_count_is_refused_rather_than_crashing(self):
        # Reading a field off a non-object raised inside the comparison, and the
        # exception escaped the handler, so the evaluator exited WITHOUT writing
        # a blocked decision. run_evaluate asserts a zero exit and a decision
        # file, so a crash fails there rather than here.
        for malformed in (None, [], ["errors"], "case_count", 7):
            with self.subTest(case_count=malformed):
                value = candidate()
                value["case_count"] = malformed

                decision, _, _, _, _ = self.run_evaluate(value)

                self.assertTrue(decision["blocked"])
                # Assert the shape guard's OWN wording. Matching only
                # "case_count" passes without the guard, because a pre-existing
                # "case_count.errors=None" failure contains that substring.
                self.assertTrue(
                    any("want an object" in failure for failure in decision["failures"]),
                    decision["failures"],
                )

    def test_boolean_case_count_fields_are_refused(self):
        # Python compares False == 0, so a boolean would otherwise satisfy a
        # want-zero check while describing no measurement at all.
        for field in ("errors", "unreachable"):
            for boolean in (False, True):
                with self.subTest(field=field, value=boolean):
                    value = candidate()
                    value["case_count"] = dict(value["case_count"])
                    value["case_count"][field] = boolean

                    decision, _, _, _, _ = self.run_evaluate(value)

                    self.assertTrue(decision["blocked"])
                    self.assertTrue(
                        any(f"case_count.{field}" in f for f in decision["failures"]),
                        decision["failures"],
                    )


if __name__ == "__main__":
    unittest.main()
