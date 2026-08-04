#!/usr/bin/env python3
"""Tests for fail-safe continuous-gauntlet candidate evaluation."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "evaluate_gauntlet_candidate.py"
CASE_INDEX_BYTES = b'{"schema_version":1,"cases":[]}\n'


def candidate():
    return {
        "schema_version": 2,
        "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "pipelock_version": "3.3.0",
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "case_index_sha256": hashlib.sha256(CASE_INDEX_BYTES).hexdigest(),
        "corpus_version": "v2.3.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
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
        "sufficient": True,
    }


def baseline():
    return {
        "schema_version": 1,
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


class CandidateEvaluationTest(unittest.TestCase):
    def run_evaluate(
        self,
        candidate_value=None,
        baseline_value=None,
        raw_candidate=None,
        missing_candidate=False,
        include_case_index_evidence=True,
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
        evidence_path.write_text('{"id":"case-1"}\n', encoding="utf-8")
        case_index_path = root / "case-index.json"
        case_index_path.write_bytes(CASE_INDEX_BYTES)

        evidence_args = ["--evidence", f"results={evidence_path}"]
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

    def test_each_regression_direction_blocks_after_decision_is_written(self):
        mutations = {
            "containment drop": lambda value: value["scores"]["applicable"].__setitem__("containment", 0.9),
            "false positive increase": lambda value: value["scores"]["applicable"].__setitem__(
                "false_positive_rate", 0.1
            ),
            "runner error": lambda value: value["case_count"].__setitem__("errors", 1),
            "insufficient": lambda value: value.__setitem__("sufficient", False),
            "wrong release": lambda value: value.__setitem__("pipelock_version", "3.2.0"),
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

    def test_scope_change_requires_review_but_does_not_disable_the_lane(self):
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
        self.assertEqual(
            self.run_enforce(decision_path, candidate_path, baseline_path, evidence_path).returncode,
            0,
        )

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

    def test_missing_candidate_digest_and_case_index_evidence_fail_closed(self):
        value = candidate()
        del value["case_index_sha256"]

        decision, _, _, _, _ = self.run_evaluate(
            value, include_case_index_evidence=False
        )

        self.assertTrue(decision["blocked"])
        self.assertTrue(any("case_index_sha256" in failure for failure in decision["failures"]))

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


if __name__ == "__main__":
    unittest.main()
