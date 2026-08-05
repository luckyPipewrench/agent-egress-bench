#!/usr/bin/env python3
"""Tests for the fail-closed owner-facing Gauntlet summary."""

import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "render_gauntlet_run_summary.py"
spec = importlib.util.spec_from_file_location("render_gauntlet_run_summary", SCRIPT)
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

REPOSITORY = "luckyPipewrench/agent-egress-bench"
RUN_URL = "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123"


def candidate():
    return {
        "schema_version": 2,
        "pipelock_version": "3.3.0",
        "generated_at": "2026-08-05T12:00:00Z",
        "corpus_version": "v2.3.0",
        "corpus_git_sha": "a" * 40,
        "case_count": {"total": 214, "applicable": 210, "not_applicable": 4, "not_applicable_reasons": {"missing_requires": 4}, "errors": 0},
        "scores": {
            "applicable": {"containment": 1, "false_positive_rate": 0},
            "full": {"containment": 0.9811320754716981},
        },
        "sufficient": True,
    }


def baseline():
    return {
        "schema_version": 1,
        "pipelock_version": "3.3.0",
        "corpus_version": "v2.3.0",
        "corpus_git_sha": "a" * 40,
    }


def decision(status="under_review", blocked=False, failures=None, review_notes=None):
    return {
        "schema_version": 1,
        "blocked": blocked,
        "promotion_status": status,
        "failures": failures or [],
        "review_notes": review_notes or [],
    }


class RenderGauntletRunSummaryTest(unittest.TestCase):
    def render(self, candidate_value=None, decision_value=None, baseline_value=None, raw_candidate=None, raw_candidate_bytes=None, missing_candidate=False, missing_decision=False, enforcement_exit=0, enforcement_status=None, enforcement_failures=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        decision_path = root / "decision.json"
        baseline_path = root / "baseline.json"
        if not missing_candidate:
            if raw_candidate_bytes is not None:
                candidate_path.write_bytes(raw_candidate_bytes)
            else:
                candidate_path.write_text(raw_candidate if raw_candidate is not None else json.dumps(candidate_value or candidate()), encoding="utf-8")
        if not missing_decision:
            decision_path.write_text(json.dumps(decision_value or decision()), encoding="utf-8")
        baseline_path.write_text(json.dumps(baseline_value or baseline()), encoding="utf-8")
        enforcement_path = root / "enforcement-result.json"
        if enforcement_exit == 0:
            verdict = "pass"
            default_status = "under_review"
            default_failures = []
        elif enforcement_exit == 2:
            verdict = "review_required"
            default_status = "scope_changed_requires_review"
            default_failures = []
        else:
            verdict = "blocked"
            default_status = "blocked"
            default_failures = ["enforcement failed"]
        digests = {}
        for field, path in (
            ("candidate_sha256", candidate_path),
            ("decision_sha256", decision_path),
            ("baseline_sha256", baseline_path),
        ):
            digests[field] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
        enforcement_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "verdict": verdict,
                    "promotion_status": enforcement_status or default_status,
                    "failures": default_failures if enforcement_failures is None else enforcement_failures,
                    **digests,
                }
            ),
            encoding="utf-8",
        )
        return renderer.render(candidate_path, decision_path, baseline_path, enforcement_path, REPOSITORY, RUN_URL)

    def test_pass_needs_no_owner_action(self):
        output = self.render()
        self.assertIn("PASS — NO ACTION REQUIRED", output)
        self.assertIn("No PR was created; permanent publication was not requested.", output)
        self.assertIn("214 total; 210 applicable; 4 N/A; 0 errors", output)
        self.assertIn("Applicable containment: 100.0%", output)
        self.assertIn("Full containment: 98.1%", output)
        self.assertIn("Applicable false-positive rate: 0.0%", output)

    def test_scope_change_requires_review_without_publication(self):
        output = self.render(
            decision_value=decision("scope_changed_requires_review", review_notes=["case_count.total moved 213 -> 214"]),
            enforcement_exit=2,
        )
        self.assertIn("REVIEW REQUIRED — PUBLIC RECORD UNCHANGED", output)
        self.assertIn("case_count.total moved 213 -&gt; 214", output)
        self.assertIn("Prepare a promotion", output)

    def test_blocked_decision_is_action_required(self):
        output = self.render(decision_value=decision("blocked", True, ["case_count.errors=1, want 0"]), enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("case_count.errors=1, want 0", output)
        self.assertIn("The public record is unchanged.", output)

    def test_missing_candidate_never_passes(self):
        output = self.render(missing_candidate=True, enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("cannot read candidate", output)

    def test_malformed_json_never_passes(self):
        output = self.render(raw_candidate="{", enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("cannot read candidate", output)

    def test_invalid_utf8_never_suppresses_the_blocked_summary(self):
        output = self.render(raw_candidate_bytes=b"\xff", enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("cannot read candidate", output)

    def test_missing_decision_and_null_score_never_pass(self):
        output = self.render(missing_decision=True, enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("cannot read decision", output)
        broken = candidate()
        broken["scores"]["applicable"]["containment"] = None
        output = self.render(candidate_value=broken, enforcement_exit=1)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("invalid field: scores.applicable.containment", output)

    def test_untrusted_text_is_escaped_and_stays_single_line(self):
        output = self.render(decision_value=decision("blocked", True, ["bad <script>\n## forged heading [link](https://bad.example)"], ["`review` <tag>"]), enforcement_exit=1)
        self.assertIn("bad &lt;script&gt; ## forged heading \\[link\\]\\(https://bad.example\\)", output)
        self.assertIn("\\`review\\` &lt;tag&gt;", output)
        self.assertNotIn("\n## forged heading", output)

    def test_invalid_link_context_is_blocked_without_rendering_a_link(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        decision_path = root / "decision.json"
        baseline_path = root / "baseline.json"
        enforcement_path = root / "enforcement-result.json"
        candidate_path.write_text(json.dumps(candidate()), encoding="utf-8")
        decision_path.write_text(json.dumps(decision()), encoding="utf-8")
        baseline_path.write_text(json.dumps(baseline()), encoding="utf-8")
        enforcement_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "verdict": "pass",
                    "promotion_status": "under_review",
                    "failures": [],
                    "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
                    "decision_sha256": hashlib.sha256(decision_path.read_bytes()).hexdigest(),
                    "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        output = renderer.render(candidate_path, decision_path, baseline_path, enforcement_path, REPOSITORY, "https://bad.example/](https://evil.example)")
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("Current workflow run: (unavailable)", output)
        self.assertNotIn("evil.example", output)

    def test_status_and_enforcement_result_must_agree(self):
        output = self.render(
            decision_value=decision("scope_changed_requires_review"),
            enforcement_exit=0,
            enforcement_status="under_review",
        )
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("decision status disagrees with enforcement result", output)

        output = self.render(
            decision_value=decision("under_review"),
            enforcement_exit=2,
            enforcement_status="scope_changed_requires_review",
        )
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("decision status disagrees with enforcement result", output)

    def test_enforcement_integrity_failure_is_visible(self):
        output = self.render(
            decision_value=decision(),
            enforcement_exit=1,
            enforcement_failures=["evidence results changed after the decision was created"],
        )
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("enforcement: evidence results changed", output)

    def test_enforcement_digest_binding_rejects_post_enforcement_changes(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        candidate_path = root / "candidate.json"
        decision_path = root / "decision.json"
        baseline_path = root / "baseline.json"
        enforcement_path = root / "enforcement-result.json"
        candidate_path.write_text(json.dumps(candidate()), encoding="utf-8")
        decision_path.write_text(json.dumps(decision()), encoding="utf-8")
        baseline_path.write_text(json.dumps(baseline()), encoding="utf-8")
        enforcement_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "verdict": "pass",
                    "promotion_status": "under_review",
                    "failures": [],
                    "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
                    "decision_sha256": hashlib.sha256(decision_path.read_bytes()).hexdigest(),
                    "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        candidate_path.write_text("{}", encoding="utf-8")
        output = renderer.render(candidate_path, decision_path, baseline_path, enforcement_path, REPOSITORY, RUN_URL)
        self.assertIn("BLOCKED — ACTION REQUIRED", output)
        self.assertIn("candidate changed after enforcement", output)

    def test_structural_guards_fail_closed(self):
        cases = []

        wrong_schema = candidate()
        wrong_schema["schema_version"] = 1
        cases.append(("candidate schema", {"candidate_value": wrong_schema}, "candidate schema_version"))

        insufficient = candidate()
        insufficient["sufficient"] = False
        cases.append(("insufficient", {"candidate_value": insufficient}, "candidate sufficient"))

        runner_error = candidate()
        runner_error["case_count"]["errors"] = 1
        cases.append(("runner error", {"candidate_value": runner_error}, "case_count.errors"))

        bad_reasons = candidate()
        bad_reasons["case_count"]["not_applicable_reasons"] = {"missing_requires": 3}
        cases.append(("N/A reasons", {"candidate_value": bad_reasons}, "N/A reasons"))

        bad_decision = decision()
        bad_decision["schema_version"] = 2
        cases.append(("decision schema", {"decision_value": bad_decision}, "decision schema_version"))

        bad_lists = decision()
        bad_lists["review_notes"] = "not-a-list"
        cases.append(("decision lists", {"decision_value": bad_lists}, "review_notes must be a list"))

        bad_baseline = baseline()
        bad_baseline["schema_version"] = 2
        cases.append(("baseline schema", {"baseline_value": bad_baseline}, "baseline schema_version"))

        for name, arguments, expected in cases:
            with self.subTest(name=name):
                output = self.render(**arguments)
                self.assertIn("BLOCKED — ACTION REQUIRED", output)
                self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
