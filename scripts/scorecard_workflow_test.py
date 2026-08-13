#!/usr/bin/env python3
"""Structural tests for Scorecard's dependency on same-workflow SAST evidence."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yaml"
RETIRED_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "scorecard.yaml"


class ScorecardWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.triggers = self.workflow.split("concurrency:", 1)[0]

    def test_scorecard_runs_after_codeql_in_security_workflow(self):
        self.assertFalse(RETIRED_WORKFLOW.exists())
        self.assertRegex(self.workflow, r"(?m)^  scorecard:\n    needs: codeql$")
        self.assertNotIn("workflow_run", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^permissions: read-all$")

    def test_pull_request_code_never_reaches_scorecard(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^    if: github\.event_name != 'pull_request'$",
        )

    def test_security_workflow_scans_main_pushes(self):
        self.assertRegex(self.workflow, r"(?m)^name: Security$")
        self.assertRegex(
            self.triggers,
            r"(?m)^  push:\n    branches: \[main\]$",
        )
        self.assertRegex(
            self.workflow,
            r"uses: github/codeql-action/analyze@[0-9a-f]{40}",
        )

    def test_scorecard_uses_the_same_event_commit(self):
        self.assertNotIn("ref:", self.workflow.split("  scorecard:", 1)[1])
        self.assertIn("persist-credentials: false", self.workflow)

    def test_trusted_scorecard_triggers_remain(self):
        for trigger in ("branch_protection_rule:", "workflow_dispatch:", "schedule:"):
            with self.subTest(trigger=trigger):
                self.assertIn(trigger, self.triggers)

    def test_only_pull_request_runs_are_cancelled(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^concurrency:\n"
            r"  group: security-\$\{\{ github\.ref \}\}\n"
            r"  cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}$",
        )
        self.assertEqual(self.workflow.count("timeout-minutes: 10"), 2)


if __name__ == "__main__":
    unittest.main()
