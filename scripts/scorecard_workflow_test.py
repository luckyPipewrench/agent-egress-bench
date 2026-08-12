#!/usr/bin/env python3
"""Structural tests for Scorecard's dependency on completed SAST evidence."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "scorecard.yaml"
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yaml"


class ScorecardWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.triggers = self.workflow.split("permissions:", 1)[0]

    def test_main_push_waits_for_security_workflow(self):
        self.assertNotRegex(self.triggers, r"(?m)^  push:$")
        self.assertIn("workflow_run:", self.triggers)
        self.assertIn("workflows: [Security]", self.triggers)
        self.assertIn("types: [completed]", self.triggers)
        self.assertIn("branches: [main]", self.triggers)

    def test_workflow_run_accepts_only_successful_main_pushes(self):
        self.assertIn("github.event_name != 'workflow_run' ||", self.workflow)
        self.assertIn("github.event.workflow_run.event == 'push'", self.workflow)
        self.assertIn("github.event.workflow_run.head_branch == 'main'", self.workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", self.workflow)

    def test_security_dependency_exists_and_scans_main_pushes(self):
        security = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(security, r"(?m)^name: Security$")
        trigger_block = security.split("concurrency:", 1)[0]
        self.assertRegex(
            trigger_block,
            r"(?m)^  push:\n    branches: \[main\]$",
        )
        self.assertRegex(
            security,
            r"uses: github/codeql-action/analyze@[0-9a-f]{40}",
        )

    def test_scorecard_checks_out_the_scanned_commit(self):
        self.assertIn(
            "ref: ${{ github.event.workflow_run.head_sha || github.sha }}",
            self.workflow,
        )

    def test_manual_scheduled_and_branch_protection_triggers_remain(self):
        for trigger in ("branch_protection_rule:", "workflow_dispatch:", "schedule:"):
            with self.subTest(trigger=trigger):
                self.assertIn(trigger, self.triggers)

    def test_runs_are_serialized_without_discarding_evidence(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^concurrency:\n"
            r"  group: scorecard-\$\{\{ github\.repository \}\}\n"
            r"  queue: max\n"
            r"  cancel-in-progress: false$",
        )
        self.assertRegex(self.workflow, r"(?m)^    timeout-minutes: 10$")


if __name__ == "__main__":
    unittest.main()
