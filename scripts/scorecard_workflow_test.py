#!/usr/bin/env python3
"""Structural tests for the trusted Scorecard job and what it may publish."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yaml"
RETIRED_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "scorecard.yaml"


class ScorecardWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.triggers = self.workflow.split("concurrency:", 1)[0]

    def test_scorecard_stays_in_the_trusted_security_workflow(self):
        # These three are the reason the job was moved here: a standalone
        # workflow triggered by workflow_run runs privileged and then checks out
        # the triggering run's code, which is a privilege-escalation shape.
        self.assertFalse(RETIRED_WORKFLOW.exists())
        self.assertNotIn("workflow_run", self.workflow)
        self.assertRegex(self.workflow, r"(?m)^permissions: read-all$")

    def test_scorecard_does_not_upload_sarif_or_wait_on_codeql(self):
        # This replaces an assertion that required `needs: codeql`. That
        # ordering existed so the two jobs could not upload SARIF concurrently.
        # Scorecard no longer uploads SARIF at all, so the ordering has nothing
        # left to protect, and keeping it would let a CodeQL failure take the
        # Scorecard publication down with it.
        #
        # Both halves are asserted together on purpose: dropping the dependency
        # is only safe while this job uploads no SARIF, so re-adding an upload
        # without restoring the ordering must fail here.
        self.assertNotIn("upload-sarif", self.workflow)

        jobs = self.workflow.split("jobs:\n", 1)[1]
        _, scorecard = jobs.split("\n  scorecard:\n", 1)

        # Search the whole job body, not the line right after `scorecard:`.
        # YAML does not fix key order, so `needs` placed after `if` or
        # `permissions` would slip past an anchored two-line pattern and the
        # guard would report clean while the dependency was back.
        self.assertNotRegex(scorecard, r"(?m)^\s+needs\s*:")

        # Match a permission LINE, not the phrase. The workflow comment explains
        # why the permission is absent and contains the same words, so a
        # substring check passes for the wrong reason and then fails when the
        # explanation is written.
        self.assertNotRegex(
            scorecard.split("steps:", 1)[0],
            r"(?m)^\s+security-events:\s*write\s*$",
        )

        # Publication and raw retention are the two things that make dropping
        # the code-scanning upload honest rather than a quiet removal. Assert
        # both, anchored, so deleting the artifact step fails here instead of
        # leaving the grade unreadable while this test still passes.
        self.assertRegex(scorecard, r"(?m)^\s+publish_results:\s*true\s*$")
        self.assertRegex(scorecard, r"(?m)^\s+results_file:\s*results\.sarif\s*$")
        self.assertRegex(scorecard, r"(?m)^\s+results_format:\s*sarif\s*$")
        # The step is written as `- name:` followed by `uses:`, so the action
        # reference does not sit on the dash line.
        self.assertRegex(scorecard, r"(?m)^\s+uses: actions/upload-artifact@")
        self.assertRegex(scorecard, r"(?m)^\s+path:\s*results\.sarif\s*$")

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
        jobs = self.workflow.split("jobs:\n", 1)[1]
        codeql, scorecard = jobs.split("\n  scorecard:\n", 1)
        for name, job in (("codeql", codeql), ("scorecard", scorecard)):
            with self.subTest(job=name):
                self.assertNotRegex(job, r"(?m)^\s+ref:")
        self.assertIn("persist-credentials: false", scorecard)

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
