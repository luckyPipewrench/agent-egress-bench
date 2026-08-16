#!/usr/bin/env python3
"""Structural tests for the trusted Scorecard job and what it may publish."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SECURITY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "security.yaml"
SCORECARD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "scorecard.yaml"


class ScorecardWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = SCORECARD_WORKFLOW.read_text(encoding="utf-8")
        self.security = SECURITY_WORKFLOW.read_text(encoding="utf-8")
        self.triggers = self.workflow.split("concurrency:", 1)[0]

    def test_scorecard_never_runs_against_pull_request_code(self):
        # The invariant, and it survived a move. Scorecard holds id-token: write
        # so it can authenticate a published result, so pull request code must
        # never reach it.
        #
        # It used to be enforced by an `if:` on a job inside the
        # pull-request-triggered Security workflow, which rendered a permanent
        # skipped check on every pull request. It is now enforced by this
        # workflow not listening for pull requests at all, which is the shape
        # the action documents and the shape ossf/scorecard uses itself. An
        # absent trigger is stronger than a condition, because there is no
        # branch left to get wrong.
        #
        # workflow_run stays banned for the original reason: it runs privileged
        # and can then check out the triggering run's code, which is a
        # privilege-escalation shape.
        self.assertNotIn("workflow_run", self.workflow)
        self.assertNotRegex(self.triggers, r"(?m)^\s*pull_request:")
        self.assertRegex(self.workflow, r"(?m)^permissions: read-all$")
        # And it must not have crept back into the pull-request-triggered
        # workflow, where it would need the condition again.
        self.assertNotRegex(self.security, r"(?m)^  scorecard:")

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

        scorecard = self.workflow.split("\n  scorecard:\n", 1)[1]

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

    def test_scorecard_runs_on_the_documented_triggers(self):
        # push to the default branch plus a schedule are what the action
        # documents as supported, and what ossf/scorecard uses itself.
        self.assertRegex(self.workflow, r"(?m)^name: Scorecard$")
        self.assertRegex(
            self.triggers,
            r"(?m)^  push:\n    branches: \[main\]$",
        )
        self.assertRegex(self.triggers, r"(?m)^  schedule:$")

    def test_security_workflow_still_scans_main_pushes(self):
        self.assertRegex(self.security, r"(?m)^name: Security$")
        self.assertRegex(
            self.security.split("concurrency:", 1)[0],
            r"(?m)^  push:\n    branches: \[main\]$",
        )
        self.assertRegex(
            self.security,
            r"uses: github/codeql-action/analyze@[0-9a-f]{40}",
        )

    def test_neither_job_checks_out_a_named_ref(self):
        self.assertNotRegex(self.workflow, r"(?m)^\s+ref:")
        self.assertNotRegex(self.security, r"(?m)^\s+ref:")
        # Scorecard checks out with the token withheld, so a compromised step
        # cannot reuse it against the repository.
        self.assertIn("persist-credentials: false", self.workflow)

    def test_trusted_scorecard_triggers_remain(self):
        for trigger in ("branch_protection_rule:", "workflow_dispatch:", "schedule:"):
            with self.subTest(trigger=trigger):
                self.assertIn(trigger, self.triggers)

    def test_only_pull_request_runs_are_cancelled(self):
        # This belongs to the Security workflow, which still serves pull
        # requests through CodeQL. Cancelling a superseded pull request run is
        # right there and wrong for Scorecard, whose runs publish a graded
        # result and must finish.
        self.assertRegex(
            self.security,
            r"(?m)^concurrency:\n"
            r"  group: security-\$\{\{ github\.ref \}\}\n"
            r"  cancel-in-progress: \$\{\{ github\.event_name == 'pull_request' \}\}$",
        )
        self.assertRegex(
            self.workflow,
            r"(?m)^concurrency:\n"
            r"  group: scorecard-\$\{\{ github\.ref \}\}\n"
            r"  cancel-in-progress: false$",
        )
        self.assertEqual(self.security.count("timeout-minutes: 10"), 1)
        self.assertEqual(self.workflow.count("timeout-minutes: 10"), 1)


if __name__ == "__main__":
    unittest.main()
