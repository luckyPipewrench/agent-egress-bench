#!/usr/bin/env python3
"""Structural tests for the Pipelock secret-scan workflow.

Each assertion here corresponds to a defect that was caught by a human reviewer
rather than by any check, which is why they are tests and not comments.

The scan workflow was rewritten on 2026-08-10 because the published Pipelock
action installs the latest RELEASE, and a scanner fix on Pipelock's default
branch does not reach a release for weeks. Whole-file-deletion hunk parsing was
fixed in pipelock#1145, which was absent from v3.3.0, so every pull request that
deleted a file failed with "unverifiable input: content outside unified diff
hunks" and the action surfaced that as "Secrets detected in PR diff" with no
secret present. That blocked #157 for a day.

Three properties of the rewrite are load-bearing and easy to lose silently.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pipelock.yaml"

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


class PipelockScanWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text()

    def test_both_scan_paths_survive(self):
        """Both trigger paths must keep a diff scan.

        Promotion pull requests are created with GITHUB_TOKEN, which does not
        emit a pull_request run, so the promotion workflow dispatches this one
        against the generated branch instead. Losing either path leaves a class
        of change entering main unscanned, and the loss is invisible because the
        remaining path still reports success.

        This is not hypothetical: an early draft of the rewrite dropped the
        dispatch path entirely while rewriting the file from a stale checkout.
        """
        self.assertRegex(
            self.workflow,
            r"(?m)^  workflow_dispatch:$",
            "workflow_dispatch trigger removed; promotion branches would go unscanned",
        )
        self.assertRegex(
            self.workflow,
            r"(?m)^  pull_request:$",
            "pull_request trigger removed; ordinary pull requests would go unscanned",
        )
        for step in ("Scan pull request diff", "Scan dispatched branch diff"):
            self.assertIn(
                f"- name: {step}",
                self.workflow,
                f"missing scan step: {step}",
            )

    def test_scanner_revision_is_immutable(self):
        """The scanner must be pinned to a commit, never a moving ref.

        A floating `@main` would let any later commit on Pipelock change or
        disable this repository's secret gate with no reviewed change here. The
        first version of this rewrite used `@main` and that was caught in
        review.
        """
        match = re.search(r"PIPELOCK_REV:\s*(\S+)", self.workflow)
        self.assertIsNotNone(
            match,
            "no PIPELOCK_REV pin found; the scanner build must name an immutable revision",
        )
        rev = match.group(1).strip().strip("'\"")
        self.assertRegex(
            rev,
            FULL_SHA,
            f"PIPELOCK_REV is {rev!r}; pin a full 40-character commit rather than a branch or tag, "
            "so a later upstream commit cannot silently change this gate",
        )

    def test_diff_generation_forces_text(self):
        """Diffs must be generated with --text.

        Without it, a path marked binary by an in-repo .gitattributes reduces to
        a "Binary files differ" marker and its content is never scanned, so a
        credential can be added behind a one-line attributes rule.
        """
        diff_lines = [ln for ln in self.workflow.splitlines() if "git diff" in ln]
        self.assertTrue(diff_lines, "no git diff invocation found in the scan workflow")
        for line in diff_lines:
            self.assertIn(
                "--text",
                line,
                f"diff generated without --text:\n  {line.strip()}\n"
                "an in-repo .gitattributes rule could hide added content from the scanner",
            )


if __name__ == "__main__":
    unittest.main()
