#!/usr/bin/env python3
"""Keep the released operator kit tied to the publication contract."""

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "examples" / "operator-kit"


class OperatorKitTest(unittest.TestCase):
    def test_kit_covers_setup_custody_reporting_and_appeals(self):
        readme = (KIT / "README.md").read_text(encoding="utf-8")
        custody = (KIT / "evidence-custody-checklist.md").read_text(encoding="utf-8")
        report = (KIT / "report-template.md").read_text(encoding="utf-8")

        for required in (
            "examples/runner-template/tool-profile-template.json",
            "examples/runner-template/skeleton.sh",
            "evidence-custody-checklist.md",
            "report-template.md",
            "Open an Issue",
            "Open a Discussion",
            "doesn't prove the declaration or create an assurance label",
        ):
            self.assertIn(required, readme)

        for required in (
            "Target artifact or image digest",
            "Target configuration path and SHA-256",
            "Capability-registry path, revision, and SHA-256",
            "The run directory is new or empty",
            "incomplete measurement",
            "Omitted or access-controlled evidence",
            "Each declared assurance label names the retained evidence",
            "run-metadata.json",
        ):
            self.assertIn(required, custody)

        for required in (
            "## Measured outcomes",
            "## Result-state accounting",
            "## Exercised-control coverage",
            "containment",
            "False-positive rate",
            "Unreachable",
            "Historical not-applicable",
            "Error",
            "## Limits and non-claims",
            "only when the saved evidence and execution arrangement satisfy their definitions",
        ):
            self.assertIn(required, report)

    def test_public_appeal_routes_are_consistent(self):
        governance = (ROOT / "docs" / "GOVERNANCE.md").read_text(encoding="utf-8")
        results_use = (ROOT / "docs" / "RESULTS-USE.md").read_text(encoding="utf-8")
        self.assertIn("disagree with a case's expected verdict, open a GitHub Issue", governance)
        self.assertIn("Use a GitHub Discussion instead when the disagreement is about scoring", governance)
        self.assertIn("Open a GitHub Issue for a disputed case verdict", results_use)
        self.assertIn("Open a GitHub Discussion for a scoring question", results_use)


if __name__ == "__main__":
    unittest.main()
