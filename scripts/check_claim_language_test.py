#!/usr/bin/env python3
"""Tests for the documentation claim-language gate."""

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "scripts" / "check_claim_language.py"

spec = importlib.util.spec_from_file_location("check_claim_language", MODULE_PATH)
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


class BannedTermTest(unittest.TestCase):
    def test_certification_claim_is_reported(self):
        findings = check.scan_text(Path("docs/x.md"), "Pipelock is certified under this corpus.\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("docs/x.md:1", findings[0])
        self.assertIn("not a certification", findings[0])

    def test_ranking_language_is_reported(self):
        findings = check.scan_text(Path("README.md"), "See the leaderboard for scores.\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("leaderboard", findings[0])

    def test_absolute_security_language_is_reported(self):
        text = "The tool is proven secure.\nThere are no bypasses.\n"
        findings = check.scan_text(Path("docs/x.md"), text)
        self.assertEqual(len(findings), 2)

    def test_marker_exempts_a_line(self):
        text = "It certifies nothing. <!-- claim-ok: states the non-claim -->\n"
        self.assertEqual(check.scan_text(Path("docs/x.md"), text), [])

    def test_marker_requires_a_reason(self):
        text = "Pipelock is certified. <!-- claim-ok: -->\n"
        self.assertEqual(len(check.scan_text(Path("docs/x.md"), text)), 1)

    def test_ordinary_prose_passes(self):
        text = "The runner reports containment, detection, evidence, and false positives.\n"
        self.assertEqual(check.scan_text(Path("docs/x.md"), text), [])


class DefinitionsDocumentTest(unittest.TestCase):
    def setUp(self):
        self.text = (REPO_ROOT / check.DEFINITIONS_DOC).read_text(encoding="utf-8")

    def test_live_definitions_document_passes(self):
        self.assertEqual(check.check_definitions(self.text), [])

    def test_missing_assurance_label_is_reported(self):
        damaged = self.text.replace("Challenge-verified", "Something else")
        findings = check.check_definitions(damaged)
        self.assertTrue(any("Challenge-verified" in finding for finding in findings))

    def test_removing_the_adverse_result_permission_is_reported(self):
        damaged = self.text.replace("without\nnotice, approval", "only with prior approval")
        damaged = damaged.replace("without notice, approval", "only with prior approval")
        findings = check.check_definitions(damaged)
        self.assertTrue(any("adverse results" in finding for finding in findings))


class RepositoryTest(unittest.TestCase):
    def test_repository_documentation_is_clean(self):
        self.assertEqual(check.main(), 0)


if __name__ == "__main__":
    unittest.main()
