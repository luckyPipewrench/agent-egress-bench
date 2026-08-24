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

    def test_target_specific_notice_is_reported(self):
        text = "Give the maintainer notice and a chance to correct the plugin.\n"
        findings = check.scan_text(Path("docs/x.md"), text)
        self.assertEqual(len(findings), 1)
        self.assertIn("target-specific notice", findings[0])

    def test_private_result_preview_is_reported(self):
        text = "The vendor is offered a private result preview before publication.\n"
        findings = check.scan_text(Path("docs/x.md"), text)
        self.assertEqual(len(findings), 1)
        self.assertIn("prepublication result review", findings[0])

    def test_public_setup_review_without_private_preview_passes(self):
        text = (
            "The target receives no private notice period or "
            "prepublication result preview.\n"
        )
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

    def test_bench_reference_lane_claim_is_reported(self):
        damaged = self.text + (
            "\nThe Pipelock reference lane in this repository publishes first-party "
            "regression evidence.\n"
        )
        findings = check.check_definitions(damaged)
        self.assertTrue(any("live reference lane" in finding for finding in findings))

    def test_reversed_reference_lane_claim_is_reported(self):
        damaged = self.text + (
            "\nThis repository is Pipelock's reference lane and publication home.\n"
        )
        findings = check.check_definitions(damaged)
        self.assertTrue(any("live reference lane" in finding for finding in findings))

    def reverse_the_permission(self):
        """Return the document with the adverse-results permission taken away."""
        body = check.section_text(self.text, check.ADVERSE_SECTION)
        self.assertIsNotNone(body)
        damaged = self.text.replace(
            body, "\nAn adverse result needs maintainer approval before publication.\n"
        )
        self.assertNotIn("may publish", check.section_text(damaged, check.ADVERSE_SECTION))
        return damaged

    def test_reversing_the_adverse_result_permission_is_reported(self):
        findings = check.check_definitions(self.reverse_the_permission())
        self.assertTrue(any("Adverse results" in finding for finding in findings))

    def test_permission_phrase_elsewhere_does_not_satisfy_the_check(self):
        damaged = self.reverse_the_permission().replace(
            "## Scope\n",
            "## Scope\n\nA lab may publish its schedule without notice, approval, or coordination.\n",
            1,
        )
        self.assertIn("without notice, approval", damaged)
        findings = check.check_definitions(damaged)
        self.assertTrue(any("Adverse results" in finding for finding in findings))

    def test_deleting_the_adverse_results_section_is_reported(self):
        damaged = self.text.replace("## Adverse results", "## Something else")
        findings = check.check_definitions(damaged)
        self.assertTrue(any("missing the 'Adverse results' section" in f for f in findings))

    def test_deleting_configuration_verification_is_reported(self):
        damaged = self.text.replace("## Configuration verification", "## Something else")
        findings = check.check_definitions(damaged)
        self.assertTrue(any("missing the 'Configuration verification' section" in f for f in findings))

    def test_private_configuration_review_is_reported(self):
        body = check.section_text(self.text, check.CONFIGURATION_SECTION)
        self.assertIsNotNone(body)
        damaged = self.text.replace(
            body,
            "\nThe target receives a private result preview and may veto publication.\n",
        )
        findings = check.check_definitions(damaged)
        self.assertTrue(any("setup review public" in f for f in findings))


class GauntletExamHomeTest(unittest.TestCase):
    def test_prose_workflow_link_is_not_a_badge_finding(self):
        text = (
            '<a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml">'
            '<img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml/badge.svg" '
            'alt="Pipelock Scan"></a>\n'
            "See .github/workflows/continuous-gauntlet.yaml for the optional manual workflow.\n"
        )
        self.assertEqual(check.check_readme_exam_home(text), [])

    def test_continuous_gauntlet_readme_badge_is_reported(self):
        text = (
            '<a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml">'
            '<img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml/badge.svg" '
            'alt="Pipelock Scan"></a>\n'
            '<a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/continuous-gauntlet.yaml">'
            '<img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/continuous-gauntlet.yaml/badge.svg" '
            'alt="Continuous Gauntlet"></a>\n'
        )
        findings = check.check_readme_exam_home(text)
        self.assertEqual(len(findings), 1)
        self.assertIn("continuous-gauntlet.yaml", findings[0])
        self.assertIn("not the live product schedule", findings[0])

    def test_pipelock_scan_badge_is_required(self):
        findings = check.check_readme_exam_home("<p align=\"center\">no badges</p>\n")
        self.assertTrue(any("pipelock.yaml" in finding for finding in findings))

    def test_live_readme_keeps_scan_badge_and_drops_gauntlet_badge(self):
        text = (REPO_ROOT / check.README_FILE).read_text(encoding="utf-8")
        self.assertEqual(check.check_readme_exam_home(text), [])

    def test_scheduled_pipelock_lane_claim_is_reported(self):
        text = (
            "The repository's scheduled Pipelock lane is read-only and "
            "produces review candidates, not automatic public claims.\n"
        )
        findings = check.scan_text(Path("README.md"), text)
        self.assertEqual(len(findings), 1)
        self.assertIn("scheduled Pipelock lane", findings[0])

    def test_this_repository_scheduled_lane_claim_is_reported(self):
        text = "this repository's scheduled Pipelock lane still runs the exam.\n"
        findings = check.scan_text(Path("docs/CONTINUOUS-RESULTS.md"), text)
        self.assertEqual(len(findings), 1)
        self.assertIn("scheduled Pipelock lane", findings[0])

    def test_self_operated_lane_claim_is_reported(self):
        text = (
            "Its publication policy remains independent from this "
            "repository's self-operated Pipelock lane.\n"
        )
        findings = check.scan_text(Path("docs/CONTINUOUS-RESULTS.md"), text)
        self.assertEqual(len(findings), 1)
        self.assertIn("self-operated Pipelock lane", findings[0])

    def test_old_continuous_results_opening_is_reported(self):
        old = (
            "The Pipelock reference lane separates execution, review, and publication.\n"
            "1. The read-only `Continuous Gauntlet` workflow runs the portable "
            "benchmark and retains a candidate evidence bundle.\n"
            "./scripts/run-pipelock-gauntlet.sh\n"
            "An independent lab can repeat that command with its own scheduler.\n"
        )
        findings = check.check_continuous_results(old)
        self.assertTrue(any("luckyPipewrench/pipelock" in finding for finding in findings))
        self.assertTrue(any("pipelab.org/gauntlet/results" in finding for finding in findings))

    def test_live_public_exam_claim_is_reported_with_required_strings(self):
        text = (
            "The product's scheduled candidate currently runs in luckyPipewrench/pipelock.\n"
            "https://pipelab.org/gauntlet/results/\n"
            "./scripts/run-pipelock-gauntlet.sh\n"
            "An independent lab can repeat that command with its own scheduler. "
            "An operator calling its program continuous declares the publication selection rule.\n"
            "This repository's Continuous Gauntlet workflow is the live public Pipelock execution.\n"
        )
        findings = check.check_continuous_results(text)
        self.assertTrue(any("live public Pipelock exam" in finding for finding in findings))

    def test_live_continuous_results_passes(self):
        text = (REPO_ROOT / check.CONTINUOUS_RESULTS_DOC).read_text(encoding="utf-8")
        self.assertEqual(check.check_continuous_results(text), [])

    def test_scheduled_workflow_is_reported(self):
        findings = check.check_workflow_not_scheduled(
            "on:\n  workflow_dispatch:\n  schedule:\n    - cron: '17 6 * * *'\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("must not schedule a daily", findings[0])

    def test_live_workflow_is_not_scheduled(self):
        text = (REPO_ROOT / check.CONTINUOUS_WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(check.check_workflow_not_scheduled(text), [])


class RepositoryTest(unittest.TestCase):
    def test_repository_documentation_is_clean(self):
        self.assertEqual(check.main(), 0)


if __name__ == "__main__":
    unittest.main()
