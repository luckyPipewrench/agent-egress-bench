#!/usr/bin/env python3
"""Tests for the fail-safe provenance scope validator."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_gauntlet_scope.py"


def complete_artifact():
    return {
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "case_count": {
            "total": 197,
            "applicable": 196,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
        },
        "scores": {
            "applicable": {
                "containment": 1.0,
                "false_positive_rate": 0.0,
            },
        },
    }


def all_na_artifact():
    artifact = complete_artifact()
    artifact["case_count"] = {
        "total": 197,
        "applicable": 0,
        "not_applicable": 197,
        "not_applicable_reasons": {"missing_requires": 197},
    }
    artifact["scores"]["applicable"]["containment"] = None
    return artifact


class ValidateGauntletScopeTest(unittest.TestCase):
    def run_validator(self, artifact):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", encoding="utf-8") as fh:
            json.dump(artifact, fh)
            fh.flush()
            return subprocess.run(
                [sys.executable, str(VALIDATOR), fh.name],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_complete_artifact_passes(self):
        result = self.run_validator(complete_artifact())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_required_scope_field_fails_when_missing(self):
        required_paths = [
            ("case_count", "applicable"),
            ("case_count", "total"),
            ("case_count", "not_applicable"),
            ("case_count", "not_applicable_reasons"),
            ("scores", "applicable", "containment"),
            ("scores", "applicable", "false_positive_rate"),
            ("canonical_url",),
        ]

        for path in required_paths:
            with self.subTest(path=".".join(path)):
                artifact = complete_artifact()
                target = artifact
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(".".join(path), result.stderr)

    def test_inconsistent_na_breakdown_fails(self):
        artifact = complete_artifact()
        artifact["case_count"]["not_applicable_reasons"] = {"missing_requires": 0}

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not_applicable_reasons must sum", result.stderr)

    def test_null_false_positive_rate_passes_as_na(self):
        artifact = complete_artifact()
        artifact["scores"]["applicable"]["false_positive_rate"] = None

        result = self.run_validator(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_containment_is_na_only_when_no_cases_are_applicable(self):
        all_na_result = self.run_validator(all_na_artifact())
        self.assertEqual(all_na_result.returncode, 0, all_na_result.stderr)

        all_na_with_score = all_na_artifact()
        all_na_with_score["scores"]["applicable"]["containment"] = 0.0
        all_na_with_score_result = self.run_validator(all_na_with_score)
        self.assertNotEqual(all_na_with_score_result.returncode, 0)
        self.assertIn("containment", all_na_with_score_result.stderr)

        applicable_with_na = complete_artifact()
        applicable_with_na["scores"]["applicable"]["containment"] = None
        applicable_with_na_result = self.run_validator(applicable_with_na)
        self.assertNotEqual(applicable_with_na_result.returncode, 0)
        self.assertIn("containment", applicable_with_na_result.stderr)

        applicable_with_score_result = self.run_validator(complete_artifact())
        self.assertEqual(applicable_with_score_result.returncode, 0, applicable_with_score_result.stderr)

    def test_invalid_containment_values_fail(self):
        # For runs with applicable cases, containment is the published headline.
        # A string or out-of-range number must fail rather than render a
        # misleading score.
        for bad in ("100%", 2, -1):
            with self.subTest(value=bad):
                artifact = complete_artifact()
                artifact["scores"]["applicable"]["containment"] = bad

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("containment", result.stderr)


    def test_zero_total_fails(self):
        artifact = complete_artifact()
        artifact["case_count"] = {
            "total": 0,
            "applicable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("greater than zero", result.stderr)

    def test_unsafe_canonical_url_fails(self):
        # A non-https or non-absolute canonical_url must fail: it is rendered as
        # a link, so a javascript:/relative/http value is a real safety gap.
        for bad in ("javascript:alert(1)", "not-a-url", "http://example.com/x", "//example.com/x"):
            with self.subTest(value=bad):
                artifact = complete_artifact()
                artifact["canonical_url"] = bad

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("canonical_url", result.stderr)


if __name__ == "__main__":
    unittest.main()
