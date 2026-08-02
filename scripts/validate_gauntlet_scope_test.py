#!/usr/bin/env python3
"""Tests for the fail-safe provenance scope validator."""

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_gauntlet_scope.py"
MANIFEST = REPO_ROOT / "cases" / "MANIFEST.txt"


def corpus_manifest_sha256():
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def logical_case_count():
    return len({line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()})


def complete_artifact():
    return {
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
        "corpus_manifest_sha256": corpus_manifest_sha256(),
        "logical_case_count": logical_case_count(),
        "runner_version": "0.4.0",
        "scoring_version": "2.2",
        "case_count": {
            "total": logical_case_count(),
            "applicable": logical_case_count() - 1,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
        },
        "scores": {
            "applicable": {
                "containment": 1.0,
                "false_positive_rate": 0.0,
            },
        },
        "metric_counts": {
            "applicable": {
                "containment": {"numerator": 1, "denominator": 1},
                "false_positive_rate": {"numerator": 0, "denominator": 1},
            },
        },
    }


def all_na_artifact():
    artifact = complete_artifact()
    artifact["case_count"] = {
        "total": logical_case_count(),
        "applicable": 0,
        "not_applicable": logical_case_count(),
        "not_applicable_reasons": {"missing_requires": logical_case_count()},
    }
    artifact["scores"]["applicable"]["containment"] = None
    artifact["scores"]["applicable"]["false_positive_rate"] = None
    artifact["metric_counts"]["applicable"]["containment"] = {"numerator": 0, "denominator": 0}
    artifact["metric_counts"]["applicable"]["false_positive_rate"] = {"numerator": 0, "denominator": 0}
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
            ("artifact_id",),
            ("corpus_manifest_sha256",),
            ("logical_case_count",),
            ("runner_version",),
            ("scoring_version",),
            ("metric_counts", "applicable", "containment", "numerator"),
            ("metric_counts", "applicable", "containment", "denominator"),
            ("metric_counts", "applicable", "false_positive_rate", "numerator"),
            ("metric_counts", "applicable", "false_positive_rate", "denominator"),
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

    def test_missing_corpus_digest_fails(self):
        artifact = complete_artifact()
        del artifact["corpus_manifest_sha256"]

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corpus_manifest_sha256", result.stderr)

    def test_corpus_digest_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["corpus_manifest_sha256"] = "0" * 64

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corpus_manifest_sha256", result.stderr)

    def test_logical_case_count_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["logical_case_count"] -= 1

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("logical_case_count", result.stderr)

    def test_case_count_total_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["case_count"] = {
            "total": logical_case_count() - 1,
            "applicable": logical_case_count() - 2,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("case_count.total", result.stderr)

    def test_score_must_equal_metric_numerator_over_denominator(self):
        for metric in ("containment", "false_positive_rate"):
            with self.subTest(metric=metric):
                artifact = complete_artifact()
                artifact["scores"]["applicable"][metric] = 0.5

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(metric, result.stderr)

    def test_metric_denominator_cannot_exceed_applicable_cases(self):
        artifact = complete_artifact()
        artifact["metric_counts"]["applicable"]["containment"] = {
            "numerator": logical_case_count(),
            "denominator": logical_case_count(),
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("metric denominator", result.stderr)

    def test_inconsistent_na_breakdown_fails(self):
        artifact = complete_artifact()
        artifact["case_count"]["not_applicable_reasons"] = {"missing_requires": 0}

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not_applicable_reasons must sum", result.stderr)

    def test_null_false_positive_rate_passes_as_na(self):
        artifact = complete_artifact()
        artifact["scores"]["applicable"]["false_positive_rate"] = None
        artifact["metric_counts"]["applicable"]["false_positive_rate"] = {
            "numerator": 0,
            "denominator": 0,
        }

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
