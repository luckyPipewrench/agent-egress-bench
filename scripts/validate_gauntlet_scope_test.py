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


if __name__ == "__main__":
    unittest.main()
