#!/usr/bin/env python3
"""Regression tests for no-follow Action artifact publication."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "action_artifacts.py"


class ActionArtifactsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)

    def prepare(self) -> subprocess.CompletedProcess[str]:
        return self.command("prepare", "--workspace", str(self.workspace), "--output-dir", "aeb-results")

    def test_prepare_refuses_a_symlinked_output_directory(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        (self.workspace / "aeb-results").symlink_to(outside, target_is_directory=True)
        result = self.prepare()
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Action artifact handling failed", result.stderr)
        self.assertEqual([], list(outside.iterdir()))

    def test_publish_replaces_a_container_created_metadata_symlink_without_following_it(self) -> None:
        self.assertEqual(0, self.prepare().returncode)
        stage = self.root / "stage"
        stage.mkdir()
        results = stage / "results.jsonl"
        summary = stage / "summary.json"
        metadata = stage / "run-metadata.json"
        results.write_text('{"case":"AEB-0001"}\n', encoding="utf-8")
        summary.write_text('{"measurement_status":"measured"}\n', encoding="utf-8")
        metadata.write_text('{"runner_exit_code":0}\n', encoding="utf-8")
        outside = self.root / "outside.json"
        outside.write_text("SAFE\n", encoding="utf-8")
        (self.workspace / "aeb-results" / "run-metadata.json").symlink_to(outside)

        result = self.command(
            "publish",
            "--workspace", str(self.workspace),
            "--output-dir", "aeb-results",
            "--results", str(results),
            "--summary", str(summary),
            "--metadata", str(metadata),
        )
        self.assertEqual(0, result.returncode, msg=result.stderr)
        self.assertEqual("SAFE\n", outside.read_text(encoding="utf-8"))
        published = self.workspace / "aeb-results" / "run-metadata.json"
        self.assertFalse(published.is_symlink())
        self.assertEqual(metadata.read_text(encoding="utf-8"), published.read_text(encoding="utf-8"))

    def test_publish_refuses_a_symlinked_container_artifact(self) -> None:
        self.assertEqual(0, self.prepare().returncode)
        stage = self.root / "stage"
        stage.mkdir()
        results = stage / "results.jsonl"
        metadata = stage / "run-metadata.json"
        outside = self.root / "outside.json"
        results.write_text("{}\n", encoding="utf-8")
        metadata.write_text("{}\n", encoding="utf-8")
        outside.write_text('{"measurement_status":"measured"}\n', encoding="utf-8")
        summary = stage / "summary.json"
        summary.symlink_to(outside)

        result = self.command(
            "publish",
            "--workspace", str(self.workspace),
            "--output-dir", "aeb-results",
            "--results", str(results),
            "--summary", str(summary),
            "--metadata", str(metadata),
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("not a no-follow regular file", result.stderr)


if __name__ == "__main__":
    unittest.main()
