#!/usr/bin/env python3

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.ci_scope import changed_paths, is_workflow_only


class CIScopeTest(unittest.TestCase):
    def test_accepts_only_direct_workflow_yaml_files(self) -> None:
        self.assertTrue(is_workflow_only([".github/workflows/release.yaml", ".github/workflows/validate.yml"]))

    def test_rejects_empty_change(self) -> None:
        self.assertFalse(is_workflow_only([]))

    def test_rejects_any_non_workflow_path(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/release.yaml", "scripts/release_build.py"]))

    def test_rejects_nested_or_non_yaml_workflow_paths(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/archive/release.yaml"]))
        self.assertFalse(is_workflow_only([".github/workflows/README.md"]))

    def test_rejects_path_escape(self) -> None:
        self.assertFalse(is_workflow_only([".github/workflows/../release.yaml"]))

    def test_non_workflow_deletion_cannot_hide_behind_workflow_edit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            workflow = repo / ".github/workflows/validate.yaml"
            source = repo / "scripts/helper.py"
            workflow.parent.mkdir(parents=True)
            source.parent.mkdir()
            workflow.write_text("name: before\n", encoding="utf-8")
            source.write_text("print('before')\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=repo, check=True)
            base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, text=True, capture_output=True).stdout.strip()
            workflow.write_text("name: after\n", encoding="utf-8")
            source.unlink()
            subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-q", "-m", "change"], cwd=repo, check=True)

            original = Path.cwd()
            try:
                import os

                os.chdir(repo)
                paths = changed_paths(base, "HEAD")
            finally:
                os.chdir(original)
            self.assertEqual({".github/workflows/validate.yaml", "scripts/helper.py"}, set(paths))
            self.assertFalse(is_workflow_only(paths))


if __name__ == "__main__":
    unittest.main()
