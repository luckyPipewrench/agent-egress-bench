#!/usr/bin/env python3

import unittest

from scripts.ci_scope import is_workflow_only


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


if __name__ == "__main__":
    unittest.main()
