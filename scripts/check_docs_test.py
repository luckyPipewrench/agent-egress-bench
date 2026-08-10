#!/usr/bin/env python3
"""Regression tests for local Markdown link validation."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_docs.py")
SPEC = importlib.util.spec_from_file_location("check_docs", MODULE_PATH)
check_docs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_docs)


class CheckDocsTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        docs = self.root / "docs"
        docs.mkdir()
        for name in ("SPEC.md", "RUNNER.md", "gauntlet.md", "GOVERNANCE.md"):
            (docs / name).write_text("owner\n", encoding="utf-8")
        (self.root / "AGENTS.md").write_text(
            "\n".join(f"docs/{name}" for name in ("SPEC.md", "RUNNER.md", "gauntlet.md", "GOVERNANCE.md"))
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_accepts_percent_encoded_local_target_with_title(self):
        (self.root / "guide file.md").write_text("guide\n", encoding="utf-8")
        (self.root / "README.md").write_text(
            "[guide](guide%20file.md \"Local guide\")\n", encoding="utf-8"
        )

        _, _, links = check_docs.check(self.root)

        self.assertEqual(links, 1)

    def test_accepts_angle_bracket_target_with_fragment_and_title(self):
        (self.root / "guide file.md").write_text("guide\n", encoding="utf-8")
        (self.root / "README.md").write_text(
            "[guide](<guide file.md#section> 'Local guide')\n", encoding="utf-8"
        )

        _, _, links = check_docs.check(self.root)

        self.assertEqual(links, 1)


if __name__ == "__main__":
    unittest.main()
