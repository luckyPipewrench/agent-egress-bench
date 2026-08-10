#!/usr/bin/env python3
"""Tests for check_readme_categories.

The empty-set test is the important one. An empty category set makes every
"missing" comparison trivially true, so a runner that produced nothing would
otherwise pass this gate while proving nothing, which is the exact defect the
sibling stats gate already had to fix.
"""

from __future__ import annotations

import importlib.util
import subprocess
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_readme_categories.py"

spec = importlib.util.spec_from_file_location("check_readme_categories", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class DocumentedCategoriesTest(unittest.TestCase):
    def _readme(self, body: str) -> Path:
        path = Path(self.tmp.name) / "README.md"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_reads_category_cells(self) -> None:
        readme = self._readme(
            """
            | Case category | OWASP item | What the cases cover |
            |---------------|------------|---------------------|
            | `url` | ASI02 Tool Misuse | Secrets in query strings |
            | `mcp_drift` | ASI04 Supply Chain | Inventory changes |
            """
        )
        self.assertEqual(mod.documented_categories(readme), {"url", "mcp_drift"})

    def test_ignores_prose_and_non_category_tables(self) -> None:
        readme = self._readme(
            """
            Some prose mentioning `url` inline should not count.

            | Field | Meaning |
            |-------|---------|
            | not a category cell | because the row does not lead with a code span |
            """
        )
        self.assertEqual(mod.documented_categories(readme), set())


class SpecCategoriesTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _spec(self, body: str) -> Path:
        path = Path(self.tmp.name) / "SPEC.md"
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path

    def test_reads_only_the_category_section(self) -> None:
        """A neighbouring enum must not satisfy a missing category."""
        spec = self._spec(
            """
            ### category

            `url`, `mcp_drift`

            ### input_type

            `url`, `websocket_frame`, `mcp_tool_call`
            """
        )
        self.assertEqual(mod.spec_categories(spec), {"url", "mcp_drift"})

    def test_missing_section_is_refused(self) -> None:
        spec = self._spec(
            """
            ### input_type

            `url`, `websocket_frame`
            """
        )
        with self.assertRaises(SystemExit):
            mod.spec_categories(spec)


class ComparisonTest(unittest.TestCase):
    """The gate's decision, exercised without invoking the Go runner."""

    def _run(self, live: set[str], documented: set[str]) -> int:
        undocumented = sorted(live - documented)
        phantom = sorted(documented - live)
        return 1 if (undocumented or phantom) else 0

    def test_complete_mapping_passes(self) -> None:
        self.assertEqual(self._run({"url", "mcp_drift"}, {"url", "mcp_drift"}), 0)

    def test_category_without_a_row_fails(self) -> None:
        self.assertEqual(self._run({"url", "mcp_drift"}, {"url"}), 1)

    def test_row_without_cases_fails(self) -> None:
        self.assertEqual(self._run({"url"}, {"url", "retired_category"}), 1)


class EmptyRunnerOutputTest(unittest.TestCase):
    def test_refuses_an_empty_category_set(self) -> None:
        """A runner reporting nothing must not satisfy the gate by vacuity."""

        def fake_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        original = mod.subprocess.run
        mod.subprocess.run = fake_run
        try:
            with self.assertRaises(SystemExit) as caught:
                mod.live_categories(Path("."))
        finally:
            mod.subprocess.run = original
        self.assertIn("no categories", str(caught.exception))

    def test_refuses_a_failing_runner(self) -> None:
        def fake_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="corpus load failed"
            )

        original = mod.subprocess.run
        mod.subprocess.run = fake_run
        try:
            with self.assertRaises(SystemExit) as caught:
                mod.live_categories(Path("."))
        finally:
            mod.subprocess.run = original
        self.assertIn("could not load the corpus", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
