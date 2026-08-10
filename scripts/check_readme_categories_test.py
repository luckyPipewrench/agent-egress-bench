#!/usr/bin/env python3
"""Tests for check_readme_categories.

The empty-set tests are the important ones. An empty category set makes every
"missing" comparison trivially true, so a runner that produced nothing would
otherwise pass this gate while proving nothing, which is the exact defect the
sibling stats gate already had to fix.
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_readme_categories.py"
REPO_ROOT = SCRIPT.parent.parent

spec = importlib.util.spec_from_file_location("check_readme_categories", SCRIPT)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

TABLE_HEAD = "| Case category | OWASP item | What the cases cover |\n|---|---|---|\n"


class TempFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _write(self, name: str, body: str) -> Path:
        path = Path(self.tmp.name) / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return path


class DocumentedCategoriesTest(TempFileTest):
    def test_reads_mapped_category_cells(self) -> None:
        readme = self._write(
            "README.md",
            TABLE_HEAD
            + "| `url` | ASI02 Tool Misuse | Secrets in query strings |\n"
            + "| `mcp_drift` | ASI04 Supply Chain | Inventory changes |\n",
        )
        self.assertEqual(mod.documented_categories(readme), {"url", "mcp_drift"})

    def test_accepts_not_applicable_for_benign_categories(self) -> None:
        readme = self._write(
            "README.md",
            TABLE_HEAD + "| `false_positive` | N/A | Benign traffic |\n",
        )
        self.assertEqual(mod.documented_categories(readme), {"false_positive"})

    def test_row_without_an_owasp_item_is_refused(self) -> None:
        readme = self._write(
            "README.md", TABLE_HEAD + "| `url` |  | Secrets in query strings |\n"
        )
        with self.assertRaises(SystemExit) as caught:
            mod.documented_categories(readme)
        self.assertIn("no OWASP item", str(caught.exception))

    def test_unrelated_table_does_not_satisfy_the_gate(self) -> None:
        """A code-span first cell in some other table must not count as a mapping."""
        readme = self._write(
            "README.md",
            "| Field | Meaning |\n|---|---|\n| `url` | a config key, not a category |\n",
        )
        with self.assertRaises(SystemExit) as caught:
            mod.documented_categories(readme)
        self.assertIn("could not find the mapping table", str(caught.exception))


class SpecCategoriesTest(TempFileTest):
    def test_reads_only_the_category_section(self) -> None:
        """A neighbouring enum must not satisfy a missing category."""
        spec_md = self._write(
            "SPEC.md",
            """
            ### category

            `url`, `mcp_drift`

            ### input_type

            `url`, `websocket_frame`, `mcp_tool_call`
            """,
        )
        self.assertEqual(mod.spec_categories(spec_md), {"url", "mcp_drift"})

    def test_missing_section_is_refused(self) -> None:
        spec_md = self._write(
            "SPEC.md",
            """
            ### input_type

            `url`, `websocket_frame`
            """,
        )
        with self.assertRaises(SystemExit):
            mod.spec_categories(spec_md)


class ComparisonTest(unittest.TestCase):
    """The gate's decision, exercised without invoking the Go runner."""

    def _run(self, live: set[str], documented: set[str]) -> int:
        return 1 if (live - documented or documented - live) else 0

    def test_complete_mapping_passes(self) -> None:
        self.assertEqual(self._run({"url", "mcp_drift"}, {"url", "mcp_drift"}), 0)

    def test_category_without_a_row_fails(self) -> None:
        self.assertEqual(self._run({"url", "mcp_drift"}, {"url"}), 1)

    def test_row_without_cases_fails(self) -> None:
        self.assertEqual(self._run({"url"}, {"url", "retired_category"}), 1)


class StatsParsingTest(unittest.TestCase):
    def _with_stdout(self, stdout: str, returncode: int = 0):
        def fake_run(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=[], returncode=returncode, stdout=stdout, stderr="boom"
            )

        return fake_run

    def _patch(self, fake):
        original = mod.subprocess.run
        mod.subprocess.run = fake
        self.addCleanup(lambda: setattr(mod.subprocess, "run", original))

    def test_blank_separator_does_not_truncate_the_set(self) -> None:
        self._patch(
            self._with_stdout("by_category:\n  url: 3\n\n  mcp_drift: 6\n")
        )
        self.assertEqual(mod.live_categories(Path(".")), {"url", "mcp_drift"})

    def test_missing_section_is_refused(self) -> None:
        self._patch(self._with_stdout("cases_total: 5\ncategories: 1\n"))
        with self.assertRaises(SystemExit) as caught:
            mod.live_categories(Path("."))
        self.assertIn("no 'by_category:' section", str(caught.exception))

    def test_refuses_an_empty_category_set(self) -> None:
        self._patch(self._with_stdout("by_category:\n"))
        with self.assertRaises(SystemExit) as caught:
            mod.live_categories(Path("."))
        self.assertIn("no categories", str(caught.exception))

    def test_refuses_a_failing_runner(self) -> None:
        self._patch(self._with_stdout("", returncode=1))
        with self.assertRaises(SystemExit) as caught:
            mod.live_categories(Path("."))
        self.assertIn("could not load the corpus", str(caught.exception))

    def test_refuses_a_hung_runner(self) -> None:
        def fake_run(*_args, **_kwargs):
            raise subprocess.TimeoutExpired(cmd="go", timeout=1)

        self._patch(fake_run)
        with self.assertRaises(SystemExit) as caught:
            mod.live_categories(Path("."))
        self.assertIn("did not finish", str(caught.exception))


class MultiFileCoverageTest(unittest.TestCase):
    """mcp_drift lives only in multi-file cases under cases/mcp-drift/.

    A review argued the gate could not see it, because the runner's stats might
    cover only the single-file corpus. The runner does load both, so the gate
    does see it. This asserts that against the real corpus, because a runner
    that stopped reporting multi-file categories would make the gate quietly
    stop covering a whole category rather than fail.
    """

    def test_gate_sees_the_multi_file_category(self) -> None:
        self.assertIn("mcp_drift", mod.live_categories(REPO_ROOT))


if __name__ == "__main__":
    unittest.main()
