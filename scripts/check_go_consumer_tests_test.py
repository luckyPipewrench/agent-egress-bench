#!/usr/bin/env python3
"""Regression tests for named Go consumer-proof execution."""

import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "check_go_consumer_tests", ROOT / "scripts" / "check_go_consumer_tests.py"
)
checker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(checker)


class CheckGoConsumerTestsTest(unittest.TestCase):
    def test_missing_named_test_fails_before_execution(self):
        listed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr="")
        with mock.patch.object(checker.subprocess, "run", return_value=listed) as run:
            with self.assertRaisesRegex(RuntimeError, "required Go contract test is missing: TestProof"):
                checker.run_test(Path("runner"), "TestProof")
        self.assertEqual(1, run.call_count)

    def test_list_failure_fails_closed_before_execution(self):
        listed = subprocess.CompletedProcess([], 1, stdout="", stderr="compile failed")
        with mock.patch.object(checker.subprocess, "run", return_value=listed) as run:
            with self.assertRaisesRegex(RuntimeError, "go test -list failed"):
                checker.run_test(Path("runner"), "TestProof")
        self.assertEqual(1, run.call_count)

    def test_exact_named_test_is_listed_then_executed(self):
        listed = subprocess.CompletedProcess([], 0, stdout="TestProof\nok\n", stderr="")
        executed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(checker.subprocess, "run", side_effect=[listed, executed]) as run:
            checker.run_test(Path("runner"), "TestProof")
        self.assertEqual(2, run.call_count)


if __name__ == "__main__":
    unittest.main()
