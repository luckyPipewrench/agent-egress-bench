#!/usr/bin/env python3
"""Regression tests for the compatibility inventory checker."""

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("check_contracts", ROOT / "scripts" / "check_contracts.py")
check_contracts = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_contracts)


class CheckContractsTest(unittest.TestCase):
    def test_reads_typed_grouped_go_constant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.go").write_text(
                "package fixture\n\nconst (\n\tactiveSchemaVersion int = 4\n)\n", encoding="utf-8"
            )
            self.assertEqual(
                4,
                check_contracts.read_go_constant(
                    root, {"path": "fixture.go", "symbol": "activeSchemaVersion"}
                ),
            )

    def test_rejects_schema_inventory_missing_accepted_version(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        receipt = next(
            family for family in manifest["artifact_families"] if family["family"] == "receipt_scoring_profile"
        )
        receipt["schemas"] = [schema for schema in receipt["schemas"] if schema["version"] != 1]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schemas do not cover accepted reader versions"):
                check_contracts.check(ROOT, path)

    def test_main_reports_filesystem_errors_as_gate_failures(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(check_contracts, "check", side_effect=OSError("fixture unreadable")),
            mock.patch.object(sys, "argv", ["check_contracts.py"]),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(1, check_contracts.main())
        self.assertIn("check-contracts: FAIL - fixture unreadable", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
