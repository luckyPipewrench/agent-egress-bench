#!/usr/bin/env python3
"""Regression tests for governed embedded schema inventories."""

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_schema_copies.py")
SPEC = importlib.util.spec_from_file_location("check_schema_copies", MODULE_PATH)
check_schema_copies = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_schema_copies)


class CheckSchemaCopiesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "schemas"
        self.g2 = self.root / "control-evidence" / "g2" / "authentication" / "schemas" / "cee-v0"
        self.v1 = self.root / "control-evidence" / "v1" / "verifier" / "schemas"
        self.source.mkdir()
        self.g2.mkdir(parents=True)
        self.v1.mkdir(parents=True)
        for name in check_schema_copies.G2_V0_SCHEMA_NAMES:
            self._write_pair(name, self.g2)
        for name in check_schema_copies.VERIFIER_V1_SCHEMA_NAMES:
            self._write_pair(name, self.v1)

    def tearDown(self):
        self.temporary.cleanup()

    def _write_pair(self, name, copy_dir):
        data = f"schema:{name}\n"
        (self.source / name).write_text(data, encoding="utf-8")
        (copy_dir / name).write_text(data, encoding="utf-8")

    def test_accepts_complete_exact_inventories(self):
        count = check_schema_copies.check(self.root)
        self.assertEqual(
            count,
            len(check_schema_copies.G2_V0_SCHEMA_NAMES)
            + len(check_schema_copies.VERIFIER_V1_SCHEMA_NAMES),
        )

    def test_rejects_extra_v1_embedded_schema(self):
        (self.v1 / "unexpected.schema.json").write_text("extra\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            check_schema_copies.check(self.root)

    def test_rejects_v1_copy_drift(self):
        name = next(iter(check_schema_copies.VERIFIER_V1_SCHEMA_NAMES))
        (self.v1 / name).write_text("drift\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "differs from root source"):
            check_schema_copies.check(self.root)


if __name__ == "__main__":
    unittest.main()
