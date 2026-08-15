#!/usr/bin/env python3
"""Regression tests for frozen schema immutability decisions.

These drive the real check against a temporary git repository rather than a
pure function, because the defect this guards is a diff that never looked at
the file: a pathspec that omits a frozen path reports success while the bytes
change. Only a real diff can catch that.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "check_frozen_schema_immutability", SCRIPTS / "check_frozen_schema_immutability.py"
)
frozen = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["check_frozen_schema_immutability"] = frozen
spec.loader.exec_module(frozen)


CANONICAL = "schemas/fixture-v1.schema.json"
NESTED = "control-evidence/v1/verifier/schemas/fixture-v1.schema.json"


def git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class FrozenSchemaImmutabilityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "test@example.invalid")
        git(self.root, "config", "user.name", "test")

        for relative in (CANONICAL, NESTED):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    {
                        "$id": "https://example.invalid/schemas/fixture-v1.schema.json",
                        "title": "Fixture v1",
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

        manifest = self.root / "contracts/artifacts.json"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(
            json.dumps(
                {
                    "artifact_families": [
                        {"schemas": [{"status": "frozen", "path": CANONICAL}]}
                    ],
                    "retained_schema_assets": [{"path": NESTED}],
                }
            )
            + "\n",
            encoding="utf-8",
        )
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "base")
        self.base = "HEAD"

    def tearDown(self):
        self.temporary.cleanup()

    def rewrite(self, relative, document):
        (self.root / relative).write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )

    def test_accepts_an_untouched_tree(self):
        frozen_count, touched = frozen.check(self.root, self.base)
        self.assertEqual(2, frozen_count)
        self.assertEqual(0, touched)

    def test_rejects_an_identifier_rewrite(self):
        # The exact change this gate previously permitted by exception.
        self.rewrite(
            CANONICAL,
            {
                "$id": "https://raw.example.invalid/schemas/fixture-v1.schema.json",
                "title": "Fixture v1",
            },
        )
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            frozen.check(self.root, self.base)

    def test_rejects_a_whitespace_only_change(self):
        # Parsed-JSON equality would accept this. A consumer pinning a digest
        # sees a different document, so the gate must too.
        original = (self.root / CANONICAL).read_text(encoding="utf-8")
        (self.root / CANONICAL).write_text(
            original.replace("\n  ", "\n    "), encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            frozen.check(self.root, self.base)

    def test_rejects_a_key_reorder(self):
        self.rewrite(
            CANONICAL,
            {
                "title": "Fixture v1",
                "$id": "https://example.invalid/schemas/fixture-v1.schema.json",
            },
        )
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            frozen.check(self.root, self.base)

    def test_rejects_a_change_to_a_nested_retained_asset(self):
        # A `schemas` pathspec would not see this path at all and the gate
        # would report a clean run while a published verifier copy changed.
        self.rewrite(
            NESTED,
            {
                "$id": "https://example.invalid/schemas/fixture-v1.schema.json",
                "title": "Tampered",
            },
        )
        with self.assertRaisesRegex(ValueError, "bytes changed"):
            frozen.check(self.root, self.base)

    def test_rejects_a_removed_frozen_schema(self):
        (self.root / CANONICAL).unlink()
        with self.assertRaisesRegex(ValueError, "was removed"):
            frozen.check(self.root, self.base)

    def test_collects_all_frozen_paths_from_both_manifest_sections(self):
        manifest = {
            "artifact_families": [
                {"schemas": [{"status": "frozen", "path": "schemas/a-v1.schema.json"}]}
            ],
            "retained_schema_assets": [{"path": "schemas/b-v1.schema.json"}],
        }
        self.assertEqual(
            {"schemas/a-v1.schema.json", "schemas/b-v1.schema.json"},
            frozen.frozen_schema_paths(manifest),
        )


if __name__ == "__main__":
    unittest.main()
