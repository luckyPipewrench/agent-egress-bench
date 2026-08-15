#!/usr/bin/env python3
"""Regression tests for frozen schema immutability decisions."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent
spec = importlib.util.spec_from_file_location(
    "schema_catalog", SCRIPTS / "schema_catalog.py"
)
schema_catalog = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["schema_catalog"] = schema_catalog
spec.loader.exec_module(schema_catalog)

spec = importlib.util.spec_from_file_location(
    "check_frozen_schema_immutability", SCRIPTS / "check_frozen_schema_immutability.py"
)
frozen = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(frozen)


class FrozenSchemaImmutabilityTest(unittest.TestCase):
    def setUp(self):
        self.path = "schemas/fixture-v1.schema.json"
        self.before = json.dumps(
            {
                "$id": frozen.LEGACY_SCHEMA_ID_PREFIX + "fixture-v1.schema.json",
                "title": "Fixture v1",
            }
        )

    def test_accepts_only_the_legacy_identifier_rewrite(self):
        after = json.dumps(
            {
                "$id": schema_catalog.PUBLIC_SCHEMA_ID_PREFIX + "fixture-v1.schema.json",
                "title": "Fixture v1",
            }
        )
        self.assertTrue(frozen.is_identifier_only_migration(self.path, self.before, after))

    def test_rejects_a_byte_change_alongside_the_identifier_rewrite(self):
        after = json.dumps(
            {
                "$id": schema_catalog.PUBLIC_SCHEMA_ID_PREFIX + "fixture-v1.schema.json",
                "title": "Changed fixture v1",
            }
        )
        self.assertFalse(frozen.is_identifier_only_migration(self.path, self.before, after))

    def test_collects_all_frozen_paths_from_both_manifest_sections(self):
        manifest = {
            "artifact_families": [{"schemas": [{"status": "frozen", "path": "schemas/a-v1.schema.json"}]}],
            "retained_schema_assets": [{"path": "schemas/b-v1.schema.json"}],
        }
        self.assertEqual(
            {"schemas/a-v1.schema.json", "schemas/b-v1.schema.json"},
            frozen.frozen_schema_paths(manifest),
        )


if __name__ == "__main__":
    unittest.main()
