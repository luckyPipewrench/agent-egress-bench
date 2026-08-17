#!/usr/bin/env python3
"""Regression tests for the generated outward schema-discovery feed."""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


schema_catalog = load_module("schema_catalog")
schema_discovery_feed = load_module("schema_discovery_feed")
check_schema_discovery_feed = load_module("check_schema_discovery_feed")


class SchemaDiscoveryFeedTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        schemas = self.root / "schemas"
        schemas.mkdir()
        (schemas / "fixture-v1.schema.json").write_text(
            json.dumps({"$id": "https://example.invalid/fixture-v1.schema.json"}) + "\n",
            encoding="utf-8",
        )
        (schemas / "index.json").write_bytes(
            schema_catalog.rendered_catalog(self.root, roots=("schemas",))
        )
        (schemas / "discovery.json").write_bytes(schema_discovery_feed.rendered_feed(self.root))

    def tearDown(self):
        self.temporary.cleanup()

    def test_accepts_feed_generated_from_catalog(self):
        self.assertEqual(1, check_schema_discovery_feed.check(self.root))

    def test_rejects_feed_when_catalog_changes(self):
        catalog_path = self.root / "schemas/index.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["schemas"][0]["sha256"] = "0" * 64
        catalog_path.write_text(json.dumps(catalog) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "is stale"):
            check_schema_discovery_feed.check(self.root)

    def test_feed_keeps_identity_separate_from_retrieval(self):
        feed = json.loads((self.root / "schemas/discovery.json").read_text(encoding="utf-8"))
        self.assertEqual({"format", "catalog", "catalog_sha256", "schemas"}, set(feed))
        self.assertEqual({"path", "$id"}, set(feed["schemas"][0]))


if __name__ == "__main__":
    unittest.main()
