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

    def test_missing_feed_is_refused(self):
        (self.root / "schemas/discovery.json").unlink()
        with self.assertRaisesRegex(ValueError, "must be a regular file"):
            check_schema_discovery_feed.check(self.root)

    def test_empty_feed_is_refused(self):
        (self.root / "schemas/discovery.json").write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "is empty"):
            check_schema_discovery_feed.check(self.root)

    def test_symlinked_feed_is_refused(self):
        feed = self.root / "schemas/discovery.json"
        contents = feed.read_bytes()
        target = self.root / "schemas/real-discovery.json"
        target.write_bytes(contents)
        feed.unlink()
        feed.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "must be a regular file"):
            check_schema_discovery_feed.check(self.root)

    def _catalog_bytes_with_path(self, path):
        return json.dumps(
            {
                "format": 1,
                "repository": "luckyPipewrench/agent-egress-bench",
                "schemas": [{"path": path, "$id": "https://example.invalid/x", "sha256": "0" * 64}],
            }
        ).encode("utf-8")

    def test_missing_schema_target_is_refused(self):
        with self.assertRaisesRegex(ValueError, "does not exist"):
            schema_discovery_feed.catalog_entries(
                self.root, self._catalog_bytes_with_path("schemas/not-a-real-file.schema.json")
            )

    def test_directory_schema_target_is_refused(self):
        (self.root / "schemas" / "subdir").mkdir()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            schema_discovery_feed.catalog_entries(self.root, self._catalog_bytes_with_path("schemas/subdir"))

    def test_symlinked_schema_target_is_refused(self):
        link = self.root / "schemas" / "linked-probe.schema.json"
        link.symlink_to("/etc/hostname")
        try:
            with self.assertRaisesRegex(ValueError, "is a symlink"):
                schema_discovery_feed.catalog_entries(
                    self.root, self._catalog_bytes_with_path("schemas/linked-probe.schema.json")
                )
        finally:
            link.unlink()

    def test_feed_keeps_identity_separate_from_retrieval(self):
        feed = json.loads((self.root / "schemas/discovery.json").read_text(encoding="utf-8"))
        self.assertEqual({"format", "catalog", "catalog_sha256", "schemas"}, set(feed))
        self.assertEqual({"path", "$id"}, set(feed["schemas"][0]))


if __name__ == "__main__":
    unittest.main()
