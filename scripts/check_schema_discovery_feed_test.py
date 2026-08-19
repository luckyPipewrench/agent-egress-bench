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
        # Change the identity, not the digest. A forged digest is refused earlier by the file-hash
        # check below, so mutating it here would test that guard instead of staleness.
        catalog_path = self.root / "schemas/index.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["schemas"][0]["$id"] = "https://example.invalid/renamed-v1.schema.json"
        catalog_path.write_text(json.dumps(catalog) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "is stale"):
            check_schema_discovery_feed.check(self.root)

    def test_forged_catalog_digest_is_refused(self):
        catalog_path = self.root / "schemas/index.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["schemas"][0]["sha256"] = "0" * 64
        catalog_path.write_text(json.dumps(catalog) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest does not match"):
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


class SchemaDiscoveryReadBindingTest(SchemaDiscoveryFeedTest):
    """The digest must come from the descriptor containment was checked against.

    Validating a path and then reading it back by NAME is two lookups of one name, so the check and
    the hash can describe different objects. This asserts the second lookup is gone rather than
    trying to win a race, which a unit test cannot do reliably.
    """

    def test_schema_content_is_not_read_back_by_name(self):
        schema = self.root / "schemas" / "fixture-v1.schema.json"
        catalog = (self.root / "schemas" / "index.json").read_bytes()
        original = Path.read_bytes
        observed = []

        def recording_read_bytes(self):
            observed.append(Path(self).resolve())
            return original(self)

        Path.read_bytes = recording_read_bytes
        try:
            schema_discovery_feed.catalog_entries(self.root, catalog)
        finally:
            Path.read_bytes = original

        self.assertNotIn(
            schema.resolve(),
            observed,
            "the schema file was reopened by name after its containment check",
        )

    def test_contained_file_bytes_returns_the_opened_content(self):
        contents = schema_discovery_feed._contained_file_bytes(
            self.root, 0, "schemas/fixture-v1.schema.json"
        )
        self.assertEqual(
            (self.root / "schemas" / "fixture-v1.schema.json").read_bytes(), contents
        )

    def test_directory_in_the_catalog_is_refused(self):
        (self.root / "schemas" / "nested").mkdir()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            schema_discovery_feed._contained_file_bytes(self.root, 0, "schemas/nested")

    def test_catalog_content_is_not_read_back_by_name(self):
        catalog = self.root / "schemas" / "index.json"
        original = Path.read_bytes
        observed = []

        def recording_read_bytes(self):
            observed.append(Path(self).resolve())
            return original(self)

        Path.read_bytes = recording_read_bytes
        try:
            schema_discovery_feed.catalog_bytes(self.root)
        finally:
            Path.read_bytes = original

        self.assertNotIn(
            catalog.resolve(),
            observed,
            "the catalog was reopened by name after its regular-file check",
        )

    def test_symlinked_catalog_is_refused(self):
        catalog = self.root / "schemas" / "index.json"
        contents = catalog.read_bytes()
        target = self.root / "schemas" / "real-index.json"
        target.write_bytes(contents)
        catalog.unlink()
        catalog.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "must be a regular file"):
            schema_discovery_feed.catalog_bytes(self.root)

    def test_resolved_path_bound_to_opened_inode(self):
        other = self.root / "schemas" / "other-v1.schema.json"
        other.write_text("other-bytes\n", encoding="utf-8")
        original_resolve = Path.resolve
        fixture = (self.root / "schemas" / "fixture-v1.schema.json").resolve()

        def redirected_resolve(self, *args, **kwargs):
            resolved = original_resolve(self, *args, **kwargs)
            if resolved == fixture:
                return other.resolve()
            return resolved

        Path.resolve = redirected_resolve
        try:
            with self.assertRaisesRegex(ValueError, "changed while it was being read"):
                schema_discovery_feed._contained_file_bytes(
                    self.root, 0, "schemas/fixture-v1.schema.json"
                )
        finally:
            Path.resolve = original_resolve


class SchemaCatalogIdentityBindingTest(SchemaDiscoveryFeedTest):
    """The published catalog digest must come from the object that was opened.

    O_NOFOLLOW refuses a symlink at the final component only, so a swapped parent directory can
    still aim the same pathname at a different file. Winning that race inside a unit test is not
    possible, so this drives the guard by making resolution disagree with the descriptor, which is
    the state a real swap produces.
    """

    def test_resolved_path_bound_to_opened_inode(self):
        other = self.root / "schemas" / "decoy.json"
        other.write_text("{}\n", encoding="utf-8")
        original = Path.resolve

        def resolve_to_decoy(self, strict=False):
            if self.name == "index.json":
                return original(other)
            return original(self, strict) if strict else original(self)

        Path.resolve = resolve_to_decoy
        try:
            with self.assertRaisesRegex(ValueError, "changed while it was being read"):
                schema_discovery_feed.catalog_bytes(self.root)
        finally:
            Path.resolve = original

    def test_catalog_bytes_returns_the_opened_content(self):
        self.assertEqual(
            (self.root / "schemas" / "index.json").read_bytes(),
            schema_discovery_feed.catalog_bytes(self.root),
        )
