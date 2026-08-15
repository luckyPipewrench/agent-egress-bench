#!/usr/bin/env python3
"""Regression tests for the generated schema-discovery catalog."""

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
check_schema_catalog = load_module("check_schema_catalog")

# The catalog records whatever identity a schema declares, so the fixture uses
# the same non-resolving shape the published schemas actually carry.
TEST_ROOTS = ("schemas",)
FIXTURE_ID = "https://github.com/luckyPipewrench/agent-egress-bench/schemas/fixture-v1.schema.json"


class SchemaCatalogTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        schemas = self.root / "schemas"
        schemas.mkdir()
        self.schema = schemas / "fixture-v1.schema.json"
        self.schema.write_text(
            json.dumps(
                {
                    "$id": FIXTURE_ID,
                    "title": "Fixture v1",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        (schemas / "index.json").write_bytes(
            schema_catalog.rendered_catalog(self.root, roots=TEST_ROOTS)
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_accepts_catalog_derived_from_schema_files(self):
        self.assertEqual(1, check_schema_catalog.check(self.root, roots=TEST_ROOTS))

    def test_released_catalog_has_source_commit_pinned_retrieval_urls(self):
        commit = "a" * 40
        catalog = json.loads(
            schema_catalog.rendered_catalog(
                self.root,
                source_commit=commit,
                release="v1.2.3",
                roots=TEST_ROOTS,
            )
        )
        self.assertEqual(commit, catalog["source_commit"])
        self.assertEqual("v1.2.3", catalog["release"])
        self.assertEqual(
            f"https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/{commit}/schemas/fixture-v1.schema.json",
            catalog["schemas"][0]["retrieval_url"],
        )

    def test_released_catalog_refuses_an_unpinned_or_invalid_source_commit(self):
        with self.assertRaisesRegex(ValueError, "requires both a source commit and release name"):
            schema_catalog.rendered_catalog(self.root, release="v1.2.3", roots=TEST_ROOTS)
        with self.assertRaisesRegex(ValueError, "40-character lower-case Git SHA"):
            schema_catalog.rendered_catalog(
                self.root,
                source_commit="main",
                release="v1.2.3",
                roots=TEST_ROOTS,
            )

    def test_rejects_stale_hash_after_schema_bytes_change(self):
        self.schema.write_text(
            json.dumps(
                {
                    "$id": FIXTURE_ID,
                    "title": "Changed fixture v1",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "is stale"):
            check_schema_catalog.check(self.root, roots=TEST_ROOTS)

    def test_rejects_one_identifier_declared_by_differing_bytes(self):
        # A catalog cannot answer a lookup for an identity that two different
        # documents claim. Governed copies are byte-identical, so only a real
        # collision reaches this.
        twin = self.root / "schemas" / "twin-v1.schema.json"
        twin.write_text(
            json.dumps({"$id": FIXTURE_ID, "title": "Different bytes"}) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "different bytes"):
            schema_catalog.schema_entries(self.root, roots=TEST_ROOTS)

    def test_accepts_one_identifier_declared_by_identical_bytes(self):
        # The governed verifier copies are exactly this shape and must not be
        # rejected: an over-strict rule here blocks legitimate publication.
        original = (self.schema).read_text(encoding="utf-8")
        copy = self.root / "schemas" / "copy-v1.schema.json"
        copy.write_text(original, encoding="utf-8")
        entries = schema_catalog.schema_entries(self.root, roots=TEST_ROOTS)
        self.assertEqual(2, len(entries))
        self.assertEqual({FIXTURE_ID}, {entry["$id"] for entry in entries})

    def test_rejects_catalog_entry_that_does_not_name_its_schema(self):
        catalog = self.root / "schemas" / "index.json"
        content = json.loads(catalog.read_text(encoding="utf-8"))
        content["schemas"][0]["path"] = "schemas/other-v1.schema.json"
        catalog.write_text(json.dumps(content) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "is stale"):
            check_schema_catalog.check(self.root, roots=TEST_ROOTS)

    def test_rejects_a_release_only_retrieval_url_in_the_committed_catalog(self):
        catalog = self.root / "schemas" / "index.json"
        content = json.loads(catalog.read_text(encoding="utf-8"))
        content["schemas"][0]["retrieval_url"] = "https://example.invalid/schema.json"
        catalog.write_text(json.dumps(content) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "is stale"):
            check_schema_catalog.check(self.root, roots=TEST_ROOTS)


if __name__ == "__main__":
    unittest.main()
