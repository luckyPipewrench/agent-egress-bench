#!/usr/bin/env python3
"""Tests for the published-schema closure gate."""

import unittest

from scripts import check_schema_closure


class SchemaClosureTest(unittest.TestCase):
    def test_published_exception_set_is_exact(self):
        check_schema_closure.check()

    def test_implicit_and_explicit_openness_are_detected(self):
        schema_id = "https://example.test/schema"
        for node in (
            {"type": "object"},
            {"type": "object", "additionalProperties": True},
            {"type": ["object", "null"]},
            {"properties": {"value": {"type": "string"}}},
            {"required": ["value"]},
            {"propertyNames": {"type": "string"}},
        ):
            with self.subTest(node=node):
                document = {"$id": schema_id, **node}
                self.assertEqual({(schema_id, "")}, check_schema_closure.open_objects(document))

    def test_closed_objects_and_typed_maps_need_no_exception(self):
        schema_id = "https://example.test/schema"
        for node in (
            {"type": "object", "additionalProperties": False},
            {"type": "object", "additionalProperties": {"type": "string"}},
        ):
            with self.subTest(node=node):
                document = {"$id": schema_id, **node}
                self.assertEqual(set(), check_schema_closure.open_objects(document))

    def test_object_capability_inside_composition_is_detected(self):
        schema_id = "https://example.test/schema"
        document = {
            "$id": schema_id,
            "allOf": [{"anyOf": [{"type": "string"}, {"properties": {"value": {}}}]}],
        }
        self.assertEqual(
            {(schema_id, "/allOf/0/anyOf/1")},
            check_schema_closure.open_objects(document),
        )


if __name__ == "__main__":
    unittest.main()
