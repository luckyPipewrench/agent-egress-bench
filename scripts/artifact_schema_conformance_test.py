#!/usr/bin/env python3
"""Conformance vectors and production-sample checks for artifact schemas."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "schemas" / "conformance"
SPEC = importlib.util.spec_from_file_location("artifact_schema", ROOT / "scripts" / "artifact_schema.py")
artifact_schema = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact_schema)


def apply_mutation(instance, mutation):
    value = copy.deepcopy(instance)
    if "remove" in mutation:
        parent = value
        for part in mutation["remove"][:-1]:
            parent = parent[part]
        del parent[mutation["remove"][-1]]
        return value
    parent = value
    for part in mutation["replace"][:-1]:
        parent = parent[part]
    parent[mutation["replace"][-1]] = mutation["value"]
    return value


class ArtifactSchemaConformanceTest(unittest.TestCase):
    def test_vectors(self):
        vectors = sorted(VECTOR_ROOT.glob("*.json"))
        self.assertTrue(vectors)
        for path in vectors:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = artifact_schema.load_schema(path.parent / document["schema"])
            accepted = document["accepted"]
            self.assertTrue(accepted, path)
            for vector in accepted:
                with self.subTest(vector=path.name, case=vector["description"]):
                    artifact_schema.validate(vector["instance"], schema, vector["description"])
            base = accepted[0]["instance"]
            for vector in document["rejected"]:
                with self.subTest(vector=path.name, case=vector["description"]):
                    corrupted = apply_mutation(base, vector["mutation"])
                    with self.assertRaises(ValueError):
                        artifact_schema.validate(corrupted, schema, vector["description"])

    def test_existing_promoted_records(self):
        schema = ROOT / "schemas" / "promoted-record-v1.schema.json"
        records = sorted((ROOT / "gauntlet-site" / "results" / "pipelock").glob("*/record-manifest.json"))
        self.assertTrue(records)
        for path in records:
            with self.subTest(path=path):
                artifact_schema.validate_file(json.loads(path.read_text()), schema, str(path))


if __name__ == "__main__":
    unittest.main()
