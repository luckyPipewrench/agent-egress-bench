#!/usr/bin/env python3
"""Conformance vectors and production-sample checks for artifact schemas."""

import copy
import importlib.util
import json
import tempfile
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


def materialize(vector, vector_path):
    if "instance" in vector:
        value = copy.deepcopy(vector["instance"])
    else:
        source = (vector_path.parent / vector["source"]).resolve()
        value = json.loads(source.read_text(encoding="utf-8"))
    for mutation in vector.get("mutations", []):
        value = apply_mutation(value, mutation)
    return value


class ArtifactSchemaConformanceTest(unittest.TestCase):
    def test_vectors(self):
        vectors = sorted(VECTOR_ROOT.glob("*.json"))
        self.assertTrue(vectors)
        for path in vectors:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = artifact_schema.load_schema(path.parent / document["schema"])
            accepted = document["accepted"]
            rejected = document["rejected"]
            self.assertTrue(accepted, path)
            self.assertTrue(rejected, path)
            for vector in accepted:
                with self.subTest(vector=path.name, case=vector["description"]):
                    validated = artifact_schema.validate(
                        materialize(vector, path), schema, vector["description"]
                    )
                    self.assertIsNotNone(validated)
            for vector in rejected:
                with self.subTest(vector=path.name, case=vector["description"]):
                    base = materialize(accepted[vector.get("accepted_index", 0)], path)
                    corrupted = apply_mutation(base, vector["mutation"])
                    with self.assertRaises(ValueError):
                        artifact_schema.validate(corrupted, schema, vector["description"])

    def test_non_finite_numbers_are_rejected(self):
        schema = artifact_schema.load_schema(ROOT / "schemas" / "promotion-baseline-v1.schema.json")
        source = (
            ROOT
            / "gauntlet-site"
            / "results"
            / "pipelock"
            / "5869b18cf5027d502bc5d0fd8b8f6899872a8b379137226c617670a295222886"
            / "reviewed-baseline.json"
        )
        baseline = json.loads(source.read_text(encoding="utf-8"))
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                corrupted = copy.deepcopy(baseline)
                corrupted["score_floors"]["full"]["containment"] = value
                with self.assertRaisesRegex(ValueError, "finite JSON number"):
                    artifact_schema.validate(corrupted, schema, "promotion baseline")

    def test_vector_corpora_require_both_directions(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            vector_root = temporary_root / "vectors"
            vector_root.mkdir()
            (temporary_root / "schema.json").write_text(
                json.dumps({"type": "object"}), encoding="utf-8"
            )
            (vector_root / "accepted-only.json").write_text(
                json.dumps(
                    {
                        "schema": "../schema.json",
                        "accepted": [{"description": "empty object", "instance": {}}],
                        "rejected": [],
                    }
                ),
                encoding="utf-8",
            )
            global VECTOR_ROOT
            original_root = VECTOR_ROOT
            VECTOR_ROOT = vector_root
            try:
                result = unittest.TestResult()
                ArtifactSchemaConformanceTest("test_vectors").run(result)
            finally:
                VECTOR_ROOT = original_root
            self.assertEqual(1, len(result.failures))
            self.assertIn("is not true", result.failures[0][1])

    def test_existing_promoted_records(self):
        schema = ROOT / "schemas" / "promoted-record-v1.schema.json"
        records = sorted((ROOT / "gauntlet-site" / "results" / "pipelock").glob("*/record-manifest.json"))
        self.assertTrue(records)
        for path in records:
            with self.subTest(path=path):
                validated = artifact_schema.validate_file(
                    json.loads(path.read_text()), schema, str(path)
                )
                self.assertIsNotNone(validated)

    def test_existing_promotion_baselines(self):
        schema = ROOT / "schemas" / "promotion-baseline-v1.schema.json"
        baselines = [ROOT / "ci" / "gauntlet-baseline.json"]
        baselines.extend(
            sorted(
                path
                for pattern in ("*/source-baseline.json", "*/reviewed-baseline.json")
                for path in (ROOT / "gauntlet-site" / "results" / "pipelock").glob(pattern)
            )
        )
        for path in baselines:
            with self.subTest(path=path):
                validated = artifact_schema.validate_file(
                    json.loads(path.read_text()), schema, str(path)
                )
                self.assertIsNotNone(validated)


if __name__ == "__main__":
    unittest.main()
