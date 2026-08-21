#!/usr/bin/env python3
"""Conformance vectors and production-sample checks for artifact schemas."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from scripts import artifact_contracts

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "schemas" / "conformance"
SPEC = importlib.util.spec_from_file_location("artifact_schema", ROOT / "scripts" / "artifact_schema.py")
artifact_schema = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(artifact_schema)
MAX_CONFORMANCE_INPUT_BYTES = 4 << 20


def confined_file(base, source):
    candidate = (base / source).resolve(strict=True)
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact conformance source escapes repository root: {source}") from exc
    if not candidate.is_file():
        raise ValueError(f"artifact conformance source is not a regular file: {source}")
    if candidate.stat().st_size > MAX_CONFORMANCE_INPUT_BYTES:
        raise ValueError(f"artifact conformance source exceeds {MAX_CONFORMANCE_INPUT_BYTES} bytes: {source}")
    return candidate


def apply_mutation(instance, mutation):
    value = copy.deepcopy(instance)
    if "remove" in mutation:
        parent = value
        for part in mutation["remove"][:-1]:
            parent = parent[part]
        del parent[mutation["remove"][-1]]
        return value
    if "add" in mutation:
        parent = value
        for part in mutation["add"][:-1]:
            parent = parent[part]
        field = mutation["add"][-1]
        if field in parent:
            raise ValueError(f"add mutation target already exists: {field}")
        parent[field] = mutation["value"]
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
        source = confined_file(vector_path.parent, vector["source"])
        value = json.loads(source.read_text(encoding="utf-8"))
    for mutation in vector.get("mutations", []):
        value = apply_mutation(value, mutation)
    return value


class ArtifactSchemaConformanceTest(unittest.TestCase):
    def test_sources_are_confined_regular_and_bounded(self):
        with tempfile.TemporaryDirectory() as outside_directory:
            outside = Path(outside_directory) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes repository root"):
                confined_file(VECTOR_ROOT, str(outside))
        with tempfile.TemporaryDirectory(dir=ROOT) as inside_directory:
            inside = Path(inside_directory)
            with self.assertRaisesRegex(ValueError, "not a regular file"):
                confined_file(inside, ".")
            oversized = inside / "oversized.json"
            oversized.write_bytes(b"x" * (MAX_CONFORMANCE_INPUT_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "exceeds"):
                confined_file(inside, oversized.name)

    def test_vectors(self):
        vectors = sorted(VECTOR_ROOT.glob("*.json"))
        self.assertTrue(vectors)
        for path in vectors:
            document = json.loads(path.read_text(encoding="utf-8"))
            schema = artifact_schema.load_schema(confined_file(path.parent, document["schema"]))
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

    def test_unsupported_schema_keywords_fail_closed(self):
        schema = {
            "type": "object",
            "properties": {"value": {"type": "string", "maxLength": 1}},
        }
        with self.assertRaisesRegex(ValueError, "unsupported schema keywords.*maxLength"):
            artifact_schema.validate({"value": "too long"}, schema, "unsupported keyword")

    def test_active_provenance_required_fields_are_individually_non_vacuous(self):
        vector_path = VECTOR_ROOT / "provenance-candidate-v6.json"
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        instance = materialize(vector["accepted"][0], vector_path)
        schema = artifact_schema.load_schema(ROOT / "schemas" / "provenance-candidate-v6.schema.json")
        checks = []

        def walk(value, node, schema_path, instance_path):
            if "$ref" in node:
                reference_path = [part.replace("~1", "/").replace("~0", "~") for part in node["$ref"][2:].split("/")]
                target = schema
                for part in reference_path:
                    target = target[part]
                walk(value, target, reference_path, instance_path)
                return
            if isinstance(value, dict):
                for field in node.get("required", []):
                    checks.append((schema_path, instance_path, field))
                for field, child in node.get("properties", {}).items():
                    if field in value:
                        walk(value[field], child, schema_path + ["properties", field], instance_path + [field])

        walk(instance, schema, [], [])
        self.assertGreater(len(checks), 70)
        for schema_path, instance_path, field in checks:
            with self.subTest(path=".".join(instance_path + [field])):
                weakened = copy.deepcopy(schema)
                node = weakened
                for part in schema_path:
                    node = node[part]
                node["required"].remove(field)
                corrupted = copy.deepcopy(instance)
                parent = corrupted
                for part in instance_path:
                    parent = parent[part]
                del parent[field]
                validated = artifact_schema.validate(corrupted, weakened, field)
                self.assertIsNotNone(validated)
                with self.assertRaises(ValueError):
                    artifact_schema.validate(corrupted, schema, field)

    def test_active_provenance_object_closures_are_individually_non_vacuous(self):
        vector_path = VECTOR_ROOT / "provenance-candidate-v6.json"
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        instance = materialize(vector["accepted"][0], vector_path)
        schema = artifact_schema.load_schema(ROOT / "schemas" / "provenance-candidate-v6.schema.json")
        checks = []

        def walk(value, node, schema_path, instance_path):
            if "$ref" in node:
                reference_path = [part.replace("~1", "/").replace("~0", "~") for part in node["$ref"][2:].split("/")]
                target = schema
                for part in reference_path:
                    target = target[part]
                walk(value, target, reference_path, instance_path)
                return
            if isinstance(value, dict):
                if node.get("additionalProperties") is False:
                    checks.append((schema_path, instance_path))
                for field, child in node.get("properties", {}).items():
                    if field in value:
                        walk(value[field], child, schema_path + ["properties", field], instance_path + [field])

        walk(instance, schema, [], [])
        self.assertGreater(len(checks), 15)
        for schema_path, instance_path in checks:
            with self.subTest(path=".".join(instance_path) or "root"):
                weakened = copy.deepcopy(schema)
                node = weakened
                for part in schema_path:
                    node = node[part]
                node.pop("additionalProperties")
                corrupted = copy.deepcopy(instance)
                parent = corrupted
                for part in instance_path:
                    parent = parent[part]
                parent["unexpected"] = True
                validated = artifact_schema.validate(corrupted, weakened, "closure")
                self.assertIsNotNone(validated)
                with self.assertRaises(ValueError):
                    artifact_schema.validate(corrupted, schema, "closure")

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
        schemas = artifact_contracts.schema_paths("promoted_record")
        records = sorted((ROOT / "gauntlet-site" / "results" / "pipelock").glob("*/record-manifest.json"))
        self.assertTrue(records)
        for path in records:
            with self.subTest(path=path):
                document = json.loads(path.read_text())
                schema = schemas.get(document.get("schema_version"))
                self.assertIsNotNone(schema, "promoted record has no governed schema reader")
                validated = artifact_schema.validate_file(
                    document, schema, str(path)
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
