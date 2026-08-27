#!/usr/bin/env python3
"""Regression tests for the compatibility inventory checker."""

import contextlib
import importlib.util
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("check_contracts", ROOT / "scripts" / "check_contracts.py")
check_contracts = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_contracts)


class CheckContractsTest(unittest.TestCase):
    def test_governed_schema_consumers_use_the_manifest_resolver(self):
        consumers = (
            "scripts/build_gauntlet_provenance.py",
            "scripts/evaluate_gauntlet_candidate.py",
            "scripts/promote_gauntlet_candidate.py",
            "scripts/validate_gauntlet_scope.py",
        )
        copied_path = re.compile(
            r"schemas/(?:provenance-candidate|case-index|promoted-record|promotion-baseline)-v"
        )
        copied_active_version = re.compile(
            r"(?m)^ACTIVE_(?:CASE_INDEX|PROVENANCE_CANDIDATE|PROMOTED_RECORD)_SCHEMA_VERSION\s*=\s*[0-9]+\s*$"
        )
        for relative in consumers:
            source = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(path=relative):
                self.assertIn("artifact_contracts", source)
                self.assertIsNone(copied_path.search(source))
                self.assertIsNone(copied_active_version.search(source))
        skeleton = (ROOT / "examples/runner-template/skeleton.sh").read_text(encoding="utf-8")
        self.assertIn("artifact_contracts.py", skeleton)
        self.assertIsNone(re.search(r"schema_version:\s*[0-9]+", skeleton))

    def test_reads_typed_grouped_go_constant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fixture.go").write_text(
                "package fixture\n\nconst (\n\tactiveSchemaVersion int = 4\n)\n", encoding="utf-8"
            )
            self.assertEqual(
                4,
                check_contracts.read_go_constant(
                    root, {"path": "fixture.go", "symbol": "activeSchemaVersion"}
                ),
            )

    def test_rejects_source_version_shared_by_two_families(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        summary = next(f for f in manifest["artifact_families"] if f["family"] == "summary")
        provenance = next(
            f for f in manifest["artifact_families"] if f["family"] == "provenance_candidate"
        )
        provenance["source_versions"] = summary["source_versions"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError, "source version .* is shared by families summary and provenance_candidate"
            ):
                check_contracts.check(ROOT, path)

    def test_accepts_families_without_source_versions(self):
        manifest = ROOT / "contracts" / "artifacts.json"
        families = json.loads(manifest.read_text(encoding="utf-8"))["artifact_families"]
        self.assertEqual(
            {"promoted_record", "promotion_baseline", "provenance_candidate", "result_pointer"},
            {family["family"] for family in families if not family["source_versions"]},
        )
        check_contracts.check(ROOT, manifest)

    def test_rejects_schema_inventory_missing_accepted_version(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        receipt = next(
            family for family in manifest["artifact_families"] if family["family"] == "receipt_scoring_profile"
        )
        receipt["schemas"] = [schema for schema in receipt["schemas"] if schema["version"] != 1]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "schemas do not cover accepted reader versions"):
                check_contracts.check(ROOT, path)

    def test_tool_profile_reader_contracts_distinguish_scoring_from_retained_readers(self):
        manifest = ROOT / "contracts" / "artifacts.json"
        tool_profile = next(
            family
            for family in json.loads(manifest.read_text(encoding="utf-8"))["artifact_families"]
            if family["family"] == "tool_profile"
        )
        self.assertEqual([1, 3, 4], tool_profile["accepted_reader_versions"])
        self.assertEqual([4], tool_profile["scoring_reader_versions"])
        self.assertEqual(
            {
                "runner_scoring": ("scoring", [4]),
                "validator_scoring": ("scoring", [4]),
                "control_evidence_v0": ("retained_evidence", [1, 3]),
                "control_evidence_v1": ("retained_evidence", [1, 4]),
            },
            {
                entry["consumer"]: (entry["role"], entry["accepted_versions"])
                for entry in tool_profile["reader_contracts"]
            },
        )
        check_contracts.check(ROOT, manifest)

    def test_rejects_reader_contract_that_omits_an_accepted_version(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][2]["accepted_versions"] = [1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must cover accepted_reader_versions"):
                check_contracts.check(ROOT, path)

    def test_rejects_scoring_reader_version_mismatch(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["scoring_reader_versions"] = [1]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match scoring reader contracts"):
                check_contracts.check(ROOT, path)

    def test_rejects_duplicate_reader_contract_consumer(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][1]["consumer"] = "runner_scoring"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "consumers must be unique"):
                check_contracts.check(ROOT, path)

    def test_rejects_reader_contract_path_mismatch(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][0]["path"] = "runner/not-a-reader.go"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "path must be listed in reader"):
                check_contracts.check(ROOT, path)

    def test_rejects_reader_contract_version_outside_family_support(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][2]["accepted_versions"] = [99]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "accepts a version absent"):
                check_contracts.check(ROOT, path)

    def test_rejects_reader_contract_role_mismatch(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][0]["role"] = "retained_evidence"
        tool_profile["reader_contracts"][2]["role"] = "scoring"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match scoring reader contracts"):
                check_contracts.check(ROOT, path)

    def test_rejects_unknown_reader_contract_role(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        tool_profile = next(family for family in manifest["artifact_families"] if family["family"] == "tool_profile")
        tool_profile["reader_contracts"][0]["role"] = "unrecognized"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "role must be one of"):
                check_contracts.check(ROOT, path)

    def test_rejects_changed_frozen_schema_bytes(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        frozen = next(
            schema
            for family in manifest["artifact_families"]
            for schema in family["schemas"]
            if schema["status"] == "frozen"
        )
        frozen["sha256"] = "0" * 64

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bytes do not match frozen schema digest"):
                check_contracts.check(ROOT, path)

    def test_rejects_changed_retained_schema_bytes(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        manifest["retained_schema_assets"][0]["sha256"] = "0" * 64

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bytes do not match retained schema asset digest"):
                check_contracts.check(ROOT, path)

    def test_main_reports_filesystem_errors_as_gate_failures(self):
        stderr = io.StringIO()
        with (
            mock.patch.object(check_contracts, "check", side_effect=OSError("fixture unreadable")),
            mock.patch.object(sys, "argv", ["check_contracts.py"]),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(1, check_contracts.main())
        self.assertIn("check-contracts: FAIL - fixture unreadable", stderr.getvalue())


class MalformedJsonTypeTest(unittest.TestCase):
    """A malformed input must reach the gate's own failure path.

    Every assertion here demands ValueError, which `main` turns into a
    `check-contracts: FAIL - ...` line. An AttributeError from an unchecked `.get`
    escapes that handler, so these tests fail if the type checks are removed.
    """

    def write_schema(self, root, document):
        schemas = root / "schemas"
        schemas.mkdir()
        (schemas / "fixture-v1.schema.json").write_text(json.dumps(document), encoding="utf-8")

    def test_rejects_non_object_properties(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_schema(root, {"title": "Fixture v1", "properties": "nope"})
            with self.assertRaisesRegex(ValueError, "properties must be an object"):
                check_contracts.versioned_schema_inventory(root)

    def test_rejects_non_object_schema_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.write_schema(root, {"title": "Fixture v1", "properties": {"schema_version": "nope"}})
            with self.assertRaisesRegex(ValueError, "properties.schema_version must be an object"):
                check_contracts.versioned_schema_inventory(root)

    def test_accepts_a_schema_that_declares_no_version_const(self):
        self.assertIsNone(check_contracts.declared_schema_version({"properties": {}}, "fixture"))
        self.assertEqual(
            4,
            check_contracts.declared_schema_version(
                {"properties": {"schema_version": {"const": 4}}}, "fixture"
            ),
        )

    def test_rejects_required_field_without_property_definition(self):
        with self.assertRaisesRegex(
            ValueError, "required fields lack property definitions: \\['untyped'\\]"
        ):
            check_contracts.require_top_level_required_properties(
                {
                    "required": ["typed", "untyped"],
                    "properties": {"typed": {"type": "string"}},
                },
                "fixture",
            )

    def test_accepts_required_fields_with_property_definitions(self):
        check_contracts.require_top_level_required_properties(
            {
                "required": ["typed"],
                "properties": {"typed": {"type": "string"}},
            },
            "fixture",
        )

    def test_rejects_unconstrained_required_property_definition(self):
        for unconstrained in (
            {},
            True,
            {"title": "typed"},
            {"description": "typed"},
            {"$defs": {"value": {"type": "string"}}},
            {"minLength": 1},
            {"pattern": "^[a-z]+$"},
            {"anyOf": [{}]},
            {"$ref": "#/$defs/missing"},
        ):
            with self.subTest(unconstrained=unconstrained):
                with self.assertRaisesRegex(
                    ValueError, "required field definitions accept null: \\['typed'\\]"
                ):
                    check_contracts.require_top_level_required_properties(
                        {"required": ["typed"], "properties": {"typed": unconstrained}},
                        "fixture",
                    )

    def test_accepts_required_property_definitions_that_reject_null(self):
        fixtures = (
            {"type": "string"},
            {"enum": ["one", "two"]},
            {"const": 1},
            {"anyOf": [{"type": "string"}, {"type": "integer"}]},
            {"allOf": [{"minLength": 1}, {"type": "string"}]},
            {"not": {"type": "null"}},
            {"$ref": "#/$defs/value"},
        )
        for constrained in fixtures:
            with self.subTest(constrained=constrained):
                check_contracts.require_top_level_required_properties(
                    {
                        "$defs": {"value": {"type": "string"}},
                        "required": ["typed"],
                        "properties": {"typed": constrained},
                    },
                    "fixture",
                )

    def test_check_applies_required_property_gate_to_every_active_schema(self):
        manifest = ROOT / "contracts" / "artifacts.json"
        expected = {
            entry["path"]
            for family in json.loads(manifest.read_text(encoding="utf-8"))["artifact_families"]
            for entry in family["schemas"]
            if entry["status"] == "active"
        }
        with mock.patch.object(
            check_contracts,
            "require_top_level_required_properties",
            wraps=check_contracts.require_top_level_required_properties,
        ) as gate:
            check_contracts.check(ROOT, manifest)
        self.assertEqual(expected, {call.args[1] for call in gate.call_args_list})

    def test_rejects_non_object_source_version_entry(self):
        manifest = json.loads((ROOT / "contracts" / "artifacts.json").read_text(encoding="utf-8"))
        manifest["artifact_families"][0]["source_versions"] = ["runner/case.go"]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source_versions entries must be objects"):
                check_contracts.check(ROOT, path)


class ReadGoConstantTest(unittest.TestCase):
    """The governing value must come from a real constant.

    Each case below satisfied an earlier version of this matcher. A commented or
    quoted declaration passed while the constant was gone, and any line shaped
    `name = 4` passed even as a mutable variable, so the gate could report a
    governing version the compiler never saw.
    """

    def read(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "case.go"
            path.write_text(source, encoding="utf-8")
            return check_contracts.read_go_constant(
                Path(directory), {"path": "case.go", "symbol": "activeSchemaVersion"}
            )

    def assert_rejected(self, source):
        with self.assertRaisesRegex(ValueError, "cannot find integer constant"):
            self.read(source)

    def test_accepts_standalone_and_grouped_declarations(self):
        self.assertEqual(4, self.read("package main\n\nconst activeSchemaVersion = 4\n"))
        self.assertEqual(4, self.read("package main\n\nconst activeSchemaVersion int = 4\n"))
        self.assertEqual(
            4, self.read("package main\n\nconst (\n\tactiveSchemaVersion = 4\n)\n")
        )

    def test_rejects_a_mutable_variable(self):
        self.assert_rejected("package main\n\nvar activeSchemaVersion = 4\n")

    def test_rejects_an_assignment_outside_a_const_block(self):
        self.assert_rejected(
            "package main\n\nvar activeSchemaVersion int\n\n"
            "func init() {\n\tactiveSchemaVersion = 4\n}\n"
        )

    def test_rejects_commented_and_quoted_declarations(self):
        self.assert_rejected("package main\n\n// const activeSchemaVersion = 4\n")
        self.assert_rejected("package main\n\n/* const activeSchemaVersion = 4 */\n")
        self.assert_rejected('package main\n\nvar s = "const activeSchemaVersion = 4"\n')
        self.assert_rejected("package main\n\nvar s = `const activeSchemaVersion = 4`\n")

    def test_rejects_conflicting_declarations(self):
        with self.assertRaisesRegex(ValueError, "conflicting values"):
            self.read(
                "package main\n\nconst (\n\tactiveSchemaVersion = 4\n)\n\n"
                "const activeSchemaVersion = 5\n"
            )


class ReadPythonConstantTest(unittest.TestCase):
    def read(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.py"
            path.write_text(source, encoding="utf-8")
            return check_contracts.read_python_constant(
                Path(directory), {"path": "contract.py", "symbol": "ACTIVE_SCHEMA_VERSION"}
            )

    def test_accepts_module_level_integer_literal(self):
        self.assertEqual(5, self.read("ACTIVE_SCHEMA_VERSION = 5\n"))
        self.assertEqual(5, self.read("ACTIVE_SCHEMA_VERSION: int = 5\n"))

    def test_rejects_an_alias_to_another_family(self):
        with self.assertRaisesRegex(ValueError, "must be an integer literal"):
            self.read("SUMMARY_SCHEMA_VERSION = 5\nACTIVE_SCHEMA_VERSION = SUMMARY_SCHEMA_VERSION\n")

    def test_rejects_non_module_assignments_and_strings(self):
        for source in (
            "def configure():\n    ACTIVE_SCHEMA_VERSION = 5\n",
            'text = "ACTIVE_SCHEMA_VERSION = 5"\n',
        ):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, "cannot find integer constant"):
                    self.read(source)


if __name__ == "__main__":
    unittest.main()
