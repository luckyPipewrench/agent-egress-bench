#!/usr/bin/env python3
"""Regression tests for the compatibility inventory checker."""

import contextlib
import importlib.util
import io
import json
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


if __name__ == "__main__":
    unittest.main()
