#!/usr/bin/env python3
"""Regression tests for the fail-closed case governance gate."""

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent
ROOT = SCRIPTS.parent
sys.path.insert(0, str(SCRIPTS))
import case_governance  # noqa: E402
import check_case_governance  # noqa: E402


class CaseGovernanceGateTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "schemas").mkdir()
        shutil.copyfile(
            ROOT / "schemas" / "case-governance-decision-v1.schema.json",
            self.root / "schemas" / "case-governance-decision-v1.schema.json",
        )
        (self.root / case_governance.DECISION_DIRECTORY).mkdir(parents=True)

    def tearDown(self):
        self.temporary.cleanup()

    def write_single_case(self, case_id="fixture-case-001"):
        path = self.root / "cases" / "url" / f"{case_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "id": case_id,
                    "description": "Exercises a fixture request.",
                    "expected_verdict": "block",
                    "why_expected": "fixture_requires_blocking",
                    "source": "Synthetic fixture",
                    "false_positive_risk": "low",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        return case_id

    def write_multifile_case(self, case_id="fixture-drift-001"):
        directory = self.root / "cases" / "mcp-drift" / case_id
        directory.mkdir(parents=True)
        (directory / "case.yaml").write_text(
            """id: fixture-drift-001
description: |
  Exercises a fixture description change.
expected_verdict: warn
false_positive_risk: medium
why_expected: |
  The fixture needs an operator review.
source: |
  Synthetic temporal fixture.
""",
            encoding="utf-8",
        )
        for name in ("before.json", "after.json", "expected.json", "notes.md"):
            (directory / name).write_text("{}\n", encoding="utf-8")
        return case_id

    def expected_record(self, case_id):
        return case_governance.record_for_case(case_governance.load_cases(self.root)[case_id])

    def write_record(self, record):
        path = self.root / case_governance.DECISION_DIRECTORY / (
            record["case_id"] + case_governance.DECISION_SUFFIX
        )
        path.write_bytes(case_governance.rendered_record(record))
        return path

    def test_accepts_a_complete_single_file_record(self):
        case_id = self.write_single_case()
        self.write_record(self.expected_record(case_id))
        self.assertEqual(1, check_case_governance.check(self.root))

    def test_accepts_a_complete_multifile_record(self):
        case_id = self.write_multifile_case()
        self.write_record(self.expected_record(case_id))
        self.assertEqual(1, check_case_governance.check(self.root))

    def test_rejects_a_missing_record(self):
        self.write_single_case()
        with self.assertRaisesRegex(ValueError, "missing decision records"):
            check_case_governance.check(self.root)

    def test_rejects_malformed_record(self):
        case_id = self.write_single_case()
        path = self.root / case_governance.DECISION_DIRECTORY / (case_id + case_governance.DECISION_SUFFIX)
        path.write_text("{\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "cannot read decision record"):
            check_case_governance.check(self.root)

    def test_rejects_a_record_for_an_unknown_case(self):
        case_id = self.write_single_case()
        record = self.expected_record(case_id)
        record["case_id"] = "unknown-case-001"
        self.write_record(record)
        with self.assertRaisesRegex(ValueError, "points at unknown case ID"):
            check_case_governance.check(self.root)

    def test_rejects_case_inconsistent_record(self):
        case_id = self.write_single_case()
        record = copy.deepcopy(self.expected_record(case_id))
        record["expected_verdict"] = "allow"
        self.write_record(record)
        with self.assertRaisesRegex(ValueError, "inconsistent with case.*expected_verdict"):
            check_case_governance.check(self.root)

    def test_rejects_duplicate_json_field_before_schema_validation(self):
        case_id = self.write_single_case()
        record = self.expected_record(case_id)
        path = self.root / case_governance.DECISION_DIRECTORY / (case_id + case_governance.DECISION_SUFFIX)
        path.write_text(
            "{" + json.dumps("schema_version") + ":1," + json.dumps("schema_version") + ":1}",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            check_case_governance.check(self.root)


if __name__ == "__main__":
    unittest.main()
