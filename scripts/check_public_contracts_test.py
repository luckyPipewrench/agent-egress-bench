import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import check_public_contracts


class PublicContractGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source = Path(__file__).resolve().parents[1]
        paths = (
            "contracts/case-shapes-v4.json",
            "contracts/result-states-v6.json",
            "schemas/case-v4.schema.json",
            "schemas/multi-file-case-v4.schema.json",
            "schemas/result-v6.schema.json",
            "docs/SPEC.md",
            "docs/gauntlet.md",
            "docs/GOVERNANCE.md",
        )
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / relative, destination)

    def tearDown(self):
        self.temp.cleanup()

    def test_current_public_contracts_pass(self):
        check_public_contracts.check(self.root)

    def test_wrong_result_score_fails(self):
        path = self.root / "contracts/result-states-v6.json"
        contract = json.loads(path.read_text())
        contract["matrix"][0]["score"] = "fail"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "invalid score binding"):
            check_public_contracts.check(self.root)

    def test_missing_result_state_requirement_fails(self):
        path = self.root / "schemas/result-v6.schema.json"
        schema = json.loads(path.read_text())
        schema["properties"]["evidence"]["required"] = []
        path.write_text(json.dumps(schema))
        with self.assertRaisesRegex(ValueError, "require result_state"):
            check_public_contracts.check(self.root)

    def test_result_state_enum_drift_fails(self):
        path = self.root / "schemas/result-v6.schema.json"
        schema = json.loads(path.read_text())
        schema["properties"]["evidence"]["properties"]["result_state"]["enum"].append("unknown")
        path.write_text(json.dumps(schema))
        with self.assertRaisesRegex(ValueError, "result_state enum differs"):
            check_public_contracts.check(self.root)

    def test_result_schema_scoring_version_requirement_drift_fails(self):
        path = self.root / "schemas/result-v6.schema.json"
        schema = json.loads(path.read_text())
        schema["properties"]["scoring_version"].pop("minLength")
        path.write_text(json.dumps(schema))
        with self.assertRaisesRegex(ValueError, "must require a non-empty string"):
            check_public_contracts.check(self.root)

    def test_parity_reader_version_drift_fails(self):
        original = check_public_contracts.runner_parity.RESULT_SCHEMA_VERSION
        self.addCleanup(setattr, check_public_contracts.runner_parity, "RESULT_SCHEMA_VERSION", original)
        check_public_contracts.runner_parity.RESULT_SCHEMA_VERSION = 4
        with self.assertRaisesRegex(ValueError, "parity reader result schema version"):
            check_public_contracts.check(self.root)

    def test_parity_reader_scoring_version_drift_fails(self):
        original = check_public_contracts.runner_parity.SCORING_VERSION
        self.addCleanup(setattr, check_public_contracts.runner_parity, "SCORING_VERSION", original)
        check_public_contracts.runner_parity.SCORING_VERSION = "2.7"
        with self.assertRaisesRegex(ValueError, "result-states identity or version"):
            check_public_contracts.check(self.root)

    def test_documented_case_shape_drift_fails(self):
        path = self.root / "docs/SPEC.md"
        path.write_text(path.read_text().replace("`fetch_proxy`, `http_proxy`, `websocket` |", "`fetch_proxy`, `http_proxy` |", 1))
        with self.assertRaisesRegex(ValueError, "SPEC case-shape table differs"):
            check_public_contracts.check(self.root)

    def test_budget_override_drift_fails(self):
        path = self.root / "contracts/result-states-v6.json"
        contract = json.loads(path.read_text())
        contract["case_specific_overrides"][0]["scores_by_budget_block_timing"]["before_over_budget"] = "pass"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "budget timing override is invalid"):
            check_public_contracts.check(self.root)

    def test_budget_override_evidence_field_drift_fails(self):
        path = self.root / "contracts/result-states-v6.json"
        contract = json.loads(path.read_text())
        contract["case_specific_overrides"][0]["when"]["required_evidence_fields"][0] = "wrong_field"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "budget timing override is invalid"):
            check_public_contracts.check(self.root)

    def test_adapter_only_state_drift_fails(self):
        path = self.root / "contracts/result-states-v6.json"
        contract = json.loads(path.read_text())
        contract["adapter_only_states"]["skip"]["active_result"]["score"] = "pass"
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "skip must map to active error/error"):
            check_public_contracts.check(self.root)

    def test_historical_only_state_drift_fails(self):
        path = self.root / "contracts/result-states-v6.json"
        contract = json.loads(path.read_text())
        contract["historical_only_states"] = {}
        path.write_text(json.dumps(contract))
        with self.assertRaisesRegex(ValueError, "historical-only states"):
            check_public_contracts.check(self.root)


if __name__ == "__main__":
    unittest.main()
