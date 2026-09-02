from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_neutrality_boundary import has_product_acceptance_shape, violations


class NeutralityBoundaryTest(unittest.TestCase):
    def fixture(self) -> Path:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "scripts").mkdir()
        (root / "ci").mkdir()
        (root / "examples/vendor").mkdir(parents=True)
        (root / ".github/workflows").mkdir(parents=True)
        (root / ".github/workflows/validate.yaml").write_text("run: make preflight\n", encoding="utf-8")
        (root / ".github/workflows/release.yaml").write_text("run: make release\n", encoding="utf-8")
        return root

    def test_neutral_contract_validation_passes(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight: check-contracts\ncheck-contracts:\n\t@python3 scripts/check_contracts.py\n",
            encoding="utf-8",
        )
        (root / "scripts/check_contracts.py").write_text("print('ok')\n", encoding="utf-8")
        self.assertEqual([], violations(root))

    def test_transitive_product_runner_fails(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight: check-score\ncheck-score:\n\t@./scripts/check-score.sh\n",
            encoding="utf-8",
        )
        (root / "scripts/check-score.sh").write_text(
            "./scripts/run-vendor-gauntlet.sh\n", encoding="utf-8"
        )
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_reference_adapter_entrypoint_is_traversed_without_product_policy(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight: test-adapter\ntest-adapter:\n\t@./examples/vendor/bridge_test.sh\n",
            encoding="utf-8",
        )
        (root / "examples/vendor/bridge_test.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual([], violations(root))

    def test_release_workflow_make_target_reaching_product_runner_fails(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight:\nrelease:\n\t@./examples/vendor/release.sh\n",
            encoding="utf-8",
        )
        (root / "examples/vendor/release.sh").write_text(
            "./scripts/run-vendor-gauntlet.sh\n", encoding="utf-8"
        )
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_workflow_multiple_make_goals_are_all_traversed(self) -> None:
        root = self.fixture()
        (root / ".github/workflows/validate.yaml").write_text(
            "run: make preflight release\n", encoding="utf-8"
        )
        (root / ".github/workflows/release.yaml").write_text(
            "run: echo release\n", encoding="utf-8"
        )
        (root / "Makefile").write_text(
            "preflight:\nrelease:\n\t@./scripts/run-vendor-gauntlet.sh\n",
            encoding="utf-8",
        )
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_workflow_make_options_do_not_hide_goals(self) -> None:
        root = self.fixture()
        (root / ".github/workflows/validate.yaml").write_text(
            "run: make -C . -j2 release\n", encoding="utf-8"
        )
        (root / ".github/workflows/release.yaml").write_text(
            "run: echo release\n", encoding="utf-8"
        )
        (root / "Makefile").write_text(
            "preflight:\nrelease:\n\t@./scripts/run-vendor-gauntlet.sh\n",
            encoding="utf-8",
        )
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_python_dispatcher_reaching_product_runner_fails(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight:\n\t@python3 scripts/dispatch.py\nrelease:\n",
            encoding="utf-8",
        )
        (root / "scripts/dispatch.py").write_text(
            'import subprocess\nsubprocess.run(["./scripts/run-vendor-gauntlet.sh"], check=True)\n',
            encoding="utf-8",
        )
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_recursive_make_reaching_product_runner_fails(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight:\n\t@./scripts/dispatch.sh\nrelease:\nhidden:\n"
            "\t@./scripts/run-vendor-gauntlet.sh\n",
            encoding="utf-8",
        )
        (root / "scripts/dispatch.sh").write_text("make hidden\n", encoding="utf-8")
        (root / "scripts/run-vendor-gauntlet.sh").write_text("exit 0\n", encoding="utf-8")
        self.assertEqual(
            ["mandatory validation reaches product runner scripts/run-vendor-gauntlet.sh"],
            violations(root),
        )

    def test_referenced_path_cannot_escape_repository(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight:\n\t@cat scripts/../../outside.json\nrelease:\n",
            encoding="utf-8",
        )
        self.assertEqual(
            ["mandatory validation path escapes repository: scripts/../../outside.json"],
            violations(root),
        )

    def test_product_acceptance_policy_fails(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight: check-score\ncheck-score:\n\t@python3 scripts/check_score.py ci/vendor-expectation.json\n",
            encoding="utf-8",
        )
        (root / "scripts/check_score.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "ci/vendor-expectation.json").write_text(
            json.dumps({"tool_version": "1.2.3", "expected_failed_cases": ["CASE-1"]}),
            encoding="utf-8",
        )
        self.assertEqual(
            ["mandatory validation reaches product acceptance policy ci/vendor-expectation.json"],
            violations(root),
        )

    def test_retained_result_baseline_is_integrity_evidence(self) -> None:
        root = self.fixture()
        (root / "Makefile").write_text(
            "preflight: check-record\ncheck-record:\n"
            "\t@python3 scripts/check_record.py ci/gauntlet-baseline.json\nrelease:\n",
            encoding="utf-8",
        )
        (root / "scripts/check_record.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "ci/gauntlet-baseline.json").write_text(
            json.dumps({"pipelock_version": "1.2.3", "score_floors": {"containment": 1}}),
            encoding="utf-8",
        )
        self.assertEqual([], violations(root))

    def test_reference_adapter_is_not_product_acceptance(self) -> None:
        self.assertFalse(has_product_acceptance_shape({"tool_version": "1.2.3", "schema_version": 1}))


if __name__ == "__main__":
    unittest.main()
