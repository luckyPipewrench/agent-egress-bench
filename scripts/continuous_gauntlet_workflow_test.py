#!/usr/bin/env python3
"""Structural tests for the fail-safe continuous-gauntlet workflow."""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "continuous-gauntlet.yaml"
MAKEFILE = REPO_ROOT / "Makefile"


def step_block(workflow, name):
    marker = f"      - name: {name}\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow step: {name}")
    next_step = workflow.find("\n      - name:", start + len(marker))
    next_action = workflow.find("\n      - uses:", start + len(marker))
    candidates = [offset for offset in (next_step, next_action) if offset >= 0]
    end = min(candidates) if candidates else len(workflow)
    return workflow[start:end]


class ContinuousGauntletWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def run_wrapper(self, results):
        marker = "          python3 - <<'PY'\n"
        start = self.workflow.index(marker) + len(marker)
        end = self.workflow.index("\n          PY\n", start)
        source = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in self.workflow[start:end].splitlines()
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "cases").mkdir()
        (root / "cases" / "MANIFEST.txt").write_text("a\nb\nc\n", encoding="utf-8")
        artifact_dir = root / "artifacts"
        artifact_dir.mkdir()
        summary_path = artifact_dir / "raw-summary.json"
        summary = {
            "gauntlet_version": "1",
            "scoring_version": "2.4",
            "runner_version": "0.4.2",
            "tool": "Pipelock",
            "tool_version": "3.3.0",
            "corpus_version": "test",
            "corpus_sha256": "a" * 64,
            "tool_profile_sha256": "b" * 64,
            "case_count": {
                "total": 3,
                "applicable": 2,
                "not_applicable": 1,
                "not_applicable_reasons": {"missing_requires": 1},
                "errors": 0,
            },
            "scores": {
                "applicable": {
                    "containment": 1.0,
                    "false_positive_rate": 0.0,
                    "detection": 1.0,
                    "evidence": 1.0,
                },
                "full": {
                    "containment": 0.5,
                    "false_positive_rate": 0.0,
                    "detection": 1.0,
                    "evidence": 1.0,
                },
            },
            "sufficient": False,
        }
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        results_path = artifact_dir / "results.jsonl"
        results_path.write_text(
            "".join(json.dumps(row) + "\n" for row in results), encoding="utf-8"
        )
        command_path = artifact_dir / "command.txt"
        command_path.write_text("aeb-gauntlet --fixtures --multifile-cases cases/mcp-drift\n", encoding="utf-8")
        stats_path = artifact_dir / "make-stats.txt"
        stats_path.write_text("block: 2\nallow: 1\nwarn: 0\n", encoding="utf-8")
        case_index_path = artifact_dir / "case-index.json"
        case_index_path.write_text(
            json.dumps({
                "schema_version": 1,
                "cases": [
                    {"case_id": "a", "expected_verdict": "block"},
                    {"case_id": "b", "expected_verdict": "allow"},
                    {"case_id": "c", "expected_verdict": "block"},
                ],
            }),
            encoding="utf-8",
        )
        artifact_path = artifact_dir / "candidate.json"
        env = {
            **os.environ,
            "SUMMARY_PATH": str(summary_path),
            "COMMAND_PATH": str(command_path),
            "STATS_PATH": str(stats_path),
            "RESULTS_PATH": str(results_path),
            "CASE_INDEX_PATH": str(case_index_path),
            "GITHUB_REPOSITORY": "luckyPipewrench/agent-egress-bench",
            "GITHUB_RUN_ID": "123",
            "CORPUS_GIT_SHA": "c" * 40,
            "CORPUS_REF_KIND": "origin/main",
            "CORPUS_DIRTY": "false",
            "PIPELOCK_TAG": "v3.3.0",
            "PIPELOCK_VERSION": "3.3.0",
            "PIPELOCK_ASSET": "pipelock.tar.gz",
            "PIPELOCK_REPO": "luckyPipewrench/pipelock",
            "GENERATED_AT": "2026-08-04T00:00:00Z",
            "ARTIFACT_JSON": str(artifact_path),
        }
        result = subprocess.run(
            [sys.executable, "-c", source],
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, artifact_path

    def test_collection_upload_and_enforcement_order_is_fail_safe(self):
        ensure = self.workflow.index("      - name: Ensure fail-closed decision exists")
        upload = self.workflow.index("      - name: Upload provenance artifact")
        enforce = self.workflow.index("      - name: Enforce candidate decision")
        self.assertLess(ensure, upload)
        self.assertLess(upload, enforce)

        ensure_block = step_block(self.workflow, "Ensure fail-closed decision exists")
        upload_block = step_block(self.workflow, "Upload provenance artifact")
        enforce_block = step_block(self.workflow, "Enforce candidate decision")
        for block in (ensure_block, upload_block, enforce_block):
            self.assertIn("if: ${{ !cancelled() }}", block)
        self.assertIn("promotion-decision.json", ensure_block)
        self.assertIn("evaluate_gauntlet_candidate.py evaluate", ensure_block)
        self.assertIn("repository evaluator unavailable after an earlier workflow failure", ensure_block)
        self.assertIn("promotion-decision.json", upload_block)
        self.assertIn("evaluate_gauntlet_candidate.py enforce", enforce_block)
        for evidence in ("raw_summary", "results", "runner_stderr", "command", "stats", "case_index"):
            self.assertIn(f'--evidence "{evidence}=', ensure_block)
            self.assertIn(f'--evidence "{evidence}=', enforce_block)

    def test_scheduled_lane_has_no_public_write_permission(self):
        self.assertRegex(self.workflow, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("pull-requests: write", self.workflow)

    def test_checkout_failure_still_leaves_a_blocked_decision(self):
        block = step_block(self.workflow, "Ensure fail-closed decision exists")
        marker = "        run: |\n"
        source = block[block.index(marker) + len(marker):]
        source = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in source.splitlines()
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            github_env = root / "github-env"
            step_summary = root / "step-summary"
            env = {
                **os.environ,
                "GAUNTLET_ARTIFACT_DIR": "artifacts",
                "PIPELOCK_TAG": "v3.3.0",
                "GITHUB_ENV": str(github_env),
                "GITHUB_STEP_SUMMARY": str(step_summary),
            }
            result = subprocess.run(
                ["bash", "-c", source],
                cwd=root,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            decision = json.loads(
                (root / "artifacts" / "promotion-decision.json").read_text(encoding="utf-8")
            )
            self.assertTrue(decision["blocked"])
            self.assertIn("evaluator unavailable", decision["failures"][0])

    def test_stats_creates_its_declared_cache_directories(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        match = re.search(r"(?ms)^stats:\n(?P<body>(?:\t.*\n)+)", makefile)
        self.assertIsNotNone(match)
        body = match.group("body")
        mkdir = body.index('mkdir -p "$(TMPDIR)" "$(GOCACHE)"')
        run = body.index("go run . --stats --cases ../cases")
        self.assertLess(mkdir, run)

    def test_wrapper_binds_every_manifest_case_and_handles_not_applicable_rows(self):
        results = [
            {
                "case_id": "a",
                "expected_verdict": "block",
                "actual_verdict": "block",
                "evidence": {"scanner": "test"},
            },
            {
                "case_id": "b",
                "expected_verdict": "allow",
                "actual_verdict": "allow",
                "evidence": {},
            },
            {
                "case_id": "c",
                "expected_verdict": "block",
                "actual_verdict": "not_applicable",
                "evidence": {},
            },
        ]
        result, artifact_path = self.run_wrapper(results)
        self.assertEqual(result.returncode, 0, result.stderr)
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(artifact["metric_counts"]["applicable"]["containment"], {
            "numerator": 1,
            "denominator": 1,
        })
        self.assertEqual(artifact["metric_counts"]["full"]["containment"], {
            "numerator": 1,
            "denominator": 2,
        })

    def test_wrapper_rejects_duplicate_and_unknown_case_ids(self):
        base = [
            {"case_id": "a", "expected_verdict": "block", "actual_verdict": "block", "evidence": {}},
            {"case_id": "b", "expected_verdict": "allow", "actual_verdict": "allow", "evidence": {}},
            {"case_id": "c", "expected_verdict": "block", "actual_verdict": "not_applicable", "evidence": {}},
        ]
        duplicate = [base[0], {**base[1], "case_id": "a"}, base[2]]
        result, _ = self.run_wrapper(duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate case IDs", result.stderr)

        unknown = [base[0], base[1], {**base[2], "case_id": "z"}]
        result, _ = self.run_wrapper(unknown)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("do not match cases/MANIFEST.txt", result.stderr)

    def test_wrapper_rejects_expected_verdict_label_swap(self):
        swapped = [
            {"case_id": "a", "expected_verdict": "allow", "actual_verdict": "allow", "evidence": {}},
            {"case_id": "b", "expected_verdict": "block", "actual_verdict": "block", "evidence": {"scanner": "test"}},
            {"case_id": "c", "expected_verdict": "block", "actual_verdict": "not_applicable", "evidence": {}},
        ]
        result, _ = self.run_wrapper(swapped)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match loader case index", result.stderr)

    def test_runner_timeout_preserves_cleanup_budget(self):
        run_block = step_block(self.workflow, "Run canonical benchmark")
        self.assertIn('run_cmd=(timeout --signal=TERM --kill-after=30s 28m "${cmd[@]}")', run_block)
        self.assertIn('"${run_cmd[@]}" > "$jsonl_path"', run_block)


if __name__ == "__main__":
    unittest.main()
