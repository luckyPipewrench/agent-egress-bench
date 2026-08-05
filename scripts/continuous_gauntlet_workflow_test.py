#!/usr/bin/env python3
"""Structural tests for the fail-safe continuous Gauntlet workflow."""

import importlib.util
import hashlib
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "continuous-gauntlet.yaml"
ENTRYPOINT = REPO_ROOT / "scripts" / "run-pipelock-gauntlet.sh"
RELEASE_PIN = REPO_ROOT / "examples" / "pipelock" / "release.env"
PIPELOCK_PROFILE = REPO_ROOT / "examples" / "pipelock" / "tool-profile.json"
PIPELOCK_README = REPO_ROOT / "examples" / "pipelock" / "README.md"
PIPELOCK_CONFIG = REPO_ROOT / "examples" / "pipelock" / "pipelock-benchmark.yaml"
MAKEFILE = REPO_ROOT / "Makefile"


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "build_gauntlet_provenance", REPO_ROOT / "scripts" / "build_gauntlet_provenance.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EVIDENCE_LABELS = tuple(load_builder().RAW_EVIDENCE) + ("execution_decision", "run_bundle")


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
        self.entrypoint = ENTRYPOINT.read_text(encoding="utf-8")

    def test_portable_entrypoint_is_the_only_canonical_invocation(self):
        run_block = step_block(self.workflow, "Run portable canonical benchmark")
        self.assertIn("./scripts/run-pipelock-gauntlet.sh", run_block)
        self.assertIn("--deadline-epoch", run_block)
        self.assertIn("--reserve-seconds $((6 * 60))", run_block)
        self.assertIn("--benchmark-timeout-seconds $((24 * 60))", run_block)
        self.assertNotIn("GH_TOKEN", run_block)
        self.assertIn("JOB_TIMEOUT_MINUTES", self.workflow)
        self.assertIn("JOB_STARTED_EPOCH + JOB_TIMEOUT_MINUTES * 60", run_block)
        self.assertNotIn("--fixtures", self.workflow)
        self.assertNotIn("--multifile-cases", self.workflow)
        self.assertIn("--fixtures", self.entrypoint)
        self.assertIn("--multifile-cases", self.entrypoint)

    def test_zero_argument_entrypoint_avoids_old_bash_empty_array_expansion(self):
        self.assertIn("original_arg_count=$#", self.entrypoint)
        self.assertIn("original_arg_index < original_arg_count", self.entrypoint)
        self.assertIn('${original_args[$original_arg_index]}', self.entrypoint)
        self.assertNotRegex(self.entrypoint, r"\$\{original_args\[[@*]\]")

    def test_canonical_entrypoint_avoids_old_bash_empty_reason_array_expansion(self):
        self.assertIn("noncanonical_reason_count=0", self.entrypoint)
        self.assertIn("reason_index < noncanonical_reason_count", self.entrypoint)
        self.assertIn('${noncanonical_reasons[$reason_index]}', self.entrypoint)
        self.assertNotRegex(self.entrypoint, r"\$\{noncanonical_reasons\[[@*]\]")

    def test_reviewed_release_pin_is_not_duplicated_in_consumers(self):
        release_pin = RELEASE_PIN.read_text(encoding="utf-8")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_TAG=v[^\s]+$")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_VERSION=[^\s]+$")
        version = re.search(r"(?m)^PIPELOCK_VERSION=([^\s]+)$", release_pin).group(1)
        self.assertNotIn(version, self.workflow)
        self.assertNotIn(version, self.entrypoint)
        self.assertIn('source "$release_pin"', self.entrypoint)

    def test_stdio_profile_does_not_claim_unexercised_subject_budget(self):
        profile = json.loads(PIPELOCK_PROFILE.read_text(encoding="utf-8"))
        self.assertIs(profile["supports"]["budget_enforcement"], False)
        self.assertNotIn("denial_of_wallet", profile["claims"])
        readme = " ".join(PIPELOCK_README.read_text(encoding="utf-8").split())
        self.assertIn("Budget capability scope", readme)
        self.assertIn("one authenticated session", readme)
        self.assertIn("not a trusted identity boundary", readme)
        config = PIPELOCK_CONFIG.read_text(encoding="utf-8")
        self.assertRegex(config, r"(?m)^\s+max_tool_calls_per_session: 0$")

    def test_collection_upload_and_enforcement_order_is_fail_safe(self):
        ensure = self.workflow.index("      - name: Ensure fail-closed decision exists")
        summary = self.workflow.index("      - name: Render owner-facing run summary")
        review_upload = self.workflow.index("      - name: Upload owner review artifact")
        upload = self.workflow.index("      - name: Upload provenance artifact")
        enforce = self.workflow.index("      - name: Enforce candidate decision")
        self.assertLess(ensure, upload)
        self.assertLess(ensure, summary)
        self.assertLess(upload, enforce)
        self.assertLess(enforce, summary)
        self.assertLess(summary, review_upload)

        ensure_block = step_block(self.workflow, "Ensure fail-closed decision exists")
        upload_block = step_block(self.workflow, "Upload provenance artifact")
        review_upload_block = step_block(self.workflow, "Upload owner review artifact")
        enforce_block = step_block(self.workflow, "Enforce candidate decision")
        evaluate_block = step_block(self.workflow, "Evaluate candidate without publishing")
        for block in (ensure_block, upload_block, enforce_block, review_upload_block):
            self.assertIn("if: ${{ !cancelled() }}", block)
        self.assertIn("promotion-decision.json", ensure_block)
        self.assertIn("repository evaluator unavailable after an earlier workflow failure", ensure_block)
        self.assertIn("promotion-decision.json", upload_block)
        self.assertIn("execution-decision.json", upload_block)
        self.assertIn("run-bundle.json", upload_block)
        self.assertIn("enforcement-result.json", review_upload_block)
        self.assertIn("owner-summary.md", review_upload_block)
        self.assertIn("evaluate_gauntlet_candidate.py enforce", enforce_block)
        self.assertIn('test -n "${ARTIFACT_JSON:-}"', enforce_block)
        for evidence in EVIDENCE_LABELS:
            for block in (evaluate_block, ensure_block, enforce_block):
                self.assertIn(f'--evidence "{evidence}=', block)

    def test_owner_summary_uses_renderer_after_fail_closed_decision(self):
        block = step_block(self.workflow, "Render owner-facing run summary")
        self.assertIn("if: ${{ !cancelled() }}", block)
        self.assertIn("scripts/render_gauntlet_run_summary.py", block)
        self.assertIn('--candidate "$candidate_path"', block)
        self.assertIn('--decision "$decision_path"', block)
        self.assertIn("--baseline ci/gauntlet-baseline.json", block)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', block)
        self.assertIn('--run-url "$run_url"', block)
        self.assertIn('--enforcement-result "$artifact_dir/enforcement-result.json"', block)
        self.assertIn("BLOCKED — ACTION REQUIRED", block)
        self.assertIn("summary could not be rendered", block)
        self.assertIn("public record is unchanged", block)
        self.assertIn('> "$summary_path" || summary_exit=$?', block)
        self.assertIn('} > "$summary_path"', block)
        self.assertIn('cat "$summary_path" >> "$GITHUB_STEP_SUMMARY"', block)
        self.assertIn('exit "$summary_exit"', block)
        ensure_block = step_block(self.workflow, "Ensure fail-closed decision exists")
        self.assertNotIn("GITHUB_STEP_SUMMARY", ensure_block)

        enforce_block = step_block(self.workflow, "Enforce candidate decision")
        self.assertIn('--result "$artifact_dir/enforcement-result.json"', enforce_block)
        self.assertIn('exit "$decision_exit"', enforce_block)

    def test_platform_finalization_supplies_a_real_github_url(self):
        block = step_block(self.workflow, "Finalize GitHub provenance artifact")
        self.assertIn("build_gauntlet_provenance.py finalize", block)
        self.assertIn('https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}', block)
        self.assertNotIn("example.invalid", self.workflow)

    def test_stable_release_metadata_is_checked_behaviorally(self):
        start = self.entrypoint.index('actual_tag="$(jq -r')
        end = self.entrypoint.index('  asset_url="$(jq -r', start)
        validation_block = self.entrypoint[start:end]
        shell = "\n".join(
            (
                "set -Eeuo pipefail",
                'die() { printf "%s\\n" "$*" >&2; exit 1; }',
                'PIPELOCK_TAG="v3.3.0"',
                'release_json="$1"',
                validation_block,
            )
        )
        cases = (
            ({"tag_name": "v3.3.0", "draft": False, "prerelease": False}, True),
            ({"tag_name": "v3.3.0", "draft": True, "prerelease": False}, False),
            ({"tag_name": "v3.3.0", "draft": False, "prerelease": True}, False),
            ({"tag_name": "v3.3.0", "prerelease": False}, False),
            ({"tag_name": "v3.2.9", "draft": False, "prerelease": False}, False),
        )
        with tempfile.TemporaryDirectory() as temporary:
            release_json = Path(temporary) / "release.json"
            for payload, accepted in cases:
                with self.subTest(payload=payload):
                    release_json.write_text(json.dumps(payload), encoding="utf-8")
                    result = subprocess.run(
                        ["bash", "-c", shell, "bash", str(release_json)],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_checksum_selector_accepts_text_and_binary_markers(self):
        selector_line = next(
            line
            for line in self.entrypoint.splitlines()
            if line.strip().startswith('checksum_line="$(awk ')
        )
        awk_program = selector_line.split("'", 2)[1]
        asset = "pipelock_3.3.0_linux_amd64.tar.gz"
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            checksums = Path(temporary) / "checksums.txt"
            for marker in (" ", "*"):
                expected = f"{digest} {marker}{asset}"
                with self.subTest(marker=marker):
                    checksums.write_text(expected + "\n", encoding="utf-8")
                    result = subprocess.run(
                        ["awk", "-v", f"asset={asset}", awk_program, str(checksums)],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

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

    def test_owner_summary_shell_emits_content_even_when_renderer_blocks(self):
        block = step_block(self.workflow, "Render owner-facing run summary")
        marker = "        run: |\n"
        source = block[block.index(marker) + len(marker):]
        source = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in source.splitlines()
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_path = root / "continuous-gauntlet-pipelock.json"
            decision_path = root / "promotion-decision.json"
            baseline_path = REPO_ROOT / "ci" / "gauntlet-baseline.json"
            enforcement_path = root / "enforcement-result.json"
            candidate = {
                "schema_version": 2,
                "pipelock_version": "3.3.0",
                "generated_at": "2026-08-05T12:00:00Z",
                "corpus_version": "v2.3.0",
                "corpus_git_sha": "a" * 40,
                "case_count": {
                    "total": 214,
                    "applicable": 210,
                    "not_applicable": 4,
                    "not_applicable_reasons": {"missing_requires": 4},
                    "errors": 0,
                },
                "scores": {
                    "applicable": {"containment": 1, "false_positive_rate": 0},
                    "full": {"containment": 0.9811320754716981},
                },
                "sufficient": True,
            }
            decision = {
                "schema_version": 1,
                "blocked": False,
                "promotion_status": "under_review",
                "failures": [],
                "review_notes": [],
            }
            candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
            decision_path.write_text(json.dumps(decision), encoding="utf-8")
            enforcement_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "verdict": "pass",
                        "promotion_status": "under_review",
                        "failures": [],
                        "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest(),
                        "decision_sha256": hashlib.sha256(decision_path.read_bytes()).hexdigest(),
                        "baseline_sha256": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )
            candidate_path.write_bytes(b"\xff")
            step_summary = root / "step-summary"
            env = {
                **os.environ,
                "GAUNTLET_ARTIFACT_DIR": str(root),
                "ARTIFACT_JSON": str(candidate_path),
                "DECISION_PATH": str(decision_path),
                "GITHUB_REPOSITORY": "luckyPipewrench/agent-egress-bench",
                "GITHUB_RUN_ID": "123",
                "GITHUB_STEP_SUMMARY": str(step_summary),
            }
            result = subprocess.run(
                ["bash", "-c", source],
                cwd=REPO_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            summary = step_summary.read_text(encoding="utf-8")
            self.assertIn("BLOCKED — ACTION REQUIRED", summary)
            self.assertIn("cannot read candidate", summary)

    def test_owner_summary_shell_writes_fallback_when_renderer_is_unavailable(self):
        block = step_block(self.workflow, "Render owner-facing run summary")
        marker = "        run: |\n"
        source = block[block.index(marker) + len(marker):]
        source = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in source.splitlines()
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            step_summary = root / "step-summary"
            env = {
                **os.environ,
                "GAUNTLET_ARTIFACT_DIR": str(root / "artifacts"),
                "GITHUB_REPOSITORY": "luckyPipewrench/agent-egress-bench",
                "GITHUB_RUN_ID": "123",
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
            self.assertNotEqual(result.returncode, 0)
            summary = step_summary.read_text(encoding="utf-8")
            self.assertIn("BLOCKED — ACTION REQUIRED", summary)
            self.assertIn("could not be rendered", summary)
            self.assertEqual(
                summary,
                (root / "artifacts" / "owner-summary.md").read_text(encoding="utf-8"),
            )

    def test_stats_creates_its_declared_cache_directories(self):
        makefile = MAKEFILE.read_text(encoding="utf-8")
        match = re.search(r"(?ms)^stats:\n(?P<body>(?:\t.*\n)+)", makefile)
        self.assertIsNotNone(match)
        body = match.group("body")
        mkdir = body.index('mkdir -p "$(TMPDIR)" "$(GOCACHE)"')
        run = body.index("go run . --stats --cases ../cases")
        self.assertLess(mkdir, run)


if __name__ == "__main__":
    unittest.main()
