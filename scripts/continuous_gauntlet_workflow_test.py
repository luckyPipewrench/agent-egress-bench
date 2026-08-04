#!/usr/bin/env python3
"""Structural tests for the fail-safe continuous Gauntlet workflow."""

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
MAKEFILE = REPO_ROOT / "Makefile"
EVIDENCE_LABELS = (
    "raw_summary",
    "results",
    "runner_stderr",
    "command",
    "stats",
    "case_index",
    "entrypoint_command",
    "run_metadata",
    "pipelock_release",
    "release_checksums",
    "pipelock_version_output",
    "corpus_manifest",
    "execution_decision",
    "run_bundle",
)


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
        self.assertNotIn("--fixtures", self.workflow)
        self.assertNotIn("--multifile-cases", self.workflow)
        self.assertIn("--fixtures", self.entrypoint)
        self.assertIn("--multifile-cases", self.entrypoint)

    def test_reviewed_release_pin_is_not_duplicated_in_consumers(self):
        release_pin = RELEASE_PIN.read_text(encoding="utf-8")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_TAG=v[^\s]+$")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_VERSION=[^\s]+$")
        version = re.search(r"(?m)^PIPELOCK_VERSION=([^\s]+)$", release_pin).group(1)
        self.assertNotIn(version, self.workflow)
        self.assertNotIn(version, self.entrypoint)
        self.assertIn('source "$release_pin"', self.entrypoint)

    def test_collection_upload_and_enforcement_order_is_fail_safe(self):
        ensure = self.workflow.index("      - name: Ensure fail-closed decision exists")
        upload = self.workflow.index("      - name: Upload provenance artifact")
        enforce = self.workflow.index("      - name: Enforce candidate decision")
        self.assertLess(ensure, upload)
        self.assertLess(upload, enforce)

        ensure_block = step_block(self.workflow, "Ensure fail-closed decision exists")
        upload_block = step_block(self.workflow, "Upload provenance artifact")
        enforce_block = step_block(self.workflow, "Enforce candidate decision")
        evaluate_block = step_block(self.workflow, "Evaluate candidate without publishing")
        for block in (ensure_block, upload_block, enforce_block):
            self.assertIn("if: ${{ !cancelled() }}", block)
        self.assertIn("promotion-decision.json", ensure_block)
        self.assertIn("repository evaluator unavailable after an earlier workflow failure", ensure_block)
        self.assertIn("promotion-decision.json", upload_block)
        self.assertIn("execution-decision.json", upload_block)
        self.assertIn("run-bundle.json", upload_block)
        self.assertIn("evaluate_gauntlet_candidate.py enforce", enforce_block)
        for evidence in EVIDENCE_LABELS:
            for block in (evaluate_block, ensure_block, enforce_block):
                self.assertIn(f'--evidence "{evidence}=', block)

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
