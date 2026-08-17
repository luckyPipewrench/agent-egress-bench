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


BUILDER = load_builder()
EVIDENCE_LABELS = tuple(BUILDER.RAW_EVIDENCE | BUILDER.V4_RAW_EVIDENCE) + (
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
        self.assertNotIn("GH_TOKEN", run_block)
        self.assertIn("JOB_TIMEOUT_MINUTES", self.workflow)
        self.assertIn("JOB_STARTED_EPOCH + JOB_TIMEOUT_MINUTES * 60", run_block)
        self.assertNotIn("--fixtures", self.workflow)
        self.assertNotIn("--multifile-cases", self.workflow)
        self.assertIn("--fixtures", self.entrypoint)
        self.assertNotIn("--multifile-cases", self.entrypoint)

    def test_zero_argument_entrypoint_avoids_old_bash_empty_array_expansion(self):
        self.assertIn("original_arg_count=$#", self.entrypoint)
        self.assertIn("original_arg_index < original_arg_count", self.entrypoint)
        self.assertIn('${original_args[$original_arg_index]}', self.entrypoint)
        self.assertNotRegex(self.entrypoint, r"\$\{original_args\[[@*]\]")

    def test_doctor_reports_every_check_as_json_without_starting_a_run(self):
        before = set((REPO_ROOT / "continuous-gauntlet-runs").glob("*"))
        result = subprocess.run(
            ["bash", str(ENTRYPOINT), "--doctor-json"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema_version"], 1)
        self.assertTrue(report["ready"])
        codes = {check["code"] for check in report["checks"]}
        self.assertIn("platform_linux", codes)
        self.assertIn("command_jq", codes)
        self.assertIn("mcp_stdio_bridge", codes)
        self.assertIn("repository_root", codes)
        self.assertIn("release_pin", codes)
        self.assertEqual(before, set((REPO_ROOT / "continuous-gauntlet-runs").glob("*")))

    def test_doctor_collects_all_missing_prerequisites_before_failing(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_path = Path(temporary)
            for name in (
                "dirname", "uname", "git", "python3", "go", "curl",
                "sha256sum", "tar", "timeout", "realpath", "make",
            ):
                target = "/usr/bin/uname" if name == "uname" else "/usr/bin/true"
                if name == "dirname":
                    target = "/usr/bin/dirname"
                (fake_path / name).symlink_to(target)
            result = subprocess.run(
                ["/bin/bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "PATH": str(fake_path)},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        statuses = {check["code"]: check["status"] for check in report["checks"]}
        self.assertFalse(report["ready"])
        self.assertEqual(statuses["command_jq"], "missing")
        self.assertEqual(statuses["mcp_stdio_bridge"], "missing")
        self.assertIn("release_pin", statuses)

    def test_doctor_rejects_a_malformed_release_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin = Path(temporary) / "release.env"
            pin.write_text(
                "PIPELOCK_REPO=luckyPipewrench/pipelock\n"
                "PIPELOCK_TAG=v3.3.0\n"
                "PIPELOCK_VERSION=3.3.0\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--release-pin", str(pin), "--doctor-json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        release_pin = next(check for check in report["checks"] if check["code"] == "release_pin")
        self.assertEqual(release_pin["status"], "invalid")
        self.assertTrue(release_pin["remediation"])

    def test_doctor_keeps_json_contract_when_release_pin_is_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            pin = Path(temporary) / "release.env"
            pin.mkdir()
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--release-pin", str(pin), "--doctor-json"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        release_pin = next(check for check in report["checks"] if check["code"] == "release_pin")
        self.assertEqual(release_pin["status"], "invalid")

    def test_canonical_entrypoint_avoids_old_bash_empty_reason_array_expansion(self):
        self.assertIn("noncanonical_reason_count=0", self.entrypoint)
        self.assertIn("reason_index < noncanonical_reason_count", self.entrypoint)
        self.assertIn('${noncanonical_reasons[$reason_index]}', self.entrypoint)
        self.assertNotRegex(self.entrypoint, r"\$\{noncanonical_reasons\[[@*]\]")

    def test_reviewed_release_pin_is_not_duplicated_in_consumers(self):
        release_pin = RELEASE_PIN.read_text(encoding="utf-8")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_TAG=v[^\s]+$")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_VERSION=[^\s]+$")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_ASSET_SHA256_AMD64=[0-9a-f]{64}$")
        self.assertRegex(release_pin, r"(?m)^PIPELOCK_ASSET_SHA256_ARM64=[0-9a-f]{64}$")
        version = re.search(r"(?m)^PIPELOCK_VERSION=([^\s]+)$", release_pin).group(1)
        self.assertNotIn(version, self.workflow)
        self.assertNotIn(version, self.entrypoint)
        self.assertNotIn('source "$release_pin"', self.entrypoint)
        self.assertIn("--release-pin", self.entrypoint)
        self.assertIn("reviewed release pin is invalid", self.entrypoint)

    def test_target_runs_under_a_filesystem_restricted_environment(self):
        self.assertIn("go build -o \"$target_sandbox\" ./cmd/target-sandbox", self.entrypoint)
        self.assertIn('pipelock_bin="$target_wrapper"', self.entrypoint)
        self.assertIn('sha256sum "$target_binary"', self.entrypoint)
        self.assertIn("target sandbox integrity check failed", self.entrypoint)
        self.assertIn("benchmark target modified the corpus checkout", self.entrypoint)
        sandbox = (REPO_ROOT / "runner" / "cmd" / "target-sandbox" / "main.go").read_text(
            encoding="utf-8"
        )
        self.assertIn("restrictFilesystem(args[0]", sandbox)
        self.assertIn("closeInheritedDescriptors()", sandbox)
        self.assertIn("restrictDelegationChannels()", sandbox)
        self.assertIn("SECCOMP_RET_ERRNO", sandbox)

    def test_release_pin_parser_accepts_only_the_five_data_fields(self):
        start = self.entrypoint.index("parse_release_pin() {")
        end = self.entrypoint.index("\nrequire_uint()", start)
        parser_function = self.entrypoint[start:end]
        shell = "\n".join(
            (
                "set -Eeuo pipefail",
                parser_function,
                'parse_release_pin "$1"',
            )
        )
        digests = (
            f"PIPELOCK_ASSET_SHA256_AMD64={'a' * 64}\n"
            f"PIPELOCK_ASSET_SHA256_ARM64={'b' * 64}\n"
        )
        cases = (
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.0\n"
                "PIPELOCK_VERSION=3.3.0\n" + digests,
                True,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.1\n"
                "PIPELOCK_VERSION=3.3.1\n" + digests,
                True,
            ),
            ("PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.0\n", False),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_REPO=luckyPipewrench/pipelock\n"
                "PIPELOCK_TAG=v3.3.0\nPIPELOCK_VERSION=3.3.0\n" + digests,
                False,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=$(touch /tmp/not-run)\n"
                "PIPELOCK_VERSION=3.3.0\n" + digests,
                False,
            ),
            (
                "PIPELOCK_REPO=other/tool\nPIPELOCK_TAG=v3.3.0\nPIPELOCK_VERSION=3.3.0\n"
                + digests,
                False,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.1\n"
                "PIPELOCK_VERSION=3.3.0\n" + digests,
                False,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nUNKNOWN=value\n"
                "PIPELOCK_TAG=v3.3.0\nPIPELOCK_VERSION=3.3.0\n" + digests,
                False,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.0\n"
                "PIPELOCK_VERSION=3.3.0\n"
                "PIPELOCK_ASSET_SHA256_AMD64=not-a-digest\n"
                f"PIPELOCK_ASSET_SHA256_ARM64={'b' * 64}\n",
                False,
            ),
            (
                "PIPELOCK_REPO=luckyPipewrench/pipelock\nPIPELOCK_TAG=v3.3.0\n"
                "PIPELOCK_VERSION=3.3.0\n"
                f"PIPELOCK_ASSET_SHA256_AMD64={'a' * 64}\n",
                False,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            pin = Path(temporary) / "release.env"
            for payload, accepted in cases:
                with self.subTest(payload=payload):
                    pin.write_text(payload, encoding="utf-8")
                    result = subprocess.run(
                        ["bash", "-c", shell, "bash", str(pin)],
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, accepted, result.stderr)

            target = Path(temporary) / "target.env"
            target.write_text(cases[0][0], encoding="utf-8")
            pin.unlink()
            pin.symlink_to(target)
            result = subprocess.run(
                ["bash", "-c", shell, "bash", str(pin)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_run_path_rejects_release_pin_symlink_before_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target.env"
            target.write_text(RELEASE_PIN.read_text(encoding="utf-8"), encoding="utf-8")
            pin = Path(temporary) / "release.env"
            pin.symlink_to(target)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--release-pin", str(pin), "--development"],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reviewed release pin cannot be a symbolic link", result.stderr)

    def test_stdio_profile_does_not_claim_unexercised_subject_budget(self):
        profile = json.loads(PIPELOCK_PROFILE.read_text(encoding="utf-8"))
        self.assertNotIn("supports", profile)
        self.assertNotIn("denial_of_wallet", profile["claims"])
        self.assertEqual(profile["capability_registry"]["id"], "aeb.core-capabilities")
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
        self.assertIn('${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}', block)
        self.assertNotIn("example.invalid", self.workflow)

    def test_runner_and_artifacts_are_pinned_to_one_attempt(self):
        self.assertRegex(self.workflow, r"(?m)^    runs-on: ubuntu-24\.04$")
        # Pinned to an exact patch for reproducibility. Asserting the literal
        # version here is what let the pin fall behind a security patch without
        # anything objecting, so require the exact-patch SHAPE and require it to
        # equal the toolchain the govulncheck job scans. A bump then moves both.
        pins = re.findall(r'go-version: "(\d+\.\d+\.\d+)"', self.workflow)
        self.assertEqual(len(pins), 1, f"expected exactly one exact-patch Go pin, found {pins}")
        validate_workflow = (
            Path(__file__).resolve().parent.parent / ".github" / "workflows" / "validate.yaml"
        ).read_text(encoding="utf-8")
        scanned = re.findall(r'go-version: "(\d+\.\d+\.\d+)"', validate_workflow)
        self.assertEqual(
            len(scanned), 1, f"expected exactly one exact-patch Go pin in validate.yaml, found {scanned}"
        )
        self.assertEqual(
            pins[0],
            scanned[0],
            "the benchmark toolchain and the vulnerability-scanned toolchain must match",
        )
        upload = step_block(self.workflow, "Upload provenance artifact")
        owner_upload = step_block(self.workflow, "Upload owner review artifact")
        self.assertIn("continuous-gauntlet-pipelock-${{ github.run_attempt }}", upload)
        self.assertIn("continuous-gauntlet-owner-review-${{ github.run_attempt }}", owner_upload)

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

    def test_downloaded_release_bytes_match_the_reviewed_architecture_digest(self):
        digest_check = '[[ "$asset_sha256" == "$expected_asset_sha256" ]]'
        self.assertIn(digest_check, self.entrypoint)
        self.assertLess(self.entrypoint.index('curl -fsSL "$asset_url"'), self.entrypoint.index(digest_check))
        self.assertLess(self.entrypoint.index(digest_check), self.entrypoint.index('tar -xzf "$work_dir/$asset"'))

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
