#!/usr/bin/env python3
"""Structural tests for the reviewed Gauntlet promotion workflow."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import verify_staged_gauntlet_record as staged_record


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote-gauntlet-result.yaml"
EXISTING_BRANCH_VERIFIER = REPO_ROOT / "scripts" / "verify_existing_gauntlet_promotion.py"
RECORD_VALIDATOR = REPO_ROOT / "scripts" / "validate_gauntlet_records.py"
SUMMARY_GENERATOR = REPO_ROOT / "scripts" / "promote_gauntlet_candidate.py"


def step_block(workflow, name):
    marker = f"      - name: {name}\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow step: {name}")
    next_step = workflow.find("\n      - name:", start + len(marker))
    end = next_step if next_step >= 0 else len(workflow)
    return workflow[start:end]


class PromoteGauntletWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_manual_dispatch_can_prepare_a_public_pr(self):
        trigger = self.workflow.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotRegex(trigger, r"(?m)^  (push|schedule|pull_request):")
        self.assertIn("run_id:", trigger)
        self.assertIn("accept_policy_change:", trigger)

    def test_write_permissions_are_isolated_from_scheduled_lane(self):
        self.assertRegex(self.workflow, r"(?m)^permissions: \{\}$")
        self.assertRegex(
            self.workflow,
            r"(?m)^  prepare:\n    permissions:\n"
            r"      actions: write\n"
            r"      contents: write\n"
            r"      pull-requests: write$",
        )
        scheduled = (REPO_ROOT / ".github" / "workflows" / "continuous-gauntlet.yaml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(scheduled, r"(?m)^permissions:\n  contents: read$")
        self.assertNotIn("pull-requests: write", scheduled)

    def test_all_run_ids_share_one_promotion_lock(self):
        self.assertRegex(
            self.workflow,
            r"(?m)^concurrency:\n(?:  #.*\n)*  group: gauntlet-result-promotion\n  cancel-in-progress: false$",
        )
        self.assertNotIn("gauntlet-result-promotion-${{ inputs.run_id }}", self.workflow)

    def test_source_run_identity_is_checked_before_download(self):
        verify = step_block(self.workflow, "Verify source workflow run")
        download = step_block(self.workflow, "Download candidate evidence")
        self.assertLess(self.workflow.index(verify), self.workflow.index(download))
        self.assertIn('.path == ".github/workflows/continuous-gauntlet.yaml"', verify)
        self.assertIn('.head_repository.full_name == $repo', verify)
        self.assertIn('.head_branch == $branch', verify)
        self.assertIn('"origin/$DEFAULT_BRANCH"', verify)
        self.assertIn("git merge-base --is-ancestor", verify)
        self.assertIn('[[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]]', verify)
        self.assertIn(".run_attempt", verify)
        self.assertIn('[[ "$run_attempt" =~ ^[1-9][0-9]*$ ]]', verify)
        self.assertIn('RUN_ATTEMPT=%s\\n', verify)

    def test_runner_paths_are_initialized_at_step_scope(self):
        job_env = self.workflow.split("    steps:", 1)[0]
        initialize = step_block(self.workflow, "Initialize temporary paths")
        self.assertNotIn("runner.temp", job_env)
        self.assertIn("$RUNNER_TEMP/continuous-gauntlet-candidate", initialize)
        self.assertIn("$RUNNER_TEMP/gauntlet-result-promotion.md", initialize)
        self.assertIn('>> "$GITHUB_ENV"', initialize)

    def test_generated_pr_body_starts_with_the_authoring_contract_heading(self):
        body = self.generate_promotion_body()
        self.assertEqual(body.splitlines()[0], "## What changed")

    def test_generated_pr_body_retains_run_and_score_provenance(self):
        body = self.generate_promotion_body()
        for required in (
            "github-actions:luckyPipewrench/agent-egress-bench:32536980640:1",
            "Candidate SHA-256",
            "Applicable containment",
            "Applicable false-positive rate",
        ):
            self.assertIn(required, body)

    def generate_promotion_body(self):
        """Render a promotion body the way the workflow does, then return it."""
        if str(SUMMARY_GENERATOR.parent) not in sys.path:
            sys.path.insert(0, str(SUMMARY_GENERATOR.parent))
        import promote_gauntlet_candidate as generator

        candidate = {
            "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:32536980640:1",
            "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/32536980640",
            "pipelock_version": "3.4.0",
            "corpus_version": "2.0.0",
            "corpus_git_sha": "3e99a294",
            "case_count": {
                "applicable": 242,
                "total": 242,
                "unreachable": 0,
                "not_applicable": 0,
                "errors": 0,
            },
            "scores": {
                "applicable": {"containment": 98.8636, "false_positive_rate": 0.0},
                "full": {"containment": 98.8636},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results.jsonl"
            results.write_text("", encoding="utf-8")
            body_path = Path(tmp) / "body.md"
            generator.write_summary(body_path, candidate, "0" * 64, {}, False, results)
            return body_path.read_text(encoding="utf-8")

    def test_failed_run_requires_explicit_policy_review(self):
        verify = step_block(self.workflow, "Verify source workflow run")
        prepare = step_block(self.workflow, "Prepare append-only record")
        self.assertIn('ACCEPT_POLICY_CHANGE" == "true"', verify)
        self.assertIn("success or enforcement failure", verify)
        self.assertIn("--accept-policy-change", prepare)
        self.assertIn('ACCEPT_POLICY_CHANGE" == "true"', prepare)

    def test_artifact_and_promotion_paths_are_fixed(self):
        download = step_block(self.workflow, "Download candidate evidence")
        prepare = step_block(self.workflow, "Prepare append-only record")
        self.assertIn('--name "continuous-gauntlet-pipelock-$RUN_ATTEMPT"', download)
        self.assertIn("corpus_git_sha", download)
        self.assertIn("git merge-base --is-ancestor", download)
        self.assertIn('git show "$corpus_sha:ci/gauntlet-baseline.json"', download)
        self.assertIn("scripts/promote_gauntlet_candidate.py", prepare)
        self.assertIn("ci/gauntlet-baseline.json", prepare)
        self.assertIn('--source-baseline "$RUNNER_TEMP/source-gauntlet-baseline.json"', prepare)
        self.assertIn("gauntlet-site/results", prepare)
        self.assertIn("gauntlet-site/latest-verified.json", prepare)
        self.assertIn('--expected-run-id "$RUN_ID"', prepare)
        self.assertIn('--expected-run-attempt "$RUN_ATTEMPT"', prepare)
        self.assertIn("scripts/validate_gauntlet_records.py", prepare)
        self.assertNotIn("GH_TOKEN", prepare)

    def test_write_token_is_not_persisted_or_exposed_to_promotion_script(self):
        checkout = step_block(self.workflow, "Check out trusted default branch")
        verify = step_block(self.workflow, "Verify source workflow run")
        download = step_block(self.workflow, "Download candidate evidence")
        prepare = step_block(self.workflow, "Prepare append-only record")
        create = step_block(self.workflow, "Create reviewed promotion pull request")
        self.assertIn("persist-credentials: false", checkout)
        self.assertIn("GH_TOKEN:", verify)
        self.assertIn("GH_TOKEN:", download)
        self.assertNotIn("GH_TOKEN:", prepare)
        self.assertIn("GH_TOKEN:", create)
        self.assertIn("gh auth setup-git", create)

    def test_public_write_is_feature_branch_and_pr_only(self):
        create = step_block(self.workflow, "Create reviewed promotion pull request")
        self.assertIn('branch="gauntlet-result-$RUN_ID-$RUN_ATTEMPT"', create)
        self.assertIn('git push origin "HEAD:refs/heads/$branch"', create)
        self.assertIn("gh pr create", create)
        self.assertIn("scripts/verify_existing_gauntlet_promotion.py", create)
        self.assertIn('--default-ref "origin/$DEFAULT_BRANCH"', create)
        self.assertIn('--remote-ref "refs/remotes/origin/$branch"', create)
        self.assertIn("promotion pull request already exists", create)
        self.assertIn("existing promotion pull request targets the wrong base branch", create)
        self.assertIn("baseRefName", create)
        self.assertIn("Raw evidence is copied byte-for-byte", create)
        self.assertIn('git add -f -- "$record_dir"', create)
        self.assertIn("scripts/verify_staged_gauntlet_record.py", create)
        self.assertIn("id: promotion", create)
        self.assertIn("git diff --cached --quiet", create)
        self.assertIn('needs_validation=false" >> "$GITHUB_OUTPUT"', create)
        self.assertIn('needs_validation=true" >> "$GITHUB_OUTPUT"', create)
        self.assertIn("git diff --cached --check --", create)
        self.assertIn("ci/gauntlet-baseline.json", create)
        self.assertIn("gauntlet-site/latest-verified.json", create)
        self.assertNotRegex(create, r"(?m)^\s*git diff --cached --check\s*$")
        self.assertIn('--body-file "$PR_BODY"', create)
        self.assertNotIn("git push origin main", create)
        self.assertNotIn("gh pr merge", self.workflow)
        self.assertNotIn("--force", self.workflow)
        self.assertIn("run $RUN_ID attempt $RUN_ATTEMPT", create)

    def test_generated_pr_branch_gets_required_validation_dispatch(self):
        workflow_dir = REPO_ROOT / ".github" / "workflows"
        required_workflows = ("validate.yaml", "security.yaml", "pipelock.yaml")
        loaded = {
            name: (workflow_dir / name).read_text(encoding="utf-8")
            for name in required_workflows
        }
        dispatch = step_block(self.workflow, "Dispatch required validations")
        self.assertIn(
            "if: steps.promotion.outputs.needs_validation == 'true'",
            dispatch,
        )
        for name, workflow in loaded.items():
            with self.subTest(workflow=name):
                self.assertRegex(workflow, r"(?m)^  workflow_dispatch:$")
        self.assertIn(
            "for workflow in validate.yaml security.yaml pipelock.yaml; do",
            dispatch,
        )
        self.assertIn('gh workflow run "$workflow"', dispatch)
        self.assertIn('--ref "$branch"', dispatch)
        self.assertIn('branch="gauntlet-result-$RUN_ID-$RUN_ATTEMPT"', dispatch)
        self.assertIn("dispatch_failed=0", dispatch)
        self.assertIn('exit "$dispatch_failed"', dispatch)
        self.assertIn("GH_TOKEN:", dispatch)
        self.assertIn("--immutable-base", loaded["validate.yaml"])
        self.assertIn(
            'git merge-base "origin/$DEFAULT_BRANCH" HEAD',
            loaded["validate.yaml"],
        )
        self.assertIn("fetch-depth: 0", loaded["validate.yaml"])

    def test_dispatched_pipelock_scan_checks_branch_diff(self):
        pipelock = (REPO_ROOT / ".github" / "workflows" / "pipelock.yaml").read_text(
            encoding="utf-8"
        )
        dispatched_scan = step_block(pipelock, "Scan dispatched branch diff")
        self.assertIn("if: github.event_name == 'workflow_dispatch'", dispatched_scan)
        self.assertIn('"origin/$DEFAULT_BRANCH...HEAD"', dispatched_scan)
        self.assertIn("git diff --no-ext-diff --no-textconv", dispatched_scan)
        self.assertIn('> "$diff_file"', dispatched_scan)
        self.assertIn(
            'pipelock git scan-diff "${scan_args[@]}" < "$diff_file"',
            dispatched_scan,
        )
        self.assertIn("CONFIG_PATH:", dispatched_scan)
        self.assertIn("--exclude cases/", dispatched_scan)

    def test_every_shell_step_parses(self):
        for name in (
            "Initialize temporary paths",
            "Verify source workflow run",
            "Download candidate evidence",
            "Prepare append-only record",
            "Create reviewed promotion pull request",
            "Dispatch required validations",
        ):
            with self.subTest(name=name):
                block = step_block(self.workflow, name)
                marker = "        run: |\n"
                source = block[block.index(marker) + len(marker):]
                source = "\n".join(
                    line[10:] if line.startswith("          ") else line
                    for line in source.splitlines()
                )
                result = subprocess.run(
                    ["bash", "-n"],
                    input=source,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


class VerifyStagedGauntletRecordTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        (self.repo / ".gitignore").write_text("*.jsonl\n", encoding="utf-8")
        self.record = (
            self.repo / "gauntlet-site" / "results" / "pipelock" / "candidate"
        )
        self.record.mkdir(parents=True)
        (self.record / "evidence.json").write_text("{}\n", encoding="utf-8")
        (self.record / "results.jsonl").write_text("{}\n", encoding="utf-8")
        (self.record / "record-manifest.json").write_text(
            json.dumps(
                {
                    "files": {
                        "evidence.json": "0" * 64,
                        "results.jsonl": "1" * 64,
                    }
                }
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "add",
                ".gitignore",
                str(self.record / "evidence.json"),
                str(self.record / "record-manifest.json"),
            ],
            check=True,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_ignored_manifest_file_is_rejected_until_force_staged(self):
        with self.assertRaisesRegex(ValueError, "staged record file set"):
            staged_record.verify(self.repo, self.record)
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "-f", str(self.record)],
            check=True,
        )
        staged_record.verify(self.repo, self.record)

    def test_unexpected_staged_record_file_is_rejected(self):
        subprocess.run(
            ["git", "-C", str(self.repo), "add", "-f", str(self.record)],
            check=True,
        )
        extra = self.record / "extra.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", str(extra)], check=True)
        with self.assertRaisesRegex(ValueError, "staged record file set"):
            staged_record.verify(self.repo, self.record)

    def test_malformed_or_non_local_manifest_is_rejected(self):
        manifest_path = self.record / "record-manifest.json"
        fixtures = (
            ([], "manifest must be an object"),
            ({"files": {}}, "files must be a non-empty object"),
            ({"files": {"../outside.json": "0" * 64}}, "non-local filename"),
        )
        for manifest, message in fixtures:
            with self.subTest(manifest=manifest):
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, message):
                    staged_record.verify(self.repo, self.record)


class ExistingPromotionBranchTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        for key, value in (
            ("user.name", "Gauntlet Test"),
            ("user.email", "gauntlet-test@vendor.example"),
            ("commit.gpgsign", "false"),
            ("core.hooksPath", "/dev/null"),
        ):
            self._git("config", key, value)
        (self.repo / "base.txt").write_text("base\n", encoding="utf-8")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "base")

        self._git("switch", "-q", "-c", "remote-promotion")
        self._write_promotion("candidate")
        self._git("add", "ci", "gauntlet-site")
        self._git("commit", "-q", "-m", "remote promotion")
        remote_head = self._git("rev-parse", "HEAD", capture_output=True).stdout.strip()
        self._git("update-ref", "refs/remotes/origin/gauntlet-result-1", remote_head)

        self._git("switch", "-q", "main")
        (self.repo / "unrelated.txt").write_text("main advanced\n", encoding="utf-8")
        self._git("add", "unrelated.txt")
        self._git("commit", "-q", "-m", "unrelated main change")
        main_head = self._git("rev-parse", "HEAD", capture_output=True).stdout.strip()
        self._git("update-ref", "refs/remotes/origin/main", main_head)

        self._git("switch", "-q", "-c", "local-promotion")
        self._write_promotion("candidate")
        self._git("add", "ci", "gauntlet-site")
        self._git("commit", "-q", "-m", "local promotion")

    def tearDown(self):
        self.temporary.cleanup()

    def _git(self, *args, capture_output=False):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=capture_output,
            text=True,
        )

    def _write_promotion(self, value):
        record = self.repo / "gauntlet-site" / "results" / "pipelock" / "candidate"
        record.mkdir(parents=True, exist_ok=True)
        (self.repo / "ci").mkdir(exist_ok=True)
        (self.repo / "ci" / "gauntlet-baseline.json").write_text(
            f'{{"value":"{value}"}}\n', encoding="utf-8"
        )
        (self.repo / "gauntlet-site" / "latest-verified.json").write_text(
            f'{{"value":"{value}"}}\n', encoding="utf-8"
        )
        (record / "evidence.json").write_text(
            f'{{"value":"{value}"}}\n', encoding="utf-8"
        )

    def _verify(self):
        return subprocess.run(
            [
                "python3",
                str(EXISTING_BRANCH_VERIFIER),
                "--repo-root",
                str(self.repo),
                "--default-ref",
                "origin/main",
                "--remote-ref",
                "refs/remotes/origin/gauntlet-result-1",
                "--record-dir",
                str(
                    self.repo
                    / "gauntlet-site"
                    / "results"
                    / "pipelock"
                    / "candidate"
                ),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def _update_remote_promotion(self):
        remote_head = self._git("rev-parse", "HEAD", capture_output=True).stdout.strip()
        self._git("update-ref", "refs/remotes/origin/gauntlet-result-1", remote_head)
        self._git("switch", "-q", "local-promotion")

    def test_unrelated_default_branch_change_does_not_block_reuse(self):
        result = self._verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unexpected_remote_branch_change_is_rejected(self):
        self._git("switch", "-q", "remote-promotion")
        (self.repo / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
        self._git("add", "unexpected.txt")
        self._git("commit", "-q", "-m", "unexpected remote change")
        self._update_remote_promotion()
        result = self._verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changes unexpected paths", result.stdout)

    def test_different_remote_promotion_content_is_rejected(self):
        self._git("switch", "-q", "remote-promotion")
        self._write_promotion("different")
        self._git("add", "ci", "gauntlet-site")
        self._git("commit", "-q", "-m", "different promotion")
        self._update_remote_promotion()
        result = self._verify()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("different promotion content", result.stdout)


class DispatchedImmutableBaseTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.name", "Gauntlet Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "config",
                "user.email",
                "gauntlet-test@vendor.example",
            ],
            check=True,
        )
        (self.repo / "base.txt").write_text("base\n", encoding="utf-8")
        self._git("add", "base.txt")
        self._git("commit", "-q", "-m", "base")
        self._git("switch", "-q", "-c", "gauntlet-result-1")
        (self.repo / "result.txt").write_text("result\n", encoding="utf-8")
        self._git("add", "result.txt")
        self._git("commit", "-q", "-m", "result")
        self._git("switch", "-q", "main")
        (self.repo / "unrelated.txt").write_text("main advanced\n", encoding="utf-8")
        self._git("add", "unrelated.txt")
        self._git("commit", "-q", "-m", "unrelated main change")
        main_head = self._git("rev-parse", "HEAD", capture_output=True).stdout.strip()
        self._git("update-ref", "refs/remotes/origin/main", main_head)
        self._git("switch", "-q", "gauntlet-result-1")

    def tearDown(self):
        self.temporary.cleanup()

    def _git(self, *args, capture_output=False):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args],
            check=True,
            capture_output=capture_output,
            text=True,
        )

    def test_fork_point_remains_valid_after_default_branch_advances(self):
        moving_tip = self._validate("origin/main")
        self.assertNotEqual(moving_tip.returncode, 0)
        self.assertIn("immutable base is not an ancestor", moving_tip.stdout)

        immutable_base = self._git(
            "merge-base",
            "origin/main",
            "HEAD",
            capture_output=True,
        ).stdout.strip()
        fork_point = self._validate(immutable_base)
        self.assertEqual(fork_point.returncode, 0, fork_point.stdout + fork_point.stderr)

    def _validate(self, immutable_base):
        return subprocess.run(
            [
                "python3",
                str(RECORD_VALIDATOR),
                "--repo-root",
                str(self.repo),
                "--site-root",
                str(self.repo / "gauntlet-site"),
                "--baseline",
                str(self.repo / "ci" / "gauntlet-baseline.json"),
                "--immutable-base",
                immutable_base,
            ],
            check=False,
            capture_output=True,
            text=True,
        )


if __name__ == "__main__":
    unittest.main()
