#!/usr/bin/env python3
"""Structural tests for the reviewed Gauntlet promotion workflow."""

import re
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote-gauntlet-result.yaml"


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
        self.assertRegex(
            self.workflow,
            r"(?m)^permissions:\n  actions: write\n  contents: write\n  pull-requests: write$",
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

    def test_runner_paths_are_initialized_at_step_scope(self):
        job_env = self.workflow.split("    steps:", 1)[0]
        initialize = step_block(self.workflow, "Initialize temporary paths")
        self.assertNotIn("runner.temp", job_env)
        self.assertIn("$RUNNER_TEMP/continuous-gauntlet-candidate", initialize)
        self.assertIn("$RUNNER_TEMP/gauntlet-result-promotion.md", initialize)
        self.assertIn('>> "$GITHUB_ENV"', initialize)

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
        self.assertIn("--name continuous-gauntlet-pipelock", download)
        self.assertIn("corpus_git_sha", download)
        self.assertIn("git merge-base --is-ancestor", download)
        self.assertIn("scripts/promote_gauntlet_candidate.py", prepare)
        self.assertIn("ci/gauntlet-baseline.json", prepare)
        self.assertIn("gauntlet-site/results", prepare)
        self.assertIn("gauntlet-site/latest-verified.json", prepare)
        self.assertIn('--expected-run-id "$RUN_ID"', prepare)
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
        self.assertIn('branch="gauntlet-result-$RUN_ID"', create)
        self.assertIn('git push origin "HEAD:refs/heads/$branch"', create)
        self.assertIn("gh pr create", create)
        self.assertIn("existing promotion branch has different content", create)
        self.assertIn("promotion pull request already exists", create)
        self.assertIn("existing promotion pull request targets the wrong base branch", create)
        self.assertIn("baseRefName", create)
        self.assertIn("Raw evidence is copied byte-for-byte", create)
        self.assertIn('git add -f -- "$record_dir"', create)
        self.assertIn("gauntlet-record-expected-files.txt", create)
        self.assertIn("gauntlet-record-staged-files.txt", create)
        self.assertIn("git ls-files --", create)
        self.assertIn('diff -u "$expected_files" "$staged_files"', create)
        self.assertIn("git diff --cached --check --", create)
        self.assertIn("ci/gauntlet-baseline.json", create)
        self.assertIn("gauntlet-site/latest-verified.json", create)
        self.assertNotRegex(create, r"(?m)^\s*git diff --cached --check\s*$")
        self.assertIn('--body-file "$PR_BODY"', create)
        self.assertNotIn("git push origin main", create)
        self.assertNotIn("gh pr merge", self.workflow)
        self.assertNotIn("--force", self.workflow)

    def test_generated_pr_branch_gets_required_validation_dispatch(self):
        workflow_dir = REPO_ROOT / ".github" / "workflows"
        required_workflows = ("validate.yaml", "security.yaml", "pipelock.yaml")
        loaded = {
            name: (workflow_dir / name).read_text(encoding="utf-8")
            for name in required_workflows
        }
        dispatch = step_block(self.workflow, "Dispatch required validations")
        for name, workflow in loaded.items():
            with self.subTest(workflow=name):
                self.assertRegex(workflow, r"(?m)^  workflow_dispatch:$")
        self.assertIn(
            "for workflow in validate.yaml security.yaml pipelock.yaml; do",
            dispatch,
        )
        self.assertIn('gh workflow run "$workflow"', dispatch)
        self.assertIn('--ref "$branch"', dispatch)
        self.assertIn("GH_TOKEN:", dispatch)
        self.assertIn("--immutable-base", loaded["validate.yaml"])
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


if __name__ == "__main__":
    unittest.main()
