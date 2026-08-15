#!/usr/bin/env python3
"""Structural gates for the release workflow's publication boundary."""

from __future__ import annotations

import argparse
import re
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/release.yaml"


def job_block(workflow: str, name: str) -> str:
    match = re.search(rf"(?m)^  {re.escape(name)}:\n", workflow)
    if match is None:
        raise AssertionError(f"release workflow is missing job {name!r}")
    next_job = re.search(r"(?m)^  [A-Za-z][A-Za-z0-9_-]*:\n", workflow[match.end():])
    return workflow[match.start(): match.end() + next_job.start() if next_job else len(workflow)]


def without_comments(workflow: str) -> str:
    return "\n".join("" if line.lstrip().startswith("#") else line.split(" #", 1)[0] for line in workflow.splitlines()) + "\n"


def check_workflow(path: Path) -> None:
    workflow = without_comments(path.read_text(encoding="utf-8"))
    preamble = workflow[:workflow.index("jobs:\n")]
    release = job_block(workflow, "release")
    attest = job_block(workflow, "attest")
    publish = job_block(workflow, "publish")
    required = (
        "tags:\n      - 'v*'",
        "workflow_dispatch:",
    )
    release_required = (
        "fetch-depth: 0",
        "persist-credentials: false",
        "go-version: '1.25.13'",
        "run: make preflight",
        "goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94",
        "version: v2.17.1",
        "install-only: true",
        "./scripts/release-build.sh --tag snapshot --commit \"$GITHUB_SHA\" --snapshot",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "path: dist/release/",
        "retention-days: 14",
    )
    for value in required:
        if value not in workflow:
            raise AssertionError(f"release workflow is missing required release guard: {value!r}")
    for value in release_required:
        if value not in release:
            raise AssertionError(f"release build is missing required release guard: {value!r}")
    if "permissions:\n  contents: read" not in preamble or "attestations: write" in preamble or "id-token: write" in preamble:
        raise AssertionError("manual workflow token is not read-only")
    if "permissions:" in release:
        raise AssertionError("release build or manual dry run overrides its read-only token")
    if "if: github.event_name == 'push'" not in attest or "attestations: write" not in attest or "id-token: write" not in attest:
        raise AssertionError("attestation write permission is not confined to tag pushes")
    if "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c" not in attest or "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8" not in attest:
        raise AssertionError("tag-only attestation does not consume the built release artifacts")
    if "subject-path: dist/release/*\n" not in attest:
        raise AssertionError("all release assets are not attested")
    if "needs: [release, attest]" not in publish or "if: github.event_name == 'push'" not in publish or "contents: write" not in publish or "gh release create \"$GITHUB_REF_NAME\" dist/release/* --title \"$GITHUB_REF_NAME\" --verify-tag --draft" not in publish:
        raise AssertionError("GitHub release creation is not gated to tag pushes")
    if "--json isDraft" not in publish or "refusing to overwrite published release" not in publish or "gh release upload \"$GITHUB_REF_NAME\" dist/release/* --clobber" not in publish or "gh release edit \"$GITHUB_REF_NAME\" --draft=false" not in publish:
        raise AssertionError("draft release retry is not safe")


class ReleaseWorkflowTest(unittest.TestCase):
    def test_workflow_has_release_and_dry_run_boundaries(self) -> None:
        check_workflow(WORKFLOW)

    def test_release_creation_guard_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            workflow = WORKFLOW.read_text(encoding="utf-8")
            publish_start = workflow.index("  publish:\n")
            condition = workflow.index("if: github.event_name == 'push'", publish_start)
            candidate.write_text(workflow[:condition] + "if: always()" + workflow[condition + len("if: github.event_name == 'push'"):], encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "GitHub release creation"):
                check_workflow(candidate)

    def test_manual_token_boundary_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("permissions:\n  contents: read\n", "permissions:\n  contents: read\n  attestations: write\n", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "manual workflow token"):
                check_workflow(candidate)

    def test_all_release_assets_are_attested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("subject-path: dist/release/*", "subject-path: dist/release/*.tar.gz", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "all release assets"):
                check_workflow(candidate)

    def test_partial_publish_stays_draft(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("--verify-tag --draft", "--verify-tag", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "GitHub release creation"):
                check_workflow(candidate)

    def test_commented_release_guard_does_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("run: make preflight", "# run: make preflight", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "release build is missing"):
                check_workflow(candidate)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", type=Path)
    args, remaining = parser.parse_known_args()
    if args.workflow:
        check_workflow(args.workflow)
    else:
        unittest.main(argv=[__file__, *remaining])
