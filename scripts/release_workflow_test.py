#!/usr/bin/env python3
"""Structural gates for the release workflow's publication boundary."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/release.yaml"


def check_workflow(path: Path) -> None:
    workflow = path.read_text(encoding="utf-8")
    required = (
        "tags:\n      - 'v*'",
        "workflow_dispatch:",
        "fetch-depth: 0",
        "persist-credentials: false",
        "go-version: '1.25.13'",
        "run: make preflight",
        "goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94",
        "version: v2.17.1",
        "install-only: true",
        "./scripts/release-build.sh --tag snapshot --commit \"$GITHUB_SHA\" --snapshot",
        "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
        "dist/release/agent-egress-bench_*_linux_*.tar.gz",
        "dist/release/agent-egress-bench_*_darwin_*.tar.gz",
        "dist/release/agent-egress-bench_*_windows_*.zip",
        "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
        "path: dist/release/",
        "retention-days: 14",
        "if: github.event_name == 'push'",
        "gh release create \"$GITHUB_REF_NAME\" dist/release/* --title \"$GITHUB_REF_NAME\" --verify-tag",
    )
    for value in required:
        if value not in workflow:
            raise AssertionError(f"release workflow is missing required release guard: {value!r}")
    create_index = workflow.index("gh release create")
    conditional_index = workflow.rfind("if: github.event_name == 'push'", 0, create_index)
    if conditional_index < 0:
        raise AssertionError("GitHub release creation is not gated to tag pushes")


class ReleaseWorkflowTest(unittest.TestCase):
    def test_workflow_has_release_and_dry_run_boundaries(self) -> None:
        check_workflow(WORKFLOW)

    def test_release_creation_guard_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("if: github.event_name == 'push'", "if: always()", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "release guard"):
                check_workflow(candidate)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", type=Path)
    args, remaining = parser.parse_known_args()
    if args.workflow:
        check_workflow(args.workflow)
    else:
        unittest.main(argv=[__file__, *remaining])
