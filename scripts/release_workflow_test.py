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
VALIDATE_WORKFLOW = REPO / ".github/workflows/validate.yaml"
RELEASE_BUILD = REPO / "scripts/release-build.sh"


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
    image = job_block(workflow, "image")
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
    if 'release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{commit}")"' not in release or './scripts/release-build.sh --tag "$GITHUB_REF_NAME" --commit "$release_commit"' not in release:
        raise AssertionError("release build does not resolve the pushed tag to its commit")
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
    image_required = (
        "needs: [release, attest]",
        "if: github.event_name == 'push'",
        "fetch-depth: 0",
        "packages: write",
        "attestations: write",
        "id-token: write",
        "docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c",
        "version: v0.36.1",
        "--platform linux/amd64,linux/arm64",
        "--provenance=mode=max",
        "--sbom=true",
        "--push",
        'release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{commit}")"',
        '--build-arg "AEB_COMMIT=$release_commit"',
        '--label "org.opencontainers.image.revision=$release_commit"',
        "reported_version=",
        "docker logout ghcr.io",
        'docker pull "$pinned_image"',
        "subject-name: ghcr.io/luckypipewrench/agent-egress-bench-runner",
        "subject-digest: ${{ steps.publish.outputs.digest }}",
        "push-to-registry: true",
        "runner-image.ref",
        "release_build.py checksums",
        "release_build.py verify --release-dir dist/release --repo-root .",
        "subject-path: dist/release/*",
        "name: agent-egress-bench-release-final-${{ github.sha }}",
    )
    if any(value not in image for value in image_required):
        raise AssertionError("runner image publication is not pinned, multi-architecture, or tag-gated")
    if "needs: [release, attest, image]" not in publish or "if: github.event_name == 'push'" not in publish or "contents: write" not in publish or "python3 scripts/release_publish.py --tag \"$GITHUB_REF_NAME\" --dist dist/release" not in publish or "name: agent-egress-bench-release-final-${{ github.sha }}" not in publish:
        raise AssertionError("GitHub release creation is not gated to tag pushes")
    if "Create an owned draft release or resume one on workflow retry" not in publish or "release_publish.py" not in publish:
        raise AssertionError("draft release retry is not safe")


def check_validate_release_integration(path: Path) -> None:
    workflow = without_comments(path.read_text(encoding="utf-8"))
    validate = job_block(workflow, "validate")
    required = (
        "goreleaser/goreleaser-action@f06c13b6b1a9625abc9e6e439d9c05a8f2190e94",
        "distribution: goreleaser",
        "version: v2.17.1",
        "install-only: true",
        "run: make test-release-snapshot",
    )
    if any(value not in validate for value in required):
        raise AssertionError("validation workflow does not run the pinned release archive integration test")


class ReleaseWorkflowTest(unittest.TestCase):
    def test_workflow_has_release_and_dry_run_boundaries(self) -> None:
        check_workflow(WORKFLOW)

    def test_validation_workflow_runs_the_pinned_release_archive_integration(self) -> None:
        check_validate_release_integration(VALIDATE_WORKFLOW)

    def test_release_build_runs_repo_backed_verification_with_or_without_a_native_runner(self) -> None:
        commands = {
            line.strip()
            for line in RELEASE_BUILD.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("python3 scripts/release_build.py verify ")
        }
        self.assertEqual(
            {
                'python3 scripts/release_build.py verify --release-dir "$release_dir" --repo-root . --executable "$native_dir/aeb-gauntlet"',
                'python3 scripts/release_build.py verify --release-dir "$release_dir" --repo-root .',
            },
            commands,
        )

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

    def test_multi_architecture_image_guard_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("--platform linux/amd64,linux/arm64", "--platform linux/amd64", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_image_waits_for_release_asset_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("needs: [release, attest]", "needs: release", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_durable_image_identity_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("runner-image.ref", "discarded-image.ref"), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_image_identity_checksum_binding_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("python3 scripts/release_build.py checksums", "true # removed checksum binding", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_anonymous_image_pull_guard_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("docker logout ghcr.io", "true", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_publication_uses_the_owned_draft_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace('python3 scripts/release_publish.py --tag "$GITHUB_REF_NAME" --dist dist/release', "true", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "GitHub release creation"):
                check_workflow(candidate)

    def test_draft_resume_is_scoped_to_a_workflow_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("Create an owned draft release or resume one on workflow retry", "Create a draft GitHub release", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "draft release retry"):
                check_workflow(candidate)

    def test_commented_release_guard_does_not_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace("run: make preflight", "# run: make preflight", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "release build is missing"):
                check_workflow(candidate)

    def test_tag_commit_resolution_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            candidate.write_text(WORKFLOW.read_text(encoding="utf-8").replace('release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{commit}")"', 'release_commit="$GITHUB_SHA"', 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "does not resolve the pushed tag"):
                check_workflow(candidate)

    def test_runner_image_uses_the_resolved_tag_commit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "release.yaml"
            workflow = WORKFLOW.read_text(encoding="utf-8")
            image_start = workflow.index("  image:\n")
            target = 'release_commit="$(git rev-parse "${GITHUB_REF_NAME}^{commit}")"'
            target_start = workflow.index(target, image_start)
            candidate.write_text(workflow[:target_start] + 'release_commit="$GITHUB_SHA"' + workflow[target_start + len(target):], encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "runner image publication"):
                check_workflow(candidate)

    def test_release_archive_integration_is_load_bearing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "validate.yaml"
            candidate.write_text(VALIDATE_WORKFLOW.read_text(encoding="utf-8").replace("run: make test-release-snapshot", "run: true", 1), encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "does not run the pinned release archive integration"):
                check_validate_release_integration(candidate)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workflow", type=Path)
    args, remaining = parser.parse_known_args()
    if args.workflow:
        check_workflow(args.workflow)
    else:
        unittest.main(argv=[__file__, *remaining])
