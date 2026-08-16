#!/usr/bin/env python3
"""Contract tests for the OCI runner, reusable Action, and devcontainer."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RunnerImageContractTest(unittest.TestCase):
    def run_action(self, *, image: str, metadata: dict[str, object] | None = None, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            if metadata is not None:
                (workspace / "runner-image.json").write_text(json.dumps(metadata), encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "docker").write_text("#!/bin/sh\necho docker-called:\"$*\" >&2\nexit 23\n", encoding="utf-8")
            (bin_dir / "gh").chmod(0o755)
            (bin_dir / "docker").chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_ACTION_PATH": str(ROOT),
                "INPUT_PROFILE": "profile.json",
                "INPUT_ADAPTER": "proxy",
                "INPUT_IMAGE": image,
                "INPUT_IMAGE_METADATA": "runner-image.json" if metadata is not None else "",
            }
            env.update(extra_env or {})
            return subprocess.run([str(ROOT / "scripts" / "run-oci-action.sh")], text=True, capture_output=True, env=env)

    def test_dockerfile_pins_multi_arch_build_and_runtime_images(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
        self.assertEqual(2, len(from_lines))
        for line in from_lines:
            self.assertRegex(line, r"@sha256:[0-9a-f]{64}(?: AS build)?$")
        self.assertIn("FROM --platform=$BUILDPLATFORM", from_lines[0])
        self.assertIn('GOOS="$TARGETOS" GOARCH="$TARGETARCH"', text)
        self.assertIn("COPY capability-registry ./capability-registry", text)
        self.assertNotIn("-mod=vendor", text)
        self.assertFalse((ROOT / "runner" / "vendor").exists())
        self.assertIn('ENTRYPOINT ["/usr/local/bin/aeb-gauntlet"]', text)

    def test_action_enforces_digest_and_strict_offline_execution(self) -> None:
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "run-oci-action.sh").read_text(encoding="utf-8")
        self.assertIn("using: composite", action)
        self.assertIn("measurement-status:", action)
        self.assertIn("@sha256:[0-9a-f]{64}", script)
        self.assertIn("--network none", script)
        self.assertIn("--require-complete", script)
        self.assertIn("-require-complete=*", script)
        self.assertIn('if [[ "$measurement_status" != measured && "$run_exit" -eq 0 ]]', script)
        self.assertIn('rm -f -- "$results_path" "$summary_path" "$metadata_path"', script)
        self.assertIn("offline mode requires a preloaded digest-pinned image", script)
        self.assertIn("attestation verify", script)
        self.assertIn("--signer-workflow", script)
        self.assertIn("allow-unverified-image", action)
        result = subprocess.run(["bash", "-n", str(ROOT / "scripts" / "run-oci-action.sh")], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, msg=result.stderr)

    def test_unrelated_digest_pinned_image_is_rejected_before_docker(self) -> None:
        image = f"registry.invalid/unrelated/runner@sha256:{'a' * 64}"
        result = self.run_action(image=image)
        self.assertEqual(2, result.returncode)
        self.assertIn("image must use the approved release repository", result.stderr)
        self.assertNotIn("docker-called", result.stderr)

    def test_arbitrary_image_requires_explicit_unverified_opt_in(self) -> None:
        image = f"registry.invalid/reviewed-mirror/runner@sha256:{'b' * 64}"
        result = self.run_action(image=image, extra_env={"INPUT_ALLOW_UNVERIFIED_IMAGE": "true"})
        self.assertEqual(23, result.returncode)
        self.assertIn(f"docker-called:pull {image}", result.stderr)

    def test_signed_metadata_must_bind_the_exact_image_digest(self) -> None:
        image = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'c' * 64}"
        metadata = {
            "schema_version": 1,
            "image": f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'d' * 64}",
            "digest": f"sha256:{'d' * 64}",
            "source_repository": "https://github.com/luckyPipewrench/agent-egress-bench",
            "source_commit": "1" * 40,
            "release_tag": "v1.2.3",
        }
        result = self.run_action(image=image, metadata=metadata)
        self.assertEqual(2, result.returncode)
        self.assertIn("runner image does not match signed release metadata", result.stderr)
        self.assertNotIn("docker-called", result.stderr)

    def test_offline_official_image_requires_local_attestation_material(self) -> None:
        image = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'e' * 64}"
        metadata = {
            "schema_version": 1,
            "image": image,
            "digest": f"sha256:{'e' * 64}",
            "source_repository": "https://github.com/luckyPipewrench/agent-egress-bench",
            "source_commit": "2" * 40,
            "release_tag": "v1.2.3",
        }
        result = self.run_action(image=image, metadata=metadata, extra_env={"INPUT_OFFLINE": "true"})
        self.assertEqual(2, result.returncode)
        self.assertIn("image-attestation is required", result.stderr)
        self.assertNotIn("docker-called", result.stderr)

    def test_devcontainer_builds_the_same_pinned_runner_image(self) -> None:
        text = (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        self.assertIn('"dockerfile": "../Dockerfile"', text)
        self.assertIn('"context": ".."', text)
        self.assertIn('"overrideCommand": true', text)
        self.assertNotIn('"image":', text)

    def test_removed_vendor_tree_is_not_excluded_from_review_or_self_scan(self) -> None:
        coderabbit = (ROOT / ".coderabbit.yaml").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "pipelock.yaml").read_text(encoding="utf-8")
        self.assertNotIn("runner/vendor", coderabbit)
        self.assertNotIn("runner/vendor", workflow)

    def test_release_build_publishes_and_checks_both_required_architectures(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yaml").read_text(encoding="utf-8")
        self.assertIn("docker/setup-buildx-action@bb05f3f5519dd87d3ba754cc423b652a5edd6d2c", workflow)
        self.assertIn("version: v0.36.1", workflow)
        self.assertIn("--platform linux/amd64,linux/arm64", workflow)
        self.assertIn("--provenance=mode=max", workflow)
        self.assertIn("--sbom=true", workflow)
        self.assertIn("--push", workflow)
        self.assertIn("reported_version=", workflow)
        self.assertIn('{("linux", "amd64"), ("linux", "arm64")}', workflow)
        self.assertIn("subject-name: ghcr.io/luckypipewrench/agent-egress-bench-runner", workflow)
        self.assertIn("subject-digest: ${{ steps.publish.outputs.digest }}", workflow)
        self.assertIn("runner-image.json", workflow)
        self.assertIn("runner-image.attestation.jsonl", workflow)
        self.assertIn("runner-image.trusted-root.jsonl", workflow)

if __name__ == "__main__":
    unittest.main()
