#!/usr/bin/env python3
"""Contract tests for the OCI runner, reusable Action, and devcontainer."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RunnerImageContractTest(unittest.TestCase):
    def test_dockerfile_pins_multi_arch_build_and_runtime_images(self) -> None:
        text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
        self.assertEqual(2, len(from_lines))
        for line in from_lines:
            self.assertRegex(line, r"@sha256:[0-9a-f]{64}(?: AS build)?$")
        self.assertIn("FROM --platform=$BUILDPLATFORM", from_lines[0])
        self.assertIn('GOOS="$TARGETOS" GOARCH="$TARGETARCH"', text)
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
        self.assertIn("offline mode requires a preloaded digest-pinned image", script)
        result = subprocess.run(["bash", "-n", str(ROOT / "scripts" / "run-oci-action.sh")], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, msg=result.stderr)

    def test_devcontainer_builds_the_same_pinned_runner_image(self) -> None:
        text = (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        self.assertIn('"dockerfile": "../Dockerfile"', text)
        self.assertIn('"context": ".."', text)
        self.assertIn('"overrideCommand": true', text)
        self.assertNotIn('"image":', text)

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

if __name__ == "__main__":
    unittest.main()
