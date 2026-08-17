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
    def test_local_offline_doctor_reports_ready_without_starting_a_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text(
                "#!/bin/sh\n"
                "[ \"$1 $2\" = \"image inspect\" ] || exit 97\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            image = f"registry.invalid/reviewed/runner@sha256:{'a' * 64}"
            result = subprocess.run(
                [
                    str(ROOT / "scripts" / "run-oci-action.sh"),
                    "--profile", "profile.json",
                    "--adapter", "proxy",
                    "--image", image,
                    "--allow-unverified-image",
                    "--doctor-json",
                ],
                cwd=workspace,
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["ready"])
            self.assertFalse((workspace / "aeb-results").exists())

    def test_local_offline_doctor_accepts_a_root_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            profile = fixture / "profile.json"
            profile.write_text("{}\n", encoding="utf-8")
            bin_dir = fixture / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            docker.chmod(0o755)
            image = f"registry.invalid/reviewed/runner@sha256:{'a' * 64}"
            result = subprocess.run(
                [
                    str(ROOT / "scripts" / "run-oci-action.sh"),
                    "--profile", str(profile).removeprefix("/"),
                    "--adapter", "proxy",
                    "--image", image,
                    "--allow-unverified-image",
                    "--doctor-json",
                ],
                cwd="/",
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(json.loads(result.stdout)["ready"])

    def test_local_offline_doctor_collects_missing_inputs(self) -> None:
        result = subprocess.run(
            [str(ROOT / "scripts" / "run-oci-action.sh"), "--doctor-json"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(0, result.returncode)
        report = json.loads(result.stdout)
        statuses = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual("missing", statuses["profile"])
        self.assertEqual("missing", statuses["adapter"])
        self.assertEqual("invalid", statuses["image_digest"])

    def test_local_offline_doctor_rejects_verified_mode_for_a_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            image = f"registry.invalid/reviewed/runner@sha256:{'a' * 64}"
            (workspace / "image.ref").write_text(f"{image}\n", encoding="utf-8")
            for name in ("attestation.jsonl", "trusted-root.jsonl"):
                (workspace / name).write_text("placeholder\n", encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            docker.chmod(0o755)
            gh = bin_dir / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if args[:2] != ['attestation', 'verify']: raise SystemExit(91)\n"
                "if pathlib.Path(args[2]).name != 'image.ref': raise SystemExit(92)\n"
                "pairs = {'--repo': 'luckyPipewrench/agent-egress-bench', '--signer-workflow': 'github.com/luckyPipewrench/agent-egress-bench/.github/workflows/release.yaml'}\n"
                "for flag, value in pairs.items():\n"
                "  if flag not in args or args[args.index(flag) + 1] != value: raise SystemExit(93)\n"
                "for flag, name in [('--bundle', 'attestation.jsonl'), ('--custom-trusted-root', 'trusted-root.jsonl')]:\n"
                "  if flag not in args or pathlib.Path(args[args.index(flag) + 1]).name != name: raise SystemExit(94)\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            result = subprocess.run(
                [
                    str(ROOT / "scripts" / "run-oci-action.sh"),
                    "--profile", "profile.json",
                    "--adapter", "proxy",
                    "--image", image,
                    "--image-metadata", "image.ref",
                    "--image-attestation", "attestation.jsonl",
                    "--attestation-trusted-root", "trusted-root.jsonl",
                    "--doctor-json",
                ],
                cwd=workspace,
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            report = json.loads(result.stdout)
            statuses = {check["code"]: check["status"] for check in report["checks"]}
            self.assertEqual("invalid", statuses["image_repository"])
            self.assertEqual("invalid", statuses["publisher_identity"])

    def test_local_offline_doctor_checks_publisher_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            image = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'a' * 64}"
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            (workspace / "image.ref").write_text(f"{image}\n", encoding="utf-8")
            for name in ("attestation.jsonl", "trusted-root.jsonl"):
                (workspace / name).write_text("placeholder\n", encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            docker = bin_dir / "docker"
            docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            docker.chmod(0o755)
            gh = bin_dir / "gh"
            gh.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "if args[:2] != ['attestation', 'verify']: raise SystemExit(91)\n"
                "if pathlib.Path(args[2]).name != 'image.ref': raise SystemExit(92)\n"
                "pairs = {'--repo': 'luckyPipewrench/agent-egress-bench', '--signer-workflow': 'github.com/luckyPipewrench/agent-egress-bench/.github/workflows/release.yaml'}\n"
                "for flag, value in pairs.items():\n"
                "  if flag not in args or args[args.index(flag) + 1] != value: raise SystemExit(93)\n"
                "for flag, name in [('--bundle', 'attestation.jsonl'), ('--custom-trusted-root', 'trusted-root.jsonl')]:\n"
                "  if flag not in args or pathlib.Path(args[args.index(flag) + 1]).name != name: raise SystemExit(94)\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            gh.chmod(0o755)
            result = subprocess.run(
                [
                    str(ROOT / "scripts" / "run-oci-action.sh"),
                    "--profile", "profile.json",
                    "--adapter", "proxy",
                    "--image", image,
                    "--image-metadata", "image.ref",
                    "--image-attestation", "attestation.jsonl",
                    "--attestation-trusted-root", "trusted-root.jsonl",
                    "--doctor-json",
                ],
                cwd=workspace,
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            statuses = {check["code"]: check["status"] for check in json.loads(result.stdout)["checks"]}
            self.assertEqual("ok", statuses["image_repository"])
            self.assertEqual("ok", statuses["publisher_identity"])

    def test_local_offline_cli_is_read_only_until_required_inputs_exist(self) -> None:
        script = ROOT / "scripts" / "run-oci-action.sh"
        help_result = subprocess.run(
            [str(script), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, help_result.returncode, help_result.stderr)
        self.assertIn("network access disabled", help_result.stdout)
        self.assertIn("--attestation-trusted-root", help_result.stdout)

        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(
                [str(script), "--profile", "missing.json"],
                cwd=directory,
                env={**os.environ, "INPUT_ADAPTER": "ambient-adapter", "INPUT_IMAGE": "ambient-image"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("adapter is required", result.stderr)
            self.assertEqual([], list(Path(directory).iterdir()))

    def test_local_offline_cli_rejects_unknown_options(self) -> None:
        result = subprocess.run(
            [str(ROOT / "scripts" / "run-oci-action.sh"), "--online"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("unknown local option: --online", result.stderr)

    def test_local_offline_cli_never_pulls_and_records_unverified_image(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            docker_log = workspace / "docker.log"
            docker = bin_dir / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['MOCK_DOCKER_LOG'], 'a', encoding='utf-8') as log: log.write(json.dumps(args) + '\\n')\n"
                "if args[:1] == ['pull']: raise SystemExit(97)\n"
                "if args[:2] == ['image', 'inspect']:\n"
                "  if '--format' in args: print('sha256:local-offline-image')\n"
                "  raise SystemExit(0)\n"
                "if args[:1] == ['info']: print('[]'); raise SystemExit(0)\n"
                "if args[:1] == ['run']:\n"
                "  volumes = [args[index + 1] for index, value in enumerate(args) if value == '--volume']\n"
                "  output = next(value.split(':/aeb-output:', 1)[0] for value in volumes if ':/aeb-output:' in value)\n"
                "  with open(os.path.join(output, 'summary.json'), 'w', encoding='utf-8') as summary: json.dump({'measurement_status': 'measured'}, summary)\n"
                "  raise SystemExit(0)\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            image = f"registry.invalid/reviewed/runner@sha256:{'a' * 64}"
            result = subprocess.run(
                [
                    str(ROOT / "scripts" / "run-oci-action.sh"),
                    "--profile", "profile.json",
                    "--adapter", "dryrun",
                    "--image", image,
                    "--allow-unverified-image",
                ],
                cwd=workspace,
                env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "MOCK_DOCKER_LOG": str(docker_log)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            calls = [json.loads(line) for line in docker_log.read_text(encoding="utf-8").splitlines()]
            self.assertFalse(any(call[:1] == ["pull"] for call in calls))
            run = next(call for call in calls if call[:1] == ["run"])
            self.assertIn("none", run)
            metadata = json.loads((workspace / "aeb-results" / "run-metadata.json").read_text(encoding="utf-8"))
            self.assertFalse(metadata["publisher_verified"])

    def run_action(self, *, image: str, metadata: str | None = None, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            if metadata is not None:
                (workspace / "runner-image.ref").write_text(metadata, encoding="utf-8")
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
                "INPUT_IMAGE_METADATA": "runner-image.ref" if metadata is not None else "",
            }
            env.update(extra_env or {})
            return subprocess.run([str(ROOT / "scripts" / "run-oci-action.sh")], text=True, capture_output=True, env=env)

    def run_completed_action(
        self, security_options: str, *, verified: bool = False, verifier_exit: int = 0
    ) -> tuple[subprocess.CompletedProcess[str], str, dict[str, object] | None]:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / "profile.json").write_text("{}\n", encoding="utf-8")
            bin_dir = workspace / "bin"
            bin_dir.mkdir()
            docker_log = workspace / "docker.log"
            docker = bin_dir / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['MOCK_DOCKER_LOG'], 'a', encoding='utf-8') as log: log.write(json.dumps(args) + '\\n')\n"
                "if args[:1] == ['pull']: raise SystemExit(0)\n"
                "if args[:2] == ['image', 'inspect']:\n"
                "  if '--format' in args: print('sha256:mock-local-image-id')\n"
                "  raise SystemExit(0)\n"
                "if args[:1] == ['info']:\n"
                "  print(os.environ['MOCK_SECURITY_OPTIONS'])\n"
                "  raise SystemExit(0)\n"
                "if args[:1] == ['run']:\n"
                "  volumes = [args[index + 1] for index, value in enumerate(args) if value == '--volume']\n"
                "  output = next(value.split(':/aeb-output:', 1)[0] for value in volumes if ':/aeb-output:' in value)\n"
                "  with open(os.path.join(output, 'summary.json'), 'w', encoding='utf-8') as summary: json.dump({'measurement_status': 'measured'}, summary)\n"
                "  raise SystemExit(0)\n"
                "raise SystemExit(2)\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            if verified:
                image = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'f' * 64}"
                (workspace / "runner-image.ref").write_text(image + "\n", encoding="utf-8")
                (workspace / "attestation.json").write_text("offline bundle\n", encoding="utf-8")
                (workspace / "trusted-root.json").write_text("trusted root\n", encoding="utf-8")
                gh = bin_dir / "gh"
                gh.write_text(
                    "#!/usr/bin/env python3\n"
                    "import os, pathlib, sys\n"
                    "args = sys.argv[1:]\n"
                    "if args[:2] != ['attestation', 'verify']: raise SystemExit(91)\n"
                    "if pathlib.Path(args[2]).name != 'image-metadata': raise SystemExit(92)\n"
                    "pairs = {'--repo': 'luckyPipewrench/agent-egress-bench', '--signer-workflow': 'github.com/luckyPipewrench/agent-egress-bench/.github/workflows/release.yaml'}\n"
                    "for flag, value in pairs.items():\n"
                    "  if flag not in args or args[args.index(flag) + 1] != value: raise SystemExit(93)\n"
                    "for flag, name in [('--bundle', 'image-attestation'), ('--custom-trusted-root', 'attestation-trusted-root')]:\n"
                    "  if flag not in args or pathlib.Path(args[args.index(flag) + 1]).name != name: raise SystemExit(94)\n"
                    "raise SystemExit(int(os.environ['MOCK_VERIFIER_EXIT']))\n",
                    encoding="utf-8",
                )
                gh.chmod(0o755)
            else:
                image = f"registry.invalid/reviewed/runner@sha256:{'f' * 64}"
            env = {
                **os.environ,
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_ACTION_PATH": str(ROOT),
                "INPUT_PROFILE": "profile.json",
                "INPUT_ADAPTER": "proxy",
                "INPUT_IMAGE": image,
                "INPUT_OFFLINE": "true" if verified else "false",
                "INPUT_ALLOW_UNVERIFIED_IMAGE": "false" if verified else "true",
                "INPUT_IMAGE_METADATA": "runner-image.ref" if verified else "",
                "INPUT_IMAGE_ATTESTATION": "attestation.json" if verified else "",
                "INPUT_ATTESTATION_TRUSTED_ROOT": "trusted-root.json" if verified else "",
                "MOCK_DOCKER_LOG": str(docker_log),
                "MOCK_SECURITY_OPTIONS": security_options,
                "MOCK_VERIFIER_EXIT": str(verifier_exit),
            }
            result = subprocess.run([str(ROOT / "scripts" / "run-oci-action.sh")], text=True, capture_output=True, env=env)
            metadata_file = workspace / "aeb-results" / "run-metadata.json"
            metadata = json.loads(metadata_file.read_text(encoding="utf-8")) if metadata_file.exists() else None
            docker_calls = docker_log.read_text(encoding="utf-8") if docker_log.exists() else ""
            return result, docker_calls, metadata

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
        self.assertIn("adduser -S -D -u 65532 -G aeb aeb", text)
        self.assertIn("install -d -o aeb -g aeb /work", text)
        self.assertIn("USER aeb:aeb", text)
        self.assertLess(text.index("USER aeb:aeb"), text.index('ENTRYPOINT ["/usr/local/bin/aeb-gauntlet"]'))
        self.assertIn('ENTRYPOINT ["/usr/local/bin/aeb-gauntlet"]', text)

    def test_action_enforces_digest_and_strict_offline_execution(self) -> None:
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        script = (ROOT / "scripts" / "run-oci-action.sh").read_text(encoding="utf-8")
        self.assertIn("using: composite", action)
        self.assertIn("measurement-status:", action)
        self.assertIn("@sha256:[0-9a-f]{64}", script)
        self.assertIn("--network none", script)
        self.assertIn("--security-opt no-new-privileges=true", script)
        self.assertIn("--cap-drop ALL", script)
        self.assertIn("--read-only", script)
        self.assertIn("--tmpfs /tmp:rw,nosuid,nodev,mode=1777", script)
        self.assertIn("name=selinux", script)
        self.assertNotIn("label=disable", script)
        self.assertIn("--require-complete", script)
        self.assertIn("-require-complete=*", script)
        self.assertIn('if [[ "$measurement_status" != measured && "$run_exit" -eq 0 ]]', script)
        self.assertIn("action_artifacts.py\" prepare", script)
        self.assertIn("action_artifacts.py\" publish", script)
        self.assertIn("action_artifacts.py\" inspect-summary", script)
        self.assertIn('--volume "$workspace_real:/work:ro$volume_label_suffix"', script)
        self.assertIn('--volume "$container_stage:/aeb-output:rw$volume_label_suffix"', script)
        self.assertIn('"measurement_status": os.environ["AEB_ACTION_MEASUREMENT_STATUS"]', script)
        self.assertIn('"runner_exit_code": int(os.environ["AEB_ACTION_RUNNER_EXIT"])', script)
        self.assertIn('"action_exit_code": int(os.environ["AEB_ACTION_EXIT"])', script)
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
        metadata = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'d' * 64}\n"
        result = self.run_action(image=image, metadata=metadata)
        self.assertEqual(2, result.returncode)
        self.assertIn("runner image does not match the signed release reference", result.stderr)
        self.assertNotIn("docker-called", result.stderr)

    def test_offline_official_image_requires_local_attestation_material(self) -> None:
        image = f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'e' * 64}"
        metadata = image + "\n"
        result = self.run_action(image=image, metadata=metadata, extra_env={"INPUT_OFFLINE": "true"})
        self.assertEqual(2, result.returncode)
        self.assertIn("image-attestation is required", result.stderr)
        self.assertNotIn("docker-called", result.stderr)

    def test_selinux_and_non_selinux_daemons_get_explicit_mount_modes(self) -> None:
        selinux_result, selinux_log, selinux_metadata = self.run_completed_action('["name=seccomp", "name=selinux"]')
        self.assertEqual(0, selinux_result.returncode, msg=selinux_result.stderr)
        selinux_run = next(call for call in map(json.loads, selinux_log.splitlines()) if call[:1] == ["run"])
        selinux_volumes = [selinux_run[index + 1] for index, value in enumerate(selinux_run) if value == "--volume"]
        self.assertTrue(any(value.endswith(":/work:ro,z") for value in selinux_volumes))
        self.assertTrue(any(value.endswith(":/aeb-output:rw,z") for value in selinux_volumes))
        self.assertNotIn("SELinux labeling is unavailable", selinux_result.stderr)
        self.assertFalse(selinux_metadata["publisher_verified"])

        plain_result, plain_log, _ = self.run_completed_action('["name=seccomp"]')
        self.assertEqual(0, plain_result.returncode, msg=plain_result.stderr)
        plain_run = next(call for call in map(json.loads, plain_log.splitlines()) if call[:1] == ["run"])
        plain_volumes = [plain_run[index + 1] for index, value in enumerate(plain_run) if value == "--volume"]
        self.assertTrue(any(value.endswith(":/work:ro") for value in plain_volumes))
        self.assertTrue(any(value.endswith(":/aeb-output:rw") for value in plain_volumes))
        self.assertFalse(any(value.endswith(",z") for value in plain_volumes))
        self.assertIn("SELinux labeling is unavailable", plain_result.stderr)

    def test_successful_publisher_verification_is_recorded(self) -> None:
        result, _, metadata = self.run_completed_action('["name=seccomp"]', verified=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIsNotNone(metadata)
        self.assertTrue(metadata["publisher_verified"])

    def test_failed_publisher_verification_stops_before_docker_run(self) -> None:
        result, docker_log, metadata = self.run_completed_action(
            '["name=seccomp"]', verified=True, verifier_exit=1
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("metadata provenance verification failed", result.stderr)
        self.assertFalse(any(call[:1] == ["run"] for call in map(json.loads, docker_log.splitlines())))
        self.assertIsNone(metadata)

    def test_devcontainer_builds_the_same_pinned_runner_image(self) -> None:
        text = (ROOT / ".devcontainer" / "devcontainer.json").read_text(encoding="utf-8")
        self.assertIn('"dockerfile": "../Dockerfile"', text)
        self.assertIn('"context": ".."', text)
        self.assertIn('"overrideCommand": true', text)
        self.assertIn('"remoteUser": "aeb"', text)
        self.assertIn('"updateRemoteUserUID": true', text)
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
        self.assertIn("runner-image.ref", workflow)
        self.assertIn("release_build.py checksums", workflow)
        self.assertIn("agent-egress-bench-release-final-${{ github.sha }}", workflow)

if __name__ == "__main__":
    unittest.main()
