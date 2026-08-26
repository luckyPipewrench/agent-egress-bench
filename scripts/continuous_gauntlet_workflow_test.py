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
BEARER_AUDIENCE_CASE = (
    REPO_ROOT / "cases" / "headers" / "header-dlp-bearer-audience-010.json"
)
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

    def test_entrypoint_pins_local_go_toolchain(self):
        self.assertIn("export GOTOOLCHAIN=local", self.entrypoint)
        self.assertLess(
            self.entrypoint.index("export GOTOOLCHAIN=local"),
            self.entrypoint.index("installed_go_version()"),
        )

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
        self.assertIn('--tool-version-command "$tool_version_command"', self.entrypoint)
        self.assertIn("'[$binary, \"--version\"]'", self.entrypoint)
        self.assertNotIn("--multifile-cases", self.entrypoint)

    def test_zero_argument_entrypoint_avoids_old_bash_empty_array_expansion(self):
        self.assertIn("original_arg_count=$#", self.entrypoint)
        self.assertIn("original_arg_index < original_arg_count", self.entrypoint)
        self.assertIn('${original_args[$original_arg_index]}', self.entrypoint)
        self.assertNotRegex(self.entrypoint, r"\$\{original_args\[[@*]\]")

    def test_canonical_pinned_commit_may_be_in_origin_main_history(self):
        ancestry_guard = (
            'git merge-base --is-ancestor "$corpus_git_sha" refs/remotes/origin/main'
        )
        self.assertIn(ancestry_guard, self.entrypoint)
        self.assertNotIn('[[ "$corpus_git_sha" == "$origin_main_sha" ]]', self.entrypoint)

        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)

            def git(*arguments):
                return subprocess.run(
                    ["git", *arguments],
                    cwd=repo,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(git("init").returncode, 0)
            self.assertEqual(git("config", "user.name", "Test Operator").returncode, 0)
            self.assertEqual(git("config", "user.email", "operator@example.test").returncode, 0)
            (repo / "fixture").write_text("one\n", encoding="utf-8")
            self.assertEqual(git("add", "fixture").returncode, 0)
            self.assertEqual(git("commit", "-m", "first").returncode, 0)
            first = git("rev-parse", "HEAD").stdout.strip()
            (repo / "fixture").write_text("two\n", encoding="utf-8")
            self.assertEqual(git("commit", "-am", "second").returncode, 0)
            main_tip = git("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(
                git("update-ref", "refs/remotes/origin/main", main_tip).returncode,
                0,
            )

            self.assertEqual(
                git("merge-base", "--is-ancestor", first, "refs/remotes/origin/main").returncode,
                0,
            )
            self.assertEqual(git("checkout", "--detach", first).returncode, 0)
            (repo / "other").write_text("side\n", encoding="utf-8")
            self.assertEqual(git("add", "other").returncode, 0)
            self.assertEqual(git("commit", "-m", "divergent").returncode, 0)
            divergent = git("rev-parse", "HEAD").stdout.strip()
            self.assertEqual(
                git(
                    "merge-base",
                    "--is-ancestor",
                    divergent,
                    "refs/remotes/origin/main",
                ).returncode,
                1,
            )

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
        self.assertIn("command_make", codes)
        self.assertIn("go_version", codes)
        self.assertIn("mcp_stdio_bridge", codes)
        self.assertIn("repository_root", codes)
        self.assertIn("release_pin", codes)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertEqual(go_version["status"], "ok")
        self.assertEqual(before, set((REPO_ROOT / "continuous-gauntlet-runs").glob("*")))

    def test_doctor_collects_all_missing_prerequisites_before_failing(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_path = Path(temporary)
            for name in (
                "dirname", "uname", "git", "python3", "curl",
                "sha256sum", "tar", "timeout", "realpath", "make",
            ):
                target = "/usr/bin/uname" if name == "uname" else "/usr/bin/true"
                if name == "dirname":
                    target = "/usr/bin/dirname"
                (fake_path / name).symlink_to(target)
            result = subprocess.run(
                ["/bin/bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": str(fake_path)},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        report = json.loads(result.stdout)
        statuses = {check["code"]: check["status"] for check in report["checks"]}
        self.assertFalse(report["ready"])
        self.assertEqual(statuses["command_go"], "missing")
        self.assertEqual(statuses["command_jq"], "missing")
        self.assertEqual(statuses["mcp_stdio_bridge"], "missing")
        self.assertEqual(statuses["go_version"], "missing")
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

    def test_doctor_rejects_an_older_go_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_go = Path(temporary) / "go"
            fake_go.write_text(
                "#!/bin/sh\nprintf 'go version go1.24.0 linux/amd64\\n'\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{temporary}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertFalse(report["ready"])
        self.assertEqual(go_version["status"], "too_old")
        self.assertIn("go.dev/dl", go_version["remediation"])

    def test_every_go_invocation_honors_the_selected_toolchain(self):
        # A bare `go build` or `go run` added later would silently ignore --go and
        # AEB_GO, so the run would use a toolchain the doctor never checked. Parse
        # the command position rather than searching for a substring.
        offenders = []
        for number, line in enumerate(self.entrypoint.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Strip leading VAR=value assignments, which precede the command.
            words = stripped.split()
            index = 0
            while index < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[index]):
                index += 1
            if index < len(words) - 1 and words[index] == "go" and words[index + 1] in {
                "build", "run", "test", "install", "vet", "version", "env", "mod",
            }:
                offenders.append(f"{number}: {stripped}")
        self.assertEqual(offenders, [], "bare go invocations bypass --go/AEB_GO")

    def _stub_go(self, directory, version_line, name="go"):
        stub = Path(directory) / name
        stub.write_text(
            f"#!/bin/sh\nprintf '{version_line}\\n'\n",
            encoding="utf-8",
        )
        stub.chmod(0o755)
        return stub

    def test_doctor_checks_the_selected_go_binary_rather_than_path(self):
        # An evaluator on a distribution that ships an older Go points --go at a
        # newer toolchain installed elsewhere. The selected binary must be the one
        # reported, not whichever `go` happens to be first on PATH.
        with tempfile.TemporaryDirectory() as temporary:
            stale = self._stub_go(temporary, "go version go1.24.0 linux/amd64")
            selected_dir = Path(temporary) / "selected"
            selected_dir.mkdir()
            selected = self._stub_go(selected_dir, "go version go1.25.0 linux/amd64")
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--go", str(selected), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{stale.parent}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        report = json.loads(result.stdout)
        statuses = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual(statuses["command_go"], "ok")
        self.assertEqual(statuses["go_version"], "ok")

    def test_go_override_cannot_bypass_the_minimum_version(self):
        # The override selects a toolchain; it must never waive the floor. A
        # too-old --go has to fail exactly like a too-old PATH toolchain.
        with tempfile.TemporaryDirectory() as temporary:
            selected = self._stub_go(temporary, "go version go1.24.0 linux/amd64")
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--go", str(selected), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": ""},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertFalse(report["ready"])
        self.assertEqual(go_version["status"], "too_old")

    def test_a_relative_go_selection_is_canonicalized_before_use(self):
        # The build and validation steps cd into runner/ and validate/, so a
        # relative selection validated from the repository root would resolve
        # somewhere else once they run: doctor reports ready and the run then
        # fails, or silently picks a different file at the same relative path.
        # Assert on the path the toolchain is actually INVOKED as, not on the
        # doctor verdict, which passes either way and would make this vacuous.
        with tempfile.TemporaryDirectory() as temporary:
            recorded = Path(temporary) / "invoked-as"
            stub_dir = REPO_ROOT / "_reltest_toolchain"
            stub_dir.mkdir(exist_ok=True)
            stub = stub_dir / "go"
            stub.write_text(
                "#!/bin/sh\n"
                f'printf "%s\\n" "$0" >> {recorded}\n'
                "printf 'go version go1.25.0 linux/amd64\\n'\n",
                encoding="utf-8",
            )
            stub.chmod(0o755)
            try:
                subprocess.run(
                    ["bash", str(ENTRYPOINT), "--go", "./_reltest_toolchain/go", "--doctor-json"],
                    cwd=REPO_ROOT,
                    env={**os.environ, "AEB_GO": ""},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                invocations = recorded.read_text(encoding="utf-8").split()
            finally:
                stub.unlink(missing_ok=True)
                stub_dir.rmdir()
        self.assertTrue(invocations, "the selected toolchain was never invoked")
        for path in invocations:
            self.assertTrue(
                path.startswith("/"),
                f"toolchain invoked by relative path {path!r}; it would resolve "
                "differently after the script changes directory",
            )

    def test_the_selected_toolchain_is_never_reassigned_after_canonicalization(self):
        # The doctor cannot prove this on its own: it validates the selection
        # without entering runner/ or validate/, so a test that only runs
        # --doctor-json would still pass if a later execution path re-derived a
        # relative value. Combined with the bare-go-invocation guard, asserting
        # that go_bin is assigned only before canonicalization means every
        # consumer, including the ones that change directory, sees the absolute
        # path.
        lines = self.entrypoint.splitlines()
        canonicalize_at = None
        assignments = []
        for number, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Anchor on the resolution itself. The same shape test appears in the
            # availability helper, so matching that would anchor too early and
            # flag the legitimate --go flag assignment.
            if canonicalize_at is None and re.match(r"^go_bin_resolved=", stripped):
                canonicalize_at = number
            if re.match(r"^go_bin=", stripped):
                assignments.append(number)
        self.assertIsNotNone(canonicalize_at, "the canonicalization block is gone")
        late = [n for n in assignments if n > canonicalize_at]
        self.assertEqual(
            late, [],
            f"go_bin reassigned at {late} after canonicalization at line {canonicalize_at}; "
            "a consumer that changes directory would resolve the un-canonicalized value",
        )

    def _kernel_sandbox_probe(self, lsm_contents, seccomp_field=True, seccomp_filter=True):
        """Drive the whole doctor with substituted kernel probe paths.

        Exercises run_doctor rather than kernel_sandbox_state alone. Testing the
        classifier in isolation verified the label and not its consequence, and
        that is exactly how an inconclusive result shipped while still failing
        the doctor: the helper said unknown, which was correct, and the doctor
        counted it as a failed prerequisite, which was not.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lsm_path = root / ("lsm" if lsm_contents is not None else "absent-lsm")
            if lsm_contents is not None:
                lsm_path.write_text(lsm_contents, encoding="utf-8")
            status_path = root / "status"
            status_path.write_text("Seccomp:\t2\n" if seccomp_field else "Name:\tsh\n", encoding="utf-8")
            filter_path = root / ("actions_avail" if seccomp_filter else "absent-filter")
            if seccomp_filter:
                filter_path.write_text("kill_process filter\n", encoding="utf-8")

            # The entrypoint derives repo_root from its own location, so the
            # patched copy has to live beside the original. Running it from a
            # temp directory makes repo_root resolve to that directory and the
            # repository-root and release-pin checks fail for reasons that have
            # nothing to do with the kernel probe.
            patched = ENTRYPOINT.parent / "run-pipelock-gauntlet.kernelprobe-test.sh"
            script = ENTRYPOINT.read_text(encoding="utf-8")
            script = script.replace('"/sys/kernel/security/lsm"', f'"{lsm_path}"')
            script = script.replace('"/proc/self/status"', f'"{status_path}"')
            script = script.replace('"/proc/sys/kernel/seccomp/actions_avail"', f'"{filter_path}"')
            patched.write_text(script, encoding="utf-8")
            try:
                result = subprocess.run(
                    ["bash", str(patched), "--doctor-json"],
                    cwd=REPO_ROOT,
                    env={**os.environ, "AEB_GO": ""},
                    text=True, capture_output=True, check=False,
                )
            finally:
                patched.unlink(missing_ok=True)
            report = json.loads(result.stdout)
            check = next(c for c in report["checks"] if c["code"] == "kernel_sandbox")
            return check["status"], report["ready"], result.returncode

    def test_kernel_sandbox_probe_classifies_each_state(self):
        # The target runs under Landlock and seccomp. Before this check the
        # doctor reported ready and the run died on `query Landlock ABI:
        # function not implemented`, after the evaluator had paid for a release
        # download and a toolchain build.
        for name, kwargs, want in (
            ("landlock present", {"lsm_contents": "capability,yama,landlock,bpf"}, "ok"),
            ("landlock alone", {"lsm_contents": "landlock"}, "ok"),
            ("landlock last", {"lsm_contents": "capability,landlock"}, "ok"),
            ("landlock absent", {"lsm_contents": "capability,yama,apparmor"}, "unavailable"),
            ("no seccomp field", {"lsm_contents": "capability,landlock", "seccomp_field": False}, "unavailable"),
        ):
            with self.subTest(name):
                status, _, _ = self._kernel_sandbox_probe(**kwargs)
                self.assertEqual(status, want)

    def test_kernel_sandbox_unknown_does_not_fail_the_doctor(self):
        # The availability half, and the one that shipped wrong. An unreadable
        # LSM list means securityfs is not mounted, which says nothing about the
        # kernel. Reporting it and refusing the machine are different things:
        # the operator whose run is blocked for no reason turns the check off.
        # Assert on `ready` and the exit code, not just the reported status,
        # because the status was already right while the verdict was wrong.
        for name, kwargs in (
            ("unreadable LSM list", {"lsm_contents": None}),
            ("seccomp filter support unprovable", {"lsm_contents": "capability,landlock", "seccomp_filter": False}),
        ):
            with self.subTest(name):
                status, ready, code = self._kernel_sandbox_probe(**kwargs)
                self.assertEqual(status, "unknown")
                self.assertTrue(ready, "an inconclusive probe must not refuse the machine")
                self.assertEqual(code, 0, "an inconclusive probe must not fail the doctor")

    def test_doctor_rejects_a_realpath_without_the_required_gnu_options(self):
        # Presence is not capability. BusyBox realpath takes no options, so a
        # doctor that only checks for the command reports ready and the run then
        # fails during release-pin resolution.
        with tempfile.TemporaryDirectory() as temporary:
            stub = Path(temporary) / "realpath"
            stub.write_text(
                "#!/bin/sh\n"
                'for a in "$@"; do\n'
                '  case "$a" in\n'
                '    -*) echo "realpath: $a: No such file or directory" >&2; exit 1 ;;\n'
                "  esac\n"
                "done\n"
                'printf "%s\\n" "$@"\n',
                encoding="utf-8",
            )
            stub.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{temporary}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        check = next(c for c in report["checks"] if c["code"] == "command_realpath")
        self.assertEqual(check["status"], "unsupported")
        self.assertTrue(check["remediation"])

    def test_aeb_go_environment_variable_selects_the_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            stale = self._stub_go(temporary, "go version go1.24.0 linux/amd64")
            selected_dir = Path(temporary) / "selected"
            selected_dir.mkdir()
            selected = self._stub_go(selected_dir, "go version go1.25.0 linux/amd64")
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={
                    **os.environ,
                    "AEB_GO": str(selected),
                    "PATH": f"{stale.parent}:{os.environ.get('PATH', '')}",
                },
                text=True,
                capture_output=True,
                check=False,
            )
        report = json.loads(result.stdout)
        statuses = {check["code"]: check["status"] for check in report["checks"]}
        self.assertEqual(statuses["go_version"], "ok")

    def test_go_override_rejects_a_directory_and_a_missing_path(self):
        # Pointing --go at a toolchain's bin directory instead of its go binary is
        # the likeliest operator mistake, and a directory is executable.
        with tempfile.TemporaryDirectory() as temporary:
            for candidate in (temporary, str(Path(temporary) / "absent" / "go")):
                result = subprocess.run(
                    ["bash", str(ENTRYPOINT), "--go", candidate, "--doctor-json"],
                    cwd=REPO_ROOT,
                    env={**os.environ, "AEB_GO": ""},
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0, candidate)
                report = json.loads(result.stdout)
                statuses = {check["code"]: check["status"] for check in report["checks"]}
                self.assertEqual(statuses["command_go"], "missing", candidate)

    def test_doctor_rejects_prerelease_go_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_go = Path(temporary) / "go"
            fake_go.write_text(
                "#!/bin/sh\nprintf 'go version go1.25rc1 linux/amd64\\n'\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{temporary}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertFalse(report["ready"])
        self.assertEqual(go_version["status"], "unreadable")
        self.assertIn("go.dev/dl", go_version["remediation"])

    def test_doctor_rejects_devel_go_toolchain(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_go = Path(temporary) / "go"
            fake_go.write_text(
                "#!/bin/sh\nprintf 'go version devel go1.26-abcdef linux/amd64\\n'\n",
                encoding="utf-8",
            )
            fake_go.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{temporary}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertFalse(report["ready"])
        self.assertEqual(go_version["status"], "unreadable")

    def test_doctor_rejects_an_unreadable_go_version(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake_go = Path(temporary) / "go"
            fake_go.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake_go.chmod(0o755)
            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--doctor-json"],
                cwd=REPO_ROOT,
                env={**os.environ, "AEB_GO": "", "PATH": f"{temporary}:{os.environ.get('PATH', '')}"},
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        go_version = next(check for check in report["checks"] if check["code"] == "go_version")
        self.assertFalse(report["ready"])
        self.assertEqual(go_version["status"], "unreadable")

    def test_readme_tells_operators_doctor_checks_go_version(self):
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("does not check the installed Go version", readme)
        self.assertNotIn("does not check the selected Go version", readme)
        # "selected" rather than "installed" since --go and AEB_GO can choose a
        # toolchain that is not the one on PATH. Either wording satisfies the
        # operator-facing promise this guard exists to protect.
        self.assertTrue(
            "the installed Go version" in readme or "the selected Go version" in readme,
            "README must tell operators that doctor checks the Go version",
        )
        self.assertIn("distribution `golang` package", readme)
        # The override has to be discoverable, or an evaluator on a distribution
        # with an older Go concludes the benchmark simply will not run.
        self.assertIn("--go", readme)
        self.assertIn("AEB_GO", readme)
        self.assertIn("Make", readme)
        self.assertIn(
            "git clone --branch main https://github.com/luckyPipewrench/agent-egress-bench.git",
            readme,
        )

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

    def test_runtime_profile_uses_the_verified_release_version(self):
        self.assertIn('runtime_profile_path="$output_dir/tool-profile.json"', self.entrypoint)
        self.assertIn('--arg version "$PIPELOCK_VERSION"', self.entrypoint)
        self.assertIn("'.tool_version = $version'", self.entrypoint)
        self.assertIn('--profile "$runtime_profile_path"', self.entrypoint)
        self.assertNotIn("--profile examples/pipelock/tool-profile.json", self.entrypoint)
        self.assertIn('failure_reason="runtime tool profile generation failed"', self.entrypoint)

        source_profile = json.loads(PIPELOCK_PROFILE.read_text(encoding="utf-8"))
        result = subprocess.run(
            ["jq", "--arg", "version", "9.9.9", ".tool_version = $version", str(PIPELOCK_PROFILE)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tool_version"], "9.9.9")
        self.assertNotEqual(source_profile["tool_version"], "9.9.9")

    def test_canonical_runner_binds_absolute_corpus_and_receipt_commit(self):
        self.assertIn('--cases "$repo_root/cases"', self.entrypoint)
        self.assertNotIn("--cases ./cases", self.entrypoint)
        self.assertIn('.corpus_git_status == "clean" and .corpus_git_sha == $sha', self.entrypoint)
        self.assertIn("canonical receipt does not bind the clean corpus commit", self.entrypoint)

    def test_target_runs_under_a_filesystem_restricted_environment(self):
        self.assertIn("\"$go_bin\" build -o \"$target_sandbox\" ./cmd/target-sandbox", self.entrypoint)
        self.assertIn('pipelock_bin="$target_wrapper"', self.entrypoint)
        self.assertIn(
            'PIPELOCK_POSTURE_PROOF=$work_dir/absent-posture-proof.json',
            self.entrypoint,
        )
        self.assertIn("/usr/bin/env", self.entrypoint)
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
        self.assertRegex(config, r"(?ms)^reverse_proxy:\n(?:\s+#.*\n)*\s+enabled: false$")

    def test_bearer_audience_case_uses_the_header_scanning_proxy_surface(self):
        case = json.loads(BEARER_AUDIENCE_CASE.read_text(encoding="utf-8"))
        self.assertEqual(case["transport"], "http_proxy")
        self.assertEqual(case["input_type"], "header")
        self.assertEqual(case["payload"]["method"], "POST")

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
        for filename in BUILDER.V4_RAW_EVIDENCE.values():
            self.assertIn(filename, upload_block)
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

    def test_validate_workflow_uploads_go_coverage(self):
        validate_workflow = (
            Path(__file__).resolve().parent.parent / ".github" / "workflows" / "validate.yaml"
        ).read_text(encoding="utf-8")
        self.assertIn("coverage:", validate_workflow)
        self.assertIn("-coverprofile=coverage.out", validate_workflow)
        self.assertIn(
            "codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f",
            validate_workflow,
        )
        self.assertIn("fail_ci_if_error: false", validate_workflow)
        self.assertIn("continue-on-error: true", validate_workflow)
        self.assertIn("runner/coverage.out", validate_workflow)
        self.assertIn("validate/coverage.out", validate_workflow)
        self.assertIn("capability-registry/coverage.out", validate_workflow)
        self.assertIn("github.event_name != 'workflow_dispatch'", validate_workflow)
        scanned = re.findall(r'go-version: "(\d+\.\d+\.\d+)"', validate_workflow)
        self.assertEqual(
            len(scanned),
            1,
            f"coverage job must not add a second exact-patch Go pin, found {scanned}",
        )

    def test_workflow_is_not_scheduled(self):
        trigger = self.workflow[self.workflow.index("on:") : self.workflow.index("concurrency:")]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertNotIn("schedule:", trigger)
        self.assertNotIn("cron:", trigger)

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
