#!/usr/bin/env python3
"""Regression tests for the release identity and downloaded-artifact verifier."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import zipfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/release_build.py"


class ReleaseBuildTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        files = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z"], check=True, capture_output=True
        ).stdout.decode("utf-8").split("\0")
        self.assertIn("contracts/method-independence-v1.json", files)
        for name in filter(None, files):
            source, destination = REPO / name, self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            shutil.copymode(source, destination)
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "release-test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Release Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "commit.gpgsign", "false"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "tag.gpgSign", "false"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.hooksPath", "/dev/null"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "test fixture"], check=True)
        self.commit = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        subprocess.run(["git", "-C", str(self.root), "tag", "-a", "v1.0.0", "-m", "baseline", self.commit], check=True)
        self.identity = self.root / ".release/release-identity.json"
        self.snapshot_version = f"1.0.0-SNAPSHOT-{self.git_short(self.commit)}"

    def tearDown(self) -> None:
        try:
            self.temp.cleanup()
        except OSError:
            shutil.rmtree(self.temp.name, ignore_errors=True)

    def invoke(self, *args: str, expect: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, expect, msg=result.stderr)
        return result

    def git_short(self, commit: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.root), "show", "--format=%h", "--quiet", commit],
            check=True, text=True, capture_output=True,
        ).stdout.strip()

    def prepare(self) -> None:
        self.invoke(
            "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version,
            "--commit", self.commit, "--snapshot", "--output", str(self.identity),
        )

    @staticmethod
    def fixture_release_binary(goos: str, goarch: str, binary: str = "aeb-gauntlet") -> bytes:
        # A real archive carries two different programs. The fixture pads each
        # one differently so it does too; identical bytes are themselves a
        # release defect and have their own test.
        return ReleaseBuildTest.fixture_runner_binary(goos, goarch) + binary.encode("ascii")

    @staticmethod
    def fixture_runner_binary(goos: str, goarch: str) -> bytes:
        if goos == "linux":
            machines = {"amd64": 62, "arm64": 183}
            result = bytearray(20)
            result[:6] = b"\x7fELF\x02\x01"
            result[18:20] = machines[goarch].to_bytes(2, "little")
            return bytes(result)
        if goos == "darwin":
            cpus = {"amd64": 0x01000007, "arm64": 0x0100000C}
            return b"\xcf\xfa\xed\xfe" + cpus[goarch].to_bytes(4, "little")
        if goos == "windows":
            machines = {"amd64": 0x8664, "arm64": 0xAA64}
            result = bytearray(70)
            result[:2] = b"MZ"
            result[60:64] = (64).to_bytes(4, "little")
            result[64:68] = b"PE\0\0"
            result[68:70] = machines[goarch].to_bytes(2, "little")
            return bytes(result)
        raise AssertionError(f"unsupported fixture platform: {goos} {goarch}")

    def write_runner_archives(
        self,
        dist: Path,
        identity: bytes,
        release: dict,
        include_binaries: bool = True,
        binary_overrides: dict[tuple[str, str], bytes] | None = None,
        mode_overrides: dict[tuple[str, str], int] | None = None,
        binaries: tuple[str, ...] = ("aeb-gauntlet", "aeb-validate"),
    ) -> None:
        self.write_schema_assets(dist, identity)
        binary_overrides = binary_overrides or {}
        mode_overrides = mode_overrides or {}
        for platform in release["runner"]["platforms"]:
            goos, goarch = platform["goos"], platform["goarch"]
            name = f"agent-egress-bench_{self.snapshot_version}_{goos}_{goarch}"
            override = binary_overrides.get((goos, goarch))
            if goos == "windows":
                with zipfile.ZipFile(dist / f"{name}.zip", "w") as archive:
                    archive.writestr(".release/release-identity.json", identity)
                    if include_binaries:
                        for binary in binaries:
                            body = override if override is not None else self.fixture_release_binary(goos, goarch, binary)
                            archive.writestr(f"{binary}.exe", body)
            else:
                with tarfile.open(dist / f"{name}.tar.gz", "w:gz") as archive:
                    info = tarfile.TarInfo(".release/release-identity.json")
                    info.size = len(identity)
                    archive.addfile(info, __import__("io").BytesIO(identity))
                    if include_binaries:
                        for binary in binaries:
                            body = override if override is not None else self.fixture_release_binary(goos, goarch, binary)
                            info = tarfile.TarInfo(binary)
                            info.size = len(body)
                            info.mode = mode_overrides.get((goos, goarch), 0o755)
                            archive.addfile(info, __import__("io").BytesIO(body))

    def write_schema_assets(self, dist: Path, identity: bytes) -> None:
        release = json.loads(identity)
        version = release["release"]["version"]
        catalog = dist / f"agent-egress-bench_{version}_schema-catalog.json"
        subprocess.run(
            [
                sys.executable,
                str(self.root / "scripts/write_schema_catalog.py"),
                "--release",
                release["release"]["tag"],
                "--output",
                str(catalog),
            ],
            check=True,
        )
        self.invoke(
            "schema-bundle",
            "--repo-root",
            str(self.root),
            "--identity",
            str(self.identity),
            "--catalog",
            str(catalog),
            "--dist",
            str(dist),
        )
        self.invoke(
            "release-notes",
            "--identity",
            str(self.identity),
            "--catalog",
            str(catalog),
            "--output",
            str(dist / "release-notes.md"),
        )

    def forge_release(self, identity: dict) -> Path:
        release = Path(self.temp.name) / "fakerel"
        shutil.rmtree(release, ignore_errors=True)
        release.mkdir()
        identity_bytes = json.dumps(identity, sort_keys=True).encode("utf-8")
        identity_path = release / "release-identity.json"
        identity_path.write_bytes(identity_bytes)
        data_name = f"agent-egress-bench_{identity['release']['version']}_data.tar.gz"
        with tarfile.open(release / data_name, "w:gz") as archive:
            info = tarfile.TarInfo("release-identity.json")
            info.size = len(identity_bytes)
            archive.addfile(info, io.BytesIO(identity_bytes))
        assets = [identity_path, release / data_name]
        (release / "checksums.txt").write_text(
            "\n".join(f"{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}" for asset in assets) + "\n",
            encoding="utf-8",
        )
        return release

    def assert_forged_release_refused(self, identity: dict, message: str) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(self.forge_release(identity))],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_contract_source_disagreement_fails_before_identity_exists(self) -> None:
        contracts = self.root / "contracts/artifacts.json"
        data = json.loads(contracts.read_text(encoding="utf-8"))
        data["artifact_families"][0]["active_writer_version"] = 99
        contracts.write_text(json.dumps(data), encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "contracts/artifacts.json"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "broken contract"], check=True)
        broken_commit = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", f"1.0.0-SNAPSHOT-{self.git_short(broken_commit)}", "--commit", broken_commit, "--snapshot", "--output", str(self.identity)],
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("declares v99", result.stderr)
        self.assertFalse(self.identity.exists())

    def test_identity_rejects_changed_schema_bytes(self) -> None:
        self.prepare()
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        identity["schema_contract"]["families"][0]["schema_sha256"] = "0" * 64
        self.identity.write_text(json.dumps(identity), encoding="utf-8")
        result = subprocess.run([sys.executable, str(SCRIPT), "check-identity", "--repo-root", str(self.root), "--identity", str(self.identity)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema_contract.families[0] digest disagrees with data_files", result.stderr)

    def test_identity_carries_result_pointer_validator_and_schema_engine(self) -> None:
        self.prepare()
        data_files = json.loads(self.identity.read_text(encoding="utf-8"))["data_files"]
        self.assertTrue(
            {"scripts/artifact_schema.py", "scripts/validate_result_pointers.py"}.issubset(data_files)
        )
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        extracted = self.root / "pointer-validator"
        extracted.mkdir()
        with tarfile.open(next(dist.glob("*_data.tar.gz")), "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        pointers_root = extracted / "result-pointers"
        if pointers_root.exists():
            shutil.rmtree(pointers_root)
        pointers_root.mkdir()
        (pointers_root / "README.md").write_text(
            "Listing is not approval.\n",
            encoding="utf-8",
        )
        (pointers_root / "index.json").write_text(
            json.dumps(
                {"schema_version": 1, "listed_is_not_approved": True, "entries": []},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [sys.executable, str(extracted / "scripts/validate_result_pointers.py")],
            cwd=extracted,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout.strip(), "validate-result-pointers: 0 pointer(s)")

    def test_identity_rejects_changed_corpus_version(self) -> None:
        self.prepare()
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        identity["corpus"]["version"] = "v999.0.0"
        self.identity.write_text(json.dumps(identity), encoding="utf-8")
        result = subprocess.run([sys.executable, str(SCRIPT), "check-identity", "--repo-root", str(self.root), "--identity", str(self.identity)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disagrees with the checked-out source tree", result.stderr)

    def test_identity_reads_compiled_runner_metadata_not_comments(self) -> None:
        summary = self.root / "runner/summary.go"
        summary.write_text('// corpusVersion = "v999.0.0"\n' + summary.read_text(encoding="utf-8"), encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "runner/summary.go"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "commented version"], check=True)
        commit = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        identity = self.root / ".release/comment-identity.json"
        version = f"1.0.0-SNAPSHOT-{self.git_short(commit)}"
        self.invoke("prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", version, "--commit", commit, "--snapshot", "--output", str(identity))
        self.assertEqual("v2.4.0", json.loads(identity.read_text(encoding="utf-8"))["corpus"]["version"])

    def test_snapshot_version_uses_the_configured_goreleaser_template(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "tag", "-a", "v1.1.0-snaptest", "-m", "snapshot base", self.commit], check=True)
        result = self.invoke("snapshot-version", "--repo-root", str(self.root), "--commit", self.commit)
        self.assertEqual(f"1.1.0-snaptest-SNAPSHOT-{self.git_short(self.commit)}", result.stdout.strip())

    def test_snapshot_version_matches_gits_configured_abbreviation(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "config", "core.abbrev", "12"], check=True)
        result = self.invoke("snapshot-version", "--repo-root", str(self.root), "--commit", self.commit)
        self.assertEqual(f"1.0.0-SNAPSHOT-{self.commit[:12]}", result.stdout.strip())

    def test_snapshot_identity_rejects_a_nonproducer_abbreviation(self) -> None:
        produced = self.git_short(self.commit)
        wrong_length = 8 if len(produced) == 7 else 7
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "prepare",
                "--repo-root",
                str(self.root),
                "--tag",
                "snapshot",
                "--version",
                f"1.0.0-SNAPSHOT-{self.commit[:wrong_length]}",
                "--commit",
                self.commit,
                "--snapshot",
                "--output",
                str(self.identity),
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot identity must use tag snapshot", result.stderr)
        self.assertFalse(self.identity.exists())

    def test_snapshot_version_rejects_an_unsupported_goreleaser_template(self) -> None:
        config = self.root / ".goreleaser.yaml"
        config.write_text(config.read_text(encoding="utf-8").replace("{{ .ShortCommit }}", "{{ .Tag }}", 1), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "snapshot-version", "--repo-root", str(self.root), "--commit", self.commit],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("snapshot.version_template uses an unsupported value", result.stderr)

    def test_release_shell_uses_goreleaser_snapshot_version(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "tag", "-a", "v1.1.0-snaptest", "-m", "snapshot base", self.commit], check=True)
        expected = f"1.1.0-snaptest-SNAPSHOT-{self.git_short(self.commit)}"
        fake_bin = Path(self.temp.name) / "bin"
        fake_bin.mkdir()
        fake = fake_bin / "goreleaser"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import sys\n"
            "identity = json.load(open('.release/release-identity.json', encoding='utf-8'))\n"
            f"expected = {expected!r}\n"
            "if identity['release']['version'] != expected:\n"
            "    print('snapshot identity version did not come from GoReleaser configuration', file=sys.stderr)\n"
            "    raise SystemExit(64)\n"
            "print('snapshot identity version came from GoReleaser configuration', file=sys.stderr)\n"
            "raise SystemExit(23)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        result = subprocess.run(
            ["bash", str(self.root / "scripts/release-build.sh"), "--tag", "snapshot", "--commit", self.commit, "--snapshot"],
            cwd=self.root,
            text=True,
            capture_output=True,
            env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
        )
        self.assertEqual(result.returncode, 23, msg=result.stderr)
        self.assertIn("snapshot identity version came from GoReleaser configuration", result.stderr)

    def test_release_shell_peels_an_annotated_tag_object_for_a_tagged_build(self) -> None:
        tag_object = subprocess.run(["git", "-C", str(self.root), "rev-parse", "v1.0.0"], check=True, text=True, capture_output=True).stdout.strip()
        fake_bin = Path(self.temp.name) / "bin"
        fake_bin.mkdir()
        fake = fake_bin / "goreleaser"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import sys\n"
            "identity = json.load(open('.release/release-identity.json', encoding='utf-8'))\n"
            f"expected = {self.commit!r}\n"
            "if identity['release']['tag'] != 'v1.0.0' or identity['source']['commit'] != expected:\n"
            "    print('tag object was not peeled to the tagged commit', file=sys.stderr)\n"
            "    raise SystemExit(64)\n"
            "print('tag object was peeled to the tagged commit', file=sys.stderr)\n"
            "raise SystemExit(23)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        result = subprocess.run(
            ["bash", str(self.root / "scripts/release-build.sh"), "--tag", "v1.0.0", "--commit", tag_object],
            cwd=self.root,
            text=True,
            capture_output=True,
            env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
        )
        self.assertEqual(result.returncode, 23, msg=result.stderr)
        self.assertIn("tag object was peeled to the tagged commit", result.stderr)

    def test_identity_rejects_untracked_release_input(self) -> None:
        (self.root / "cases/untracked-release-input.txt").write_text("not in the commit\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked or untracked changes", result.stderr)

    def test_identity_rejects_untracked_runner_source(self) -> None:
        (self.root / "runner/untracked_release_override.go").write_text("package main\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked or untracked changes", result.stderr)

    def test_identity_rejects_ignored_runner_build_input(self) -> None:
        path = self.root / "runner/ignored_release_override.go"
        path.write_text("package main\n\nfunc init() { releaseVersion += \"\" }\n", encoding="utf-8")
        exclude = self.root / ".git/info/exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        exclude.write_text((exclude.read_text(encoding="utf-8") if exclude.exists() else "") + "runner/ignored_release_override.go\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ignored runner build inputs", result.stderr)

    def test_identity_rejects_ignored_untracked_release_data(self) -> None:
        (self.root / "cases/untracked-release-input.pyc").write_bytes(b"not in the commit\n")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release data differs from the tracked source tree", result.stderr)

    def test_identity_reports_absent_git(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
            env={**os.environ, "PATH": "/nonexistent"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release verification failed: git rev-parse HEAD failed", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_download_verifier_rejects_tampered_checksum_artifact(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        self.invoke("verify", "--release-dir", str(dist))
        data_bundle = next(dist.glob("*_data.tar.gz"))
        data_bundle.write_bytes(data_bundle.read_bytes() + b"tampered")
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum mismatch", result.stderr)

    def test_release_checksums_bind_the_published_runner_image_identity(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        image_identity = dist / "runner-image.ref"
        image_identity.write_text(f"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:{'a' * 64}\n", encoding="utf-8")
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        checksums = (dist / "checksums.txt").read_text(encoding="utf-8")
        self.assertIn(f"{hashlib.sha256(image_identity.read_bytes()).hexdigest()}  runner-image.ref", checksums)
        self.invoke("verify", "--release-dir", str(dist))

    def test_release_verifier_rejects_a_noncanonical_runner_image_identity(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        (dist / "runner-image.ref").write_text(f"registry.invalid/runner@sha256:{'a' * 64}\n", encoding="utf-8")
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("runner-image.ref is not the canonical published image reference", result.stderr)

    def test_release_binds_citation_metadata_into_the_data_bundle_and_checksums(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        self.assertEqual(
            hashlib.sha256((self.root / "CITATION.cff").read_bytes()).hexdigest(),
            identity["data_files"]["CITATION.cff"],
        )
        data_bundle = next(dist.glob("*_data.tar.gz"))
        with tarfile.open(data_bundle, "r:gz") as archive:
            citation = archive.extractfile("CITATION.cff")
            self.assertIsNotNone(citation)
            assert citation is not None
            self.assertEqual((self.root / "CITATION.cff").read_bytes(), citation.read())
        self.write_runner_archives(dist, self.identity.read_bytes(), identity)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        checksums = {
            name: digest
            for digest, name in (
                line.split("  ", 1)
                for line in (dist / "checksums.txt").read_text(encoding="utf-8").splitlines()
            )
        }
        self.assertIn(data_bundle.name, checksums)
        self.assertEqual(hashlib.sha256(data_bundle.read_bytes()).hexdigest(), checksums[data_bundle.name])
        self.invoke("verify", "--release-dir", str(dist))

    def test_data_bundle_alone_can_drive_a_run(self) -> None:
        # The release advertises a corpus an operator can run. --profile is
        # mandatory, so a bundle that carries cases but no tool profile ships a
        # corpus nobody outside this repository can execute. Asserting the file
        # is present would pass for a template the runner rejects, so this runs
        # the real runner against the extracted bundle and nothing else.
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        extracted = self.root / "extracted"
        extracted.mkdir()
        with tarfile.open(next(dist.glob("*_data.tar.gz")), "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        profile = extracted / "examples/runner-template/tool-profile-template.json"
        self.assertTrue(profile.is_file(), "the data bundle must carry a tool profile the runner accepts")
        for relative in (
            "docs/RESULTS-USE.md",
            "examples/operator-kit/README.md",
            "examples/operator-kit/evidence-custody-checklist.md",
            "examples/operator-kit/report-template.md",
        ):
            self.assertTrue(
                (extracted / relative).is_file(),
                f"the data bundle must carry {relative}",
            )
        summary = self.root / "bundle-run-summary.json"
        # /tmp is quota-constrained on the development hosts, so every Go
        # command runs against the shared caches rather than filling it.
        go_env = dict(os.environ)
        for name, value in (("TMPDIR", Path.home() / ".cache/pipelock-tmp"), ("GOCACHE", Path.home() / ".cache/go-build")):
            value.mkdir(parents=True, exist_ok=True)
            go_env[name] = str(value)
        run = subprocess.run(
            ["go", "run", ".", "--cases", str(extracted / "cases"), "--profile", str(profile), "--output", str(summary)],
            cwd=self.root / "runner",
            text=True,
            capture_output=True,
            env=go_env,
        )
        self.assertEqual(run.returncode, 0, msg=run.stderr)
        self.assertTrue(summary.is_file(), "a run driven by the bundle must write its summary")
        self.assertEqual(json.loads(summary.read_text(encoding="utf-8"))["tool"], json.loads(profile.read_text(encoding="utf-8"))["tool"])

    def test_extracted_data_bundle_carries_a_runnable_offline_doctor(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke(
            "data-bundle",
            "--repo-root", str(self.root),
            "--identity", str(self.identity),
            "--dist", str(dist),
        )
        extracted = self.root / "operator-kit"
        extracted.mkdir()
        with tarfile.open(next(dist.glob("*_data.tar.gz")), "r:gz") as archive:
            archive.extractall(extracted, filter="data")
        doctor = extracted / "scripts/run-oci-action.sh"
        self.assertTrue(doctor.stat().st_mode & 0o111, "the released operator command must be executable")
        bin_dir = self.root / "doctor-bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text("#!/bin/sh\n[ \"$1 $2\" = \"image inspect\" ]\n", encoding="utf-8")
        docker.chmod(0o755)
        image = f"registry.invalid/reviewed/runner@sha256:{'a' * 64}"
        result = subprocess.run(
            [
                str(doctor),
                "--profile", "examples/runner-template/tool-profile-template.json",
                "--adapter", "dryrun",
                "--image", image,
                "--allow-unverified-image",
                "--doctor-json",
            ],
            cwd=extracted,
            env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
            text=True,
            capture_output=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        doctor_report = json.loads(result.stdout)
        self.assertTrue(doctor_report["ready"])
        self.assertFalse(doctor_report["publisher_verified"])
        publisher_check = next(check for check in doctor_report["checks"] if check["code"] == "publisher_material")
        self.assertEqual("waived", publisher_check["status"])
        self.assertFalse((extracted / "aeb-results").exists())

    def test_release_binds_a_schema_bundle_to_the_commit_pinned_catalog(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        self.write_runner_archives(dist, self.identity.read_bytes(), identity)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        self.invoke("verify", "--release-dir", str(dist))

        catalog_path = next(dist.glob("*_schema-catalog.json"))
        bundle_path = next(dist.glob("*_schemas.tar.gz"))
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        self.assertEqual(self.commit, catalog["source_commit"])
        self.assertEqual("snapshot", catalog["release"])
        with tarfile.open(bundle_path, "r:gz") as archive:
            contents = {
                entry.name: archive.extractfile(entry).read()
                for entry in archive.getmembers()
                if entry.isfile()
            }
        self.assertEqual(catalog_path.read_bytes(), contents["schemas/index.json"])
        self.assertEqual(
            {"schemas/index.json", *(entry["path"] for entry in catalog["schemas"])},
            set(contents),
        )
        for entry in catalog["schemas"]:
            self.assertEqual(
                f"https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/{self.commit}/{entry['path']}",
                entry["retrieval_url"],
            )
            self.assertEqual(entry["sha256"], hashlib.sha256(contents[entry["path"]]).hexdigest())

    def test_download_verifier_rejects_a_release_without_schema_bundle(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        next(dist.glob("*_schemas.tar.gz")).unlink()
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing its data bundle, schema artifacts, or declared runner platforms", result.stderr)

    def test_download_verifier_rejects_schema_bytes_changed_after_rechecksum(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        bundle_path = next(dist.glob("*_schemas.tar.gz"))
        catalog = json.loads(next(dist.glob("*_schema-catalog.json")).read_text(encoding="utf-8"))
        changed_path = catalog["schemas"][0]["path"]
        with tarfile.open(bundle_path, "r:gz") as archive:
            contents = {
                entry.name: archive.extractfile(entry).read()
                for entry in archive.getmembers()
                if entry.isfile()
            }
        contents[changed_path] += b"\n"
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name, data in sorted(contents.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema bundle digest does not match release catalog", result.stderr)

    def test_download_verifier_rejects_a_substituted_schema_identity(self) -> None:
        # A digest proves the bytes and says nothing about the name they are
        # published under. With the catalog $id substituted, every other signal
        # still reads green: the paths resolve, the digests match the real
        # schemas, and the checksums are regenerated over the altered catalog.
        # An offline consumer would register correct bytes under the wrong
        # identity and validate against a contract it never chose.
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))

        catalog_path = next(dist.glob("*_schema-catalog.json"))
        bundle_path = next(dist.glob("*_schemas.tar.gz"))
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["schemas"][0]["$id"] = "https://example.invalid/schemas/substituted-v1.schema.json"
        catalog_bytes = (json.dumps(catalog, indent=2) + "\n").encode("utf-8")
        catalog_path.write_bytes(catalog_bytes)

        # Repack the bundle so its embedded catalog copy agrees with the asset,
        # leaving the digest and file-list checks satisfied.
        with tarfile.open(bundle_path, "r:gz") as archive:
            contents = {
                entry.name: archive.extractfile(entry).read()
                for entry in archive.getmembers()
                if entry.isfile()
            }
        contents["schemas/index.json"] = catalog_bytes
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name, data in sorted(contents.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, "a substituted schema identity verified clean")
        self.assertIn("declares an $id the release catalog does not name", result.stderr)

    def test_repo_backed_verifier_rejects_regenerated_schema_content(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))

        catalog_path = next(dist.glob("*_schema-catalog.json"))
        bundle_path = next(dist.glob("*_schemas.tar.gz"))
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        changed = catalog["schemas"][0]
        with tarfile.open(bundle_path, "r:gz") as archive:
            contents = {
                entry.name: archive.extractfile(entry).read()
                for entry in archive.getmembers()
                if entry.isfile()
            }
        schema = json.loads(contents[changed["path"]])
        schema["description"] = "release-only schema mutation"
        changed_bytes = (json.dumps(schema, indent=2) + "\n").encode("utf-8")
        contents[changed["path"]] = changed_bytes
        changed["sha256"] = hashlib.sha256(changed_bytes).hexdigest()
        catalog_bytes = (json.dumps(catalog, indent=2) + "\n").encode("utf-8")
        catalog_path.write_bytes(catalog_bytes)
        contents["schemas/index.json"] = catalog_bytes
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name, data in sorted(contents.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))

        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist), "--repo-root", str(self.root)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0, "regenerated schema content verified clean")
        self.assertIn("release schema content does not match the supplied source tree", result.stderr)

    def test_repo_backed_verifier_allows_catalog_serialization_and_tar_metadata_changes(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))

        catalog_path = next(dist.glob("*_schema-catalog.json"))
        bundle_path = next(dist.glob("*_schemas.tar.gz"))
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        catalog["schemas"].reverse()
        catalog_bytes = json.dumps(catalog, separators=(",", ":"), sort_keys=True).encode("utf-8")
        catalog_path.write_bytes(catalog_bytes)
        with tarfile.open(bundle_path, "r:gz") as archive:
            contents = {
                entry.name: archive.extractfile(entry).read()
                for entry in archive.getmembers()
                if entry.isfile()
            }
        contents["schemas/index.json"] = catalog_bytes
        with tarfile.open(bundle_path, "w:gz") as archive:
            for name, data in reversed(sorted(contents.items())):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(data))

        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        self.invoke("verify", "--release-dir", str(dist), "--repo-root", str(self.root))

    def test_repo_backed_verifier_allows_a_release_rebuilt_from_the_same_schema_surface(self) -> None:
        schema = self.root / "schemas/repo-backed-test-v1.schema.json"
        schema.write_text(
            json.dumps(
                {
                    "$schema": "https://json-schema.org/draft/2020-12/schema",
                    "$id": "https://example.invalid/schemas/repo-backed-test-v1.schema.json",
                    "type": "object",
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        subprocess.run([sys.executable, str(self.root / "scripts/write_schema_catalog.py")], cwd=self.root, check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "schemas/index.json", str(schema.relative_to(self.root))], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "add schema fixture"], check=True)
        self.commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        self.snapshot_version = f"1.0.0-SNAPSHOT-{self.git_short(self.commit)}"

        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        self.invoke("verify", "--release-dir", str(dist), "--repo-root", str(self.root))

    def test_repo_backed_verifier_rejects_partial_or_unreadable_schema_source(self) -> None:
        for failure in ("missing", "invalid JSON"):
            with self.subTest(failure=failure):
                self.prepare()
                dist = self.root / "dist"
                self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
                identity = self.identity.read_bytes()
                self.write_runner_archives(dist, identity, json.loads(identity))
                self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
                schema = self.root / "schemas/case-v4.schema.json"
                original = schema.read_bytes()
                if failure == "missing":
                    schema.unlink()
                    expected = "release schema paths do not match the supplied source tree"
                else:
                    schema.write_text("{", encoding="utf-8")
                    expected = "cannot re-derive the supplied source tree schema catalog"
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist), "--repo-root", str(self.root)],
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(result.returncode, 0, f"{failure} schema source verified clean")
                self.assertIn(expected, result.stderr)
                schema.write_bytes(original)
                shutil.rmtree(dist)
                self.identity.unlink()

    def test_download_verifier_runs_from_the_documented_extract_layout(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))

        downloaded = Path(self.temp.name) / "aeb-release"
        downloaded.mkdir()
        for asset in dist.iterdir():
            shutil.copyfile(asset, downloaded / asset.name)
        data_bundle = next(downloaded.glob("*_data.tar.gz"))
        extracted = downloaded / "extracted"
        extracted.mkdir()
        subprocess.run(["tar", "-xzf", str(data_bundle), "-C", str(extracted)], check=True)

        result = subprocess.run(
            [sys.executable, str(extracted / "scripts/release_build.py"), "verify", "--release-dir", ".."],
            cwd=extracted,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)

    def test_download_verifier_rejects_a_forged_empty_release(self) -> None:
        self.prepare()
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        identity["release"] = {"tag": "v9.9.9", "version": "9.9.9", "snapshot": False}
        identity["source"] = {"repository": "luckyPipewrench/agent-egress-bench", "commit": "0" * 40, "commit_timestamp": 1}
        identity["runner"]["platforms"] = []
        identity["data_files"] = {}
        self.assert_forged_release_refused(identity, "runner.platforms must contain the exact supported platform matrix")

    def test_download_verifier_rejects_absent_corpus_metadata(self) -> None:
        self.prepare()
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        del identity["corpus"]
        self.assert_forged_release_refused(identity, "release identity must contain exactly")

    def test_download_verifier_rejects_method_independence_downgrades(self) -> None:
        self.prepare()
        mutations = {
            "shared ownership": ("shared_target_vendor_ownership", True),
            "proprietary verifier": ("proprietary_verifier_required", True),
            "vendor registry": ("mandatory_vendor_registry", "registry.vendor.example"),
            "mandatory chain": ("mandatory_transparency_chain", "chain.vendor.example"),
            "lab branding": ("lab_branding_control", "method-owner"),
            "lab scheduling": ("lab_scheduling_control", "method-owner"),
        }
        original = json.loads(self.identity.read_text(encoding="utf-8"))
        for label, (field, value) in mutations.items():
            with self.subTest(label=label):
                identity = json.loads(json.dumps(original))
                identity["method_independence"][field] = value
                self.assert_forged_release_refused(identity, "method-independence invariants are invalid")

    def test_download_verifier_rejects_method_contract_digest_disagreement(self) -> None:
        self.prepare()
        identity = json.loads(self.identity.read_text(encoding="utf-8"))
        identity["method_independence"]["contract_sha256"] = "a" * 64
        self.assert_forged_release_refused(identity, "contract digest disagrees with data_files")

    def test_download_verifier_rejects_release_contract_digest_disagreements(self) -> None:
        self.prepare()
        original = json.loads(self.identity.read_text(encoding="utf-8"))
        last_family = len(original["schema_contract"]["families"]) - 1
        mutations = (
            (
                "corpus manifest",
                lambda identity: identity["corpus"].__setitem__("manifest_sha256", "a" * 64),
                "corpus manifest digest disagrees with data_files",
            ),
            (
                "corpus manifest data file",
                lambda identity: identity["data_files"].__setitem__(identity["corpus"]["manifest_path"], "a" * 64),
                "corpus manifest digest disagrees with data_files",
            ),
            (
                "artifacts manifest",
                lambda identity: identity["schema_contract"].__setitem__("artifacts_manifest_sha256", "a" * 64),
                "artifacts manifest digest disagrees with data_files",
            ),
            (
                "artifacts manifest data file",
                lambda identity: identity["data_files"].__setitem__(identity["schema_contract"]["artifacts_manifest_path"], "a" * 64),
                "artifacts manifest digest disagrees with data_files",
            ),
            (
                "active schema",
                lambda identity: identity["schema_contract"]["families"][last_family].__setitem__("schema_sha256", "a" * 64),
                f"schema_contract.families[{last_family}] digest disagrees with data_files",
            ),
            (
                "active schema data file",
                lambda identity: identity["data_files"].__setitem__(identity["schema_contract"]["families"][last_family]["schema_path"], "a" * 64),
                f"schema_contract.families[{last_family}] digest disagrees with data_files",
            ),
        )
        for label, mutate, message in mutations:
            with self.subTest(label=label):
                identity = json.loads(json.dumps(original))
                mutate(identity)
                self.assert_forged_release_refused(identity, message)

    def test_identity_rejects_a_vendor_owned_method_contract(self) -> None:
        contract_path = self.root / "contracts/method-independence-v1.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["shared_target_vendor_ownership"] = True
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "contracts/method-independence-v1.json"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "vendor-owned method"], check=True)
        broken_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root),
                "--tag", "snapshot", "--version", f"1.0.0-SNAPSHOT-{self.git_short(broken_commit)}",
                "--commit", broken_commit, "--snapshot", "--output", str(self.identity),
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not preserve the public release invariants", result.stderr)
        self.assertFalse(self.identity.exists())

    def test_identity_rejects_duplicate_method_contract_keys(self) -> None:
        contract_path = self.root / "contracts/method-independence-v1.json"
        contract = contract_path.read_text(encoding="utf-8").replace(
            '  "shared_target_vendor_ownership": false,',
            '  "shared_target_vendor_ownership": true,\n  "shared_target_vendor_ownership": false,',
        )
        contract_path.write_text(contract, encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "contracts/method-independence-v1.json"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "duplicate ownership key"], check=True)
        broken_commit = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root),
                "--tag", "snapshot", "--version", f"1.0.0-SNAPSHOT-{self.git_short(broken_commit)}",
                "--commit", broken_commit, "--snapshot", "--output", str(self.identity),
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contains duplicate key 'shared_target_vendor_ownership'", result.stderr)
        self.assertFalse(self.identity.exists())

    def test_download_verifier_rejects_truncated_identity(self) -> None:
        self.assert_forged_release_refused({"schema_version": 1, "release": {"tag": "v9.9.9", "version": "9.9.9", "snapshot": False}}, "release identity must contain exactly")

    def test_download_verifier_rejects_archive_without_runner_binary(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release, include_binaries=False)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain exactly one aeb-gauntlet", result.stderr)

    def test_download_verifier_rejects_an_executable_that_is_not_in_the_release(self) -> None:
        # --executable and --validator-executable used to accept any file that
        # printed the expected identity line, so pointing one at an unrelated
        # program made an archive report as verified while saying nothing about
        # the archive. The file handed over must be the same bytes as that
        # binary inside a release archive, checked before it is run.
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        stranger = self.root / "stranger"
        stranger.write_bytes(self.fixture_release_binary("linux", "amd64", "aeb-validate") + b"stranger")
        stranger.chmod(0o755)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist), "--validator-executable", str(stranger)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not the aeb-validate in any release archive", result.stderr)

    def test_download_verifier_rejects_one_program_under_both_binary_names(self) -> None:
        # Name, executable mode, and machine type are all satisfied by the wrong
        # program under the right name. Replacing the validator with a second
        # copy of the runner passed every one of them, so the release reported
        # itself intact while shipping no way to check a result. A GoReleaser
        # build pointed at one directory twice produces the same archive.
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        same = {(platform["goos"], platform["goarch"]): self.fixture_runner_binary(platform["goos"], platform["goarch"]) for platform in release["runner"]["platforms"]}
        self.write_runner_archives(dist, identity, release, binary_overrides=same)
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("carries the same program under more than one release binary name", result.stderr)

    def test_download_verifier_rejects_an_archive_without_the_validator(self) -> None:
        # The release advertises a runner and a result validator in one archive.
        # A verifier that stopped at the runner would publish a package that
        # could produce results and could not check them, and the omission would
        # surface only when an operator tried to check somebody else's run.
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release, binaries=("aeb-gauntlet",))
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain exactly one aeb-validate", result.stderr)

    def test_download_verifier_rejects_a_text_runner_binary(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release, binary_overrides={("linux", "amd64"): b"fixture runner"})
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain a 64-bit Linux amd64 ELF aeb-gauntlet", result.stderr)

    def test_download_verifier_rejects_a_non_executable_runner_binary(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release, mode_overrides={("linux", "amd64"): 0o644})
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must mark its linux amd64 aeb-gauntlet executable", result.stderr)

    def test_download_verifier_rejects_a_wrong_platform_runner_binary(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        release = json.loads(identity)
        self.write_runner_archives(dist, identity, release, binary_overrides={("linux", "amd64"): self.fixture_runner_binary("linux", "arm64")})
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must contain a 64-bit Linux amd64 ELF aeb-gauntlet", result.stderr)

    def test_download_verifier_rejects_an_unstamped_executable(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        identity = self.identity.read_bytes()
        self.write_runner_archives(dist, identity, json.loads(identity))
        self.invoke("checksums", "--identity", str(self.identity), "--dist", str(dist))
        executable = Path(self.temp.name) / "aeb-gauntlet"
        executable.write_text("#!/usr/bin/env bash\nprintf 'aeb-gauntlet devel unknown\\n'\n", encoding="utf-8")
        executable.chmod(0o755)
        result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(dist), "--executable", str(executable)], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        # The digest gate now runs first and rejects this before it is executed,
        # which is the stronger of the two refusals: a stand-in that printed the
        # correct version used to pass. The version comparison itself is only
        # reachable once the bytes match a release archive, so it is exercised
        # directly below rather than through an archive fixture that would have
        # to embed a runnable program.
        self.assertIn("aeb-gauntlet executable is not the aeb-gauntlet in any release archive", result.stderr)

    def test_version_mismatch_is_rejected_once_the_executable_matches_the_release(self) -> None:
        # Reached when the supplied file IS a release archive member but reports
        # a different release than the identity records, which is what a binary
        # built from another commit looks like.
        module = self.release_build_module()
        executable = Path(self.temp.name) / "aeb-gauntlet"
        executable.write_text("#!/usr/bin/env bash\nprintf 'aeb-gauntlet 9.9.9 " + "0" * 40 + "\\n'\n", encoding="utf-8")
        executable.chmod(0o755)
        identity = {"release": {"version": "1.2.3"}, "source": {"commit": "a" * 40}}
        digests = {"aeb-gauntlet": {hashlib.sha256(executable.read_bytes()).hexdigest()}}
        with self.assertRaises(module.ReleaseError) as caught:
            module.verify_executable_identity(executable, "aeb-gauntlet", identity, digests)
        self.assertIn("version output does not match release identity", str(caught.exception))

    def test_version_output_is_read_under_a_bound(self) -> None:
        # A downloaded binary that never stops printing used to be read without
        # a limit, so verifying a release could exhaust the memory of the
        # machine doing the verifying.
        module = self.release_build_module()
        executable = Path(self.temp.name) / "aeb-gauntlet"
        executable.write_text("#!/usr/bin/env bash\nwhile :; do printf 'aaaaaaaaaaaaaaaa'; done\n", encoding="utf-8")
        executable.chmod(0o755)
        with self.assertRaises(module.ReleaseError):
            module.run_bounded_version(executable, "aeb-gauntlet")

    def test_version_read_is_bounded_when_a_descendant_holds_the_pipe(self) -> None:
        # A size cap alone was not enough. A binary that printed a few bytes and
        # then slept never reached the cap and never closed the pipe, so the
        # read waited and the timeout was never consulted. Killing only the
        # binary did not help either, because its child inherits the pipe and
        # holds it open. Measured both ways: each hung until killed.
        module = self.release_build_module()
        executable = Path(self.temp.name) / "aeb-gauntlet"
        executable.write_text("#!/usr/bin/env bash\nprintf 'aeb-gauntlet 1.0.0 '\nsleep 600\n", encoding="utf-8")
        executable.chmod(0o755)
        original = module.VERSION_READ_TIMEOUT_SECONDS
        module.VERSION_READ_TIMEOUT_SECONDS = 3
        try:
            started = time.monotonic()
            with self.assertRaises(module.ReleaseError):
                module.run_bounded_version(executable, "aeb-gauntlet")
            self.assertLess(time.monotonic() - started, 30, "the read was not bounded in time")
        finally:
            module.VERSION_READ_TIMEOUT_SECONDS = original

    def test_process_group_termination_is_defined_for_both_platforms(self) -> None:
        # The watchdog runs in a thread, so anything it raises is lost and the
        # read it exists to bound waits forever. os.killpg does not exist on
        # Windows at all, so the POSIX-only version raised AttributeError there
        # and left the verifier hanging on exactly the input the bound was
        # added for. Both spellings are checked here because CI runs on Linux
        # and would never execute the Windows path.
        module = self.release_build_module()
        self.assertIn("start_new_session", module.process_group_options())
        original = module.os.name
        try:
            module.os.name = "nt"
            self.assertIn("creationflags", module.process_group_options())
        finally:
            module.os.name = original

        class NeverDies:
            pid = -1

            def __init__(self) -> None:
                self.killed = False

            def kill(self) -> None:
                self.killed = True

        # A pid that cannot be signalled stands in for every way the platform
        # call can fail. The contract is that the process still gets killed and
        # nothing propagates out of the watchdog thread.
        stand_in = NeverDies()
        module.kill_process_group(stand_in)
        self.assertTrue(stand_in.killed, "the fallback kill must still run when the group call fails")

        # The Windows branch never runs on this CI, so assert the call it makes
        # rather than the effect. Without this the branch could be deleted and
        # every test here would still pass, which is how the POSIX-only version
        # shipped in the first place.
        calls = []
        original_run = module.subprocess.run
        module.os.name = "nt"
        module.subprocess.run = lambda *args, **kwargs: calls.append(args[0])
        try:
            module.kill_process_group(NeverDies())
        finally:
            module.subprocess.run = original_run
            module.os.name = original
        self.assertEqual(len(calls), 1, "the Windows path must terminate the tree")
        self.assertEqual(calls[0][:4], ["taskkill", "/F", "/T", "/PID"])

    def release_build_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_build_under_test", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_checksums_reports_an_absent_distribution_directory(self) -> None:
        self.prepare()
        missing = self.root / "missing-dist"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "checksums", "--identity", str(self.identity), "--dist", str(missing)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release verification failed: release distribution directory is absent", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_data_bundle_is_reproducible_for_one_identity(self) -> None:
        self.prepare()
        dist = self.root / "dist"
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        bundle = next(dist.glob("*_data.tar.gz"))
        first = bundle.read_bytes()
        bundle.unlink()
        self.invoke("data-bundle", "--repo-root", str(self.root), "--identity", str(self.identity), "--dist", str(dist))
        self.assertEqual(first, next(dist.glob("*_data.tar.gz")).read_bytes())

    def test_release_shell_rejects_unsafe_dist_before_cleanup(self) -> None:
        sentinel = Path(self.temp.name) / "do-not-delete"
        sentinel.mkdir()
        result = subprocess.run(
            ["bash", str(self.root / "scripts/release-build.sh"), "--tag", "snapshot", "--commit", self.commit, "--snapshot", "--dist", str(sentinel)],
            cwd=self.root,
            text=True,
            capture_output=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertTrue(sentinel.is_dir())
        self.assertIn("only the configured dist directory", result.stderr)

    def test_release_shell_reports_missing_option_values(self) -> None:
        for option in ("--tag", "--commit", "--dist"):
            with self.subTest(option=option):
                result = subprocess.run(
                    ["bash", str(self.root / "scripts/release-build.sh"), option],
                    cwd=self.root,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"release-build: {option} requires a value", result.stderr)

    def test_release_shell_sets_shared_go_caches(self) -> None:
        fake_bin = Path(self.temp.name) / "bin"
        fake_bin.mkdir()
        fake_go = fake_bin / "go"
        fake_go.write_text(
            "#!/usr/bin/env bash\n"
            "if [[ \"${TMPDIR:-}\" == \"$HOME/.cache/pipelock-tmp\" && \"${GOCACHE:-}\" == \"$HOME/.cache/go-build\" ]]; then\n"
            "  echo 'shared Go caches configured' >&2\n"
            "else\n"
            "  echo 'shared Go caches missing' >&2\n"
            "fi\n"
            "exit 71\n",
            encoding="utf-8",
        )
        fake_go.chmod(0o755)
        environment = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
        environment.pop("TMPDIR", None)
        environment.pop("GOCACHE", None)
        result = subprocess.run(
            ["bash", str(self.root / "scripts/release-build.sh"), "--tag", "snapshot", "--commit", self.commit, "--snapshot"],
            cwd=self.root,
            text=True,
            capture_output=True,
            env=environment,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("shared Go caches configured", result.stderr)


if __name__ == "__main__":
    unittest.main()
