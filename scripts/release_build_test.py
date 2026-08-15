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
        for name in filter(None, files):
            source, destination = REPO / name, self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "release-test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Release Test"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "core.hooksPath", "/dev/null"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "test fixture"], check=True)
        self.commit = subprocess.run(["git", "-C", str(self.root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
        subprocess.run(["git", "-C", str(self.root), "tag", "-a", "v1.0.0", "-m", "baseline", self.commit], check=True)
        self.identity = self.root / ".release/release-identity.json"
        self.snapshot_version = f"1.0.0-SNAPSHOT-{self.commit[:7]}"

    def tearDown(self) -> None:
        try:
            self.temp.cleanup()
        except OSError:
            shutil.rmtree(self.temp.name, ignore_errors=True)

    def invoke(self, *args: str, expect: int = 0) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([sys.executable, str(SCRIPT), *args], text=True, capture_output=True)
        self.assertEqual(result.returncode, expect, msg=result.stderr)
        return result

    def prepare(self) -> None:
        self.invoke(
            "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version,
            "--commit", self.commit, "--snapshot", "--output", str(self.identity),
        )

    def write_runner_archives(self, dist: Path, identity: bytes, release: dict, include_binaries: bool = True) -> None:
        for platform in release["runner"]["platforms"]:
            name = f"agent-egress-bench_{self.snapshot_version}_{platform['goos']}_{platform['goarch']}"
            if platform["goos"] == "windows":
                with zipfile.ZipFile(dist / f"{name}.zip", "w") as archive:
                    archive.writestr(".release/release-identity.json", identity)
                    if include_binaries:
                        archive.writestr("aeb-gauntlet.exe", b"fixture runner")
            else:
                with tarfile.open(dist / f"{name}.tar.gz", "w:gz") as archive:
                    info = tarfile.TarInfo(".release/release-identity.json")
                    info.size = len(identity)
                    archive.addfile(info, __import__("io").BytesIO(identity))
                    if include_binaries:
                        info = tarfile.TarInfo("aeb-gauntlet")
                        runner = b"fixture runner"
                        info.size = len(runner)
                        info.mode = 0o755
                        archive.addfile(info, __import__("io").BytesIO(runner))

    def forge_release(self, identity: dict) -> Path:
        release = Path(self.temp.name) / "fakerel"
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
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", f"1.0.0-SNAPSHOT-{broken_commit[:7]}", "--commit", broken_commit, "--snapshot", "--output", str(self.identity)],
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
        self.assertIn("disagrees with the checked-out source tree", result.stderr)

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
        version = f"1.0.0-SNAPSHOT-{commit[:7]}"
        self.invoke("prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", version, "--commit", commit, "--snapshot", "--output", str(identity))
        self.assertEqual("v2.4.0", json.loads(identity.read_text(encoding="utf-8"))["corpus"]["version"])

    def test_snapshot_version_uses_the_configured_goreleaser_template(self) -> None:
        subprocess.run(["git", "-C", str(self.root), "tag", "-a", "v1.1.0-snaptest", "-m", "snapshot base", self.commit], check=True)
        result = self.invoke("snapshot-version", "--repo-root", str(self.root), "--commit", self.commit)
        self.assertEqual(f"1.1.0-snaptest-SNAPSHOT-{self.commit[:7]}", result.stdout.strip())

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
        expected = f"1.1.0-snaptest-SNAPSHOT-{self.commit[:7]}"
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
