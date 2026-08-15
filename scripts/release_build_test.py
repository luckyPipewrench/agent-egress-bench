#!/usr/bin/env python3
"""Regression tests for the release identity and downloaded-artifact verifier."""

from __future__ import annotations

import json
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

    def test_identity_rejects_untracked_release_input(self) -> None:
        (self.root / "cases/untracked-release-input.txt").write_text("not in the commit\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "prepare", "--repo-root", str(self.root), "--tag", "snapshot", "--version", self.snapshot_version, "--commit", self.commit, "--snapshot", "--output", str(self.identity)],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tracked or untracked changes", result.stderr)

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


if __name__ == "__main__":
    unittest.main()
