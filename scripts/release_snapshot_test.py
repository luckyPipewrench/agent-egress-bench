#!/usr/bin/env python3
"""Integration coverage for the pinned GoReleaser snapshot archive layout."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/release_build.py"
PINNED_GORELEASER_VERSION = "2.17.1"


class ReleaseSnapshotTest(unittest.TestCase):
    def tearDown(self) -> None:
        shutil.rmtree(REPO / "dist", ignore_errors=True)
        shutil.rmtree(REPO / ".release", ignore_errors=True)

    def test_pinned_goreleaser_snapshot_keeps_the_nested_identity(self) -> None:
        goreleaser = shutil.which("goreleaser")
        self.assertIsNotNone(goreleaser, "pinned GoReleaser must be installed before this integration test")
        version = subprocess.run([goreleaser, "--version"], text=True, capture_output=True, check=True)
        self.assertRegex(version.stdout + version.stderr, rf"(?<![0-9.])v?{re.escape(PINNED_GORELEASER_VERSION)}(?![0-9.])")

        snapshot = subprocess.run(["make", "release-snapshot"], cwd=REPO, text=True, capture_output=True)
        self.assertEqual(snapshot.returncode, 0, msg=snapshot.stdout + snapshot.stderr)

        release_dir = REPO / "dist/release"
        verification = subprocess.run([sys.executable, str(SCRIPT), "verify", "--release-dir", str(release_dir)], text=True, capture_output=True)
        self.assertEqual(verification.returncode, 0, msg=verification.stderr)
        identity = release_dir / "release-identity.json"
        self.assertTrue(identity.is_file())
        archive = next(release_dir.glob("agent-egress-bench_*_linux_amd64.tar.gz"))
        with tarfile.open(archive, "r:gz") as bundle:
            entries = [entry for entry in bundle.getmembers() if entry.isfile()]
        self.assertEqual(
            {".release/release-identity.json", "LICENSE", "NOTICE", "aeb-gauntlet"},
            {entry.name for entry in entries},
        )


if __name__ == "__main__":
    unittest.main()
