#!/usr/bin/env python3
"""Regression tests for draft ownership and exact release asset publication."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts/release_publish.py"


class ReleasePublishFixture(unittest.TestCase):
    """Shared fixture only. Carries no test methods, so a subclass inherits the harness
    without unittest rediscovering and rerunning every parent test under the child's name.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for name in ("archive.tar.gz", "checksums.txt"):
            (self.dist / name).write_text(name, encoding="utf-8")
        sys.path.insert(0, str(SCRIPT.parent))
        import release_build

        identity = {
            "release": {"version": "1.0.0", "tag": "v1.0.0"},
            "source": {"commit": "0" * 40},
        }
        catalog = {
            "format": 1,
            "repository": f"https://github.com/{release_build.REPOSITORY}",
            "source_commit": "0" * 40,
            "release": "v1.0.0",
            "schemas": [
                {
                    "path": "schemas/fixture-v1.schema.json",
                    "$id": "https://example.invalid/fixture-v1.schema.json",
                    "sha256": "0" * 64,
                    "retrieval_url": release_build.RAW_SCHEMA_URL.format(
                        commit="0" * 40, path="schemas/fixture-v1.schema.json"
                    ),
                }
            ],
        }
        catalog_name, _ = release_build.schema_asset_names(identity)
        catalog_bytes = json.dumps(catalog).encode("utf-8")
        (self.dist / "release-identity.json").write_text(json.dumps(identity), encoding="utf-8")
        (self.dist / catalog_name).write_bytes(catalog_bytes)
        (self.dist / "release-notes.md").write_bytes(
            release_build.rendered_release_notes(identity, catalog_bytes)
        )
        self.state_path = self.root / "release.json"
        self.calls_path = self.root / "calls.json"
        self.gh = self.root / "gh"
        self.gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "state_path = Path(os.environ['MOCK_GH_STATE'])\n"
            "calls_path = Path(os.environ['MOCK_GH_CALLS'])\n"
            "state = json.loads(state_path.read_text()) if state_path.exists() else None\n"
            "calls = json.loads(calls_path.read_text()) if calls_path.exists() else []\n"
            "args = sys.argv[1:]\n"
            "calls.append(args)\n"
            "def save():\n"
            "  calls_path.write_text(json.dumps(calls))\n"
            "  if state is not None: state_path.write_text(json.dumps(state))\n"
            "if args[:2] == ['release', 'view']:\n"
            "  save()\n"
            "  if state is None:\n"
            "    print('release not found', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            "  print(json.dumps(state))\n"
            "elif args[:2] == ['release', 'create']:\n"
            "  files = [Path(item).name for item in args[3:args.index('--title')]]\n"
            "  notes = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  state = {'isDraft': True, 'body': notes, 'assets': [{'name': name} for name in files]}\n"
            "  save()\n"
            "elif args[:2] == ['release', 'upload']:\n"
            "  files = [Path(item).name for item in args[3:args.index('--clobber')]]\n"
            "  by_name = {item['name']: item for item in state['assets']}\n"
            "  by_name.update({name: {'name': name} for name in files})\n"
            "  state['assets'] = list(by_name.values())\n"
            "  save()\n"
            "elif args[:2] == ['release', 'edit']:\n"
            "  if '--notes-file' in args:\n"
            "    state['body'] = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  if '--draft=false' in args:\n"
            "    state['isDraft'] = False\n"
            "  save()\n"
            "else:\n"
            "  print('unsupported mock gh call', args, file=sys.stderr)\n"
            "  raise SystemExit(2)\n",
            encoding="utf-8",
        )
        self.gh.chmod(0o755)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_state(self, *, body: str, assets: list[str], is_draft: bool = True) -> None:
        self.state_path.write_text(json.dumps({"isDraft": is_draft, "body": body, "assets": [{"name": name} for name in assets]}), encoding="utf-8")

    def calls(self) -> list[list[str]]:
        return json.loads(self.calls_path.read_text(encoding="utf-8")) if self.calls_path.exists() else []

    def publish(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--tag", "v1.0.0", "--dist", str(self.dist), "--gh", str(self.gh)],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )


class ReleasePublishTest(ReleasePublishFixture):
    def test_missing_release_notes_is_refused_before_any_gh_call(self) -> None:
        (self.dist / "release-notes.md").unlink()
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing release-notes.md", result.stderr)
        self.assertEqual([], self.calls())

    def test_empty_release_notes_is_refused_before_any_gh_call(self) -> None:
        (self.dist / "release-notes.md").write_text("   \n", encoding="utf-8")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing release-notes.md", result.stderr)
        self.assertEqual([], self.calls())

    def test_release_notes_without_ownership_marker_is_refused(self) -> None:
        (self.dist / "release-notes.md").write_text("## Schema contracts\n", encoding="utf-8")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ownership marker", result.stderr)
        self.assertEqual([], self.calls())

    def test_release_notes_marker_matches_the_generator(self) -> None:
        # The build and publish modules each hardcode the marker. If they drift, publish refuses
        # every generated notes file, and nothing else would catch it until release day.
        sys.path.insert(0, str(SCRIPT.parent))
        import release_build
        import release_publish

        self.assertEqual(release_build.RELEASE_NOTES_MARKER, release_publish.DRAFT_MARKER)

    def test_edited_release_notes_are_refused_despite_the_marker(self) -> None:
        notes = self.dist / "release-notes.md"
        notes.write_text(notes.read_text(encoding="utf-8") + "\nan added claim\n", encoding="utf-8")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the notes generated", result.stderr)
        self.assertEqual([], self.calls())

    def test_creates_marked_draft_with_exact_assets_before_publication(self) -> None:
        result = self.publish()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertFalse(state["isDraft"])
        self.assertIn("agent-egress-bench-release-workflow-v1", state["body"])
        self.assertEqual(
            [
                "agent-egress-bench_1.0.0_schema-catalog.json",
                "archive.tar.gz",
                "checksums.txt",
                "release-identity.json",
                "release-notes.md",
            ],
            sorted(asset["name"] for asset in state["assets"]),
        )

    def test_unrelated_draft_is_refused_before_upload_or_publication(self) -> None:
        self.write_state(body="draft written elsewhere", assets=["extra.bin"])
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without the release workflow ownership marker", result.stderr)
        self.assertEqual([['release', 'view', 'v1.0.0', '--json', 'isDraft,body,assets']], self.calls())
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertTrue(state["isDraft"])
        self.assertEqual(["extra.bin"], [asset["name"] for asset in state["assets"]])

    def test_owned_draft_with_extra_asset_is_not_published(self) -> None:
        self.write_state(body="<!-- agent-egress-bench-release-workflow-v1 -->", assets=["extra.bin"])
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assets do not exactly match", result.stderr)
        self.assertFalse([call for call in self.calls() if "--draft=false" in call])
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertTrue(state["isDraft"])
        self.assertIn("extra.bin", [asset["name"] for asset in state["assets"]])


class ReleaseAssetBindingTest(ReleasePublishFixture):
    """The upload must carry the asset bytes that were validated, not a later replacement.

    `release_assets` rejects symlinks and non-files by NAME. Handing those names to gh leaves the
    real read until later, so this drives the exact window: the gh stand-in replaces the source file
    on disk and only then reads the paths it was handed.
    """

    def tampering_gh(self) -> Path:
        gh = self.root / "gh-tamper"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "seen_path = Path(os.environ['MOCK_GH_SEEN'])\n"
            "target = Path(os.environ['MOCK_GH_TAMPER_TARGET'])\n"
            "args = sys.argv[1:]\n"
            "if args[:2] == ['release', 'view']:\n"
            "  print('release not found', file=sys.stderr)\n"
            "  raise SystemExit(1)\n"
            "if args[:2] == ['release', 'create']:\n"
            # Replace the source AFTER validation ran and BEFORE this process reads what it was
            # given. A pathname argument reads the replacement; a bound descriptor does not.
            "  target.write_text('tampered', encoding='utf-8')\n"
            "  paths = args[3:args.index('--title')]\n"
            "  seen = {Path(item).name: Path(item).read_text(encoding='utf-8') for item in paths}\n"
            "  seen_path.write_text(json.dumps(seen))\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        return gh

    def test_upload_carries_validated_bytes_after_a_source_swap(self) -> None:
        seen_path = self.root / "seen.json"
        target = self.dist / "archive.tar.gz"
        original = target.read_text(encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--tag", "v1.0.0", "--dist", str(self.dist), "--gh", str(self.tampering_gh())],
            text=True,
            capture_output=True,
            env={
                "MOCK_GH_STATE": str(self.state_path),
                "MOCK_GH_CALLS": str(self.calls_path),
                "MOCK_GH_SEEN": str(seen_path),
                "MOCK_GH_TAMPER_TARGET": str(target),
            },
        )
        # Assert the run reached the upload for the reason expected. Without it a regression that
        # fails earlier, during the snapshot copy for instance, still passes the byte comparison
        # as long as the stand-in wrote its file, which would leave this test vacuous.
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("disappeared before publication", result.stderr)
        self.assertTrue(seen_path.exists(), "the stand-in never reached the upload arguments")
        seen = json.loads(seen_path.read_text(encoding="utf-8"))
        self.assertEqual("tampered", target.read_text(encoding="utf-8"))
        self.assertEqual(original, seen["archive.tar.gz"])

    def test_duplicate_asset_names_are_refused(self) -> None:
        nested = self.dist / "nested"
        nested.mkdir()
        # Only regular files in the top level become assets, so build the collision by pointing the
        # binder at two sources that share a basename.
        (nested / "archive.tar.gz").write_text("second", encoding="utf-8")
        sys.path.insert(0, str(SCRIPT.parent))
        import contextlib as _contextlib

        import release_publish

        with _contextlib.ExitStack() as stack:
            with self.assertRaisesRegex(release_publish.PublishError, "more than one asset named"):
                release_publish._verified_asset_snapshot(
                    [self.dist / "archive.tar.gz", nested / "archive.tar.gz"], stack
                )

    def test_fifo_asset_is_refused_without_hanging(self) -> None:
        import os
        import signal

        import release_publish

        fifo = self.root / "pipe.bin"
        os.mkfifo(fifo)
        out = self.root / "copied.bin"

        class _Blocked(Exception):
            pass

        def _alarm(_signum, _frame):
            raise _Blocked("open blocked on a FIFO")

        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(2)
        try:
            with self.assertRaisesRegex(release_publish.PublishError, "not a regular file"):
                release_publish._copy_verified_asset(fifo, out, "pipe.bin")
        finally:
            signal.alarm(0)

    def test_notes_and_uploaded_identity_stay_paired_after_a_source_swap(self) -> None:
        # Swap identity on disk after the first of (notes check, asset snapshot) returns. If notes
        # are checked against dist and assets are copied later, the upload carries identity B under
        # notes generated from identity A. Snapshot-then-verify keeps the pair.
        sys.path.insert(0, str(SCRIPT.parent))
        import release_publish

        identity = self.dist / "release-identity.json"
        seen_path = self.root / "seen-pair.json"
        swapped = {"done": False}
        original_notes = release_publish._verified_notes_snapshot
        original_assets = release_publish._verified_asset_snapshot

        def swap_after(fn):
            def wrapped(*args, **kwargs):
                result = fn(*args, **kwargs)
                if not swapped["done"]:
                    identity.write_text(
                        json.dumps(
                            {
                                "release": {"version": "9.9.9", "tag": "v9.9.9"},
                                "source": {"commit": "1" * 40},
                            }
                        ),
                        encoding="utf-8",
                    )
                    swapped["done"] = True
                return result

            return wrapped

        gh = self.root / "gh-pair"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import sys\n"
            "from pathlib import Path\n"
            f"seen = Path({str(seen_path)!r})\n"
            "args = sys.argv[1:]\n"
            "if args[:2] == ['release', 'view']:\n"
            "  print('release not found', file=sys.stderr)\n"
            "  raise SystemExit(1)\n"
            "if args[:2] == ['release', 'create']:\n"
            "  paths = args[3:args.index('--title')]\n"
            "  payload = {}\n"
            "  for item in paths:\n"
            "    path = Path(item)\n"
            "    if path.name == 'release-identity.json':\n"
            "      payload['identity'] = path.read_text(encoding='utf-8')\n"
            "    if path.name == 'release-notes.md':\n"
            "      payload['notes'] = path.read_text(encoding='utf-8')\n"
            "  seen.write_text(json.dumps(payload))\n"
            "raise SystemExit(0)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        release_publish._verified_notes_snapshot = swap_after(original_notes)
        release_publish._verified_asset_snapshot = swap_after(original_assets)
        try:
            with self.assertRaises(release_publish.PublishError):
                release_publish.publish("v1.0.0", self.dist, str(gh))
        finally:
            release_publish._verified_notes_snapshot = original_notes
            release_publish._verified_asset_snapshot = original_assets
        self.assertTrue(seen_path.exists(), "the stand-in never reached the upload arguments")
        payload = json.loads(seen_path.read_text(encoding="utf-8"))
        uploaded = json.loads(payload["identity"])
        self.assertEqual("1.0.0", uploaded["release"]["version"])
        self.assertIn("1.0.0", payload["notes"])
        self.assertNotIn("9.9.9", payload["notes"])

    def test_still_a_draft_after_publication_is_refused(self) -> None:
        gh = self.root / "gh-keep-draft"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "state_path = Path(os.environ['MOCK_GH_STATE'])\n"
            "args = sys.argv[1:]\n"
            "state = json.loads(state_path.read_text()) if state_path.exists() else None\n"
            "if args[:2] == ['release', 'view']:\n"
            "  if state is None:\n"
            "    print('release not found', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            "  print(json.dumps(state))\n"
            "elif args[:2] == ['release', 'create']:\n"
            "  files = [Path(item).name for item in args[3:args.index('--title')]]\n"
            "  notes = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  state = {'isDraft': True, 'body': notes, 'assets': [{'name': name} for name in files]}\n"
            "  state_path.write_text(json.dumps(state))\n"
            "elif args[:2] == ['release', 'edit']:\n"
            "  if '--notes-file' in args:\n"
            "    state['body'] = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  # Ignore --draft=false so an incomplete publication can be observed.\n"
            "  state_path.write_text(json.dumps(state))\n"
            "else:\n"
            "  raise SystemExit(2)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--tag", "v1.0.0", "--dist", str(self.dist), "--gh", str(gh)],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("still a draft after publication", result.stderr)

    def test_published_asset_set_mismatch_is_refused(self) -> None:
        gh = self.root / "gh-swap-assets"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "state_path = Path(os.environ['MOCK_GH_STATE'])\n"
            "args = sys.argv[1:]\n"
            "state = json.loads(state_path.read_text()) if state_path.exists() else None\n"
            "if args[:2] == ['release', 'view']:\n"
            "  if state is None:\n"
            "    print('release not found', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
            "  print(json.dumps(state))\n"
            "elif args[:2] == ['release', 'create']:\n"
            "  files = [Path(item).name for item in args[3:args.index('--title')]]\n"
            "  notes = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  state = {'isDraft': True, 'body': notes, 'assets': [{'name': name} for name in files]}\n"
            "  state_path.write_text(json.dumps(state))\n"
            "elif args[:2] == ['release', 'edit']:\n"
            "  if '--notes-file' in args:\n"
            "    state['body'] = Path(args[args.index('--notes-file') + 1]).read_text(encoding='utf-8')\n"
            "  if '--draft=false' in args:\n"
            "    state['isDraft'] = False\n"
            "    state['assets'] = state['assets'] + [{'name': 'extra.bin'}]\n"
            "  state_path.write_text(json.dumps(state))\n"
            "else:\n"
            "  raise SystemExit(2)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--tag", "v1.0.0", "--dist", str(self.dist), "--gh", str(gh)],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assets do not match dist/release", result.stderr)


class AssetSnapshotCoherenceTest(unittest.TestCase):
    """An open descriptor fixes WHICH object is read, not what it contains.

    The earlier binding work closed the swap window: the copy holds the inode, so a rename or a
    symlink replacement cannot redirect it. A writer that rewrites that same inode while the copy
    streams is a different failure. It hands the snapshot a mix of old and new bytes, which is a
    version that never existed on disk, and the release notes are then checked against that mix.
    """

    def setUp(self) -> None:
        sys.path.insert(0, str(SCRIPT.parent))
        import release_publish

        self.module = release_publish
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "archive.tar.gz"
        self.source.write_bytes(b"original-bytes")
        self.target = self.root / "copy.tar.gz"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_a_write_during_the_copy_is_refused(self) -> None:
        original = self.module.shutil.copyfileobj

        def rewriting_copy(handle, out):
            original(handle, out)
            # A writer landing here has already been let through by every check that ran before the
            # read, which is the whole point: nothing after the open looks at the file again.
            self.source.write_bytes(b"tampered-bytes")

        self.module.shutil.copyfileobj = rewriting_copy
        try:
            with self.assertRaises(self.module.PublishError) as caught:
                self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        finally:
            self.module.shutil.copyfileobj = original
        self.assertIn("while it was being read", str(caught.exception))

    def test_a_short_copy_is_refused(self) -> None:
        original = self.module.shutil.copyfileobj

        def truncating_copy(handle, out):
            out.write(handle.read(4))

        self.module.shutil.copyfileobj = truncating_copy
        try:
            with self.assertRaises(self.module.PublishError) as caught:
                self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        finally:
            self.module.shutil.copyfileobj = original
        self.assertIn("changed size while it was being read", str(caught.exception))

    def test_an_untouched_asset_copies(self) -> None:
        self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        self.assertEqual(b"original-bytes", self.target.read_bytes())


if __name__ == "__main__":
    unittest.main()
