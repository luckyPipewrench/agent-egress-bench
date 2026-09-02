#!/usr/bin/env python3
"""Regression tests for draft ownership and exact release asset publication."""

from __future__ import annotations

import json
import os
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
            "corpus": {"version": "v1.0.0", "case_count": 1},
            "runner": {"runner_version": "1.0.0", "scoring_version": "1.0"},
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

    def write_owned_draft(self) -> None:
        self.write_state(
            body=(self.dist / "release-notes.md").read_text(encoding="utf-8"),
            assets=sorted(path.name for path in self.dist.iterdir() if path.is_file()),
        )

    def publish(self, *, finalize: bool = False, dry_run: bool = False) -> subprocess.CompletedProcess[str]:
        args = [sys.executable, str(SCRIPT), "--tag", "v1.0.0", "--dist", str(self.dist), "--gh", str(self.gh)]
        if finalize:
            args.append("--finalize")
        if dry_run:
            args.append("--dry-run")
        return subprocess.run(
            args,
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

    def test_creates_marked_draft_with_exact_assets(self) -> None:
        result = self.publish()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertTrue(state["isDraft"])
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

    def test_dry_run_verifies_without_calling_github(self) -> None:
        result = self.publish(dry_run=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual([], self.calls())

    def test_finalize_refuses_to_create_and_publish_in_one_invocation(self) -> None:
        result = self.publish(finalize=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without an existing owned draft", result.stderr)
        self.assertFalse(self.state_path.exists())

    def test_finalize_publishes_an_existing_exact_owned_draft(self) -> None:
        self.write_owned_draft()
        result = self.publish(finalize=True)
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertFalse(json.loads(self.state_path.read_text(encoding="utf-8"))["isDraft"])

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
        # Swapping identity AFTER the snapshot returns is exactly the case snapshot-then-verify
        # is built to survive: the copies already hold the original bytes, so publication proceeds
        # with them and the swap changes nothing. Refusing here instead would mean the snapshot
        # had not taken the bytes it claims to.
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

    def test_malformed_post_publication_metadata_is_returned_to_draft(self) -> None:
        """Unknown metadata after undrafting cannot leave the release public.

        The existing mismatch test covers a valid-but-wrong asset list. A malformed or incomplete
        `gh release view` reply follows the same failure direction: it cannot prove the public
        release is sound, so it must be withdrawn before reporting the error.
        """
        import release_publish

        notes = "<!-- agent-egress-bench-release-workflow-v1 -->\n"
        assets = [self.root / "archive.tar.gz"]
        draft = {"isDraft": True, "body": notes, "assets": [{"name": "archive.tar.gz"}]}
        # GitHub has already made the release public, but its response lacks the asset list the
        # verifier needs. Previously actual_asset_names raised directly and skipped _withdraw.
        malformed_public = {"isDraft": False, "body": notes}
        # The fourth read is the withdrawal confirmation. A zero exit from the edit says the
        # command was accepted, not that the release came down, so the state is read back.
        withdrawn = {"isDraft": True, "body": notes, "assets": [{"name": "archive.tar.gz"}]}
        releases = iter((draft, draft, malformed_public, withdrawn))
        calls = []
        original_inspect = release_publish.inspect_draft
        original_command = release_publish.command
        release_publish.inspect_draft = lambda *_: next(releases)
        release_publish.command = lambda _gh, *args: calls.append(args) or ""
        try:
            with self.assertRaisesRegex(release_publish.PublishError, "returned to draft"):
                release_publish._publish_with_notes(
                    "v1.0.0",
                    self.dist,
                    "gh",
                    assets,
                    ["archive.tar.gz"],
                    self.root / "notes.md",
                    notes,
                    finalize=True,
                )
        finally:
            release_publish.inspect_draft = original_inspect
            release_publish.command = original_command
        self.assertIn(("release", "edit", "v1.0.0", "--draft=true"), calls)

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
            # The refusal is incidental: this stand-in answers `release view` with "not found"
            # even after `release create`, so publication stops there. Asserting only that SOME
            # PublishError was raised would pass for any failure, including one that never
            # reached the upload, which is the shape this test exists to inspect. Pin the
            # message so the run has to get as far as the arguments it then checks.
            with self.assertRaisesRegex(release_publish.PublishError, "disappeared before publication"):
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
        self.write_owned_draft()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v1.0.0",
                "--dist",
                str(self.dist),
                "--gh",
                str(gh),
                "--finalize",
            ],
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
            "  if '--draft=true' in args:\n"
            "    state['isDraft'] = True\n"
            "  state_path.write_text(json.dumps(state))\n"
            "else:\n"
            "  raise SystemExit(2)\n",
            encoding="utf-8",
        )
        gh.chmod(0o755)
        self.write_owned_draft()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v1.0.0",
                "--dist",
                str(self.dist),
                "--gh",
                str(gh),
                "--finalize",
            ],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assets do not match dist/release", result.stderr)
        # Reporting the divergence and walking away leaves a release carrying bytes nothing
        # checked. The exposure cannot be undone; staying public can be.
        self.assertIn("returned to draft", result.stderr)
        self.assertIs(json.loads(self.state_path.read_text(encoding="utf-8"))["isDraft"], True)

    def test_a_withdrawal_that_does_not_take_is_not_reported_as_success(self) -> None:
        """The edit is accepted and the release stays public.

        A zero exit says the command was accepted, not that the release came down. A no-op
        response or a concurrent re-publication leaves it public, and an operator reading
        "it has been returned to draft" will not go and look.
        """
        gh = self.root / "gh-withdraw-noop"
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
            # Accepts the withdrawal and does nothing, which is the whole point.
            "  if '--draft=true' in args:\n"
            "    raise SystemExit(0)\n"
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
        self.write_owned_draft()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v1.0.0",
                "--dist",
                str(self.dist),
                "--gh",
                str(gh),
                "--finalize",
            ],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("assets do not match dist/release", result.stderr)
        self.assertIn("withdrawal could not be confirmed", result.stderr)
        self.assertNotIn("has been returned to draft", result.stderr)
        self.assertIs(json.loads(self.state_path.read_text(encoding="utf-8"))["isDraft"], False)

    def test_an_unreadable_withdrawal_state_is_reported_as_unconfirmed(self) -> None:
        """The edit succeeds and the confirmation read fails.

        The read raises its own error about inspecting the release, which never says the
        divergent release may still be public. An operator reading a diagnostic instead of
        the state they have to act on will not go and take it down.
        """
        gh = self.root / "gh-withdraw-unreadable"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "from pathlib import Path\n"
            "state_path = Path(os.environ['MOCK_GH_STATE'])\n"
            "flag = state_path.with_suffix('.withdrawn')\n"
            "args = sys.argv[1:]\n"
            "state = json.loads(state_path.read_text()) if state_path.exists() else None\n"
            "if args[:2] == ['release', 'view']:\n"
            # Only the read AFTER the withdrawal fails, so the run gets that far.
            "  if flag.exists():\n"
            "    print('upstream is unavailable', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
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
            "  if '--draft=true' in args:\n"
            "    flag.write_text('1')\n"
            "    raise SystemExit(0)\n"
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
        self.write_owned_draft()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v1.0.0",
                "--dist",
                str(self.dist),
                "--gh",
                str(gh),
                "--finalize",
            ],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("withdrawal could not be confirmed", result.stderr)
        self.assertIn("may still be public", result.stderr)
        self.assertNotIn("has been returned to draft", result.stderr)

    def test_a_failed_withdrawal_is_reported_rather_than_hidden(self) -> None:
        gh = self.root / "gh-swap-assets-nowithdraw"
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
            "  if '--draft=true' in args:\n"
            "    print('permission denied', file=sys.stderr)\n"
            "    raise SystemExit(1)\n"
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
        self.write_owned_draft()
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v1.0.0",
                "--dist",
                str(self.dist),
                "--gh",
                str(gh),
                "--finalize",
            ],
            text=True,
            capture_output=True,
            env={"MOCK_GH_STATE": str(self.state_path), "MOCK_GH_CALLS": str(self.calls_path)},
        )
        self.assertNotEqual(result.returncode, 0)
        # The divergence is the finding; the failed withdrawal is how much worse the state is.
        # Replacing one message with the other would hide which of the two happened.
        self.assertIn("assets do not match dist/release", result.stderr)
        self.assertIn("may still be public", result.stderr)


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

    def test_a_write_that_survives_the_metadata_check_is_refused(self) -> None:
        """An equal-size rewrite whose observed metadata never moved.

        This is the case metadata cannot catch. The stand-in runs the real metadata comparison,
        which passes because it sees the pristine file, and only then rewrites the source. A
        writer restoring st_mtime_ns with utimensat, or a filesystem whose timestamp granularity
        is coarser than the write, produces the same state.
        """
        original = self.module._require_stable_during_read

        def rewrite_after_metadata_passes(descriptor, before, copied, label):
            original(descriptor, before, copied, label)
            self.source.write_bytes(b"tampered-bytes")

        self.module._require_stable_during_read = rewrite_after_metadata_passes
        try:
            with self.assertRaises(self.module.PublishError) as caught:
                self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        finally:
            self.module._require_stable_during_read = original
        self.assertIn("did not read back as the bytes that were copied", str(caught.exception))
        self.assertEqual(len(b"original-bytes"), len(b"tampered-bytes"))

    def test_the_metadata_check_still_reports_an_ordinary_racing_write(self) -> None:
        original = self.module._require_source_still_hashes_to
        self.module._require_source_still_hashes_to = lambda *_: None
        try:
            self.source.write_bytes(b"original-bytes")
            descriptor = os.open(self.source, os.O_RDONLY)
            try:
                before = os.fstat(descriptor)
                self.source.write_bytes(b"a-longer-set-of-bytes")
                with self.assertRaises(self.module.PublishError) as caught:
                    self.module._require_stable_during_read(
                        descriptor, before, len(b"original-bytes"), "release asset archive.tar.gz"
                    )
            finally:
                os.close(descriptor)
        finally:
            self.module._require_source_still_hashes_to = original
        self.assertIn("while it was being read", str(caught.exception))

    def test_a_short_copy_is_refused(self) -> None:
        original = self.module._require_source_still_hashes_to
        # Neutralized so the size check is what answers, not the digest that would also catch it.
        self.module._require_source_still_hashes_to = lambda *_: None
        real_fdopen = self.module.os.fdopen

        class _Short:
            def __init__(self, handle):
                self._handle = handle
                self._served = False

            def read(self, size):
                if self._served:
                    return b""
                self._served = True
                return self._handle.read(4)

            def __enter__(self):
                self._handle.__enter__()
                return self

            def __exit__(self, *exc):
                return self._handle.__exit__(*exc)

        self.module.os.fdopen = lambda *a, **k: _Short(real_fdopen(*a, **k))
        try:
            with self.assertRaises(self.module.PublishError) as caught:
                self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        finally:
            self.module.os.fdopen = real_fdopen
            self.module._require_source_still_hashes_to = original
        self.assertIn("changed size while it was being read", str(caught.exception))

    def test_an_untouched_asset_copies(self) -> None:
        self.module._copy_verified_asset(self.source, self.target, "archive.tar.gz")
        self.assertEqual(b"original-bytes", self.target.read_bytes())


if __name__ == "__main__":
    unittest.main()
