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


class ReleasePublishTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for name in ("archive.tar.gz", "checksums.txt", "release-identity.json"):
            (self.dist / name).write_text(name, encoding="utf-8")
        (self.dist / "release-notes.md").write_text(
            "<!-- agent-egress-bench-release-workflow-v1 -->\n\n## Schema contracts\n",
            encoding="utf-8",
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

    def test_creates_marked_draft_with_exact_assets_before_publication(self) -> None:
        result = self.publish()
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertFalse(state["isDraft"])
        self.assertIn("agent-egress-bench-release-workflow-v1", state["body"])
        self.assertEqual(["archive.tar.gz", "checksums.txt", "release-identity.json", "release-notes.md"], sorted(asset["name"] for asset in state["assets"]))

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


if __name__ == "__main__":
    unittest.main()
