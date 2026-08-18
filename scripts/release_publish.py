#!/usr/bin/env python3
"""Publish one verified release directory only into its own draft release."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


# This marker is deliberately stable across job reruns. It proves that a draft
# was made by this workflow rather than being an unrelated draft for the tag.
DRAFT_OWNER = "agent-egress-bench-release-workflow-v1"
DRAFT_MARKER = f"<!-- {DRAFT_OWNER} -->"
RELEASE_NOTES_NAME = "release-notes.md"


class PublishError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PublishError(message)


def command(gh: str, *args: str) -> str:
    try:
        result = subprocess.run([gh, *args], text=True, capture_output=True, check=False)
    except OSError as exc:
        fail(f"cannot run GitHub CLI: {exc}")
    if result.returncode:
        fail(f"GitHub CLI {' '.join(args[:2])} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout


def release_assets(dist: Path) -> list[Path]:
    if not dist.is_dir():
        fail(f"release distribution directory is absent: {dist}")
    assets = sorted(path for path in dist.iterdir() if path.is_file() and not path.is_symlink())
    if not assets:
        fail("release distribution directory has no regular assets")
    return assets


def inspect_draft(gh: str, tag: str) -> dict[str, Any] | None:
    try:
        result = subprocess.run(
            [gh, "release", "view", tag, "--json", "isDraft,body,assets"],
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot run GitHub CLI: {exc}")
    if result.returncode:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        if "release not found" in diagnostic.lower():
            return None
        fail(f"cannot inspect existing release {tag}: {diagnostic}")
    try:
        release = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"GitHub CLI returned malformed release metadata: {exc}")
    if not isinstance(release, dict):
        fail("GitHub CLI returned malformed release metadata")
    return release


def require_owned_draft(release: dict[str, Any], tag: str) -> None:
    if release.get("isDraft") is not True:
        fail(f"refusing to overwrite published release {tag}")
    body = release.get("body")
    if not isinstance(body, str) or DRAFT_MARKER not in body:
        fail(f"refusing to resume draft {tag} without the release workflow ownership marker")


def actual_asset_names(release: dict[str, Any]) -> list[str]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("GitHub CLI returned release metadata without an asset list")
    names: list[str] = []
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or not asset["name"]:
            fail("GitHub CLI returned release metadata with an invalid asset")
        names.append(asset["name"])
    return sorted(names)


def publish(tag: str, dist: Path, gh: str) -> None:
    assets = release_assets(dist)
    expected_names = [asset.name for asset in assets]
    notes = dist / RELEASE_NOTES_NAME
    if not notes.is_file() or notes.is_symlink() or not notes.read_text(encoding="utf-8").strip():
        fail(f"release distribution is missing {RELEASE_NOTES_NAME}")
    if DRAFT_MARKER not in notes.read_text(encoding="utf-8"):
        fail(f"{RELEASE_NOTES_NAME} is missing the release workflow ownership marker")
    release = inspect_draft(gh, tag)
    asset_arguments = [str(asset) for asset in assets]
    if release is None:
        command(gh, "release", "create", tag, *asset_arguments, "--title", tag, "--verify-tag", "--draft", "--notes-file", str(notes))
    else:
        require_owned_draft(release, tag)
        command(gh, "release", "upload", tag, *asset_arguments, "--clobber")

    command(gh, "release", "edit", tag, "--notes-file", str(notes))

    release = inspect_draft(gh, tag)
    if release is None:
        fail(f"release {tag} disappeared before publication")
    require_owned_draft(release, tag)
    actual_names = actual_asset_names(release)
    # Exact equality, not containment. `gh release upload --clobber` replaces
    # same-named assets and leaves anything else in place, so a draft that
    # already held a foreign asset would publish it alongside ours: an official
    # release carrying a file absent from checksums.txt and outside the
    # attestation set, which is precisely what a consumer's verification refuses.
    if actual_names != sorted(expected_names):
        fail(f"draft {tag} assets do not exactly match dist/release: expected={sorted(expected_names)}, actual={actual_names}")
    command(gh, "release", "edit", tag, "--draft=false")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args()
    try:
        publish(args.tag, args.dist, args.gh)
    except PublishError as exc:
        print(f"release publication failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
