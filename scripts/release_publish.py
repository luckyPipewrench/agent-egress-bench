#!/usr/bin/env python3
"""Publish one verified release directory only into its own draft release."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


# This marker is deliberately stable across job reruns. It proves that a draft
# was made by this workflow rather than being an unrelated draft for the tag.
DRAFT_OWNER = "agent-egress-bench-release-workflow-v1"
DRAFT_MARKER = f"<!-- {DRAFT_OWNER} -->"
# A release notes body is prose. Anything approaching this size is a wrong or hostile file.
MAX_NOTES_BYTES = 1 << 20
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


def _verified_notes_snapshot(dist: Path, stack: contextlib.ExitStack) -> tuple[Path, str]:
    """Return a path holding the exact notes bytes that were validated.

    Validating the notes file and then handing its PATHNAME to gh leaves a window: gh re-reads the
    file later, so a write or a symlink swap in between publishes bytes nobody checked. Read once,
    validate those bytes, and copy them into a file this process owns, so what gh publishes is
    exactly what passed validation.
    """
    notes = dist / RELEASE_NOTES_NAME
    try:
        descriptor = os.open(notes, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        fail(f"release distribution is missing {RELEASE_NOTES_NAME}")
    try:
        status = os.fstat(descriptor)
        # Check the object actually opened, not the name. A FIFO would otherwise block the release on
        # a read that never returns, and a device file would supply unbounded input.
        if not stat.S_ISREG(status.st_mode):
            fail(f"{RELEASE_NOTES_NAME} is not a regular file")
        if status.st_size > MAX_NOTES_BYTES:
            fail(f"{RELEASE_NOTES_NAME} is larger than {MAX_NOTES_BYTES} bytes")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_NOTES_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_NOTES_BYTES:
        fail(f"{RELEASE_NOTES_NAME} is larger than {MAX_NOTES_BYTES} bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # A traceback here would be an uncontrolled exit from a publication path; refuse instead.
        fail(f"{RELEASE_NOTES_NAME} is not valid UTF-8")
    if not text.strip():
        fail(f"release distribution is missing {RELEASE_NOTES_NAME}")
    if DRAFT_MARKER not in text:
        fail(f"{RELEASE_NOTES_NAME} is missing the release workflow ownership marker")
    directory = stack.enter_context(tempfile.TemporaryDirectory())
    snapshot = Path(directory) / RELEASE_NOTES_NAME
    snapshot.write_bytes(raw)
    return snapshot, text


def publish(tag: str, dist: Path, gh: str) -> None:
    assets = release_assets(dist)
    expected_names = [asset.name for asset in assets]
    with contextlib.ExitStack() as stack:
        notes, notes_text = _verified_notes_snapshot(dist, stack)
        _publish_with_notes(tag, dist, gh, assets, expected_names, notes, notes_text)


def _publish_with_notes(tag, dist, gh, assets, expected_names, notes, notes_text) -> None:
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
    # The snapshot proves what was SENT. This proves what the release actually carries, so a body
    # replaced between the edit and publication cannot be undrafted.
    body = release.get("body")
    # Exact comparison. Accepting a body that differs only at its boundaries would weaken the check
    # into "looks close enough", which is not what a published release body needs.
    if not isinstance(body, str) or body != notes_text:
        fail(f"draft {tag} body does not match the verified release notes")
    # One update sets the verified body AND clears the draft. Doing those separately leaves a window
    # in which another editor can replace the body between the check and publication.
    command(gh, "release", "edit", tag, "--notes-file", str(notes), "--draft=false")
    published = inspect_draft(gh, tag)
    if published is None:
        fail(f"release {tag} disappeared during publication")
    published_body = published.get("body")
    if not isinstance(published_body, str) or published_body != notes_text:
        fail(f"published release {tag} body does not match the verified release notes")


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
