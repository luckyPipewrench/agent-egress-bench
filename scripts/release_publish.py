#!/usr/bin/env python3
"""Publish one verified release directory only into its own draft release."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


# This marker is deliberately stable across job reruns. It proves that a draft
# was made by this workflow rather than being an unrelated draft for the tag.
DRAFT_OWNER = "agent-egress-bench-release-workflow-v1"
DRAFT_MARKER = f"<!-- {DRAFT_OWNER} -->"
# A release notes body is prose. Anything approaching this size is a wrong or hostile file.
MAX_NOTES_BYTES = 1 << 20
RELEASE_NOTES_NAME = "release-notes.md"


class PublishError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
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


def _require_opened_identity(source: Path, status: os.stat_result, label: str) -> None:
    """Refuse a pathname whose resolved target is not the object that was opened.

    O_NOFOLLOW refuses a symlink at the FINAL component only, so a swapped parent directory can
    still aim the same pathname at a different file. Resolving the name and comparing device and
    inode against the open descriptor closes that, and a disagreement means the tree moved during
    the walk rather than anything worth publishing.
    """
    try:
        resolved = source.resolve().stat()
    except OSError as exc:
        fail(f"cannot resolve {label}: {exc}")
    if (resolved.st_dev, resolved.st_ino) != (status.st_dev, status.st_ino):
        fail(f"{label} changed while it was being read")


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
        _require_opened_identity(notes, status, RELEASE_NOTES_NAME)
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
    _require_notes_match_release(dist, raw)
    directory = stack.enter_context(tempfile.TemporaryDirectory())
    snapshot = Path(directory) / RELEASE_NOTES_NAME
    snapshot.write_bytes(raw)
    return snapshot, text


def _require_notes_match_release(dist: Path, raw: bytes) -> None:
    """Require the notes to be exactly what this release's identity and catalog generate.

    The ownership marker only says the workflow wrote a notes file at some point. It cannot say the
    bytes are still the generated ones, so on its own it accepts an edited body carrying arbitrary
    release metadata. Regenerating from the identity and catalog and comparing byte for byte is what
    makes the published body a property of the release rather than of whoever last wrote the file.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        import release_build
    except ImportError as exc:  # pragma: no cover - a broken checkout, not a release condition
        fail(f"cannot load the release builder to verify {RELEASE_NOTES_NAME}: {exc}")
    identity_path = dist / release_build.IDENTITY_NAME
    try:
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"cannot read {release_build.IDENTITY_NAME} to verify {RELEASE_NOTES_NAME}: {exc}")
    try:
        catalog_name, _ = release_build.schema_asset_names(identity)
        catalog_bytes = (dist / catalog_name).read_bytes()
        expected = release_build.rendered_release_notes(identity, catalog_bytes)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        fail(f"cannot regenerate {RELEASE_NOTES_NAME} from the release catalog: {exc}")
    if raw != expected:
        fail(f"{RELEASE_NOTES_NAME} does not match the notes generated from this release")


def _verified_asset_snapshot(assets: list[Path], stack: contextlib.ExitStack) -> tuple[Path, list[Path]]:
    """Return process-owned copies holding the exact asset bytes that were validated.

    `release_assets` rejects symlinks and non-files by NAME, then the publish path hands those
    pathnames to gh, which opens them again later. A replacement in that window uploads bytes
    nothing checked.

    This copies rather than hard-links on purpose. A hard link binds the inode, which defeats a
    rename or a symlink swap, and does NOT defeat an in-place rewrite of the same inode: both names
    then see the new bytes. Only bytes this process already holds are safe to publish. Verified by
    reproduction: the link version failed `test_upload_carries_validated_bytes_after_a_source_swap`
    because the stand-in rewrote the file in place.

    The read comes from one descriptor, so validation and copy cannot see two different objects.

    Returns the snapshot directory alongside the copies. The notes check regenerates its expected
    body from the identity and catalog files, which are themselves assets, so it has to read them
    from this directory rather than from the source tree.
    """
    directory = Path(stack.enter_context(tempfile.TemporaryDirectory()))
    bound: list[Path] = []
    seen: set[str] = set()
    for asset in assets:
        name = asset.name
        # gh derives the uploaded asset name from the basename, so two sources collapsing to one
        # name would silently publish whichever landed last.
        if name in seen:
            fail(f"release distribution has more than one asset named {name}")
        seen.add(name)
        bound.append(_copy_verified_asset(asset, directory / name, name))
    return directory, bound


def _copy_verified_asset(source: Path, target: Path, name: str) -> Path:
    """Copy one asset out of a single opened descriptor.

    O_NOFOLLOW refuses a final-component symlink in the same operation that opens the file, which a
    separate check cannot do: between the check and the open, the name can change.
    """
    try:
        # O_NONBLOCK is load-bearing. A FIFO substituted after release_assets listed the name
        # would otherwise block forever in open(); notes already used this flag for that reason.
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        fail(f"cannot read release asset {name}: {exc}")
    try:
        status = os.fstat(descriptor)
        # A FIFO would hang publication on a read that never returns and a device file would supply
        # unbounded input, so refuse anything that is not an ordinary file.
        if not stat.S_ISREG(status.st_mode):
            fail(f"release asset {name} is not a regular file")
        _require_opened_identity(source, status, f"release asset {name}")
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as handle, open(target, "wb") as out:
                shutil.copyfileobj(handle, out)
        except OSError as exc:
            fail(f"cannot copy release asset {name}: {exc}")
    finally:
        os.close(descriptor)
    return target


def publish(tag: str, dist: Path, gh: str) -> None:
    sources = release_assets(dist)
    expected_names = [asset.name for asset in sources]
    with contextlib.ExitStack() as stack:
        # Snapshot first, then verify notes against those copies. Validating identity and catalog
        # by name and copying them later is the same two-lookup window this change closes for gh:
        # the notes can describe identity A while the upload carries identity B.
        snapshot_dir, assets = _verified_asset_snapshot(sources, stack)
        notes, notes_text = _verified_notes_snapshot(snapshot_dir, stack)
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
    # DETECTION, NOT PREVENTION. By the time this runs the release is already public, so a failure
    # here reports a bad state that readers may already have seen. It is worth keeping because a
    # silent divergence is worse than a loud one, and it must not be read as a guarantee that the
    # published release always matched.
    #
    # Residual, stated rather than implied: GitHub offers no compare-and-set on a release, so the
    # asset set is verified and then undrafted as two operations. Another editor with write access
    # can change assets in that window. The body is not exposed: one command sets the verified body
    # and clears the draft together. Closing the asset window needs an API primitive that does not
    # exist today; pretending otherwise would be the actual defect.
    published = inspect_draft(gh, tag)
    if published is None:
        fail(f"release {tag} disappeared during publication")
    # The edit asked to clear the draft. If that did not take, this process still returns success
    # unless we look: an incomplete publication must not present as done.
    if published.get("isDraft") is not False:
        fail(f"release {tag} is still a draft after publication")
    published_body = published.get("body")
    if not isinstance(published_body, str) or published_body != notes_text:
        fail(f"published release {tag} body does not match the verified release notes")
    published_names = actual_asset_names(published)
    if published_names != sorted(expected_names):
        fail(f"published release {tag} assets do not match dist/release: expected={sorted(expected_names)}, actual={published_names}")


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
