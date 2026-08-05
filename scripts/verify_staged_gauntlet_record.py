#!/usr/bin/env python3
"""Verify that Git's index contains exactly one complete Gauntlet record."""

import argparse
import difflib
import json
import subprocess
from pathlib import Path


RECORD_MANIFEST_FILENAME = "record-manifest.json"


def expected_files(record_dir):
    manifest_path = record_dir / RECORD_MANIFEST_FILENAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("record manifest must be an object")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("record manifest files must be a non-empty object")
    expected = {RECORD_MANIFEST_FILENAME}
    for filename in files:
        if (
            not isinstance(filename, str)
            or not filename
            or filename in {".", ".."}
            or Path(filename).name != filename
        ):
            raise ValueError(f"record manifest contains a non-local filename: {filename!r}")
        expected.add(filename)
    return expected


def staged_files(repo_root, record_dir):
    relative = record_dir.resolve().relative_to(repo_root.resolve()).as_posix()
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", relative],
        check=True,
        capture_output=True,
    )
    prefix = f"{relative}/".encode()
    staged = set()
    for path in result.stdout.split(b"\0"):
        if not path:
            continue
        if not path.startswith(prefix):
            raise ValueError(f"staged path escaped record directory: {path!r}")
        staged.add(path[len(prefix):].decode())
    return staged


def verify(repo_root, record_dir):
    expected = expected_files(record_dir)
    staged = staged_files(repo_root, record_dir)
    if staged == expected:
        return
    difference = "\n".join(
        difflib.unified_diff(
            sorted(expected),
            sorted(staged),
            fromfile="record-manifest",
            tofile="git-index",
            lineterm="",
        )
    )
    raise ValueError(f"staged record file set does not match its manifest:\n{difference}")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--record-dir", type=Path, required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        verify(args.repo_root, args.record_dir)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Gauntlet staged-record validation: BLOCKED: {exc}")
        return 1
    print("Gauntlet staged-record validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
