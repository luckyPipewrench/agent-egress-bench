#!/usr/bin/env python3
"""Verify that an existing Gauntlet promotion branch is safe to reuse."""

import argparse
import os
import subprocess
from pathlib import Path


STATIC_PROMOTION_PATHS = (
    Path("ci/gauntlet-baseline.json"),
    Path("gauntlet-site/latest-verified.json"),
)


def git(repo_root, *args, check=True):
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=check,
        capture_output=True,
    )


def relative_record_dir(repo_root, record_dir):
    return record_dir.resolve().relative_to(repo_root.resolve())


def verify(repo_root, default_ref, remote_ref, local_ref, record_dir):
    record_relative = relative_record_dir(repo_root, record_dir)
    merge_base = git(repo_root, "merge-base", default_ref, remote_ref).stdout.strip()
    if not merge_base:
        raise ValueError("existing promotion branch has no default-branch merge base")

    changed = git(
        repo_root,
        "diff",
        "--name-only",
        "-z",
        os.fsdecode(merge_base),
        remote_ref,
    ).stdout.split(b"\0")
    record_prefix = record_relative.as_posix() + "/"
    allowed = {path.as_posix() for path in STATIC_PROMOTION_PATHS}
    unexpected = []
    for raw_path in changed:
        if not raw_path:
            continue
        path = os.fsdecode(raw_path)
        if path not in allowed and not path.startswith(record_prefix):
            unexpected.append(path)
    if unexpected:
        raise ValueError(
            "existing promotion branch changes unexpected paths: "
            + ", ".join(sorted(unexpected))
        )

    promotion_paths = [
        *(path.as_posix() for path in STATIC_PROMOTION_PATHS),
        record_relative.as_posix(),
    ]
    comparison = git(
        repo_root,
        "diff",
        "--quiet",
        remote_ref,
        local_ref,
        "--",
        *promotion_paths,
        check=False,
    )
    if comparison.returncode == 1:
        raise ValueError("existing promotion branch has different promotion content")
    if comparison.returncode != 0:
        raise subprocess.CalledProcessError(
            comparison.returncode,
            comparison.args,
            output=comparison.stdout,
            stderr=comparison.stderr,
        )


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--default-ref", required=True)
    parser.add_argument("--remote-ref", required=True)
    parser.add_argument("--local-ref", default="HEAD")
    parser.add_argument("--record-dir", type=Path, required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    try:
        verify(
            args.repo_root,
            args.default_ref,
            args.remote_ref,
            args.local_ref,
            args.record_dir,
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"Gauntlet existing-branch validation: BLOCKED: {exc}")
        return 1
    print("Gauntlet existing-branch validation: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
