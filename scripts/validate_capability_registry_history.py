#!/usr/bin/env python3
"""Reject rewrites of capability-registry snapshots already in a Git base."""

import argparse
import subprocess
from pathlib import Path


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True
    ).stdout


def validate(repo, base):
    repo = Path(repo)
    if subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", base, "HEAD"],
        check=False,
        capture_output=True,
    ).returncode:
        raise ValueError(f"immutable base is not an ancestor of HEAD: {base}")
    paths = git(repo, "ls-tree", "-r", "--name-only", base, "--", "capability-registry").decode().splitlines()
    snapshots = [path for path in paths if path.endswith(".json")]
    if not snapshots:
        return 0
    failures = []
    for path in snapshots:
        previous = git(repo, "show", f"{base}:{path}")
        current_path = repo / path
        if not current_path.is_file():
            failures.append(f"removed immutable registry snapshot: {path}")
            continue
        if current_path.read_bytes() != previous:
            failures.append(f"rewrote immutable registry snapshot: {path}")
    if failures:
        raise ValueError("; ".join(failures))
    return len(snapshots)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=".", type=Path)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    count = validate(args.repo, args.base)
    print(f"capability registry history: OK ({count} prior snapshots unchanged)")


if __name__ == "__main__":
    main()
