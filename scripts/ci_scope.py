#!/usr/bin/env python3
"""Classify whether a change is confined to GitHub workflow contracts."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path, PurePosixPath


WORKFLOW_ROOT = PurePosixPath(".github/workflows")


def is_workflow_only(paths: list[str]) -> bool:
    if not paths:
        return False
    for raw in paths:
        path = PurePosixPath(raw)
        if path.is_absolute() or ".." in path.parts or path.parent != WORKFLOW_ROOT:
            return False
        if path.suffix not in {".yml", ".yaml"}:
            return False
    return True


def changed_paths(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMRTUXB", f"{base}...{head}"],
        check=True,
        text=True,
        capture_output=True,
    )
    return [line for line in result.stdout.splitlines() if line]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    value = "true" if is_workflow_only(changed_paths(args.base, args.head)) else "false"
    line = f"workflow_only={value}\n"
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(line)
    else:
        print(line, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
