#!/usr/bin/env python3
"""Fail when the README category mapping no longer covers the live corpus.

The README maps every case category to an OWASP Agentic Top 10 item. That table
is hand-maintained prose, so it drifts the moment a category is added: on
2026-08-09 it was missing `mcp_drift` and its lead-in sentence still claimed
eight categories while the corpus held eighteen.

Counting categories in prose is what rotted, so this gate does not check a
number. It compares the SET of categories the runner actually loads against the
set the table documents, in both directions. A category with cases and no row is
undocumented; a row with no cases documents something that does not exist.

The runner is the authority. Its exit status is checked before its output is
parsed, because an empty stats report otherwise yields an empty category set,
which trivially matches nothing missing and would pass while proving nothing.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# `| `category` | ASI02 ... |` -- the first cell of an OWASP mapping row.
TABLE_ROW = re.compile(r"^\|\s*`([a-z0-9_]+)`\s*\|")
STATS_ENTRY = re.compile(r"^\s+([a-z0-9_]+):\s*\d+\s*$")


def live_categories(repo_root: Path) -> set[str]:
    """Categories the runner loads, from its own stats output."""
    proc = subprocess.run(
        ["go", "run", ".", "--stats", "--cases", "../cases"],
        cwd=repo_root / "runner",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(
            "check-readme-categories: FAIL - the runner could not load the corpus\n"
            f"{proc.stderr.strip()}"
        )

    categories: set[str] = set()
    in_block = False
    for line in proc.stdout.splitlines():
        if line.startswith("by_category:"):
            in_block = True
            continue
        if in_block:
            match = STATS_ENTRY.match(line)
            if not match:
                break
            categories.add(match.group(1))

    if not categories:
        raise SystemExit(
            "check-readme-categories: FAIL - the runner reported no categories; "
            "refusing to compare against an empty set"
        )
    return categories


def documented_categories(readme: Path) -> set[str]:
    return {
        match.group(1)
        for line in readme.read_text(encoding="utf-8").splitlines()
        if (match := TABLE_ROW.match(line))
    }


def spec_categories(spec: Path) -> set[str]:
    """The category enum SPEC.md declares, read from under its own heading.

    Scoped to the `### category` section so the surrounding enums for
    `input_type`, `transport`, `capability_tags`, and `requires` cannot leak in
    and mask a missing category.
    """
    lines = spec.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if line.strip() != "### category":
            continue
        for candidate in lines[index + 1 :]:
            if candidate.startswith("#"):
                break
            if candidate.strip().startswith("`"):
                return set(re.findall(r"`([a-z0-9_]+)`", candidate))
        break
    raise SystemExit(
        "check-readme-categories: FAIL - could not find the category enum under "
        "'### category' in docs/SPEC.md"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".", type=Path)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    readme = repo_root / "README.md"
    if not readme.is_file():
        raise SystemExit(f"check-readme-categories: FAIL - missing {readme}")

    spec = repo_root / "docs" / "SPEC.md"
    if not spec.is_file():
        raise SystemExit(f"check-readme-categories: FAIL - missing {spec}")

    live = live_categories(repo_root)
    documented = documented_categories(readme)
    declared = spec_categories(spec)

    failed = False
    for label, names, fix in (
        ("README rows", documented, "update the OWASP mapping table in README.md"),
        ("the docs/SPEC.md category enum", declared, "update the enum under '### category'"),
    ):
        missing = sorted(live - names)
        phantom = sorted(names - live)
        if missing:
            print(
                f"check-readme-categories: FAIL - categories have cases but are absent from {label}: "
                + ", ".join(missing)
            )
        if phantom:
            print(
                f"check-readme-categories: FAIL - {label} name categories with no cases: "
                + ", ".join(phantom)
            )
        if missing or phantom:
            print(f"  fix: {fix}")
            failed = True

    if failed:
        return 1

    print(f"check-readme-categories: OK ({len(live)} categories documented in README and SPEC)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
