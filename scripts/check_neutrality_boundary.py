#!/usr/bin/env python3
"""Keep product acceptance policy out of mandatory repository validation."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

MAKE_RULE = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?![=])\s*(.*)$")
REPO_PATH = re.compile(r"(?<![A-Za-z0-9_.-])((?:scripts|ci)/[A-Za-z0-9_./-]+)")
PRODUCT_RUNNER = re.compile(r"^run-[A-Za-z0-9_-]+-gauntlet\.sh$")
MANDATORY_WORKFLOWS = (".github/workflows/validate.yaml", ".github/workflows/release.yaml")


def make_graph(source: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    dependencies: dict[str, list[str]] = {}
    recipes: dict[str, str] = {}
    current: str | None = None
    for line in source.splitlines():
        match = MAKE_RULE.match(line)
        if match:
            current = match.group(1)
            dependencies[current] = match.group(2).split()
            recipes.setdefault(current, "")
            continue
        if current is not None and line.startswith("\t"):
            recipes[current] += line + "\n"
        elif line and not line[0].isspace():
            current = None
    return dependencies, recipes


def preflight_text(makefile: str) -> str:
    dependencies, recipes = make_graph(makefile)
    pending = ["preflight"]
    visited: set[str] = set()
    chunks: list[str] = []
    while pending:
        target = pending.pop()
        if target in visited:
            continue
        visited.add(target)
        chunks.append(recipes.get(target, ""))
        pending.extend(dependencies.get(target, []))
    return "\n".join(chunks)


def referenced_paths(source: str) -> set[str]:
    return {match.group(1).rstrip(".,;:'\"") for match in REPO_PATH.finditer(source)}


def has_product_acceptance_shape(value: object) -> bool:
    keys: set[str] = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            keys.update(str(key) for key in item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    identity = any(key.endswith("_version") and key != "schema_version" for key in keys)
    acceptance = bool(keys & {"failed_cases", "expected_failed_cases", "score_floors", "score_ceilings"})
    return identity and acceptance


def violations(root: Path) -> list[str]:
    makefile = root / "Makefile"
    sources = [preflight_text(makefile.read_text(encoding="utf-8"))]
    for relative in MANDATORY_WORKFLOWS:
        path = root / relative
        if path.exists():
            sources.append(path.read_text(encoding="utf-8"))

    pending = set().union(*(referenced_paths(source) for source in sources))
    visited: set[str] = set()
    failures: list[str] = []
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        visited.add(relative)
        path = root / relative
        if not path.is_file():
            continue
        if PRODUCT_RUNNER.fullmatch(path.name):
            failures.append(f"mandatory validation reaches product runner {relative}")
        if path.suffix == ".json":
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if has_product_acceptance_shape(value):
                failures.append(f"mandatory validation reaches product acceptance policy {relative}")
            continue
        # Follow shell entrypoints because they execute their referenced paths.
        # Python source and tests often mention product fixtures as inert data;
        # treating every string literal as execution would reject contract tests.
        if path.suffix == ".sh":
            text = path.read_text(encoding="utf-8")
            pending.update(referenced_paths(text))
    return sorted(set(failures))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = violations(root)
    if failures:
        for failure in failures:
            print(f"neutrality boundary: FAIL: {failure}", file=sys.stderr)
        return 1
    print("neutrality boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
