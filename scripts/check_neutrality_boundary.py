#!/usr/bin/env python3
"""Keep product acceptance policy out of mandatory repository validation."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

MAKE_RULE = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?![=])\s*(.*)$")
REPO_PATH = re.compile(r"(?<![A-Za-z0-9_.-])((?:scripts|ci|examples)/[A-Za-z0-9_./-]+)")
MAKE_COMMAND = re.compile(r"\bmake\b([^\n;&|]*)")
MAKE_OPTIONS_WITH_VALUE = frozenset(
    {
        "-C",
        "-f",
        "-I",
        "-o",
        "-W",
        "--directory",
        "--eval",
        "--file",
        "--include-dir",
        "--makefile",
        "--new-file",
        "--old-file",
        "--assume-new",
        "--assume-old",
        "--what-if",
    }
)
MAKE_OPTIONS_WITH_OPTIONAL_NUMBER = frozenset(
    {"-j", "-l", "--jobs", "--load-average", "--max-load"}
)
MAKE_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?::|\+|\?|!)?=")
PRODUCT_RUNNER = re.compile(r"^run-[A-Za-z0-9_-]+-gauntlet\.sh$")
MANDATORY_WORKFLOWS = (".github/workflows/validate.yaml", ".github/workflows/release.yaml")
INERT_PRODUCT_REFERENCES = frozenset({"scripts/check_claim_language.py"})
RETAINED_RESULT_INTEGRITY = frozenset({"ci/gauntlet-baseline.json"})


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


def make_targets_text(makefile: str, roots: set[str]) -> str:
    dependencies, recipes = make_graph(makefile)
    pending = list(roots)
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


def workflow_make_roots(source: str) -> set[str]:
    roots: set[str] = set()
    for match in MAKE_COMMAND.finditer(source):
        try:
            tokens = shlex.split(match.group(1), comments=True)
        except ValueError:
            tokens = match.group(1).split()
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token == "--":
                index += 1
                continue
            if token in MAKE_OPTIONS_WITH_VALUE:
                index += 2
                continue
            if token in MAKE_OPTIONS_WITH_OPTIONAL_NUMBER:
                index += 1
                if index < len(tokens) and re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", tokens[index]):
                    index += 1
                continue
            if any(token.startswith(f"{option}=") for option in MAKE_OPTIONS_WITH_VALUE):
                index += 1
                continue
            if re.fullmatch(r"-(?:C|f|I|o|W).+", token) or re.fullmatch(
                r"-(?:j|l)[0-9]+(?:\.[0-9]+)?", token
            ):
                index += 1
                continue
            if token.startswith("-") or MAKE_ASSIGNMENT.match(token):
                index += 1
                continue
            roots.add(token)
            index += 1
    return roots


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
    root = root.resolve()
    makefile = root / "Makefile"
    makefile_text = makefile.read_text(encoding="utf-8")
    workflow_sources: list[str] = []
    for relative in MANDATORY_WORKFLOWS:
        path = root / relative
        if path.exists():
            workflow_sources.append(path.read_text(encoding="utf-8"))

    make_roots = {"preflight"}
    for source in workflow_sources:
        make_roots.update(workflow_make_roots(source))
    sources = [make_targets_text(makefile_text, make_roots), *workflow_sources]

    pending = set().union(*(referenced_paths(source) for source in sources))
    visited: set[str] = set()
    failures: list[str] = []
    while pending:
        relative = pending.pop()
        if relative in visited:
            continue
        visited.add(relative)
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError:
            failures.append(f"mandatory validation path escapes repository: {relative}")
            continue
        if not path.is_file():
            continue
        if PRODUCT_RUNNER.fullmatch(path.name):
            failures.append(f"mandatory validation reaches product runner {relative}")
        if path.suffix == ".json":
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if relative not in RETAINED_RESULT_INTEGRITY and has_product_acceptance_shape(value):
                failures.append(f"mandatory validation reaches product acceptance policy {relative}")
            continue
        # Test modules may exercise reference adapters with controlled fixtures.
        # Other reached entrypoints are part of the mandatory execution graph.
        if path.suffix == ".sh" or (path.suffix == ".py" and not path.name.endswith("_test.py")):
            text = path.read_text(encoding="utf-8")
            references = referenced_paths(text)
            if relative in INERT_PRODUCT_REFERENCES:
                references = {
                    reference
                    for reference in references
                    if not PRODUCT_RUNNER.fullmatch(Path(reference).name)
                }
            pending.update(references)
            nested_make_roots = workflow_make_roots(text)
            if nested_make_roots:
                pending.update(
                    referenced_paths(make_targets_text(makefile_text, nested_make_roots))
                )
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
