#!/usr/bin/env python3
"""Check documentation ownership links and local Markdown targets."""

import re
import sys
from pathlib import Path
from urllib.parse import unquote


RETIRED_REFERENCES = (
    "docs/SCORING.md",
    "docs/methodology.md",
    "(SCORING.md)",
    "(methodology.md)",
)
TEXT_SUFFIXES = {".md", ".html", ".go", ".py", ".yml", ".yaml"}
MARKDOWN_LINK = re.compile(r"!?\[[^]]*\]\(([^)]+)\)")
LINK_TITLE = re.compile(r"^(?P<target>\S+)(?:\s+(?:\"[^\"]*\"|'[^']*'|\([^)]*\)))?$")
REQUIRED_OWNERS = (
    "docs/SPEC.md",
    "docs/RUNNER.md",
    "docs/gauntlet.md",
    "docs/GOVERNANCE.md",
)
AGENT_CONTRACT_TOKENS = (
    "schema_version",
    "expected_verdict",
    "capability_tags:",
    "supports fields",
)


def fail(message):
    raise ValueError(message)


def text_files(root):
    for path in sorted(root.rglob("*")):
        if ".git" in path.parts or not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size == 0:
            if path.suffix in {".md", ".html"}:
                fail(f"documentation input is empty: {path.relative_to(root)}")
            continue
        yield path


def local_markdown_target(raw_target):
    target = raw_target.strip()
    if target.startswith("<"):
        closing = target.find(">")
        if closing <= 1:
            fail(f"invalid angle-bracket Markdown target {raw_target!r}")
        target = target[1:closing]
    else:
        match = LINK_TITLE.fullmatch(target)
        if not match:
            fail(f"invalid local Markdown target {raw_target!r}")
        target = match.group("target")
    return unquote(target).split("#", 1)[0]


def check(root):
    files = list(text_files(root))
    markdown = [path for path in files if path.suffix == ".md"]
    if not files or not markdown:
        fail("documentation scan found no non-empty inputs")

    failures = []
    links_checked = 0
    for path in files:
        text = path.read_text(encoding="utf-8")
        if path != Path(__file__).resolve():
            for retired in RETIRED_REFERENCES:
                if retired in text:
                    failures.append(f"{path.relative_to(root)}: references retired owner {retired}")
        if path.suffix != ".md":
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            for raw_target in MARKDOWN_LINK.findall(line):
                target = local_markdown_target(raw_target)
                if not target or "://" in target or target.startswith("mailto:"):
                    continue
                links_checked += 1
                resolved = path.parent / target
                if not resolved.exists():
                    failures.append(
                        f"{path.relative_to(root)}:{line_number}: missing local link target {raw_target}"
                    )
    if links_checked == 0:
        fail("documentation scan found no local Markdown links")

    agents = (root / "AGENTS.md").read_text(encoding="utf-8")
    for owner in REQUIRED_OWNERS:
        if owner not in agents:
            failures.append(f"AGENTS.md: missing contract owner link {owner}")
    for token in AGENT_CONTRACT_TOKENS:
        if token in agents:
            failures.append(f"AGENTS.md: contains contract-definition token {token!r}")

    if failures:
        fail("\n  ".join(failures))
    return len(files), len(markdown), links_checked


def main():
    root = Path(__file__).resolve().parents[1]
    try:
        files, markdown, links = check(root)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"check-docs: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-docs: OK ({files} text files, {markdown} Markdown files, {links} local links)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
