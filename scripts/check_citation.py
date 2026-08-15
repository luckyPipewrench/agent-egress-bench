#!/usr/bin/env python3
"""Check that CITATION.cff describes its authors as people.

CFF 1.2.0 defines two author shapes. A person carries `given-names` and
`family-names`; an entity, meaning an organization or team, carries `name`.
Both validate against the schema, so a human written as `name: Jane Doe` is
accepted and then cited as an organization by every downstream tool. Schema
validation proves shape, not meaning, which is why this check exists.

Every author in this repository is a person. If an organization is ever added
as an author, this check fails loudly and whoever adds it updates the rule
deliberately, which is the intended cost: a citation that misattributes
authorship is worse than a build that stops.
"""

import sys
from pathlib import Path

import yaml


CITATION_PATH = Path("CITATION.cff")


def check(root: Path) -> int:
    path = root / CITATION_PATH
    if not path.is_file():
        raise ValueError(f"missing {CITATION_PATH}")

    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{CITATION_PATH} must be a YAML mapping")

    authors = document.get("authors")
    if not isinstance(authors, list) or not authors:
        raise ValueError(f"{CITATION_PATH} declares no authors")

    for index, author in enumerate(authors):
        label = f"{CITATION_PATH} authors[{index}]"
        if not isinstance(author, dict):
            raise ValueError(f"{label} must be a mapping")
        if "name" in author:
            raise ValueError(
                f"{label} uses the CFF entity field 'name', which cites a human as an "
                "organization; use 'given-names' and 'family-names'"
            )
        if not author.get("family-names"):
            raise ValueError(f"{label} has no 'family-names'")

    return len(authors)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        count = check(root)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"check-citation: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-citation: OK ({count} author(s) cited as people)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
