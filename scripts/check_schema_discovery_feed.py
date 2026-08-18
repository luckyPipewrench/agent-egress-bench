#!/usr/bin/env python3
"""Require the outward schema-discovery feed to match schemas/index.json."""

import json
import sys
from pathlib import Path

from schema_discovery_feed import FEED_PATH, rendered_feed


def check(root: Path) -> int:
    path = root / FEED_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"schema discovery feed must be a regular file: {FEED_PATH}")
    actual = path.read_bytes()
    if not actual:
        raise ValueError(f"schema discovery feed is empty: {FEED_PATH}")
    expected = rendered_feed(root)
    if actual != expected:
        raise ValueError(
            f"{FEED_PATH} is stale; regenerate it from schemas/index.json with "
            "python3 scripts/write_schema_discovery_feed.py"
        )
    return len(json.loads(actual)["schemas"])


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        count = check(root)
    except (OSError, ValueError) as exc:
        print(f"check-schema-discovery-feed: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-schema-discovery-feed: OK ({count} schema entries indexed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
