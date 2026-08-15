#!/usr/bin/env python3
"""Require the checked-in schema catalog to match the canonical schema files."""

import json
import sys
from pathlib import Path

from schema_catalog import CATALOG_PATH, rendered_catalog


def check(root: Path) -> int:
    catalog_path = root / CATALOG_PATH
    if catalog_path.is_symlink():
        raise ValueError(f"schema catalog must be a regular file, not a symlink: {CATALOG_PATH}")
    if not catalog_path.is_file():
        raise ValueError(f"missing schema catalog: {CATALOG_PATH}")
    actual = catalog_path.read_bytes()
    if not actual:
        raise ValueError(f"empty schema catalog: {CATALOG_PATH}")
    expected = rendered_catalog(root)
    if actual != expected:
        raise ValueError(
            f"{CATALOG_PATH} is stale; regenerate it from the canonical schemas with "
            "python3 scripts/write_schema_catalog.py"
        )
    return len(json.loads(actual)["schemas"])


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        count = check(root)
    except (OSError, ValueError) as exc:
        print(f"check-schema-catalog: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-schema-catalog: OK ({count} versioned schemas indexed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
