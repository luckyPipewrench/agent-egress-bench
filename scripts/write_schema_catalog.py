#!/usr/bin/env python3
"""Write the generated schema catalog from the canonical schema files."""

from pathlib import Path

from schema_catalog import CATALOG_PATH, rendered_catalog


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    destination = root / CATALOG_PATH
    destination.write_bytes(rendered_catalog(root))
    print(f"write-schema-catalog: wrote {CATALOG_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
