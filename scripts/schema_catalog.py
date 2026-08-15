#!/usr/bin/env python3
"""Build the generated public inventory for versioned JSON Schema documents."""

import hashlib
import json
import re
from pathlib import Path


PUBLIC_SCHEMA_ID_PREFIX = (
    "https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/main/schemas/"
)
VERSIONED_SCHEMA_FILENAME = re.compile(r"^.+-v[0-9]+\.schema\.json$")
CATALOG_PATH = Path("schemas/index.json")


def schema_entries(root: Path):
    """Return canonical catalog entries derived from the repository schemas."""
    schema_dir = root / "schemas"
    if not schema_dir.is_dir():
        raise ValueError("missing schemas directory")

    entries = []
    for path in sorted(schema_dir.glob("*.schema.json")):
        if not VERSIONED_SCHEMA_FILENAME.fullmatch(path.name):
            continue
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read schema {path.relative_to(root)}: {exc}") from exc
        if not isinstance(document, dict):
            raise ValueError(f"schema must be a JSON object: {path.relative_to(root)}")
        expected_id = PUBLIC_SCHEMA_ID_PREFIX + path.name
        if document.get("$id") != expected_id:
            raise ValueError(f"{path.relative_to(root)}: $id must be {expected_id!r}")
        entries.append(
            {
                "path": path.relative_to(root).as_posix(),
                "$id": expected_id,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    if not entries:
        raise ValueError("no versioned schemas discovered")
    return entries


def rendered_catalog(root: Path) -> bytes:
    catalog = {
        "format": 1,
        "repository": "https://github.com/luckyPipewrench/agent-egress-bench",
        "schemas": schema_entries(root),
    }
    return (json.dumps(catalog, indent=2) + "\n").encode("utf-8")
