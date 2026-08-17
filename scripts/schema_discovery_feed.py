#!/usr/bin/env python3
"""Build the outward schema-discovery feed from the checked-in catalog.

This feed makes schema identities easy to enumerate from a stable repository
path. It deliberately contains repository paths rather than retrieval URLs:
an ``$id`` remains an identifier, while a release catalog supplies immutable
commit-pinned retrieval locations.
"""

import hashlib
import json
from pathlib import Path

from schema_catalog import CATALOG_PATH


FEED_PATH = Path("schemas/discovery.json")


def catalog_bytes(root: Path) -> bytes:
    path = root / CATALOG_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"schema catalog must be a regular file: {CATALOG_PATH}")
    contents = path.read_bytes()
    if not contents:
        raise ValueError(f"schema catalog is empty: {CATALOG_PATH}")
    return contents


def catalog_entries(root: Path) -> list[dict[str, str]]:
    try:
        catalog = json.loads(catalog_bytes(root))
    except json.JSONDecodeError as exc:
        raise ValueError(f"schema catalog is not JSON: {exc}") from exc
    if not isinstance(catalog, dict) or set(catalog) != {"format", "repository", "schemas"}:
        raise ValueError("schema catalog has invalid fields")
    schemas = catalog.get("schemas")
    if not isinstance(schemas, list) or not schemas:
        raise ValueError("schema catalog has no schema entries")
    entries: list[dict[str, str]] = []
    for index, entry in enumerate(schemas):
        if not isinstance(entry, dict) or set(entry) != {"path", "$id", "sha256"}:
            raise ValueError(f"schema catalog entry {index} has invalid fields")
        path, schema_id = entry["path"], entry["$id"]
        if not isinstance(path, str) or not path or not isinstance(schema_id, str) or not schema_id:
            raise ValueError(f"schema catalog entry {index} has an invalid identity")
        entries.append({"path": path, "$id": schema_id})
    return entries


def rendered_feed(root: Path) -> bytes:
    """Render a deterministic feed that points consumers to the catalog."""
    catalog = catalog_bytes(root)
    feed = {
        "format": 1,
        "catalog": CATALOG_PATH.as_posix(),
        "catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "schemas": catalog_entries(root),
    }
    return (json.dumps(feed, indent=2) + "\n").encode("utf-8")
