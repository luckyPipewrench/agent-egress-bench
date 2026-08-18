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

from pathlib import PurePosixPath

from schema_catalog import CATALOG_PATH, SCHEMA_ROOTS


FEED_PATH = Path("schemas/discovery.json")


def catalog_bytes(root: Path) -> bytes:
    path = root / CATALOG_PATH
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"schema catalog must be a regular file: {CATALOG_PATH}")
    contents = path.read_bytes()
    if not contents:
        raise ValueError(f"schema catalog is empty: {CATALOG_PATH}")
    return contents


def catalog_entries(contents: bytes) -> list[dict[str, str]]:
    try:
        catalog = json.loads(contents)
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
        _require_contained_path(index, path)
        entries.append({"path": path, "$id": schema_id})
    return entries


def _require_contained_path(index: int, path: str) -> None:
    """Refuse any catalog path that would resolve outside the published schema roots.

    The feed is consumed by readers that join these values onto a checkout root, so an absolute
    path or a parent-traversal segment would send them outside the repository. Validate here rather
    than trusting the catalog, because the feed is the artifact published outward.
    """
    if path != PurePosixPath(path).as_posix() or path.startswith("/") or "\\" in path:
        raise ValueError(f"schema catalog entry {index} path is not a normalised relative path: {path!r}")
    parts = PurePosixPath(path).parts
    if not parts or any(part in ("..", ".") for part in parts):
        raise ValueError(f"schema catalog entry {index} path is not a normalised relative path: {path!r}")
    if not any(path.startswith(f"{allowed}/") for allowed in SCHEMA_ROOTS):
        raise ValueError(f"schema catalog entry {index} path is outside the published schema roots: {path!r}")

def rendered_feed(root: Path) -> bytes:
    """Render a deterministic feed that points consumers to the catalog."""
    # One read, one snapshot. The digest and the advertised identities must describe the SAME bytes,
    # or a concurrent catalog replacement produces a feed whose checksum silently refers to a
    # different catalog than the entries it lists.
    catalog = catalog_bytes(root)
    feed = {
        "format": 1,
        "catalog": CATALOG_PATH.as_posix(),
        "catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "schemas": catalog_entries(catalog),
    }
    return (json.dumps(feed, indent=2) + "\n").encode("utf-8")
