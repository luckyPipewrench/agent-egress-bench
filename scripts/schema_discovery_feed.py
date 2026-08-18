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


def catalog_entries(root: Path, contents: bytes) -> list[dict[str, str]]:
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
        _require_contained_path(root, index, path)
        entries.append({"path": path, "$id": schema_id})
    return entries


def _require_contained_path(root: Path, index: int, path: str) -> None:
    """Refuse any catalog path that does not RESOLVE inside the published schema roots.

    The feed is published outward and consumers join these values onto their own checkout, so a
    value that escapes the schema roots escapes on their machine. A lexical check alone cannot
    establish that: a component such as ``.. `` is normalised to a parent traversal by Win32 path
    rules, and a symlink inside an allowed root resolves wherever its target points. So this rejects
    the non-portable spellings first and then resolves the real target and requires it to sit beneath
    a resolved allowed root.
    """
    if path != PurePosixPath(path).as_posix() or path.startswith("/") or "\\" in path:
        raise ValueError(f"schema catalog entry {index} path is not a normalised relative path: {path!r}")
    parts = PurePosixPath(path).parts
    if not parts or any(part in ("..", ".") for part in parts):
        raise ValueError(f"schema catalog entry {index} path is not a normalised relative path: {path!r}")
    for part in parts:
        # Trailing dots and spaces, drive letters, and alternate data stream syntax all mean
        # something other than a plain name once a consumer resolves them on Windows.
        if part != part.strip() or part.endswith(".") or ":" in part:
            raise ValueError(f"schema catalog entry {index} path component is not portable: {path!r}")
    if not any(path.startswith(f"{allowed}/") for allowed in SCHEMA_ROOTS):
        raise ValueError(f"schema catalog entry {index} path is outside the published schema roots: {path!r}")
    candidate = root / path
    # Containment says where a path LANDS, not that anything is there. A missing path or a directory
    # satisfies the root check and still publishes a feed entry a consumer cannot fetch, so require a
    # real regular file before resolving. Reject a symlink by its own status rather than by where it
    # points, so a link inside an allowed root cannot pass simply by resolving back inside.
    if candidate.is_symlink():
        raise ValueError(f"schema catalog entry {index} path is a symlink: {path!r}")
    if not candidate.exists():
        raise ValueError(f"schema catalog entry {index} path does not exist: {path!r}")
    if not candidate.is_file():
        raise ValueError(f"schema catalog entry {index} path is not a regular file: {path!r}")
    target = candidate.resolve()
    for allowed in SCHEMA_ROOTS:
        allowed_root = (root / allowed).resolve()
        if target == allowed_root or allowed_root in target.parents:
            return
    raise ValueError(f"schema catalog entry {index} path resolves outside the published schema roots: {path!r}")

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
        "schemas": catalog_entries(root, catalog),
    }
    return (json.dumps(feed, indent=2) + "\n").encode("utf-8")
