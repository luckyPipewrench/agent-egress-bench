#!/usr/bin/env python3
"""Build the outward schema-discovery feed from the checked-in catalog.

This feed makes schema identities easy to enumerate from a stable repository
path. It deliberately contains repository paths rather than retrieval URLs:
an ``$id`` remains an identifier, while a release catalog supplies immutable
commit-pinned retrieval locations.
"""

import errno
import hashlib
import json
import os
import stat
from pathlib import Path

from pathlib import PurePosixPath

from schema_catalog import CATALOG_PATH, SCHEMA_ROOTS


FEED_PATH = Path("schemas/discovery.json")


def catalog_bytes(root: Path) -> bytes:
    path = root / CATALOG_PATH
    # Same two-lookup hole the schema entries just closed: is_symlink/is_file then read_bytes
    # can describe two different objects. Open once and read that descriptor.
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError(f"schema catalog must be a regular file: {CATALOG_PATH}") from exc
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"schema catalog must be a regular file: {CATALOG_PATH}")
        # Same parent-directory hole the entry reader closes. O_NOFOLLOW covers the final component
        # only, so a swapped parent could pair the published catalog name with a digest taken from a
        # different object until the resolved name is bound to the one actually opened.
        try:
            resolved = path.resolve().stat()
        except OSError as exc:
            raise ValueError(f"schema catalog could not be resolved: {CATALOG_PATH}") from exc
        if (resolved.st_dev, resolved.st_ino) != (status.st_dev, status.st_ino):
            raise ValueError(f"schema catalog changed while it was being read: {CATALOG_PATH}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            contents = handle.read()
    finally:
        os.close(descriptor)
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
    digests: dict[str, str] = {}
    seen_paths: set[str] = set()
    copies: dict[str, list[str]] = {}
    canonical: dict[str, str] = {}
    for index, entry in enumerate(schemas):
        if not isinstance(entry, dict) or set(entry) != {"path", "$id", "sha256"}:
            raise ValueError(f"schema catalog entry {index} has invalid fields")
        path, schema_id = entry["path"], entry["$id"]
        if not isinstance(path, str) or not path or not isinstance(schema_id, str) or not schema_id:
            raise ValueError(f"schema catalog entry {index} has an invalid identity")
        contents = _contained_file_bytes(root, index, path)
        digest = entry["sha256"]
        if not isinstance(digest, str) or not digest:
            raise ValueError(f"schema catalog entry {index} has an invalid digest")
        # Hash the FILE. Comparing the catalog's own digest strings only proves the catalog agrees
        # with itself, so a manipulated catalog could declare two divergent files equivalent and this
        # feed would publish that claim. The bytes on disk are the only thing worth trusting here.
        # These bytes come from the descriptor containment was checked against, so the check and the
        # hash cannot describe two different objects.
        actual = hashlib.sha256(contents).hexdigest()
        if actual != digest:
            raise ValueError(f"schema catalog entry {index} digest does not match {path!r}")
        # An identity that names two DIFFERENT files is a contradiction, not a duplicate. Refuse it
        # rather than silently picking one, because either choice publishes a wrong answer.
        if schema_id in digests and digests[schema_id] != digest:
            raise ValueError(f"schema catalog lists identity {schema_id!r} with differing content")
        digests[schema_id] = digest
        # A repeated path is a contradiction in the catalog, not something to emit twice.
        if path in seen_paths:
            raise ValueError(f"schema catalog lists path {path!r} more than once")
        seen_paths.add(path)
        if path.startswith("schemas/"):
            if schema_id in canonical:
                raise ValueError(f"schema catalog lists two canonical paths for identity {schema_id!r}")
            canonical[schema_id] = path
        else:
            copies.setdefault(schema_id, []).append(path)
    for schema_id in sorted(digests):
        if schema_id not in canonical:
            raise ValueError(f"schema catalog has no canonical schemas/ path for identity {schema_id!r}")
        record = {"$id": schema_id, "path": canonical[schema_id]}
        duplicates = sorted(copies.get(schema_id, ()))
        if duplicates:
            # Named, not dropped. These are byte-identical vendored copies; a consumer resolving by
            # identity uses `path`, and anyone auditing the tree can still see where the copies live.
            record["copies"] = duplicates
        entries.append(record)
    return entries


def _contained_file_bytes(root: Path, index: int, path: str) -> bytes:
    """Return the bytes of a catalog entry, refusing any path that does not RESOLVE inside the
    published schema roots.

    Containment and content come from ONE open descriptor on purpose. Validating a path and then
    reading it back by name is two separate lookups of the same name, so a replacement in between
    would let the check and the hash describe different objects.

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
    # O_NOFOLLOW rejects a final-component symlink in the same operation that opens the file, which
    # a separate is_symlink() check cannot do: between the check and the open, the name can change.
    try:
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        # Keep the refusals distinguishable. The open reports one failure where the previous
        # separate checks reported three, and collapsing them would hide which one a catalog hit.
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise ValueError(f"schema catalog entry {index} path is a symlink: {path!r}") from exc
        if exc.errno == errno.ENOENT:
            raise ValueError(f"schema catalog entry {index} path does not exist: {path!r}") from exc
        if exc.errno == errno.EISDIR:
            raise ValueError(f"schema catalog entry {index} path is not a regular file: {path!r}") from exc
        raise ValueError(f"schema catalog entry {index} path is not a readable regular file: {path!r}") from exc
    try:
        status = os.fstat(descriptor)
        # Containment says where a path LANDS, not that anything is there. A directory satisfies the
        # root check and still publishes a feed entry a consumer cannot fetch.
        if not stat.S_ISREG(status.st_mode):
            raise ValueError(f"schema catalog entry {index} path is not a regular file: {path!r}")
        target = candidate.resolve()
        # Bind the resolved NAME to the OPENED inode. A symlinked parent directory is the one escape
        # O_NOFOLLOW does not cover, and resolving alone would answer for a different object than the
        # one being read. Disagreement means the tree changed underneath this walk, so refuse.
        try:
            resolved = target.stat()
        except OSError as exc:
            raise ValueError(f"schema catalog entry {index} path could not be resolved: {path!r}") from exc
        if (resolved.st_dev, resolved.st_ino) != (status.st_dev, status.st_ino):
            raise ValueError(f"schema catalog entry {index} path changed while it was being read: {path!r}")
        # Resolve the checkout once and require each published root to BE the directory of that
        # name inside it. Resolving `root / allowed` on its own measures containment against
        # wherever a symlinked root points: with `schemas` a link to /etc, the allowed root becomes
        # /etc and every file under /etc is "contained". O_NOFOLLOW does not cover this, because the
        # symlink is a parent component and never the final one.
        try:
            checkout = root.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"schema catalog root could not be resolved: {root}") from exc
        allowed_roots = []
        for allowed in SCHEMA_ROOTS:
            allowed_root = (root / allowed).resolve()
            if allowed_root != checkout / allowed:
                raise ValueError(f"published schema root {allowed!r} does not resolve inside the checkout")
            allowed_roots.append(allowed_root)
        contained = any(target == allowed_root or allowed_root in target.parents for allowed_root in allowed_roots)
        if not contained:
            raise ValueError(f"schema catalog entry {index} path resolves outside the published schema roots: {path!r}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            return handle.read()
    finally:
        os.close(descriptor)

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
