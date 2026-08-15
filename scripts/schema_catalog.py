#!/usr/bin/env python3
"""Build the generated public inventory for versioned JSON Schema documents.

The catalog maps a schema's declared identity to bytes a consumer can verify.
It does NOT define that identity. A JSON Schema `$id` names a resource and is
not required to be fetchable, so the catalog reads whatever each schema already
declares and never rewrites it. Publishing a resolvable location is the
catalog's job precisely so that identity can stay fixed.
"""

import hashlib
import json
import re
import subprocess
from pathlib import Path


VERSIONED_SCHEMA_FILENAME = re.compile(r"^.+-v[0-9]+\.schema\.json$")
CATALOG_PATH = Path("schemas/index.json")

# Every directory holding published versioned schemas. The verifier copies are
# governed assets in their own right: a consumer validating a Control Evidence
# document reaches for those bytes, so a catalog that omitted them would answer
# "unknown schema" for records the repository publishes.
SCHEMA_ROOTS = (
    "schemas",
    "control-evidence/v0/verifier/schemas",
    "control-evidence/v1/verifier/schemas",
    "control-evidence/g2/authentication/schemas/cee-v0",
)


def head_commit(root: Path) -> str:
    """Return the checkout's HEAD commit, or an empty string outside git.

    Used only when publishing a release copy. Returns empty rather than
    raising in a release tarball or vendored tree, where generation must
    still work.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return ""
    return result.stdout.strip()


def schema_entries(root: Path, roots=SCHEMA_ROOTS):
    """Return catalog entries derived from every published schema root.

    `roots` is injectable for tests only. Production uses the explicit
    SCHEMA_ROOTS tuple rather than discovering directories, so deleting or
    renaming a published schema root fails here instead of silently producing
    a smaller catalog that still looks complete.
    """
    entries = []
    seen_ids = {}
    for relative_root in roots:
        schema_dir = root / relative_root
        if not schema_dir.is_dir():
            raise ValueError(f"missing schema directory: {relative_root}")
        for path in sorted(schema_dir.glob("*.schema.json")):
            if not VERSIONED_SCHEMA_FILENAME.fullmatch(path.name):
                continue
            relative = path.relative_to(root).as_posix()
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ValueError(f"cannot read schema {relative}: {exc}") from exc
            if not isinstance(document, dict):
                raise ValueError(f"schema must be a JSON object: {relative}")
            declared = document.get("$id")
            if not isinstance(declared, str) or not declared:
                raise ValueError(f"{relative}: no $id to catalog")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            # Two files may share one identity only when their bytes are
            # identical, which is what the governed verifier copies are. If
            # they differ, a consumer resolving that identity cannot tell
            # which contract applies, so refuse to publish a catalog that
            # cannot answer its own lookup.
            seen_ids.setdefault(declared, []).append((relative, digest))
            entries.append({"path": relative, "$id": declared, "sha256": digest})

    for declared, occurrences in sorted(seen_ids.items()):
        digests = {digest for _, digest in occurrences}
        if len(digests) > 1:
            paths = ", ".join(sorted(path for path, _ in occurrences))
            raise ValueError(
                f"{declared} is declared by files with different bytes: {paths}"
            )

    if not entries:
        raise ValueError("no versioned schemas discovered")
    return entries


def rendered_catalog(root: Path, source_commit: str = "", release: str = "", roots=SCHEMA_ROOTS) -> bytes:
    """Render the catalog.

    The in-repo copy carries no provenance fields on purpose. A commit cannot
    describe the commit that contains it, so embedding one would make the
    committed catalog permanently disagree with its own regeneration check and
    train everyone to ignore that check.

    Provenance belongs on the published copy instead, which is generated after
    the commit exists and names the commit and release it was cut from. A
    consumer pinning that artifact can map identity to bytes and say which
    repository state produced them.
    """
    catalog = {
        "format": 1,
        "repository": "https://github.com/luckyPipewrench/agent-egress-bench",
    }
    if source_commit:
        catalog["source_commit"] = source_commit
    if release:
        catalog["release"] = release
    catalog["schemas"] = schema_entries(root, roots)
    return (json.dumps(catalog, indent=2) + "\n").encode("utf-8")
