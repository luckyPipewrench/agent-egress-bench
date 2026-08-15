#!/usr/bin/env python3
"""Write the generated schema catalog from the canonical schema files.

Default output is the deterministic in-repo catalog. `--release` adds the
source commit and release name for a published artifact, which is the copy a
vendor should pin.
"""

import argparse
from pathlib import Path

from schema_catalog import CATALOG_PATH, head_commit, rendered_catalog


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        default="",
        help="release name to record in a published catalog artifact",
    )
    parser.add_argument(
        "--output",
        default="",
        help="destination path (defaults to the in-repo catalog)",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    destination = Path(args.output) if args.output else root / CATALOG_PATH

    # A symlinked destination writes through to whatever it points at, so
    # generating the catalog could overwrite an unrelated file. Refuse instead
    # of following it. This fails loudly and only ever on a destination nobody
    # intended, so it cannot block ordinary generation.
    if destination.is_symlink():
        parser.error(f"refusing to write through a symlinked destination: {destination}")

    source_commit = head_commit(root) if args.release else ""
    destination.write_bytes(rendered_catalog(root, source_commit, args.release))
    print(f"write-schema-catalog: wrote {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
