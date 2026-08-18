#!/usr/bin/env python3
"""Write the generated outward schema-discovery feed."""

import os
import tempfile
from pathlib import Path

from schema_discovery_feed import FEED_PATH, rendered_feed


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    destination = root / FEED_PATH
    if destination.is_symlink():
        raise SystemExit(f"write-schema-discovery-feed: refusing symlinked destination: {FEED_PATH}")
    payload = rendered_feed(root)
    # Checking the destination and then writing to it are two operations, so a replacement in between
    # would redirect this write. Create an exclusive temporary file in the same directory and replace
    # the destination atomically instead, which never writes through whatever the name points at.
    handle, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".discovery-", suffix=".json")
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    except BaseException:
        os.unlink(temporary)
        raise
    print(f"write-schema-discovery-feed: wrote {FEED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
