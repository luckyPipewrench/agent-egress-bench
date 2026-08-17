#!/usr/bin/env python3
"""Write the generated outward schema-discovery feed."""

from pathlib import Path

from schema_discovery_feed import FEED_PATH, rendered_feed


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    destination = root / FEED_PATH
    if destination.is_symlink():
        raise SystemExit(f"write-schema-discovery-feed: refusing symlinked destination: {FEED_PATH}")
    destination.write_bytes(rendered_feed(root))
    print(f"write-schema-discovery-feed: wrote {FEED_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
