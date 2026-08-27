#!/usr/bin/env python3
"""Run named Go contract proofs without treating an empty -run match as success."""

import argparse
import subprocess
import sys
from pathlib import Path


def run_test(workdir, test_name):
    listed = subprocess.run(
        ["go", "test", "-list", f"^{test_name}$", "."],
        cwd=workdir,
        text=True,
        capture_output=True,
        check=False,
    )
    if listed.returncode != 0:
        raise RuntimeError(f"{workdir}: go test -list failed:\n{listed.stderr}")
    if test_name not in listed.stdout.splitlines():
        raise RuntimeError(f"{workdir}: required Go contract test is missing: {test_name}")

    executed = subprocess.run(
        ["go", "test", "-count=1", "-run", f"^{test_name}$", "."],
        cwd=workdir,
        check=False,
    )
    if executed.returncode != 0:
        raise RuntimeError(f"{workdir}: Go contract test failed: {test_name}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("workdir", type=Path)
    parser.add_argument("test_name")
    args = parser.parse_args(argv)
    try:
        run_test(args.workdir, args.test_name)
    except (OSError, RuntimeError) as exc:
        print(f"check-go-consumer-tests: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"check-go-consumer-tests: OK ({args.workdir}: {args.test_name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
