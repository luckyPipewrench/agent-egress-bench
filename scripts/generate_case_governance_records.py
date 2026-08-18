#!/usr/bin/env python3
"""Generate deterministic per-case governance decision records."""

import argparse
import os
import sys
import tempfile
from pathlib import Path

import case_governance


def write_record(path, content):
    if path.is_symlink():
        raise ValueError(f"refusing to write through symlinked record path: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
        # mkstemp creates 0o600 and os.replace keeps it, so without this every generated record would
        # be committed owner-read-only while the rest of the repository is world-readable.
        umask = os.umask(0)
        os.umask(umask)
        os.chmod(temporary, 0o666 & ~umask)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _require_contained_output(root: Path, output: Path) -> None:
    """Refuse an output directory that is not plainly inside the repository.

    Checking only the final component misses a symlink at any ancestor, and this function then
    creates directories, writes records, and DELETES stale ones through it. That turns a documented
    generator into a way to write and remove files anywhere the invoking user can reach.
    """
    root = root.resolve()
    current = output if output.is_absolute() else (root / output)
    seen = current
    while True:
        if seen.is_symlink():
            raise ValueError(f"decision-record path component is a symlink: {seen}")
        if seen == seen.parent:
            break
        if seen == root:
            break
        seen = seen.parent
    resolved = current.resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"decision-record directory is outside the repository: {output}")


def generate(root, output):
    root = Path(root).resolve()
    output = Path(output)
    if not output.is_absolute():
        output = root / output
    _require_contained_output(root, output)
    output.mkdir(parents=True, exist_ok=True)
    if not output.is_dir():
        raise ValueError(f"decision-record path is not a directory: {output}")
    cases = case_governance.load_cases(root)
    expected_names = set()
    for case_id, case in sorted(cases.items()):
        name = f"{case_id}{case_governance.DECISION_SUFFIX}"
        expected_names.add(name)
        write_record(output / name, case_governance.rendered_record(case_governance.record_for_case(case)))
    # Remove records for cases that no longer exist. Without this, a renamed or deleted case leaves a
    # stale record behind and regeneration is not self-consistent: the checker then fails on a record
    # the generator just declined to clean up. Only files carrying the governed suffix are touched,
    # and a symlink is refused rather than followed.
    for stale in sorted(output.iterdir()):
        if stale.name in expected_names or not stale.name.endswith(case_governance.DECISION_SUFFIX):
            continue
        if stale.is_symlink() or not stale.is_file():
            raise ValueError(f"refusing to remove non-regular decision record: {stale.name}")
        stale.unlink()
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=case_governance.DECISION_DIRECTORY)
    args = parser.parse_args()
    try:
        count = generate(args.repo_root, args.output)
    except (OSError, ValueError) as exc:
        print(f"generate-case-governance-records: FAIL - {exc}", file=sys.stderr)
        return 1
    print(f"generate-case-governance-records: OK ({count} records written)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
