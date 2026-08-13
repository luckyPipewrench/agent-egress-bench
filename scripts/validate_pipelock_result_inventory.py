#!/usr/bin/env python3
"""Build and validate the historical Pipelock result migration inventory."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


INVENTORY_PATH = Path("migration/pipelock-result-inventory-v1.json")
PUBLIC_POINTERS = (
    Path("gauntlet-site/gauntlet-results.json"),
    Path("gauntlet-site/latest-verified.json"),
)
RESULTS_ROOT = Path("gauntlet-site/results/pipelock")
SOURCE_REPOSITORY = "luckyPipewrench/agent-egress-bench"
DESTINATION_REPOSITORY = "luckyPipewrench/pipelab.org"
DESTINATION_PREFIX = Path("static/gauntlet/evidence")


def sha256_bytes(value):
    return hashlib.sha256(value).hexdigest()


def git(repo_root, *args):
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def git_file_bytes(repo_root, commit, source_path):
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "show", f"{commit}:{source_path.as_posix()}"],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError(f"inventory source is missing from source_commit: {source_path}")
    return completed.stdout


def public_paths(repo_root):
    paths = list(PUBLIC_POINTERS)
    result_root = repo_root / RESULTS_ROOT
    if result_root.is_symlink() or not result_root.is_dir():
        raise ValueError("Pipelock result store must be a real directory")
    for path in sorted(result_root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"inventory source cannot be a symlink: {path.relative_to(repo_root)}")
        if path.is_file():
            paths.append(path.relative_to(repo_root))
    for path in paths:
        absolute = repo_root / path
        if absolute.is_symlink() or not absolute.is_file():
            raise ValueError(f"inventory source must be a regular file: {path}")
    return sorted(paths, key=lambda path: path.as_posix())


def public_paths_at_commit(repo_root, source_commit):
    completed = subprocess.run(
        [
            "git",
            "-C",
            str(repo_root),
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            source_commit,
            "--",
            RESULTS_ROOT.as_posix(),
        ],
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError("inventory source_commit is not retained by the repository")
    paths = [*PUBLIC_POINTERS]
    paths.extend(Path(value.decode()) for value in completed.stdout.split(b"\0") if value)
    for source_path in paths:
        git_file_bytes(repo_root, source_commit, source_path)
    return sorted(paths, key=lambda path: path.as_posix())


def destination_path(source_path):
    return DESTINATION_PREFIX / source_path.relative_to("gauntlet-site")


def entry_for(repo_root, source_path, source_commit):
    source_bytes = git_file_bytes(repo_root, source_commit, source_path)
    destination = destination_path(source_path)
    return {
        "bytes": len(source_bytes),
        "legacy_live_urls": [
            f"https://github.com/{SOURCE_REPOSITORY}/blob/main/{source_path.as_posix()}",
            f"https://raw.githubusercontent.com/{SOURCE_REPOSITORY}/main/{source_path.as_posix()}",
        ],
        "planned_destination": {
            "path": destination.as_posix(),
            "repository": DESTINATION_REPOSITORY,
            "url": f"https://pipelab.org/{destination.relative_to('static').as_posix()}",
        },
        "retention": "keep the commit-pinned source bytes as a read-only restore copy",
        "sha256": sha256_bytes(source_bytes),
        "source_path": source_path.as_posix(),
        "source_urls": [
            f"https://github.com/{SOURCE_REPOSITORY}/blob/{source_commit}/{source_path.as_posix()}",
            f"https://raw.githubusercontent.com/{SOURCE_REPOSITORY}/{source_commit}/{source_path.as_posix()}",
        ],
    }


def build_inventory(repo_root):
    source_commit = git(repo_root, "rev-parse", "HEAD")
    return {
        "entries": [entry_for(repo_root, path, source_commit) for path in public_paths(repo_root)],
        "migration": {
            "execution_owner": "luckyPipewrench/pipelock",
            "publication_owner": DESTINATION_REPOSITORY,
            "source_retention_owner": SOURCE_REPOSITORY,
            "status": "inventory_complete",
        },
        "record_verification": {
            "command": "python3 scripts/validate_gauntlet_records.py",
            "result": "verified",
        },
        "schema_version": 1,
        "source_commit": source_commit,
        "source_repository": SOURCE_REPOSITORY,
    }


def require_exact_keys(value, expected, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    actual = set(value)
    if actual != set(expected):
        raise ValueError(
            f"{label} keys differ: missing={sorted(set(expected) - actual)}, "
            f"unknown={sorted(actual - set(expected))}"
        )


def validate_entry(repo_root, entry, source_commit):
    require_exact_keys(
        entry,
        (
            "bytes",
            "legacy_live_urls",
            "planned_destination",
            "retention",
            "sha256",
            "source_path",
            "source_urls",
        ),
        "inventory entry",
    )
    source_path = Path(entry["source_path"])
    if source_path.is_absolute() or ".." in source_path.parts:
        raise ValueError(f"inventory source path is unsafe: {source_path}")
    expected = entry_for(repo_root, source_path, source_commit)
    if entry != expected:
        raise ValueError(f"inventory entry drifted from source bytes or URL contract: {source_path}")
    if source_path.is_relative_to(RESULTS_ROOT):
        current = repo_root / source_path
        if current.is_symlink() or not current.is_file():
            raise ValueError(f"immutable inventory source is missing or not a regular file: {source_path}")
        if current.read_bytes() != git_file_bytes(repo_root, source_commit, source_path):
            raise ValueError(f"immutable inventory source changed after source_commit: {source_path}")
    return source_path


def verify_record_store(repo_root):
    completed = subprocess.run(
        [sys.executable, "scripts/validate_gauntlet_records.py"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stdout.strip() or completed.stderr.strip()
        raise ValueError(f"retained record verification failed: {detail}")


def validate(repo_root, inventory_path, verify_records=True):
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    require_exact_keys(
        inventory,
        (
            "entries",
            "migration",
            "record_verification",
            "schema_version",
            "source_commit",
            "source_repository",
        ),
        "inventory",
    )
    if inventory["schema_version"] != 1:
        raise ValueError("inventory schema_version must be 1")
    if inventory["source_repository"] != SOURCE_REPOSITORY:
        raise ValueError("inventory source_repository is not canonical")
    if (
        not isinstance(inventory["source_commit"], str)
        or len(inventory["source_commit"]) != 40
        or any(character not in "0123456789abcdef" for character in inventory["source_commit"])
    ):
        raise ValueError("inventory source_commit must be a full Git commit")
    if inventory["migration"] != {
        "execution_owner": "luckyPipewrench/pipelock",
        "publication_owner": DESTINATION_REPOSITORY,
        "source_retention_owner": SOURCE_REPOSITORY,
        "status": "inventory_complete",
    }:
        raise ValueError("inventory migration ownership contract drifted")
    if inventory["record_verification"] != {
        "command": "python3 scripts/validate_gauntlet_records.py",
        "result": "verified",
    }:
        raise ValueError("inventory record verification claim drifted")
    if not isinstance(inventory["entries"], list) or not inventory["entries"]:
        raise ValueError("inventory entries must be a non-empty array")

    actual_paths = public_paths_at_commit(repo_root, inventory["source_commit"])
    recorded_paths = [
        validate_entry(repo_root, entry, inventory["source_commit"])
        for entry in inventory["entries"]
    ]
    if recorded_paths != sorted(set(recorded_paths), key=lambda path: path.as_posix()):
        raise ValueError("inventory entries must be unique and sorted by source_path")
    if recorded_paths != actual_paths:
        missing = sorted(set(actual_paths) - set(recorded_paths))
        unexpected = sorted(set(recorded_paths) - set(actual_paths))
        raise ValueError(f"inventory path set differs: missing={missing}, unexpected={unexpected}")
    if verify_records:
        verify_record_store(repo_root)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path("."))
    parser.add_argument("--inventory", type=Path, default=INVENTORY_PATH)
    parser.add_argument("--write", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    repo_root = args.repo_root.resolve()
    inventory_path = args.inventory
    if not inventory_path.is_absolute():
        inventory_path = repo_root / inventory_path
    try:
        if args.write:
            verify_record_store(repo_root)
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(
                json.dumps(build_inventory(repo_root), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        validate(repo_root, inventory_path)
    except (OSError, json.JSONDecodeError, subprocess.CalledProcessError, TypeError, ValueError) as exc:
        print(f"Pipelock result inventory: BLOCKED: {exc}")
        return 1
    print("Pipelock result inventory: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
