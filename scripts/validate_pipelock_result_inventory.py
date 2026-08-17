#!/usr/bin/env python3
"""Build and validate the historical Pipelock result migration inventory."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

import promote_gauntlet_candidate as promotion


INVENTORY_PATH = Path("migration/pipelock-result-inventory-v1.json")
PUBLIC_RESULT_CONTRACT_PATH = Path("contracts/public-result-v1.json")
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


def git_object_type(repo_root, object_name):
    completed = subprocess.run(
        ["git", "-C", str(repo_root), "cat-file", "-t", object_name],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    return completed.stdout.strip()


def git_tree_entries(repo_root, source_commit, source_path, recursive=False):
    command = ["git", "-C", str(repo_root), "ls-tree"]
    if recursive:
        command.append("-r")
    command.extend(["-z", source_commit, "--", source_path.as_posix()])
    completed = subprocess.run(command, check=False, capture_output=True)
    if completed.returncode != 0:
        raise ValueError("inventory source_commit is not retained by the repository")

    entries = []
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, object_type, _object_id = metadata.decode("ascii").split(" ", 2)
        entries.append((mode, object_type, Path(raw_path.decode("utf-8"))))
    return entries


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
    if git_object_type(repo_root, source_commit) != "commit":
        raise ValueError("inventory source_commit must resolve to a commit object")
    if git_object_type(repo_root, f"{source_commit}:{RESULTS_ROOT.as_posix()}") != "tree":
        raise ValueError("Pipelock result store must resolve to a tree at source_commit")

    entries = []
    for source_path in PUBLIC_POINTERS:
        pointer_entries = git_tree_entries(repo_root, source_commit, source_path)
        if len(pointer_entries) != 1 or pointer_entries[0][2] != source_path:
            raise ValueError(f"inventory source is missing from source_commit: {source_path}")
        entries.extend(pointer_entries)
    result_entries = git_tree_entries(repo_root, source_commit, RESULTS_ROOT, recursive=True)
    if not result_entries:
        raise ValueError("Pipelock result store must contain retained records at source_commit")
    entries.extend(result_entries)

    for mode, object_type, source_path in entries:
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise ValueError(f"inventory source must be a regular file at source_commit: {source_path}")
        git_file_bytes(repo_root, source_commit, source_path)
    paths = [source_path for _mode, _object_type, source_path in entries]
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


def validate_public_result_contract(repo_root, inventory, recorded_paths):
    contract = json.loads((repo_root / PUBLIC_RESULT_CONTRACT_PATH).read_text(encoding="utf-8"))
    require_exact_keys(
        contract,
        (
            "evidence_index",
            "record_verification",
            "required_evidence",
            "schema_required_evidence",
            "schema_version",
        ),
        "public result contract",
    )
    if contract["schema_version"] != 1:
        raise ValueError("public result contract schema_version must be 1")
    if contract["evidence_index"] != INVENTORY_PATH.as_posix():
        raise ValueError("public result contract evidence_index is not canonical")
    require_exact_keys(
        contract["record_verification"],
        ("command", "source_path"),
        "public result contract record_verification",
    )
    if contract["record_verification"]["command"] != inventory["record_verification"]["command"]:
        raise ValueError("public result contract verification command drifted from inventory")
    verifier_path = Path(contract["record_verification"]["source_path"])
    verifier = repo_root / verifier_path
    if (
        verifier_path != Path("scripts/validate_gauntlet_records.py")
        or verifier.is_symlink()
        or not verifier.is_file()
    ):
        raise ValueError("public result contract verifier source is missing or not canonical")

    required_evidence = contract["required_evidence"]
    require_exact_keys(
        required_evidence,
        ("normalized_decisions", "pinned_inputs", "raw_evidence", "reproduction", "score_and_scope"),
        "public result contract required_evidence",
    )
    if any(not isinstance(names, list) or not names for names in required_evidence.values()):
        raise ValueError("public result contract evidence roles must contain unique filenames")
    required_files = sorted(name for names in required_evidence.values() for name in names)
    if (
        required_files != sorted(set(required_files))
        or any(not isinstance(name, str) or not name or Path(name).name != name for name in required_files)
    ):
        raise ValueError("public result contract evidence roles must contain unique filenames")

    schema_evidence = contract["schema_required_evidence"]
    require_exact_keys(schema_evidence, ("4-6",), "public result contract schema_required_evidence")
    active_files = schema_evidence["4-6"]
    if (
        not isinstance(active_files, list)
        or not active_files
        or active_files != sorted(set(active_files))
        or any(not isinstance(name, str) or not name or Path(name).name != name for name in active_files)
    ):
        raise ValueError("public result contract schema evidence must contain unique sorted filenames")

    producer_files = set(promotion.evidence_files_for({"schema_version": 6}).values())
    producer_files.update(
        {
            promotion.BASELINE_SNAPSHOT_FILENAME,
            promotion.CANDIDATE_FILENAME,
            promotion.PUBLISHED_DECISION_FILENAME,
            promotion.SOURCE_BASELINE_FILENAME,
            promotion.SOURCE_PROMOTION_DECISION_FILENAME,
        }
    )
    contracted_files = set(required_files) | set(active_files)
    if contracted_files != producer_files:
        missing = sorted(producer_files - contracted_files)
        unexpected = sorted(contracted_files - producer_files)
        raise ValueError(
            f"public result contract drifted from promotion output: "
            f"missing={missing}, unexpected={unexpected}"
        )

    recorded_path_set = set(recorded_paths)
    manifest_paths = [path for path in recorded_paths if path.name == "record-manifest.json"]
    if not manifest_paths:
        raise ValueError("public result contract has no retained record manifests")
    for manifest_path in manifest_paths:
        manifest = json.loads(git_file_bytes(repo_root, inventory["source_commit"], manifest_path))
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, dict):
            raise ValueError(f"retained record manifest has no file inventory: {manifest_path}")
        candidate_path = manifest_path.parent / promotion.CANDIDATE_FILENAME
        candidate = json.loads(git_file_bytes(repo_root, inventory["source_commit"], candidate_path))
        record_required_files = set(required_files)
        if isinstance(candidate, dict) and candidate.get("schema_version") in {4, 5, 6}:
            record_required_files.update(active_files)
        missing = sorted(record_required_files - set(files))
        if missing:
            raise ValueError(f"retained record is missing public-result evidence: {manifest_path}: {missing}")
        record_root = manifest_path.parent
        missing_urls = sorted(name for name in record_required_files if record_root / name not in recorded_path_set)
        if missing_urls:
            raise ValueError(
                f"public result evidence is absent from the commit-pinned inventory: "
                f"{manifest_path}: {missing_urls}"
            )

    current_paths = public_paths(repo_root)
    current_path_set = set(current_paths)
    for manifest_path in (path for path in current_paths if path.name == "record-manifest.json"):
        manifest = json.loads((repo_root / manifest_path).read_text(encoding="utf-8"))
        files = manifest.get("files") if isinstance(manifest, dict) else None
        if not isinstance(files, dict):
            raise ValueError(f"current record manifest has no file inventory: {manifest_path}")
        candidate = json.loads(
            (repo_root / manifest_path.parent / promotion.CANDIDATE_FILENAME).read_text(encoding="utf-8")
        )
        record_required_files = set(required_files)
        if isinstance(candidate, dict) and candidate.get("schema_version") in {4, 5, 6}:
            record_required_files.update(active_files)
        missing = sorted(record_required_files - set(files))
        if missing:
            raise ValueError(f"current record is missing public-result evidence: {manifest_path}: {missing}")
        missing_paths = sorted(
            name for name in record_required_files if manifest_path.parent / name not in current_path_set
        )
        if missing_paths:
            raise ValueError(
                f"current public result evidence is missing from the repository: "
                f"{manifest_path}: {missing_paths}"
            )


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
    validate_public_result_contract(repo_root, inventory, recorded_paths)
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
