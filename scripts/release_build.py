#!/usr/bin/env python3
"""Build and verify the immutable Agent Egress Bench release contract."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SNAPSHOT_VERSION_RE = re.compile(r"^1\.0\.0-SNAPSHOT-[0-9a-f]{7}$")
IDENTITY_NAME = "release-identity.json"
CHECKSUM_NAME = "checksums.txt"
DATA_ROOTS = ("cases", "schemas", "contracts", "capability-registry/aeb.core-capabilities")
DATA_FILES = ("README.md", "LICENSE", "NOTICE", "docs/SPEC.md", "docs/GOVERNANCE.md", "docs/RUNNER.md", "scripts/release_build.py")
PLATFORMS = tuple((goos, arch) for goos in ("linux", "darwin", "windows") for arch in ("amd64", "arm64"))


class ReleaseError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise ReleaseError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON object required: {path}")
    return value


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True, check=False)
    if result.returncode:
        fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def go_constant(path: Path, symbol: str) -> int | str:
    match = re.search(rf"\b{re.escape(symbol)}\s*=\s*(?:\"([^\"]+)\"|([0-9]+))", path.read_text(encoding="utf-8"))
    if not match:
        fail(f"missing {symbol} in {path}")
    return match.group(1) if match.group(1) is not None else int(match.group(2))


def safe_name(value: str) -> str:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) == ".":
        fail(f"unsafe artifact path: {value!r}")
    return str(path)


def data_paths(repo: Path) -> list[str]:
    result: list[str] = []
    for root in DATA_ROOTS:
        base = repo / root
        if not base.is_dir():
            fail(f"required release data directory is absent: {root}")
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink():
                result.append(path.relative_to(repo).as_posix())
    for name in DATA_FILES:
        path = repo / name
        if not path.is_file() or path.is_symlink():
            fail(f"required release data file is absent: {name}")
        result.append(name)
    return sorted(result)


def contract_families(repo: Path) -> list[dict[str, Any]]:
    contracts_path = repo / "contracts/artifacts.json"
    contracts = load_json(contracts_path)
    if contracts.get("manifest_version") != 1:
        fail("contracts/artifacts.json manifest_version must be 1")
    families = contracts.get("artifact_families")
    if not isinstance(families, list) or not families:
        fail("contracts/artifacts.json artifact_families must be non-empty")
    observed = []
    for family in families:
        if not isinstance(family, dict):
            fail("artifact family must be an object")
        name, active = family.get("family"), family.get("active_writer_version")
        if not isinstance(name, str) or not isinstance(active, int):
            fail("artifact family has invalid identity")
        sources = family.get("source_versions")
        if sources is None:
            sources = []
        if not isinstance(sources, list):
            fail(f"artifact family {name} has invalid source versions")
        for source in sources:
            if not isinstance(source, dict) or not isinstance(source.get("path"), str) or not isinstance(source.get("symbol"), str):
                fail(f"artifact family {name} has invalid source version")
            actual = go_constant(repo / source["path"], source["symbol"])
            if actual != active:
                fail(f"artifact family {name} declares v{active}, but {source['path']}:{source['symbol']} is {actual!r}")
        canonical = family.get("canonical_schema_path")
        schemas = family.get("schemas")
        if canonical is None:
            if schemas != []:
                fail(f"artifact family {name} has schemas without a canonical schema")
            continue
        if not isinstance(canonical, str) or not isinstance(schemas, list):
            fail(f"artifact family {name} has invalid schema declarations")
        active_schema = None
        for schema in schemas:
            if not isinstance(schema, dict):
                fail(f"artifact family {name} has invalid schema")
            path, schema_id, version = schema.get("path"), schema.get("$id"), schema.get("version")
            if not isinstance(path, str) or not isinstance(schema_id, str) or not isinstance(version, int):
                fail(f"artifact family {name} has incomplete schema")
            if load_json(repo / path).get("$id") != schema_id:
                fail(f"artifact family {name} schema $id disagrees with {path}")
            if schema.get("status") == "active":
                if active_schema is not None:
                    fail(f"artifact family {name} declares multiple active schemas")
                active_schema = schema
        if not isinstance(active_schema, dict) or active_schema.get("version") != active or active_schema.get("path") != canonical:
            fail(f"artifact family {name} active schema does not match active writer version")
        observed.append({"family": name, "active_writer_version": active, "schema_path": canonical, "schema_sha256": sha256_file(repo / canonical), "schema_id": active_schema["$id"]})
    return sorted(observed, key=lambda value: value["family"])


def corpus(repo: Path) -> dict[str, Any]:
    path = repo / "cases/MANIFEST.txt"
    raw = path.read_bytes()
    try:
        ids = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        fail(f"cases/MANIFEST.txt is not UTF-8: {exc}")
    if not ids or len(ids) != len(set(ids)):
        fail("cases/MANIFEST.txt must contain unique non-empty IDs")
    return {"version": go_constant(repo / "runner/summary.go", "corpusVersion"), "manifest_path": "cases/MANIFEST.txt", "manifest_sha256": sha256_bytes(raw), "case_count": len(ids)}


def build_identity(repo: Path, tag: str, version: str, commit: str, snapshot: bool) -> dict[str, Any]:
    if snapshot:
        if tag != "snapshot" or not SNAPSHOT_VERSION_RE.fullmatch(version):
            fail("snapshot identity must use tag snapshot and the GoReleaser snapshot version")
    elif not VERSION_RE.fullmatch(version) or tag != f"v{version}":
        fail("release tag must be a v-prefixed semantic version that matches the release version")
    if not COMMIT_RE.fullmatch(commit):
        fail("release commit must be a 40-character lower-case Git SHA")
    if git(repo, "rev-parse", "HEAD") != commit:
        fail("release commit does not match checked-out HEAD")
    if not snapshot and git(repo, "rev-parse", f"{tag}^{{commit}}") != commit:
        fail(f"release tag {tag} does not resolve to requested commit")
    if git(repo, "status", "--porcelain", "--untracked-files=no"):
        fail("release tree has tracked changes")
    timestamp = git(repo, "show", "-s", "--format=%ct", commit)
    if not timestamp.isdigit():
        fail("release commit timestamp is invalid")
    runner = repo / "runner/summary.go"
    data = data_paths(repo)
    return {
        "schema_version": 1,
        "release": {"tag": tag, "version": version, "snapshot": snapshot},
        "source": {"repository": "luckyPipewrench/agent-egress-bench", "commit": commit, "commit_timestamp": int(timestamp)},
        "runner": {"binary": "aeb-gauntlet", "runner_version": go_constant(runner, "runnerVersion"), "scoring_version": go_constant(runner, "scoringVersion"), "platforms": [{"goos": goos, "goarch": arch} for goos, arch in PLATFORMS]},
        "corpus": corpus(repo),
        "schema_contract": {"artifacts_manifest_path": "contracts/artifacts.json", "artifacts_manifest_sha256": sha256_file(repo / "contracts/artifacts.json"), "families": contract_families(repo)},
        "data_files": {name: sha256_file(repo / name) for name in data},
        "verification": {"checksums": {"algorithm": "sha256", "path": CHECKSUM_NAME}, "command": "python3 scripts/release_build.py verify --release-dir <downloaded-release-directory>"},
    }


def read_identity(path: Path) -> dict[str, Any]:
    identity = load_json(path)
    if identity.get("schema_version") != 1:
        fail("release identity schema_version must be 1")
    return identity


def verify_identity(repo: Path, path: Path) -> dict[str, Any]:
    identity = read_identity(path)
    release, source = identity.get("release"), identity.get("source")
    if not isinstance(release, dict) or not isinstance(source, dict):
        fail("release identity is missing release or source")
    values = (release.get("tag"), release.get("version"), release.get("snapshot"), source.get("commit"))
    if not isinstance(values[0], str) or not isinstance(values[1], str) or not isinstance(values[2], bool) or not isinstance(values[3], str):
        fail("release identity has invalid release fields")
    expected = build_identity(repo, values[0], values[1], values[3], values[2])
    if canonical_json(identity) != canonical_json(expected):
        fail("release identity disagrees with the checked-out source tree")
    return identity


def add_tar_bytes(archive: tarfile.TarFile, name: str, data: bytes, timestamp: int) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = len(data), timestamp, 0o644
    archive.addfile(info, io.BytesIO(data))


def make_data_bundle(repo: Path, identity_path: Path, dist: Path) -> Path:
    identity = verify_identity(repo, identity_path)
    output = dist / f"agent-egress-bench_{identity['release']['version']}_data.tar.gz"
    dist.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(identity["data_files"]):
            add_tar_bytes(archive, name, (repo / name).read_bytes(), identity["source"]["commit_timestamp"])
        add_tar_bytes(archive, IDENTITY_NAME, identity_path.read_bytes(), identity["source"]["commit_timestamp"])
    return output


def write_checksums(dist: Path, identity_path: Path) -> Path:
    if not identity_path.is_file():
        fail(f"release identity is absent: {identity_path}")
    shutil.copyfile(identity_path, dist / IDENTITY_NAME)
    files = sorted(path for path in dist.iterdir() if path.is_file() and path.name != CHECKSUM_NAME)
    if not files:
        fail("release distribution directory has no artifacts")
    output = dist / CHECKSUM_NAME
    output.write_text("\n".join(f"{sha256_file(path)}  {path.name}" for path in files) + "\n", encoding="utf-8")
    return output


def parse_checksums(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            fail(f"malformed checksum line: {line!r}")
        digest, name = match.groups()
        safe_name(name)
        if Path(name).name != name or name in result:
            fail(f"unsafe or duplicate checksum artifact: {name!r}")
        result[name] = digest
    if not result:
        fail("checksums file is empty")
    return result


def archive_identity(path: Path) -> bytes:
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            entries = [name for name in archive.namelist() if PurePosixPath(name).name == IDENTITY_NAME]
            if len(entries) != 1 or archive.getinfo(entries[0]).is_dir():
                fail(f"{path.name} must contain exactly one regular {IDENTITY_NAME}")
            return archive.read(entries[0])
    with tarfile.open(path, "r:*") as archive:
        entries = [item for item in archive.getmembers() if PurePosixPath(item.name).name == IDENTITY_NAME]
        if len(entries) != 1 or not entries[0].isfile():
            fail(f"{path.name} must contain exactly one regular {IDENTITY_NAME}")
        handle = archive.extractfile(entries[0])
        if handle is None:
            fail(f"{path.name} has unreadable {IDENTITY_NAME}")
        return handle.read()


def bundle_contents(path: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with tarfile.open(path, "r:*") as archive:
        for item in archive.getmembers():
            name = safe_name(item.name)
            if not item.isfile() or name in result:
                fail(f"data bundle has unsafe or duplicate entry: {item.name!r}")
            handle = archive.extractfile(item)
            if handle is None:
                fail(f"data bundle has unreadable entry: {item.name!r}")
            result[name] = handle.read()
    return result


def binary_names(identity: dict[str, Any]) -> set[str]:
    version = identity["release"]["version"]
    return {f"agent-egress-bench_{version}_{item['goos']}_{item['goarch']}.{'zip' if item['goos'] == 'windows' else 'tar.gz'}" for item in identity["runner"]["platforms"]}


def verify_release(release_dir: Path, repo: Path | None, executable: Path | None) -> None:
    release_dir = release_dir.resolve()
    identity_path, checksums_path = release_dir / IDENTITY_NAME, release_dir / CHECKSUM_NAME
    if not identity_path.is_file() or not checksums_path.is_file():
        fail("release directory must contain release-identity.json and checksums.txt")
    identity, checksums = read_identity(identity_path), parse_checksums(checksums_path)
    actual = {path.name for path in release_dir.iterdir() if path.is_file() and path.name != CHECKSUM_NAME}
    if set(checksums) != actual:
        fail("checksums file does not cover exactly the release artifacts")
    for name, digest in checksums.items():
        if sha256_file(release_dir / name) != digest:
            fail(f"checksum mismatch: {name}")
    binaries = binary_names(identity)
    data_name = f"agent-egress-bench_{identity['release']['version']}_data.tar.gz"
    if data_name not in checksums or not binaries.issubset(checksums):
        fail("release is missing its data bundle or declared runner platforms")
    expected_identity = identity_path.read_bytes()
    for name in binaries:
        if archive_identity(release_dir / name) != expected_identity:
            fail(f"binary archive identity does not match release identity: {name}")
    contents = bundle_contents(release_dir / data_name)
    data_files = identity.get("data_files")
    if not isinstance(data_files, dict) or contents.get(IDENTITY_NAME) != expected_identity or set(contents) != set(data_files) | {IDENTITY_NAME}:
        fail("data bundle does not match release identity")
    for name, digest in data_files.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or sha256_bytes(contents[name]) != digest:
            fail(f"data bundle digest does not match release identity: {name}")
    if repo is not None:
        expected = build_identity(repo.resolve(), identity["release"]["tag"], identity["release"]["version"], identity["source"]["commit"], identity["release"]["snapshot"])
        if canonical_json(expected) != canonical_json(identity):
            fail("release identity does not match the supplied source tree")
    if executable is not None:
        result = subprocess.run([str(executable), "--version"], text=True, capture_output=True, check=False)
        expected = f"aeb-gauntlet {identity['release']['version']} {identity['source']['commit']}"
        if result.returncode or result.stdout.strip() != expected:
            fail("runner version output does not match release identity")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--repo-root", type=Path, default=Path("."))
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--commit", required=True)
    prepare.add_argument("--snapshot", action="store_true")
    prepare.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("check-identity")
    check.add_argument("--repo-root", type=Path, default=Path("."))
    check.add_argument("--identity", type=Path, required=True)
    bundle = commands.add_parser("data-bundle")
    bundle.add_argument("--repo-root", type=Path, default=Path("."))
    bundle.add_argument("--identity", type=Path, required=True)
    bundle.add_argument("--dist", type=Path, required=True)
    sums = commands.add_parser("checksums")
    sums.add_argument("--identity", type=Path, required=True)
    sums.add_argument("--dist", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--release-dir", type=Path, required=True)
    verify.add_argument("--repo-root", type=Path)
    verify.add_argument("--executable", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_json(build_identity(args.repo_root.resolve(), args.tag, args.version, args.commit, args.snapshot)))
        elif args.command == "check-identity":
            verify_identity(args.repo_root.resolve(), args.identity)
        elif args.command == "data-bundle":
            print(make_data_bundle(args.repo_root.resolve(), args.identity, args.dist))
        elif args.command == "checksums":
            print(write_checksums(args.dist, args.identity))
        elif args.command == "verify":
            verify_release(args.release_dir, args.repo_root, args.executable)
    except ReleaseError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
