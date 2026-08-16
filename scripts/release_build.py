#!/usr/bin/env python3
"""Build and verify the immutable Agent Egress Bench release contract."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import signal
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SNAPSHOT_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?-SNAPSHOT-[0-9a-f]{7}$")
IDENTITY_NAME = "release-identity.json"
CHECKSUM_NAME = "checksums.txt"
SCHEMA_CATALOG_PATH = "schemas/index.json"
SCHEMA_CATALOG_SUFFIX = "_schema-catalog.json"
SCHEMA_BUNDLE_SUFFIX = "_schemas.tar.gz"
REPOSITORY = "luckyPipewrench/agent-egress-bench"
RAW_SCHEMA_URL = "https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/{commit}/{path}"
# "examples" carries the operator kit: the tool-profile template the runner
# requires, the gateway plugin template, the runner skeleton, and the reference
# harness. Without it a downloaded release can report the corpus but cannot run
# it, because --profile is mandatory and nothing in the release satisfied it.
DATA_ROOTS = ("cases", "schemas", "contracts", "capability-registry/aeb.core-capabilities", "examples")
DATA_FILES = ("README.md", "LICENSE", "NOTICE", "CITATION.cff", "docs/SPEC.md", "docs/GOVERNANCE.md", "docs/RUNNER.md", "scripts/release_build.py", "scripts/schema_catalog.py")
PLATFORMS = tuple((goos, arch) for goos in ("linux", "darwin", "windows") for arch in ("amd64", "arm64"))
# Both tools ride in one platform archive. A release that shipped only the
# runner let a downloader produce a result and gave them nothing to check it
# with, which leaves the reproduction path depending on this repository.
RUNNER_BINARY = "aeb-gauntlet"
VALIDATOR_BINARY = "aeb-validate"
RELEASE_BINARIES = (RUNNER_BINARY, VALIDATOR_BINARY)


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
    try:
        result = subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True, check=False)
    except OSError as exc:
        fail(f"git {' '.join(args)} failed: {exc}")
    if result.returncode:
        fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def configured_snapshot_template(repo: Path) -> str:
    path = repo / ".goreleaser.yaml"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        fail(f"cannot read GoReleaser configuration: {exc}")
    for index, line in enumerate(lines):
        if line.strip() != "snapshot:":
            continue
        section_indent = len(line) - len(line.lstrip())
        for child in lines[index + 1:]:
            if child.strip() and len(child) - len(child.lstrip()) <= section_indent:
                break
            match = re.fullmatch(r"\s+version_template:\s*(.+?)\s*", child)
            if match is None:
                continue
            value = match.group(1)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value:
                return value
    fail("GoReleaser snapshot.version_template is required")


def snapshot_source_tag(repo: Path, commit: str) -> str:
    """Pick the tag the snapshot version is built from.

    The caller exports this as GORELEASER_CURRENT_TAG so GoReleaser uses the
    same tag rather than selecting one independently. Predicting GoReleaser's
    own choice was a second implementation of its tag resolution and could
    diverge from it; pinning the input removes that possibility instead of
    detecting it afterwards.
    """
    if not COMMIT_RE.fullmatch(commit):
        fail("snapshot commit must be a 40-character lower-case Git SHA")
    tags = git(repo, "tag", "--merged", commit, "--sort=-v:refname").splitlines()
    tag = next((candidate for candidate in tags if candidate.startswith("v") and VERSION_RE.fullmatch(candidate[1:])), "")
    if not tag:
        fail("GoReleaser snapshot source tag must be a v-prefixed semantic version")
    return tag


def snapshot_version(repo: Path, commit: str) -> str:
    tag = snapshot_source_tag(repo, commit)
    template = configured_snapshot_template(repo)
    values = {"{{ .Version }}": tag[1:], "{{ .ShortCommit }}": commit[:7]}
    if any(token not in values for token in re.findall(r"{{[^}]+}}", template)):
        fail("GoReleaser snapshot.version_template uses an unsupported value")
    rendered = template
    for token, value in values.items():
        rendered = rendered.replace(token, value)
    if "{{" in rendered or "}}" in rendered or not SNAPSHOT_VERSION_RE.fullmatch(rendered):
        fail("GoReleaser snapshot.version_template produced an invalid snapshot version")
    return rendered


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
    result = sorted(result)
    tracked = set(filter(None, git(repo, "ls-tree", "-r", "--name-only", "HEAD", "--", *DATA_ROOTS, *DATA_FILES).splitlines()))
    if set(result) != tracked:
        missing, extra = sorted(tracked - set(result)), sorted(set(result) - tracked)
        fail(f"release data differs from the tracked source tree: missing={missing}, extra={extra}")
    return result


def ignored_runner_build_inputs(repo: Path) -> list[str]:
    paths = git(repo, "ls-files", "--others", "--ignored", "--exclude-standard", "--", "runner").splitlines()
    return sorted(path for path in paths if path.endswith(".go") and not path.endswith("_test.go"))


def runner_metadata(repo: Path) -> dict[str, str]:
    result = subprocess.run(
        ["go", "run", ".", "--release-identity-metadata"],
        cwd=repo / "runner",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        fail(f"runner release metadata failed: {result.stderr.strip()}")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        fail(f"runner release metadata is not JSON: {exc}")
    fields = ("runner_version", "scoring_version", "corpus_version")
    if not isinstance(metadata, dict) or set(metadata) != set(fields) or any(not isinstance(metadata.get(field), str) or not metadata[field] for field in fields):
        fail("runner release metadata has invalid fields")
    return {field: metadata[field] for field in fields}


def contract_families(repo: Path) -> list[dict[str, Any]]:
    # Downloaded-release verification has no source checkout and ships only
    # this module. Keep the source-contract helper out of that path.
    from check_contracts import read_source_version

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
            try:
                actual = read_source_version(repo, source)
            except ValueError as exc:
                fail(str(exc))
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


def corpus(repo: Path, version: str) -> dict[str, Any]:
    path = repo / "cases/MANIFEST.txt"
    raw = path.read_bytes()
    try:
        ids = [line.strip() for line in raw.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        fail(f"cases/MANIFEST.txt is not UTF-8: {exc}")
    if not ids or len(ids) != len(set(ids)):
        fail("cases/MANIFEST.txt must contain unique non-empty IDs")
    return {"version": version, "manifest_path": "cases/MANIFEST.txt", "manifest_sha256": sha256_bytes(raw), "case_count": len(ids)}


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
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        fail("release tree has tracked or untracked changes")
    ignored_inputs = ignored_runner_build_inputs(repo)
    if ignored_inputs:
        fail(f"release tree has ignored runner build inputs: {ignored_inputs}")
    timestamp = git(repo, "show", "-s", "--format=%ct", commit)
    if not timestamp.isdigit():
        fail("release commit timestamp is invalid")
    metadata = runner_metadata(repo)
    data = data_paths(repo)
    return {
        "schema_version": 1,
        "release": {"tag": tag, "version": version, "snapshot": snapshot},
        "source": {"repository": REPOSITORY, "commit": commit, "commit_timestamp": int(timestamp)},
        "runner": {"binary": RUNNER_BINARY, "validator_binary": VALIDATOR_BINARY, "runner_version": metadata["runner_version"], "scoring_version": metadata["scoring_version"], "platforms": [{"goos": goos, "goarch": arch} for goos, arch in PLATFORMS]},
        "corpus": corpus(repo, metadata["corpus_version"]),
        "schema_contract": {"artifacts_manifest_path": "contracts/artifacts.json", "artifacts_manifest_sha256": sha256_file(repo / "contracts/artifacts.json"), "families": contract_families(repo)},
        "data_files": {name: sha256_file(repo / name) for name in data},
        "verification": {"checksums": {"algorithm": "sha256", "path": CHECKSUM_NAME}, "command": "python3 scripts/release_build.py verify --release-dir <downloaded-release-directory>"},
    }


def exact_object(value: Any, label: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} must contain exactly {sorted(fields)}")
    return value


def nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label} must be a non-empty string")
    return value


def positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        fail(f"{label} must be a positive integer")
    return value


def validate_identity_structure(identity: dict[str, Any]) -> None:
    if identity.get("schema_version") != 1:
        fail("release identity schema_version must be 1")
    exact_object(identity, "release identity", {"schema_version", "release", "source", "runner", "corpus", "schema_contract", "data_files", "verification"})

    release = exact_object(identity["release"], "release identity release", {"tag", "version", "snapshot"})
    tag = nonempty_string(release["tag"], "release identity release.tag")
    version = nonempty_string(release["version"], "release identity release.version")
    snapshot = release["snapshot"]
    if not isinstance(snapshot, bool):
        fail("release identity release.snapshot must be a boolean")
    if snapshot:
        if tag != "snapshot" or not SNAPSHOT_VERSION_RE.fullmatch(version):
            fail("release identity snapshot tag or version is invalid")
    elif not VERSION_RE.fullmatch(version) or tag != f"v{version}":
        fail("release identity release tag and version are invalid")

    source = exact_object(identity["source"], "release identity source", {"repository", "commit", "commit_timestamp"})
    if source["repository"] != REPOSITORY:
        fail("release identity source.repository is invalid")
    if not isinstance(source["commit"], str) or not COMMIT_RE.fullmatch(source["commit"]):
        fail("release identity source.commit is invalid")
    positive_int(source["commit_timestamp"], "release identity source.commit_timestamp")

    runner = exact_object(identity["runner"], "release identity runner", {"binary", "validator_binary", "runner_version", "scoring_version", "platforms"})
    if runner["binary"] != RUNNER_BINARY:
        fail("release identity runner.binary is invalid")
    if runner["validator_binary"] != VALIDATOR_BINARY:
        fail("release identity runner.validator_binary is invalid")
    nonempty_string(runner["runner_version"], "release identity runner.runner_version")
    nonempty_string(runner["scoring_version"], "release identity runner.scoring_version")
    platforms = runner["platforms"]
    if not isinstance(platforms, list):
        fail("release identity runner.platforms must be an array")
    pairs: list[tuple[str, str]] = []
    for index, platform in enumerate(platforms):
        platform = exact_object(platform, f"release identity runner.platforms[{index}]", {"goos", "goarch"})
        pairs.append((nonempty_string(platform["goos"], f"release identity runner.platforms[{index}].goos"), nonempty_string(platform["goarch"], f"release identity runner.platforms[{index}].goarch")))
    if len(pairs) != len(set(pairs)) or set(pairs) != set(PLATFORMS):
        fail("release identity runner.platforms must contain the exact supported platform matrix")

    corpus_value = exact_object(identity["corpus"], "release identity corpus", {"version", "manifest_path", "manifest_sha256", "case_count"})
    nonempty_string(corpus_value["version"], "release identity corpus.version")
    if corpus_value["manifest_path"] != "cases/MANIFEST.txt":
        fail("release identity corpus.manifest_path is invalid")
    if not isinstance(corpus_value["manifest_sha256"], str) or not SHA256_RE.fullmatch(corpus_value["manifest_sha256"]):
        fail("release identity corpus.manifest_sha256 is invalid")
    positive_int(corpus_value["case_count"], "release identity corpus.case_count")

    schema_contract = exact_object(identity["schema_contract"], "release identity schema_contract", {"artifacts_manifest_path", "artifacts_manifest_sha256", "families"})
    if schema_contract["artifacts_manifest_path"] != "contracts/artifacts.json" or not isinstance(schema_contract["artifacts_manifest_sha256"], str) or not SHA256_RE.fullmatch(schema_contract["artifacts_manifest_sha256"]):
        fail("release identity schema contract manifest is invalid")
    families = schema_contract["families"]
    if not isinstance(families, list) or not families:
        fail("release identity schema_contract.families must be non-empty")
    family_names: set[str] = set()
    for index, family in enumerate(families):
        family = exact_object(family, f"release identity schema_contract.families[{index}]", {"family", "active_writer_version", "schema_path", "schema_sha256", "schema_id"})
        name = nonempty_string(family["family"], f"release identity schema_contract.families[{index}].family")
        if name in family_names:
            fail("release identity schema_contract.families contains duplicate names")
        family_names.add(name)
        positive_int(family["active_writer_version"], f"release identity schema_contract.families[{index}].active_writer_version")
        safe_name(nonempty_string(family["schema_path"], f"release identity schema_contract.families[{index}].schema_path"))
        if not isinstance(family["schema_sha256"], str) or not SHA256_RE.fullmatch(family["schema_sha256"]):
            fail(f"release identity schema_contract.families[{index}].schema_sha256 is invalid")
        nonempty_string(family["schema_id"], f"release identity schema_contract.families[{index}].schema_id")

    data_files = identity["data_files"]
    if not isinstance(data_files, dict) or not data_files:
        fail("release identity data_files must be a non-empty object")
    for name, digest in data_files.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail("release identity data_files has an invalid entry")
        safe_name(name)
    if set(DATA_FILES) - set(data_files) or corpus_value["manifest_path"] not in data_files or any(not any(name == root or name.startswith(f"{root}/") for name in data_files) for root in DATA_ROOTS):
        fail("release identity data_files does not contain the required corpus, schema, contract, operator kit, and verifier data")

    verification = exact_object(identity["verification"], "release identity verification", {"checksums", "command"})
    checksums = exact_object(verification["checksums"], "release identity verification.checksums", {"algorithm", "path"})
    if checksums["algorithm"] != "sha256" or checksums["path"] != CHECKSUM_NAME:
        fail("release identity verification checksums are invalid")
    nonempty_string(verification["command"], "release identity verification.command")


def read_identity(path: Path) -> dict[str, Any]:
    identity = load_json(path)
    validate_identity_structure(identity)
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
    with output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=identity["source"]["commit_timestamp"], filename="") as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(identity["data_files"]):
            add_tar_bytes(archive, name, (repo / name).read_bytes(), identity["source"]["commit_timestamp"])
        add_tar_bytes(archive, IDENTITY_NAME, identity_path.read_bytes(), identity["source"]["commit_timestamp"])
    return output


def schema_asset_names(identity: dict[str, Any]) -> tuple[str, str]:
    version = identity["release"]["version"]
    prefix = f"agent-egress-bench_{version}"
    return f"{prefix}{SCHEMA_CATALOG_SUFFIX}", f"{prefix}{SCHEMA_BUNDLE_SUFFIX}"


def release_catalog_entries(identity: dict[str, Any], catalog_bytes: bytes) -> list[dict[str, str]]:
    try:
        catalog = json.loads(catalog_bytes)
    except json.JSONDecodeError as exc:
        fail(f"release schema catalog is not JSON: {exc}")
    if not isinstance(catalog, dict):
        fail("release schema catalog must be an object")
    if set(catalog) != {"format", "repository", "source_commit", "release", "schemas"}:
        fail("release schema catalog has invalid fields")
    if catalog["format"] != 1 or catalog["repository"] != f"https://github.com/{REPOSITORY}":
        fail("release schema catalog has invalid identity")
    if catalog["source_commit"] != identity["source"]["commit"] or catalog["release"] != identity["release"]["tag"]:
        fail("release schema catalog does not match release identity")
    schemas = catalog["schemas"]
    if not isinstance(schemas, list) or not schemas:
        fail("release schema catalog has no schema entries")
    paths: set[str] = set()
    entries: list[dict[str, str]] = []
    for index, entry in enumerate(schemas):
        entry = exact_object(entry, f"release schema catalog schemas[{index}]", {"path", "$id", "sha256", "retrieval_url"})
        path = safe_name(nonempty_string(entry["path"], f"release schema catalog schemas[{index}].path"))
        if path in paths or path == SCHEMA_CATALOG_PATH:
            fail("release schema catalog has duplicate or reserved schema paths")
        paths.add(path)
        declared_id = nonempty_string(entry["$id"], f"release schema catalog schemas[{index}].$id")
        digest = entry["sha256"]
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            fail(f"release schema catalog schemas[{index}].sha256 is invalid")
        expected_url = RAW_SCHEMA_URL.format(commit=identity["source"]["commit"], path=path)
        if entry["retrieval_url"] != expected_url:
            fail(f"release schema catalog schemas[{index}].retrieval_url is not pinned to the release commit")
        entries.append({"path": path, "$id": declared_id, "sha256": digest})
    return entries


def require_declared_id(contents: bytes, entry: dict[str, str], source: str) -> None:
    """Require a schema's own declared identity to match what the catalog claims.

    A digest proves the bytes; it says nothing about the name those bytes are
    published under. Without this, a catalog carrying a substituted `$id`
    passes every other check, because the paths resolve, the digests match the
    real files, and the checksums are regenerated over the altered catalog. An
    offline consumer then registers correct schema bytes under the wrong
    identity and validates its data against a contract it never chose, with
    every integrity signal reading green.
    """
    try:
        document = json.loads(contents)
    except json.JSONDecodeError as exc:
        fail(f"{source} is not JSON: {entry['path']}: {exc}")
    if not isinstance(document, dict):
        fail(f"{source} is not a JSON object: {entry['path']}")
    if document.get("$id") != entry["$id"]:
        fail(f"{source} declares an $id the release catalog does not name: {entry['path']}")


def make_schema_bundle(repo: Path, identity_path: Path, catalog_path: Path, dist: Path) -> Path:
    identity = verify_identity(repo, identity_path)
    if not catalog_path.is_file() or catalog_path.is_symlink():
        fail(f"release schema catalog is absent or unsafe: {catalog_path}")
    catalog_bytes = catalog_path.read_bytes()
    entries = release_catalog_entries(identity, catalog_bytes)
    catalog_name, bundle_name = schema_asset_names(identity)
    if catalog_path.name != catalog_name:
        fail("release schema catalog has an unexpected asset name")
    output = dist / bundle_name
    dist.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=identity["source"]["commit_timestamp"], filename="") as compressed, tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_tar_bytes(archive, SCHEMA_CATALOG_PATH, catalog_bytes, identity["source"]["commit_timestamp"])
        for entry in sorted(entries, key=lambda item: item["path"]):
            path = repo / entry["path"]
            if not path.is_file() or path.is_symlink():
                fail(f"release schema catalog names an absent or unsafe schema: {entry['path']}")
            contents = path.read_bytes()
            if sha256_bytes(contents) != entry["sha256"]:
                fail(f"release schema catalog digest does not match source schema: {entry['path']}")
            require_declared_id(contents, entry, "source schema")
            add_tar_bytes(archive, entry["path"], contents, identity["source"]["commit_timestamp"])
    return output


def write_checksums(dist: Path, identity_path: Path) -> Path:
    if not identity_path.is_file():
        fail(f"release identity is absent: {identity_path}")
    if not dist.is_dir():
        fail(f"release distribution directory is absent: {dist}")
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


def verify_release_binary(data: bytes, mode: int, goos: str, goarch: str, path: Path, binary: str = RUNNER_BINARY) -> None:
    platform = f"{goos} {goarch}"
    if goos != "windows" and mode & 0o111 == 0:
        fail(f"{path.name} must mark its {platform} {binary} executable")
    if goos == "linux":
        machines = {"amd64": 62, "arm64": 183}
        if len(data) < 20 or data[:4] != b"\x7fELF" or data[4:6] != b"\x02\x01" or data[18:20] != machines[goarch].to_bytes(2, "little"):
            fail(f"{path.name} must contain a 64-bit Linux {goarch} ELF {binary}")
        return
    if goos == "darwin":
        cpus = {"amd64": 0x01000007, "arm64": 0x0100000C}
        if len(data) < 8 or data[:4] != b"\xcf\xfa\xed\xfe" or data[4:8] != cpus[goarch].to_bytes(4, "little"):
            fail(f"{path.name} must contain a 64-bit Darwin {goarch} Mach-O {binary}")
        return
    if goos == "windows":
        machines = {"amd64": 0x8664, "arm64": 0xAA64}
        if len(data) < 64 or data[:2] != b"MZ":
            fail(f"{path.name} must contain a Windows {goarch} PE {binary}")
        offset = int.from_bytes(data[60:64], "little")
        if offset + 6 > len(data) or data[offset:offset + 4] != b"PE\0\0" or data[offset + 4:offset + 6] != machines[goarch].to_bytes(2, "little"):
            fail(f"{path.name} must contain a Windows {goarch} PE {binary}")
        return
    fail(f"unsupported release platform: {platform}")


def archive_binary_name(binary: str, goos: str) -> str:
    return f"{binary}.exe" if goos == "windows" else binary


def archive_identity(path: Path, goos: str, goarch: str, digests_out: dict[str, set[str]] | None = None) -> bytes:
    # Every binary the release advertises is checked, not only the runner. A
    # check that stopped at the runner would accept an archive whose validator
    # was absent, truncated, or built for another platform, and an operator
    # would discover that only when they tried to check a result.
    # Each binary's digest is collected so the archive can be required to carry
    # two DIFFERENT programs. Name, executable mode, and platform are all a
    # substituted binary satisfies: replacing the validator with a second copy
    # of the runner passed every other check here, and the released archive then
    # shipped no way to check a result while reporting itself intact. A build
    # misconfiguration that pointed both GoReleaser builds at one directory
    # produces exactly that, which is the likelier way to reach it.
    digests: dict[str, str] = {}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            entries = [item for item in archive.infolist() if item.filename == f".release/{IDENTITY_NAME}" and not item.is_dir()]
            if len(entries) != 1:
                fail(f"{path.name} must contain exactly one regular {IDENTITY_NAME}")
            for binary in RELEASE_BINARIES:
                expected_binary = archive_binary_name(binary, goos)
                found = [item for item in archive.infolist() if item.filename == expected_binary and not item.is_dir()]
                if len(found) != 1:
                    fail(f"{path.name} must contain exactly one {expected_binary}")
                data = archive.read(found[0])
                verify_release_binary(data, found[0].external_attr >> 16, goos, goarch, path, binary)
                digests[binary] = sha256_bytes(data)
            verify_distinct_binaries(digests, path)
            record_binary_digests(digests, digests_out)
            return archive.read(entries[0])
    with tarfile.open(path, "r:*") as archive:
        entries = [item for item in archive.getmembers() if item.name == f".release/{IDENTITY_NAME}" and item.isfile()]
        if len(entries) != 1:
            fail(f"{path.name} must contain exactly one regular {IDENTITY_NAME}")
        for binary in RELEASE_BINARIES:
            expected_binary = archive_binary_name(binary, goos)
            found = [item for item in archive.getmembers() if item.name == expected_binary and item.isfile()]
            if len(found) != 1:
                fail(f"{path.name} must contain exactly one {expected_binary}")
            member = archive.extractfile(found[0])
            if member is None:
                fail(f"{path.name} has unreadable {expected_binary}")
            data = member.read()
            verify_release_binary(data, found[0].mode, goos, goarch, path, binary)
            digests[binary] = sha256_bytes(data)
        verify_distinct_binaries(digests, path)
        record_binary_digests(digests, digests_out)
        handle = archive.extractfile(entries[0])
        if handle is None:
            fail(f"{path.name} has unreadable {IDENTITY_NAME}")
        return handle.read()


def record_binary_digests(digests: dict[str, str], digests_out: dict[str, set[str]] | None) -> None:
    if digests_out is None:
        return
    for binary, digest in digests.items():
        digests_out.setdefault(binary, set()).add(digest)


def verify_distinct_binaries(digests: dict[str, str], path: Path) -> None:
    if len(set(digests.values())) != len(digests):
        fail(f"{path.name} carries the same program under more than one release binary name")


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


def verify_schema_bundle(identity: dict[str, Any], release_dir: Path) -> tuple[list[dict[str, str]], dict[str, bytes]]:
    catalog_name, bundle_name = schema_asset_names(identity)
    catalog_path, bundle_path = release_dir / catalog_name, release_dir / bundle_name
    if not catalog_path.is_file() or not bundle_path.is_file():
        fail("release is missing its schema catalog or schema bundle")
    catalog_bytes = catalog_path.read_bytes()
    entries = release_catalog_entries(identity, catalog_bytes)
    contents = bundle_contents(bundle_path)
    if contents.get(SCHEMA_CATALOG_PATH) != catalog_bytes:
        fail("schema bundle catalog does not match the release catalog asset")
    expected_paths = {SCHEMA_CATALOG_PATH, *(entry["path"] for entry in entries)}
    if set(contents) != expected_paths:
        fail("schema bundle file list does not match the release catalog")
    for entry in entries:
        if sha256_bytes(contents[entry["path"]]) != entry["sha256"]:
            fail(f"schema bundle digest does not match release catalog: {entry['path']}")
        require_declared_id(contents[entry["path"]], entry, "bundled schema")
    return entries, contents


def verify_repo_schema_surface(repo: Path, entries: list[dict[str, str]], contents: dict[str, bytes]) -> None:
    """Compare released schema identities and bytes with a fresh repository derivation.

    Catalog JSON formatting and tar metadata are intentionally outside this
    comparison. They don't change a schema's path, identity, or bytes. Schema
    formatting remains significant because the catalog publishes byte digests.
    """
    from schema_catalog import schema_entries

    try:
        expected_entries = schema_entries(repo)
    except (OSError, ValueError) as exc:
        fail(f"cannot re-derive the supplied source tree schema catalog: {exc}")
    expected = {entry["path"]: entry for entry in expected_entries}
    released = {entry["path"]: entry for entry in entries}
    if set(released) != set(expected):
        missing = sorted(set(expected) - set(released))
        extra = sorted(set(released) - set(expected))
        fail(f"release schema paths do not match the supplied source tree: missing={missing}, extra={extra}")
    for path in sorted(expected):
        if released[path]["$id"] != expected[path]["$id"]:
            fail(f"release schema identity does not match the supplied source tree: {path}")
        if released[path]["sha256"] != expected[path]["sha256"]:
            fail(f"release schema content does not match the supplied source tree: {path}")
        try:
            source_bytes = (repo / path).read_bytes()
        except OSError as exc:
            fail(f"cannot read supplied source tree schema {path}: {exc}")
        if contents[path] != source_bytes:
            fail(f"bundled schema bytes do not match the supplied source tree: {path}")


def bundle_corpus_ids(contents: dict[str, bytes]) -> set[str]:
    result: set[str] = set()
    for name in contents:
        path = PurePosixPath(name)
        if path.parts[0] != "cases":
            continue
        if path.suffix == ".json":
            result.add(path.stem)
        elif len(path.parts) == 4 and path.name == "case.yaml":
            result.add(path.parts[2])
    return result


def verify_bundle_corpus(identity: dict[str, Any], contents: dict[str, bytes]) -> None:
    corpus_value = identity["corpus"]
    manifest_path = corpus_value["manifest_path"]
    manifest = contents[manifest_path]
    if sha256_bytes(manifest) != corpus_value["manifest_sha256"]:
        fail("data bundle corpus manifest does not match release identity")
    try:
        ids = [line.strip() for line in manifest.decode("utf-8").splitlines() if line.strip()]
    except UnicodeDecodeError as exc:
        fail(f"data bundle corpus manifest is not UTF-8: {exc}")
    if not ids or len(ids) != len(set(ids)) or len(ids) != corpus_value["case_count"]:
        fail("data bundle corpus manifest has invalid case IDs or count")
    if not set(ids).issubset(bundle_corpus_ids(contents)):
        fail("data bundle does not contain every case named by its corpus manifest")


def binary_archives(identity: dict[str, Any]) -> dict[str, tuple[str, str]]:
    version = identity["release"]["version"]
    return {
        f"agent-egress-bench_{version}_{item['goos']}_{item['goarch']}.{'zip' if item['goos'] == 'windows' else 'tar.gz'}": (item["goos"], item["goarch"])
        for item in identity["runner"]["platforms"]
    }


def verify_release(release_dir: Path, repo: Path | None, executable: Path | None, validator_executable: Path | None = None) -> None:
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
    image_reference = release_dir / "runner-image.ref"
    if image_reference.is_file():
        expected_prefix = b"ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:"
        value = image_reference.read_bytes()
        digest = value.removeprefix(expected_prefix).removesuffix(b"\n")
        if not value.startswith(expected_prefix) or value != expected_prefix + digest + b"\n" or re.fullmatch(rb"[0-9a-f]{64}", digest) is None:
            fail("runner-image.ref is not the canonical published image reference")
    binaries = binary_archives(identity)
    data_name = f"agent-egress-bench_{identity['release']['version']}_data.tar.gz"
    catalog_name, bundle_name = schema_asset_names(identity)
    if data_name not in checksums or catalog_name not in checksums or bundle_name not in checksums or not set(binaries).issubset(checksums):
        fail("release is missing its data bundle, schema artifacts, or declared runner platforms")
    expected_identity = identity_path.read_bytes()
    archive_binary_digests: dict[str, set[str]] = {}
    for name, (goos, goarch) in binaries.items():
        if archive_identity(release_dir / name, goos, goarch, archive_binary_digests) != expected_identity:
            fail(f"binary archive identity does not match release identity: {name}")
    contents = bundle_contents(release_dir / data_name)
    data_files = identity.get("data_files")
    if not isinstance(data_files, dict) or contents.get(IDENTITY_NAME) != expected_identity or set(contents) != set(data_files) | {IDENTITY_NAME}:
        fail("data bundle does not match release identity")
    for name, digest in data_files.items():
        if not isinstance(name, str) or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest) or sha256_bytes(contents[name]) != digest:
            fail(f"data bundle digest does not match release identity: {name}")
    verify_bundle_corpus(identity, contents)
    schema_entries, schema_contents = verify_schema_bundle(identity, release_dir)
    if repo is not None:
        verify_repo_schema_surface(repo.resolve(), schema_entries, schema_contents)
        expected = build_identity(repo.resolve(), identity["release"]["tag"], identity["release"]["version"], identity["source"]["commit"], identity["release"]["snapshot"])
        if canonical_json(expected) != canonical_json(identity):
            fail("release identity does not match the supplied source tree")
    if executable is not None:
        verify_executable_identity(executable, RUNNER_BINARY, identity, archive_binary_digests)
    if validator_executable is not None:
        verify_executable_identity(validator_executable, VALIDATOR_BINARY, identity, archive_binary_digests)


# An archive check can prove a member's name, mode, and machine type, and those
# are all satisfied by the wrong program under the right name. Running the
# binary and reading back what it calls itself is what separates the two, so the
# validator gets the same treatment the runner already had.
def verify_executable_identity(
    executable: Path,
    binary: str,
    identity: dict[str, Any],
    archive_binary_digests: dict[str, set[str]],
) -> None:
    if not executable.is_file() or executable.stat().st_mode & 0o111 == 0:
        fail(f"{binary} executable is absent or is not marked executable")
    # Bind the file about to be executed to the release before executing it.
    # Without this the option accepted any binary that printed the expected
    # line, so pointing it at an unrelated program made an archive appear
    # verified while establishing nothing about the archive at all.
    known = archive_binary_digests.get(binary, set())
    if sha256_file(executable) not in known:
        fail(f"{binary} executable is not the {binary} in any release archive")
    version = run_bounded_version(executable, binary)
    expected = f"{binary} {identity['release']['version']} {identity['source']['commit']}"
    if version != expected:
        fail(f"{binary} version output does not match release identity")


# The most a released binary prints here is its name, a version, and a
# 40-character commit. Reading without a bound let a downloaded binary emit
# output for the whole timeout and grow the verifier's memory until it died,
# which turns verifying a release into a way to lose the machine doing it.
VERSION_OUTPUT_LIMIT = 4096
# Overridable so a test can bound the wait without sitting through the real one.
VERSION_READ_TIMEOUT_SECONDS = 60


def process_group_options() -> dict[str, Any]:
    if os.name == "nt":
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {"start_new_session": True}


# POSIX and Windows do not share a process-group model, and the difference is
# not cosmetic here. os.killpg does not exist on Windows at all, so calling it
# there raises AttributeError inside the watchdog thread, the watchdog dies
# silently, and the read this whole mechanism exists to bound blocks forever.
# Windows terminates a tree with taskkill instead.
def kill_process_group(process: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
        else:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except Exception:
        # Whatever went wrong, the process still has to die: a watchdog that
        # raises leaves the reader waiting, which is the failure it was added
        # to prevent.
        try:
            process.kill()
        except Exception:
            pass


def run_bounded_version(executable: Path, binary: str) -> str:
    try:
        # stderr is discarded rather than captured: nothing reads it, and an
        # unread pipe is another unbounded buffer a hostile binary can fill.
        process = subprocess.Popen(
            [str(executable), "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            # Its own process group, so the watchdog can end descendants too. A
            # child of the binary inherits the pipe, so killing only the binary
            # leaves that pipe open and the read still waiting: measured with a
            # script that printed a few bytes and then slept, which hung until
            # killed even with the watchdog in place.
            #
            # The two platforms spell this differently. start_new_session is
            # POSIX-only, and passing it on Windows does nothing for the tree,
            # so Windows asks for its own process group through creationflags.
            **process_group_options(),
        )
    except OSError as exc:
        fail(f"{binary} executable cannot run: {exc}")
    # Both bounds are needed and they fail differently. The size cap alone left
    # the read blocking: a binary that printed a few bytes and then slept never
    # reached the limit and never closed the pipe, so the read waited and the
    # timeout below was never consulted. Measured, that hung until killed. A
    # watchdog kills the process instead, which closes the pipe and makes the
    # read return, so a stalled binary ends the same way a talkative one does.
    watchdog = threading.Timer(VERSION_READ_TIMEOUT_SECONDS, lambda: kill_process_group(process))
    watchdog.start()
    try:
        captured = process.stdout.read(VERSION_OUTPUT_LIMIT) if process.stdout else ""
        if process.stdout is not None:
            process.stdout.close()
        code = process.wait()
    finally:
        watchdog.cancel()
        if process.poll() is None:
            kill_process_group(process)
            process.wait()
    if code:
        fail(f"{binary} executable did not report its version cleanly")
    return captured.strip()


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
    snapshot_version_command = commands.add_parser("snapshot-version")
    snapshot_version_command.add_argument("--repo-root", type=Path, default=Path("."))
    snapshot_version_command.add_argument("--commit", required=True)
    snapshot_tag_command = commands.add_parser("snapshot-tag")
    snapshot_tag_command.add_argument("--repo-root", type=Path, default=Path("."))
    snapshot_tag_command.add_argument("--commit", required=True)
    check = commands.add_parser("check-identity")
    check.add_argument("--repo-root", type=Path, default=Path("."))
    check.add_argument("--identity", type=Path, required=True)
    bundle = commands.add_parser("data-bundle")
    bundle.add_argument("--repo-root", type=Path, default=Path("."))
    bundle.add_argument("--identity", type=Path, required=True)
    bundle.add_argument("--dist", type=Path, required=True)
    schema_bundle = commands.add_parser("schema-bundle")
    schema_bundle.add_argument("--repo-root", type=Path, default=Path("."))
    schema_bundle.add_argument("--identity", type=Path, required=True)
    schema_bundle.add_argument("--catalog", type=Path, required=True)
    schema_bundle.add_argument("--dist", type=Path, required=True)
    sums = commands.add_parser("checksums")
    sums.add_argument("--identity", type=Path, required=True)
    sums.add_argument("--dist", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--release-dir", type=Path, required=True)
    verify.add_argument("--repo-root", type=Path)
    verify.add_argument("--executable", type=Path)
    verify.add_argument("--validator-executable", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_json(build_identity(args.repo_root.resolve(), args.tag, args.version, args.commit, args.snapshot)))
        elif args.command == "snapshot-version":
            print(snapshot_version(args.repo_root.resolve(), args.commit))
        elif args.command == "snapshot-tag":
            print(snapshot_source_tag(args.repo_root.resolve(), args.commit))
        elif args.command == "check-identity":
            verify_identity(args.repo_root.resolve(), args.identity)
        elif args.command == "data-bundle":
            print(make_data_bundle(args.repo_root.resolve(), args.identity, args.dist))
        elif args.command == "schema-bundle":
            print(make_schema_bundle(args.repo_root.resolve(), args.identity, args.catalog, args.dist))
        elif args.command == "checksums":
            print(write_checksums(args.dist, args.identity))
        elif args.command == "verify":
            verify_release(args.release_dir, args.repo_root, args.executable, args.validator_executable)
    except ReleaseError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
