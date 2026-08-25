#!/usr/bin/env python3
"""Admit result pointers only when the manifest is closed and the bytes match.

Listing a pointer is not approval, ranking, or a verification mark. This checker
stores no result bytes. Live fetch is skipped for withdrawn pointers so a dead
URL can remain historical without failing the gate.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import socket
import sys
import urllib.parse
from pathlib import Path

SCRIPT_ROOT = Path(__file__).resolve().parent
if str(SCRIPT_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPT_ROOT))

from artifact_schema import load_schema, validate

ROOT = Path(__file__).resolve().parents[1]
POINTERS_ROOT = ROOT / "result-pointers"
INDEX_PATH = POINTERS_ROOT / "index.json"
ENTRIES_ROOT = POINTERS_ROOT / "entries"
SCHEMA_PATH = ROOT / "schemas" / "result-pointer-v1.schema.json"
README_PATH = POINTERS_ROOT / "README.md"
MAX_EVIDENCE_BYTES = 8 << 20
FORBIDDEN_POINTER_KEYS = frozenset(
    {
        "containment",
        "score",
        "rank",
        "ranking",
        "badge",
        "verified",
        "approved",
        "certified",
        "latest",
    }
)
REQUIRED_README_PHRASE = "listing is not approval"


def fail(message):
    raise ValueError(message)


def canonical_pointer_identity(pointer):
    """Return the immutable fields that define a pointer's filename.

    ``withdrawn`` is a lifecycle status. Excluding it lets a publisher add that
    status without renaming the established pointer or changing its evidence
    identity; every other field remains digest-addressed.
    """
    identity = {name: value for name, value in pointer.items() if name != "withdrawn"}
    return json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def pointer_id(pointer):
    return hashlib.sha256(canonical_pointer_identity(pointer)).hexdigest()


def load_json(path, label):
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular file: {path}")
    raw = path.read_bytes()
    if not raw:
        fail(f"{label} is empty: {path}")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {label} {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object: {path}")
    return value


def require_https_url(url, label):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.query or parsed.fragment or parsed.username or parsed.password:
        fail(f"{label} must be an https URL with no query, fragment, or userinfo")
    host = parsed.hostname
    if not host:
        fail(f"{label} is missing a host")
    normalized_host = host.lower()
    if normalized_host in {"localhost", "localhost.localdomain"} or normalized_host.endswith(".localhost"):
        fail(f"{label} host is not public: {host}")
    try:
        port = parsed.port
    except ValueError as exc:
        fail(f"{label} has an invalid port: {exc}")
    if port not in (None, 443):
        fail(f"{label} must use HTTPS port 443")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return parsed
    fail(f"{label} must not use a literal IP host")


def resolve_public_address(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        fail(f"cannot resolve pointer evidence host {host}: {exc}")
    if not infos:
        fail(f"cannot resolve pointer evidence host {host}")
    addresses = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            fail(f"pointer evidence host {host} resolved to a non-global address")
        addresses.append(ip.compressed)
    return addresses[0]


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to the public address we resolved while authenticating the URL host."""

    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def read_bounded(raw, limit):
    chunks = []
    seen = 0
    while True:
        chunk = raw.read(65536)
        if not chunk:
            break
        seen += len(chunk)
        if seen > limit:
            fail(f"pointer evidence exceeds {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def default_fetch(url):
    parsed = require_https_url(url, "evidence_url")
    port = 443
    address = resolve_public_address(parsed.hostname, port)
    connection = PinnedHTTPSConnection(parsed.hostname, address, port, timeout=20)
    try:
        connection.request("GET", parsed.path)
        response = connection.getresponse()
        # A redirect makes this checker initiate a second attacker-selected
        # request. Reject it before reading its body instead of recursively
        # widening the fetch surface.
        if 300 <= response.status < 400:
            fail("pointer evidence redirects are not allowed")
        if not 200 <= response.status < 300:
            fail(f"pointer evidence returned HTTP {response.status}")
        return read_bounded(response, MAX_EVIDENCE_BYTES)
    except (OSError, http.client.HTTPException) as exc:
        fail(f"cannot fetch pointer evidence: {exc}")
    finally:
        connection.close()


def check_index(index):
    if index.get("schema_version") != 1:
        fail("result-pointers/index.json schema_version must be 1")
    if index.get("listed_is_not_approved") is not True:
        fail("result-pointers/index.json must set listed_is_not_approved to true")
    extra = set(index) - {"schema_version", "listed_is_not_approved", "entries"}
    if extra:
        fail(f"result-pointers/index.json has unknown fields: {sorted(extra)}")
    entries = index.get("entries")
    if not isinstance(entries, list) or any(not isinstance(item, str) or not item for item in entries):
        fail("result-pointers/index.json entries must be a list of nonempty strings")
    if entries != sorted(entries):
        fail("result-pointers/index.json entries must be in code-point order")
    if len(entries) != len(set(entries)):
        fail("result-pointers/index.json entries must be unique")
    return entries


def check_readme(readme_path):
    if not readme_path.is_file() or readme_path.is_symlink():
        fail("result-pointers/README.md must be a regular file")
    text = readme_path.read_text(encoding="utf-8").lower()
    if REQUIRED_README_PHRASE not in text:
        fail("result-pointers/README.md must say listing is not approval")


def check_pointer(path, schema, expected_id):
    pointer = load_json(path, "result pointer")
    forbidden = FORBIDDEN_POINTER_KEYS.intersection(pointer)
    if forbidden:
        fail(f"{path.name} contains forbidden keys: {sorted(forbidden)}")
    validate(pointer, schema, path.name)
    digest = pointer_id(pointer)
    if path.stem != digest or path.suffix != ".json":
        fail(f"{path.name} must be named {digest}.json")
    if expected_id != digest:
        fail(f"{path.name} does not match index id {expected_id}")
    return pointer


def check(root=ROOT, fetch=default_fetch):
    schema = load_schema(SCHEMA_PATH if root == ROOT else root / "schemas" / "result-pointer-v1.schema.json")
    pointers_root = root / "result-pointers"
    index = load_json(pointers_root / "index.json", "result pointer index")
    ids = check_index(index)
    check_readme(pointers_root / "README.md")
    entries_root = pointers_root / "entries"
    if entries_root.exists() and (not entries_root.is_dir() or entries_root.is_symlink()):
        fail("result-pointers/entries must be a directory")
    on_disk = []
    if entries_root.is_dir():
        for path in sorted(entries_root.iterdir()):
            if path.name.startswith("."):
                continue
            if path.is_symlink() or not path.is_file() or path.suffix != ".json":
                fail(f"unexpected result pointer path: {path.name}")
            on_disk.append(path.stem)
    if on_disk != ids:
        fail("result-pointers/index.json entries must match entries/*.json")
    for pointer_id_value in ids:
        pointer = check_pointer(entries_root / f"{pointer_id_value}.json", schema, pointer_id_value)
        if pointer.get("withdrawn"):
            continue
        body = fetch(pointer["evidence_url"])
        if not body:
            fail(f"{pointer_id_value} evidence is empty")
        digest = hashlib.sha256(body).hexdigest()
        if digest != pointer["evidence_sha256"]:
            fail(f"{pointer_id_value} evidence digest mismatch")
        if "manifest_url" in pointer:
            manifest = fetch(pointer["manifest_url"])
            if not manifest:
                fail(f"{pointer_id_value} manifest is empty")
            if hashlib.sha256(manifest).hexdigest() != pointer["manifest_sha256"]:
                fail(f"{pointer_id_value} manifest digest mismatch")
    return len(ids)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=str(ROOT))
    args = parser.parse_args()
    try:
        count = check(Path(args.root))
    except ValueError as exc:
        print(f"validate-result-pointers: {exc}", file=sys.stderr)
        return 1
    print(f"validate-result-pointers: {count} pointer(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
