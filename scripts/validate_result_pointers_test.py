#!/usr/bin/env python3
"""Mechanical admission tests for result pointers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "validate_result_pointers", ROOT / "scripts" / "validate_result_pointers.py"
)
pointers = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(pointers)

SCHEMA = ROOT / "schemas" / "result-pointer-v1.schema.json"
FIXTURE_BODY = b"fixture-evidence\n"


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.offset = 0
        self.read_calls = 0

    def read(self, size):
        self.read_calls += 1
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requested = []
        self.closed = False

    def request(self, method, path):
        self.requested.append((method, path))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def pointer_object(**overrides):
    value = {
        "schema_version": 1,
        "publisher": "example-lab",
        "tool": "example-gateway",
        "tool_version": "1.0.0",
        "method_repository": "https://github.com/luckyPipewrench/agent-egress-bench",
        "method_commit": "9ba2d4040b14c8f1d2e3a4b5c6d7e8f901234567",
        "report_family": "gateway-inspectable",
        "evidence_url": "https://results.example/lab/example-gateway/1.0.0/evidence.tar",
        "evidence_sha256": hashlib.sha256(FIXTURE_BODY).hexdigest(),
    }
    value.update(overrides)
    return value


def write_tree(base, index, entries):
    pointers_root = base / "result-pointers"
    pointers_root.mkdir()
    (pointers_root / "README.md").write_text(
        "Listed pointers are findable evidence. Listing is not approval.\n",
        encoding="utf-8",
    )
    (pointers_root / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    schema_dir = base / "schemas"
    schema_dir.mkdir()
    shutil.copyfile(SCHEMA, schema_dir / "result-pointer-v1.schema.json")
    if entries:
        entry_dir = pointers_root / "entries"
        entry_dir.mkdir()
        for pointer in entries:
            digest = pointers.pointer_id(pointer)
            (entry_dir / f"{digest}.json").write_text(json.dumps(pointer, indent=2) + "\n", encoding="utf-8")
    return base


class ValidateResultPointersTest(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)

    def test_empty_index_is_admitted(self):
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": []},
            [],
        )
        self.assertEqual(pointers.check(self.temp, fetch=self.fail_fetch), 0)

    def test_matching_digest_is_admitted(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        fetched = []

        def fetch(url):
            fetched.append(url)
            return FIXTURE_BODY

        self.assertEqual(pointers.check(self.temp, fetch=fetch), 1)
        self.assertEqual(fetched, [pointer["evidence_url"]])

    def test_digest_mismatch_is_refused(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        with self.assertRaisesRegex(ValueError, "evidence digest mismatch"):
            pointers.check(self.temp, fetch=lambda url: b"other")

    def test_empty_evidence_or_manifest_is_refused(self):
        empty_digest = hashlib.sha256(b"").hexdigest()
        for label, overrides, expected in (
            ("evidence", {"evidence_sha256": empty_digest}, "evidence is empty"),
            (
                "manifest",
                {
                    "manifest_url": "https://results.example/lab/example-gateway/1.0.0/manifest.json",
                    "manifest_sha256": empty_digest,
                },
                "manifest is empty",
            ),
        ):
            with self.subTest(label=label):
                pointer = pointer_object(**overrides)
                digest = pointers.pointer_id(pointer)
                root = self.temp / label
                root.mkdir()
                write_tree(
                    root,
                    {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
                    [pointer],
                )
                def fetch(url):
                    if label == "evidence" or url == pointer.get("manifest_url"):
                        return b""
                    return FIXTURE_BODY

                with self.assertRaisesRegex(ValueError, expected):
                    pointers.check(root, fetch=fetch)

    def test_score_field_is_refused(self):
        pointer = pointer_object(containment=0.98)
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        with self.assertRaisesRegex(ValueError, "forbidden keys"):
            pointers.check(self.temp, fetch=self.fail_fetch)

    def test_unsorted_index_is_refused(self):
        first = pointer_object(publisher="z-lab")
        second = pointer_object(publisher="a-lab")
        ids = sorted([pointers.pointer_id(first), pointers.pointer_id(second)], reverse=True)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": ids},
            [first, second],
        )
        with self.assertRaisesRegex(ValueError, "code-point order"):
            pointers.check(self.temp, fetch=lambda url: FIXTURE_BODY)

    def test_withdrawn_pointer_skips_fetch(self):
        pointer = pointer_object(withdrawn={"reason": "dead_url"})
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        self.assertEqual(pointers.check(self.temp, fetch=self.fail_fetch), 1)

    def test_withdrawal_preserves_the_pointer_identity(self):
        pointer = pointer_object()
        withdrawn = pointer_object(withdrawn={"reason": "publisher_request"})
        self.assertEqual(pointers.pointer_id(withdrawn), pointers.pointer_id(pointer))

    def test_literal_ip_url_is_refused(self):
        with self.assertRaisesRegex(ValueError, "literal IP"):
            pointers.require_https_url("https://127.0.0.1/evidence.tar", "evidence_url")

    def test_non_default_port_is_refused(self):
        with self.assertRaisesRegex(ValueError, "port 443"):
            pointers.require_https_url("https://results.example:8443/evidence.tar", "evidence_url")
        with self.assertRaisesRegex(ValueError, "port 443"):
            pointers.require_https_url("https://results.example:0/evidence.tar", "evidence_url")

    def test_resolver_refuses_private_answer(self):
        with mock.patch.object(
            pointers.socket,
            "getaddrinfo",
            return_value=[(pointers.socket.AF_INET, pointers.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
        ):
            with self.assertRaisesRegex(ValueError, "non-global address"):
                pointers.resolve_public_address("results.example", 443)

    def test_fetch_refuses_a_private_resolution_before_connecting(self):
        with mock.patch.object(
            pointers.socket,
            "getaddrinfo",
            return_value=[(pointers.socket.AF_INET, pointers.socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
        ):
            with mock.patch.object(pointers, "PinnedHTTPSConnection") as connect:
                with self.assertRaisesRegex(ValueError, "non-global address"):
                    pointers.default_fetch("https://results.example/lab/evidence.tar")
        connect.assert_not_called()

    def test_fetch_pins_the_checked_address(self):
        connection = FakeConnection(FakeResponse(200, FIXTURE_BODY))
        with mock.patch.object(pointers, "resolve_public_address", return_value="8.8.8.8") as resolve:
            with mock.patch.object(pointers, "PinnedHTTPSConnection", return_value=connection) as connect:
                self.assertEqual(
                    pointers.default_fetch("https://results.example/lab/evidence.tar"),
                    FIXTURE_BODY,
                )
        resolve.assert_called_once_with("results.example", 443)
        connect.assert_called_once_with("results.example", "8.8.8.8", 443, timeout=20)
        self.assertEqual(connection.requested, [("GET", "/lab/evidence.tar")])
        self.assertTrue(connection.closed)

    def test_pinned_connection_uses_the_checked_address_with_the_url_host_for_tls(self):
        connection = pointers.PinnedHTTPSConnection("results.example", "8.8.8.8", 443, timeout=20)
        raw_socket = object()
        context = mock.Mock()
        context.wrap_socket.return_value = object()
        connection._context = context
        with mock.patch.object(pointers.socket, "create_connection", return_value=raw_socket) as create:
            connection.connect()
        create.assert_called_once_with(("8.8.8.8", 443), 20, None)
        context.wrap_socket.assert_called_once_with(raw_socket, server_hostname="results.example")

    def test_fetch_refuses_redirect_without_reading_the_response(self):
        response = FakeResponse(302, b"redirect body")
        connection = FakeConnection(response)
        with mock.patch.object(pointers, "resolve_public_address", return_value="8.8.8.8"):
            with mock.patch.object(pointers, "PinnedHTTPSConnection", return_value=connection):
                with self.assertRaisesRegex(ValueError, "redirects are not allowed"):
                    pointers.default_fetch("https://results.example/lab/evidence.tar")
        self.assertEqual(response.read_calls, 0)
        self.assertTrue(connection.closed)

    def fail_fetch(self, url):
        self.fail(f"fetch should not run: {url}")


if __name__ == "__main__":
    unittest.main()
