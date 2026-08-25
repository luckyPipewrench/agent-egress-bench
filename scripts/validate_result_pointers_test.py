#!/usr/bin/env python3
"""Mechanical admission tests for result pointers."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import tempfile
import threading
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


CONFORMANCE = json.loads((ROOT / "schemas/conformance/result-pointer-v1.json").read_text(encoding="utf-8"))


def pointer_object(**overrides):
    value = dict(CONFORMANCE["accepted"][0]["instance"])
    value["evidence_sha256"] = hashlib.sha256(FIXTURE_BODY).hexdigest()
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

    def test_stalled_resolver_is_bound_by_the_fetch_timeout(self):
        release = threading.Event()

        def stall(*args, **kwargs):
            release.wait(timeout=5)
            return [
                (pointers.socket.AF_INET, pointers.socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
            ]

        try:
            with mock.patch.object(pointers.socket, "getaddrinfo", stall):
                with self.assertRaisesRegex(ValueError, "timed out"):
                    pointers.default_fetch(
                        "https://results.example/lab/evidence.tar",
                        timeout=0.15,
                    )
        finally:
            release.set()

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
        resolve.assert_called_once_with(
            "results.example", 443, timeout=pointers.FETCH_TIMEOUT_SECONDS
        )
        connect.assert_called_once_with(
            "results.example", "8.8.8.8", 443, timeout=pointers.FETCH_TIMEOUT_SECONDS
        )
        self.assertEqual(connection.requested, [("GET", "/lab/evidence.tar")])
        self.assertTrue(connection.closed)

    def test_pinned_connection_uses_the_checked_address_with_the_url_host_for_tls(self):
        connection = pointers.PinnedHTTPSConnection(
            "results.example", "8.8.8.8", 443, timeout=pointers.FETCH_TIMEOUT_SECONDS
        )
        raw_socket = object()
        context = mock.Mock()
        context.wrap_socket.return_value = object()
        connection._context = context
        with mock.patch.object(pointers.socket, "create_connection", return_value=raw_socket) as create:
            connection.connect()
        create.assert_called_once_with(("8.8.8.8", 443), pointers.FETCH_TIMEOUT_SECONDS, None)
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

    def test_too_many_index_entries_are_refused(self):
        first = pointer_object(publisher="lab-a")
        second = pointer_object(publisher="lab-b")
        ids = sorted([pointers.pointer_id(first), pointers.pointer_id(second)])
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": ids},
            [first, second],
        )
        with mock.patch.object(pointers, "MAX_POINTER_ENTRIES", 1):
            with self.assertRaisesRegex(ValueError, "exceeds 1 entries"):
                pointers.check(self.temp, fetch=lambda url: FIXTURE_BODY)

    def test_too_many_live_fetches_are_refused(self):
        first = pointer_object(publisher="lab-a")
        second = pointer_object(publisher="lab-b")
        ids = sorted([pointers.pointer_id(first), pointers.pointer_id(second)])
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": ids},
            [first, second],
        )
        with mock.patch.object(pointers, "MAX_LIVE_FETCHES", 1):
            with self.assertRaisesRegex(ValueError, "live pointer fetches exceed 1"):
                pointers.check(self.temp, fetch=lambda url: FIXTURE_BODY)

    def test_fetch_deadline_is_refused(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        with mock.patch.object(pointers, "MAX_FETCH_DEADLINE_SECONDS", 0):
            with self.assertRaisesRegex(ValueError, "fetch deadline exceeded"):
                pointers.check(self.temp, fetch=lambda url: FIXTURE_BODY)

    def test_fetch_that_overruns_the_deadline_is_refused(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        clock = {"now": 0.0}

        def monotonic():
            return clock["now"]

        def slow_fetch(url):
            clock["now"] += 200
            return FIXTURE_BODY

        with mock.patch.object(pointers.time, "monotonic", monotonic):
            with mock.patch.object(pointers, "MAX_FETCH_DEADLINE_SECONDS", 120):
                with self.assertRaisesRegex(ValueError, "fetch deadline exceeded"):
                    pointers.check(self.temp, fetch=slow_fetch)

    def test_default_fetch_uses_the_remaining_timeout(self):
        connection = FakeConnection(FakeResponse(200, FIXTURE_BODY))
        with mock.patch.object(pointers, "resolve_public_address", return_value="8.8.8.8"):
            with mock.patch.object(pointers, "PinnedHTTPSConnection", return_value=connection) as connect:
                pointers.default_fetch(
                    "https://results.example/lab/evidence.tar",
                    timeout=3.5,
                    deadline=pointers.time.monotonic() + 10,
                )
        connect.assert_called_once_with("results.example", "8.8.8.8", 443, timeout=3.5)

    def test_check_bounds_default_fetch_to_remaining_deadline(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        connection = FakeConnection(FakeResponse(200, FIXTURE_BODY))
        with mock.patch.object(pointers.time, "monotonic", return_value=100.0):
            with mock.patch.object(pointers, "MAX_FETCH_DEADLINE_SECONDS", 8):
                with mock.patch.object(pointers, "resolve_public_address", return_value="8.8.8.8"):
                    with mock.patch.object(pointers, "PinnedHTTPSConnection", return_value=connection) as connect:
                        self.assertEqual(pointers.check(self.temp, fetch=pointers.default_fetch), 1)
        connect.assert_called_once_with("results.example", "8.8.8.8", 443, timeout=8)

    def test_history_rejects_deleted_pointer(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": []},
            [],
        )
        with self.assertRaisesRegex(ValueError, "cannot remove listed pointer"):
            pointers.check(self.temp, fetch=self.fail_fetch, baseline={digest: pointer})

    def test_history_rejects_unwithdrawal(self):
        live = pointer_object()
        withdrawn = pointer_object(withdrawn={"reason": "dead_url"})
        digest = pointers.pointer_id(withdrawn)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [live],
        )
        with self.assertRaisesRegex(ValueError, "cannot rewrite withdrawal"):
            pointers.check(self.temp, fetch=lambda url: FIXTURE_BODY, baseline={digest: withdrawn})

    def test_history_rejects_rewritten_withdrawal_reason(self):
        old = pointer_object(withdrawn={"reason": "dead_url"})
        new = pointer_object(withdrawn={"reason": "publisher_request"})
        digest = pointers.pointer_id(new)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [new],
        )
        with self.assertRaisesRegex(ValueError, "cannot rewrite withdrawal"):
            pointers.check(self.temp, fetch=self.fail_fetch, baseline={digest: old})

    def test_history_allows_adding_withdrawn(self):
        live = pointer_object()
        withdrawn = pointer_object(withdrawn={"reason": "publisher_request"})
        digest = pointers.pointer_id(withdrawn)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [withdrawn],
        )
        self.assertEqual(
            pointers.check(self.temp, fetch=self.fail_fetch, baseline={digest: live}),
            1,
        )

    def fail_fetch(self, url):
        self.fail(f"fetch should not run: {url}")


class PointerHistoryGitTest(unittest.TestCase):
    def setUp(self):
        self.temp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.git("init", "-q")
        self.git("config", "user.email", "pointer-test@example.invalid")
        self.git("config", "user.name", "Pointer Test")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.temp), *args],
            check=True,
            capture_output=True,
        ).stdout

    def test_empty_base_tree_is_a_valid_baseline(self):
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": []},
            [],
        )
        self.git("add", ".")
        self.git("commit", "-qm", "empty pointers")
        base = self.git("rev-parse", "HEAD").decode().strip()
        self.assertEqual(pointers.load_baseline_from_git(self.temp, base), {})
        self.assertEqual(pointers.check(self.temp, fetch=self.fail_fetch, baseline={}), 0)

    def test_git_baseline_rejects_deleted_pointer(self):
        pointer = pointer_object()
        digest = pointers.pointer_id(pointer)
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": [digest]},
            [pointer],
        )
        self.git("add", ".")
        self.git("commit", "-qm", "listed pointer")
        base = self.git("rev-parse", "HEAD").decode().strip()
        shutil.rmtree(self.temp / "result-pointers" / "entries")
        (self.temp / "result-pointers" / "index.json").write_text(
            json.dumps({"schema_version": 1, "listed_is_not_approved": True, "entries": []}, indent=2)
            + "\n",
            encoding="utf-8",
        )
        self.git("add", ".")
        self.git("commit", "-qm", "deleted pointer")
        baseline = pointers.load_baseline_from_git(self.temp, base)
        self.assertEqual(list(baseline), [digest])
        with self.assertRaisesRegex(ValueError, "cannot remove listed pointer"):
            pointers.check(self.temp, fetch=self.fail_fetch, baseline=baseline)

    def test_git_base_must_be_an_ancestor(self):
        write_tree(
            self.temp,
            {"schema_version": 1, "listed_is_not_approved": True, "entries": []},
            [],
        )
        self.git("add", ".")
        self.git("commit", "-qm", "main")
        self.git("checkout", "-q", "-b", "side")
        (self.temp / "result-pointers" / "README.md").write_text(
            "Listed pointers are findable evidence. Listing is not approval.\nside\n",
            encoding="utf-8",
        )
        self.git("add", ".")
        self.git("commit", "-qm", "side")
        self.git("checkout", "-q", "-")
        side = self.git("rev-parse", "side").decode().strip()
        with self.assertRaisesRegex(ValueError, "not an ancestor of HEAD"):
            pointers.load_baseline_from_git(self.temp, side)

    def fail_fetch(self, url):
        self.fail(f"fetch should not run: {url}")


if __name__ == "__main__":
    unittest.main()
