#!/usr/bin/env python3
"""Regression tests for the v4 raw capability-registry publication binding."""

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_gauntlet_provenance as provenance


class CapabilityRegistryPublicationTest(unittest.TestCase):
    def write_v4_evidence(self, root):
        snapshot_bytes = b'{"id":"test.registry","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active"}]}'
        reference = {
            "id": "test.registry",
            "format": 1,
            "revision": 1,
            "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        }
        (root / "capability-registry.json").write_bytes(snapshot_bytes)
        profile_bytes = json.dumps({"capability_registry": reference, "claims": ["url_dlp"]}).encode()
        (root / "tool-profile.json").write_bytes(profile_bytes)
        (root / "receipt-profile.json").write_text(json.dumps({"capability_registry": reference}), encoding="utf-8")
        summary = {"schema_version": 4, "capability_registry": reference, "reported_claims": ["url_dlp"], "exercised": {"capability_tags": ["url_dlp"]}, "tool_profile_sha256": hashlib.sha256(profile_bytes).hexdigest()}
        rows = [{"capability_registry": reference}]
        return summary, rows

    def test_exact_raw_snapshot_binds_summary_profile_receipt_and_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary, rows = self.write_v4_evidence(root)
            self.assertEqual(
                provenance.validate_v4_registry_binding(root, summary, rows),
                summary["capability_registry"],
            )

    def test_digest_mismatch_is_uninterpretable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary, rows = self.write_v4_evidence(root)
            summary["capability_registry"] = dict(summary["capability_registry"], sha256="0" * 64)
            with self.assertRaisesRegex(ValueError, "digest"):
                provenance.validate_v4_registry_binding(root, summary, rows)

    def test_row_triple_mismatch_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            summary, rows = self.write_v4_evidence(root)
            rows[0]["capability_registry"] = dict(rows[0]["capability_registry"], revision=2)
            with self.assertRaisesRegex(ValueError, "runner JSONL row"):
                provenance.validate_v4_registry_binding(root, summary, rows)


if __name__ == "__main__":
    unittest.main()
