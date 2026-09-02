#!/usr/bin/env python3
"""Tests for portable Gauntlet evidence construction and finalization."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from scripts import build_gauntlet_provenance


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER = REPO_ROOT / "scripts" / "build_gauntlet_provenance.py"
RUNNER = REPO_ROOT / "scripts" / "run-pipelock-gauntlet.sh"
RELEASE_PIN = REPO_ROOT / "examples" / "pipelock" / "release.env"


def parsed_release_pin():
    values = {}
    for line in RELEASE_PIN.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


PIN = parsed_release_pin()
PIN_VERSION = PIN["PIPELOCK_VERSION"]
PIN_TAG = PIN["PIPELOCK_TAG"]


class ProvenanceBuilderTest(unittest.TestCase):
    def test_active_candidate_version_uses_its_own_version_symbol(self):
        with (
            mock.patch.object(build_gauntlet_provenance, "ACTIVE_SUMMARY_SCHEMA_VERSION", 7),
            mock.patch.object(
                build_gauntlet_provenance, "ACTIVE_SUMMARY_SCHEMA_VERSIONS", frozenset({4, 5, 6, 7})
            ),
        ):
            self.assertEqual(6, build_gauntlet_provenance.provenance_candidate_schema_version(7))
            self.assertEqual(4, build_gauntlet_provenance.provenance_candidate_schema_version(4))

    def test_active_result_score_enforces_budget_timing(self):
        contract = json.loads((REPO_ROOT / "contracts" / "result-states-v5.json").read_text())
        scores = contract["case_specific_overrides"][0]["scores_by_budget_block_timing"]
        for timing, expected_score in scores.items():
            with self.subTest(timing=timing):
                self.assertEqual(
                    build_gauntlet_provenance.active_result_score(
                        "block", "block", {"budget_block_timing": timing}, True
                    ),
                    expected_score,
                )
        for evidence in ({}, {"budget_block_timing": "unknown"}):
            with self.subTest(evidence=evidence):
                with self.assertRaisesRegex(ValueError, "valid budget_block_timing"):
                    build_gauntlet_provenance.active_result_score("block", "block", evidence, True)
        with self.assertRaisesRegex(ValueError, "non-budget"):
            build_gauntlet_provenance.active_result_score(
                "block", "block", {"budget_block_timing": "before_over_budget"}, False
            )

    def test_v5_result_row_contract_conformance_vectors(self):
        active_version, accepted_versions, result_states, active_scoring_version = (
            build_gauntlet_provenance.result_reader_contract(REPO_ROOT)
        )
        corpus = json.loads(
            (REPO_ROOT / "validate" / "testdata" / "result-v5-conformance.json").read_text(
                encoding="utf-8"
            )
        )
        for vector in corpus["accepted"]:
            with self.subTest(kind="accepted", name=vector["name"]):
                build_gauntlet_provenance.validate_result_row_contract(
                    vector["row"],
                    1,
                    5,
                    active_version,
                    accepted_versions,
                    result_states,
                    active_scoring_version,
                )
        for vector in corpus["rejected"]:
            with self.subTest(kind="rejected", name=vector["name"]):
                with self.assertRaises(ValueError):
                    build_gauntlet_provenance.validate_result_row_contract(
                        vector["row"],
                        1,
                        5,
                        active_version,
                        accepted_versions,
                        result_states,
                        active_scoring_version,
                    )

    def test_current_summary_rejects_legacy_labeled_result_row(self):
        active_version, accepted_versions, result_states, active_scoring_version = (
            build_gauntlet_provenance.result_reader_contract(REPO_ROOT)
        )
        with self.assertRaisesRegex(ValueError, "must be at least summary schema_version 5"):
            build_gauntlet_provenance.validate_result_row_contract(
                {"schema_version": 4},
                1,
                5,
                active_version,
                accepted_versions,
                result_states,
                active_scoring_version,
            )

    def test_v4_summary_accepts_v4_result_row_contract(self):
        active_version, accepted_versions, result_states, active_scoring_version = (
            build_gauntlet_provenance.result_reader_contract(REPO_ROOT)
        )
        build_gauntlet_provenance.validate_result_row_contract(
            {"schema_version": 4}, 1, 4, active_version, accepted_versions, result_states, active_scoring_version
        )

    def test_active_result_rows_cannot_share_a_file_with_frozen_rows(self):
        for rows in (
            [{"schema_version": 5}, {"schema_version": 6}],
            [{"schema_version": 6}, {"schema_version": 5}],
        ):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(ValueError, "frozen result rows cannot share a file"):
                    build_gauntlet_provenance.validate_result_row_set_contract(rows, 6)
        build_gauntlet_provenance.validate_result_row_set_contract(
            [{"schema_version": 5}, {"schema_version": 5}], 6
        )

    def test_frozen_result_rows_must_omit_scoring_version(self):
        states = frozenset({"observed", "unreachable", "adapter_error"})
        accepted = frozenset({4, 5, 6})
        valid_rows = (
            ({"schema_version": 4}, 4),
            (
                {
                    "schema_version": 5,
                    "actual_verdict": "block",
                    "score": "pass",
                    "evidence": {"result_state": "observed"},
                },
                5,
            ),
        )
        for row, summary_schema_version in valid_rows:
            with self.subTest(schema_version=row["schema_version"], declared=False):
                build_gauntlet_provenance.validate_result_row_contract(
                    row, 1, summary_schema_version, 6, accepted, states, "2.8"
                )
            for scoring_version in (None, "", "2.8"):
                with self.subTest(
                    schema_version=row["schema_version"], scoring_version=scoring_version
                ):
                    with self.assertRaisesRegex(ValueError, "must not declare scoring_version"):
                        build_gauntlet_provenance.validate_result_row_contract(
                            {**row, "scoring_version": scoring_version},
                            1,
                            summary_schema_version,
                            6,
                            accepted,
                            states,
                            "2.8",
                        )

    def test_v6_result_row_requires_summary_bound_scoring_version(self):
        row = {
            "schema_version": 6,
            "actual_verdict": "block",
            "score": "pass",
            "evidence": {"result_state": "observed"},
            "scoring_version": "2.9",
        }
        states = frozenset({"observed", "unreachable", "adapter_error"})
        accepted = frozenset({4, 5, 6})
        row["scoring_version"] = "2.8"
        build_gauntlet_provenance.validate_result_row_contract(
            row, 1, 5, 6, accepted, states, "2.8", summary_scoring_version="2.8"
        )
        for value, summary_version, message in (
            ("", "2.8", "missing or empty"),
            ("2.9", "2.8", "does not match summary"),
        ):
            with self.subTest(scoring_version=value):
                row["scoring_version"] = value
                with self.assertRaisesRegex(ValueError, message):
                    build_gauntlet_provenance.validate_result_row_contract(
                        row, 1, 5, 6, accepted, states, "2.8", summary_scoring_version=summary_version
                    )

    def test_fresh_publication_requires_active_row_and_scorer(self):
        states = frozenset({"observed", "unreachable", "adapter_error"})
        accepted = frozenset({4, 5, 6})
        v5_row = {
            "schema_version": 5,
            "actual_verdict": "block",
            "score": "pass",
            "evidence": {"result_state": "observed"},
        }
        with self.assertRaisesRegex(ValueError, "must use active result schema_version 6"):
            build_gauntlet_provenance.validate_result_row_contract(
                v5_row,
                1,
                5,
                6,
                accepted,
                states,
                "2.8",
                summary_scoring_version="2.8",
                require_active=True,
            )
        v6_row = {**v5_row, "schema_version": 6, "scoring_version": "2.9"}
        with self.assertRaisesRegex(ValueError, "summary scoring_version"):
            build_gauntlet_provenance.validate_result_row_contract(
                v6_row,
                1,
                5,
                6,
                accepted,
                states,
                "2.8",
                summary_scoring_version="2.9",
                require_active=True,
            )
        with self.assertRaisesRegex(ValueError, "summary scoring_version"):
            build_gauntlet_provenance.validate_result_row_contract(
                v6_row,
                1,
                5,
                6,
                accepted,
                states,
                "2.8",
                summary_scoring_version="2.9",
                require_active=False,
            )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.run_dir = self.root / "run"
        (self.root / "cases").mkdir()
        (self.root / "contracts").mkdir()
        for name in ("artifacts.json", "result-states-v5.json", "result-states-v6.json"):
            (self.root / "contracts" / name).write_bytes(
                (REPO_ROOT / "contracts" / name).read_bytes()
            )
        self.run_dir.mkdir()
        (self.root / "cases" / "MANIFEST.txt").write_text("a\nb\nc\n", encoding="utf-8")
        self.results = [
            {
                "case_id": "a",
                "tool": "Pipelock",
                "tool_version": PIN_VERSION,
                "expected_verdict": "block",
                "actual_verdict": "block",
                "score": "pass",
                "evidence": {"scanner": "test"},
                "notes": "",
            },
            {
                "case_id": "b",
                "tool": "Pipelock",
                "tool_version": PIN_VERSION,
                "expected_verdict": "allow",
                "actual_verdict": "allow",
                "score": "pass",
                "evidence": {},
                "notes": "",
            },
            {
                "case_id": "c",
                "tool": "Pipelock",
                "tool_version": PIN_VERSION,
                "expected_verdict": "block",
                "actual_verdict": "not_applicable",
                "score": "not_applicable",
                "evidence": {},
                "notes": "",
            },
        ]
        self.write_fixture()

    def write_fixture(self, detection_score=1.0, evidence_score=1.0):
        summary = {
            "gauntlet_version": "1",
            "scoring_version": "2.4",
            "runner_version": "0.4.2",
            "tool": "Pipelock",
            "tool_version": PIN_VERSION,
            "corpus_version": "test",
            "corpus_sha256": "a" * 64,
            "tool_profile_sha256": "b" * 64,
            "case_count": {
                "total": 3,
                "applicable": 2,
                "not_applicable": 1,
                "not_applicable_reasons": {"missing_requires": 1},
                "errors": 0,
            },
            "scores": {
                "applicable": {
                    "containment": 1.0,
                    "false_positive_rate": 0.0,
                    "detection": detection_score,
                    "evidence": evidence_score,
                },
                "full": {
                    "containment": 0.5,
                    "false_positive_rate": 0.0,
                    "detection": detection_score,
                    "evidence": evidence_score,
                },
            },
            "sufficient": False,
        }
        (self.run_dir / "raw-summary.json").write_text(json.dumps(summary), encoding="utf-8")
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.results), encoding="utf-8"
        )
        (self.run_dir / "runner.stderr").write_text(
            "Fixtures: HTTP=x TLS=x WS=x DNS=x MCP_HTTP=x\n", encoding="utf-8"
        )
        (self.run_dir / "command.txt").write_text(
            "timeout 10s aeb-gauntlet --fixtures\n",
            encoding="utf-8",
        )
        (self.run_dir / "make-stats.txt").write_text(
            "block: 2\nallow: 1\nwarn: 0\n", encoding="utf-8"
        )
        (self.run_dir / "case-index.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cases": [
                        {"case_id": "a", "category": "test", "expected_verdict": "block"},
                        {"case_id": "b", "category": "test", "expected_verdict": "allow"},
                        {"case_id": "c", "category": "test", "expected_verdict": "block"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "entrypoint-command.txt").write_text(
            "./scripts/run-pipelock-gauntlet.sh\n", encoding="utf-8"
        )
        (self.run_dir / "run-metadata.json").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "local_run_id": "local:test:1",
                    "generated_at": "2026-08-04T00:00:00Z",
                    "corpus_repository": "luckyPipewrench/agent-egress-bench",
                    "corpus_ref_kind": "origin/main",
                    "corpus_git_sha": "c" * 40,
                    "dirty": False,
                    "canonical_execution": True,
                    "noncanonical_reasons": [],
                    "runner_go_version": "go version go1.25.0 linux/amd64",
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "pipelock-release.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": "luckyPipewrench/pipelock",
                    "tag": PIN_TAG,
                    "version": PIN_VERSION,
                    "asset": f"pipelock_{PIN_VERSION}_linux_amd64.tar.gz",
                    "asset_sha256": "d" * 64,
                    "binary_sha256": "e" * 64,
                    "version_output": f"pipelock version {PIN_VERSION}",
                    "released_binary": True,
                }
            ),
            encoding="utf-8",
        )
        (self.run_dir / "checksums.txt").write_text(
            "d" * 64 + f"  pipelock_{PIN_VERSION}_linux_amd64.tar.gz\n",
            encoding="utf-8",
        )
        (self.run_dir / "pipelock-version.txt").write_text(
            f"pipelock version {PIN_VERSION}\n", encoding="utf-8"
        )
        (self.run_dir / "corpus-manifest.txt").write_text("a\nb\nc\n", encoding="utf-8")

    def make_active_fixture(self, measurement_status="measured", summary_schema_version=4):
        snapshot_bytes = json.dumps(
            {
                "id": "aeb.test-capabilities",
                "format": 1,
                "revision": 1,
                "entries": [{"id": "test", "status": "active"}],
            },
            sort_keys=True,
        ).encode()
        reference = {
            "id": "aeb.test-capabilities",
            "format": 1,
            "revision": 1,
            "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
        }
        profile_bytes = json.dumps(
            {"capability_registry": reference, "claims": ["test"]}, sort_keys=True
        ).encode()
        (self.run_dir / "capability-registry.json").write_bytes(snapshot_bytes)
        (self.run_dir / "tool-profile.json").write_bytes(profile_bytes)
        (self.run_dir / "receipt-profile.json").write_text(
            json.dumps({"capability_registry": reference}), encoding="utf-8"
        )

        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["schema_version"] = summary_schema_version
        summary["case_count"]["unreachable"] = 0
        summary["capability_registry"] = reference
        summary["reported_claims"] = ["test"]
        summary["exercised"] = {
            "transports": ["fetch_proxy"],
            "categories": ["test"],
            "capability_tags": ["test"],
        }
        summary["tool_profile_sha256"] = hashlib.sha256(profile_bytes).hexdigest()
        summary["measurement_status"] = measurement_status
        summary.pop("sufficient", None)
        if summary_schema_version == 5:
            self.results[2].update(
                actual_verdict="block",
                score="pass",
                evidence={"scanner": "test", "result_state": "observed"},
            )
            summary["case_count"].update(
                applicable=3,
                not_applicable=0,
                not_applicable_reasons={},
            )
            summary["scores"]["full"]["containment"] = 1.0
            summary["scoring_version"] = "2.8"
            summary["runner_version"] = "0.4.3"
            summary["benchmark_manifest_sha256"] = "c" * 64
            summary["diagnostics"] = {
                scope: {
                    "classification_present_rate": values.pop("detection"),
                    "structured_evidence_present_rate": values.pop("evidence"),
                }
                for scope, values in summary["scores"].items()
            }
            summary["per_category"] = {
                "test": {
                    "applicable": 3,
                    "containment": 1.0,
                    "false_positive_rate": 0.0,
                    "diagnostics": {
                        "classification_present_rate": 1.0,
                        "structured_evidence_present_rate": 1.0,
                    },
                }
            }
            (self.run_dir / "case-index.json").write_text(
                json.dumps(
                    {
                        "schema_version": 3,
                        "cases": {
                            "a": {"category": "test", "expected_verdict": "block", "transport": "fetch_proxy", "capability_tags": ["test"]},
                            "b": {"category": "test", "expected_verdict": "allow", "transport": "fetch_proxy", "capability_tags": ["test"]},
                            "c": {"category": "test", "expected_verdict": "block", "transport": "fetch_proxy", "capability_tags": ["test"]},
                        },
                    }
                ),
                encoding="utf-8",
            )
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        if summary_schema_version == 5:
            (self.run_dir / "receipt-profile.json").write_text(
                json.dumps(
                    {
                        "schema_version": 5,
                        "tool": summary["tool"],
                        "tool_version": summary["tool_version"],
                        "observed_tool_version": {"status": "not_requested", "value": None},
                        "corpus_version": summary["corpus_version"],
                        "corpus_sha256": summary["corpus_sha256"],
                        "benchmark_manifest_sha256": summary["benchmark_manifest_sha256"],
                        "corpus_git_sha": "c" * 40,
                        "corpus_git_status": "clean",
                        "tool_profile_sha256": summary["tool_profile_sha256"],
                        "capability_registry": reference,
                        "verifier": {
                            "shipped": False,
                            "open_source": False,
                            "verifier_url": None,
                            "license": None,
                            "exit_code_contract": None,
                        },
                        "summary": {
                            "blocked_yes_count": 0,
                            "blocked_no_count": 0,
                            "explained_yes_count": 0,
                            "receipt_produced_yes_count": 0,
                            "receipt_independently_verifiable_yes_count": 0,
                            "false_positive_yes_count": 0,
                        },
                        "per_case": [],
                    }
                ),
                encoding="utf-8",
            )

        for row in self.results:
            row["schema_version"] = 6 if summary_schema_version == 5 else summary_schema_version
            row["capability_registry"] = reference
            if row["schema_version"] == 6:
                row["scoring_version"] = summary["scoring_version"]
                row["evidence"]["result_state"] = "observed"
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.results), encoding="utf-8"
        )
        if summary_schema_version == 5:
            self.add_publication_provenance()

    def make_active_set_fixture(self):
        self.make_active_fixture(summary_schema_version=5)
        self.results = self.results[:2]
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in self.results), encoding="utf-8"
        )
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["corpus_version"] = "v9.9.9"
        summary["case_count"] = {
            "total": 2,
            "applicable": 2,
            "unreachable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
            "errors": 0,
        }
        summary["scores"] = {
            "full": {"containment": 1.0, "false_positive_rate": 0.0},
            "applicable": {"containment": 1.0, "false_positive_rate": 0.0},
        }
        summary["diagnostics"] = {
            "full": {
                "classification_present_rate": 1.0,
                "structured_evidence_present_rate": 1.0,
            },
            "applicable": {
                "classification_present_rate": 1.0,
                "structured_evidence_present_rate": 1.0,
            },
        }
        summary["per_category"]["test"]["applicable"] = 2
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        receipt_path = self.run_dir / "receipt-profile.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["corpus_version"] = "v9.9.9"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        (self.root / "cases" / "CORPUS_VERSION").write_text("v9.9.9\n", encoding="utf-8")
        active_set_dir = self.root / "corpora" / "active-sets" / "v1"
        active_set_dir.mkdir(parents=True)
        manifest = (self.root / "cases" / "MANIFEST.txt").read_bytes()
        active_set = {
            "schema_version": 1,
            "corpus_version": "v9.9.9",
            "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "excluded_case_ids": ["c"],
            "case_count": 2,
        }
        active_set_path = active_set_dir / "v9.9.9.json"
        active_set_path.write_text(json.dumps(active_set), encoding="utf-8")
        (self.root / "ci").mkdir()
        (self.root / "ci" / "corpus-versions.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "versions": [
                        {
                            "corpus_version": "v9.9.9",
                            "case_count": 2,
                            "benchmark_manifest_sha256": summary["benchmark_manifest_sha256"],
                            "active_set_sha256": hashlib.sha256(
                                active_set_path.read_bytes()
                            ).hexdigest(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_dangling_corpus_version_symlink_is_rejected(self):
        marker_path = self.root / "cases" / "CORPUS_VERSION"
        marker_path.symlink_to("missing-corpus-version")

        with self.assertRaisesRegex(ValueError, "corpus version marker must be a regular file"):
            build_gauntlet_provenance.load_active_case_ids(
                self.root,
                {"corpus_version": "v9.9.9"},
                b"a\n",
                {"a"},
            )

    def add_publication_provenance(self):
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary.update(
            method_repository="luckyPipewrench/agent-egress-bench",
            method_commit="c" * 40,
            adapter_id="proxy",
            adapter_owner="Example Maintainers",
            target_config_ref="examples/pipelock/pipelock-benchmark.yaml",
            target_config_sha256="d" * 64,
        )
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        (self.run_dir / "command.txt").write_text(
            "timeout --signal=TERM --kill-after=30s 10s aeb-gauntlet "
            "--adapter proxy --fixtures "
            "--method-repository luckyPipewrench/agent-egress-bench "
            f"--method-commit {'c' * 40} "
            "--adapter-owner 'Example Maintainers' "
            "--target-config examples/pipelock/pipelock-benchmark.yaml "
            "--mcp-http-session-header Example-Session "
            "--mcp-http-session-format base64url_256 "
            "--mcp-http-session-refusal-header Example-Refusal "
            "--mcp-http-session-refusal-value session_required\n",
            encoding="utf-8",
        )

    def run_builder(self, *arguments):
        return subprocess.run(
            [sys.executable, str(BUILDER), *map(str, arguments)],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def bundle(self):
        return self.run_builder(
            "bundle", "--repo-root", self.root, "--run-dir", self.run_dir
        )

    def finalize(self, output=None):
        return self.run_builder(
            "finalize",
            "--repo-root",
            self.root,
            "--bundle",
            self.run_dir / "run-bundle.json",
            "--artifact-id",
            "github-actions:luckyPipewrench/agent-egress-bench:123",
            "--canonical-url",
            "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
            "--output",
            output or self.run_dir / "candidate.json",
        )

    def test_bundle_binds_manifest_case_index_and_metric_denominators(self):
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        bundle = json.loads((self.run_dir / "run-bundle.json").read_text(encoding="utf-8"))
        scope = bundle["candidate_scope"]
        self.assertEqual(
            scope["case_index_sha256"],
            hashlib.sha256((self.run_dir / "case-index.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(
            scope["metric_counts"]["applicable"]["containment"],
            {"numerator": 1, "denominator": 1},
        )
        self.assertEqual(
            scope["metric_counts"]["full"]["containment"],
            {"numerator": 1, "denominator": 2},
        )

    def test_bundle_uses_versioned_active_set_as_scored_corpus(self):
        self.make_active_set_fixture()

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads(
            (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
        )["candidate_scope"]
        self.assertEqual(scope["logical_case_count"], 2)
        self.assertEqual(scope["case_count"]["total"], 2)
        self.assertEqual(
            scope["corpus_manifest_sha256"],
            hashlib.sha256((self.root / "cases" / "MANIFEST.txt").read_bytes()).hexdigest(),
        )

    def test_bundle_rejects_active_set_unknown_exclusion(self):
        self.make_active_set_fixture()
        active_set_path = self.root / "corpora" / "active-sets" / "v1" / "v9.9.9.json"
        active_set = json.loads(active_set_path.read_text(encoding="utf-8"))
        active_set["excluded_case_ids"] = ["missing"]
        active_set_path.write_text(json.dumps(active_set), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active set excludes unknown case IDs", result.stderr)

    def test_active_complete_measurement_below_80_percent_is_retained(self):
        self.make_active_fixture()

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads(
            (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
        )["candidate_scope"]
        self.assertEqual(scope["scores"]["full"]["containment"], 0.5)
        self.assertEqual(scope["measurement_status"], "measured")
        self.assertNotIn("sufficient", scope)

    def test_active_summary_fixture_emits_scorer_bound_rows(self):
        self.make_active_fixture(summary_schema_version=6)

        rows = [
            json.loads(line)
            for line in (self.run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual({6}, {row["schema_version"] for row in rows})
        self.assertEqual({"2.4"}, {row["scoring_version"] for row in rows})

    def test_v5_moves_field_presence_out_of_scores_and_binds_it_as_diagnostics(self):
        self.make_active_fixture(summary_schema_version=5)

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads(
            (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
        )["candidate_scope"]
        self.assertEqual(scope["schema_version"], 6)
        self.assertEqual(scope["benchmark_manifest_sha256"], "c" * 64)
        self.assertEqual(set(scope["scores"]["applicable"]), {"containment", "false_positive_rate"})
        self.assertEqual(
            scope["diagnostic_counts"]["applicable"]["classification_present_rate"],
            {"numerator": 2, "denominator": 2},
        )

    def test_v5_rejects_receipt_profile_with_a_different_manifest_digest(self):
        self.make_active_fixture(summary_schema_version=5)
        receipt_path = self.run_dir / "receipt-profile.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt.update(
            schema_version=5,
            benchmark_manifest_sha256="f" * 64,
        )
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("receipt profile benchmark manifest digest does not match summary", result.stderr)

    def test_bundle_rejects_tool_profile_bytes_that_do_not_match_summary(self):
        self.make_active_fixture(summary_schema_version=5)
        profile_path = self.run_dir / "tool-profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["claims"].append("altered")
        profile_path.write_text(json.dumps(profile, sort_keys=True), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("tool profile raw snapshot digest does not match summary", result.stderr)

    def assert_v5_receipt_mutation_rejected(self, mutate, message):
        self.make_active_fixture(summary_schema_version=5)
        receipt_path = self.run_dir / "receipt-profile.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        mutate(receipt)
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_v5_rejects_missing_observed_tool_version(self):
        self.assert_v5_receipt_mutation_rejected(
            lambda receipt: receipt.pop("observed_tool_version"),
            "missing v5 provenance field observed_tool_version",
        )

    def test_v5_rejects_non_clean_corpus_for_publication(self):
        self.assert_v5_receipt_mutation_rejected(
            lambda receipt: receipt.update(corpus_git_status="dirty", corpus_git_sha=""),
            "requires clean corpus Git provenance for publication",
        )

    def test_v5_rejects_observed_tool_version_without_value(self):
        self.assert_v5_receipt_mutation_rejected(
            lambda receipt: receipt.update(observed_tool_version={"status": "observed", "value": None}),
            "observed tool version requires a non-empty value",
        )

    def test_v5_rejects_observed_tool_version_with_whitespace_only_value(self):
        self.assert_v5_receipt_mutation_rejected(
            lambda receipt: receipt.update(observed_tool_version={"status": "observed", "value": " \t "}),
            "observed tool version requires a non-empty value",
        )

    def test_v5_rejects_unavailable_tool_version_with_value(self):
        self.assert_v5_receipt_mutation_rejected(
            lambda receipt: receipt.update(observed_tool_version={"status": "not_requested", "value": "claimed"}),
            "unavailable tool version requires a null value",
        )

    def test_v6_candidate_carries_bound_publication_provenance(self):
        self.make_active_fixture(summary_schema_version=5)

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads(
            (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
        )["candidate_scope"]
        self.assertEqual(scope["schema_version"], 6)
        for field in (
            "method_repository",
            "method_commit",
            "adapter_id",
            "adapter_owner",
            "target_config_ref",
            "target_config_sha256",
        ):
            self.assertIn(field, scope)

    def test_v6_candidate_rejects_each_missing_publication_fact_by_name(self):
        for field in (
            "method_repository",
            "method_commit",
            "adapter_id",
            "adapter_owner",
            "target_config_ref",
            "target_config_sha256",
        ):
            with self.subTest(field=field):
                self.write_fixture()
                self.make_active_fixture(summary_schema_version=5)
                summary_path = self.run_dir / "raw-summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                del summary[field]
                summary_path.write_text(json.dumps(summary), encoding="utf-8")

                result = self.bundle()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)

    def test_v6_candidate_rejects_summary_command_identity_disagreement(self):
        self.make_active_fixture(summary_schema_version=5)
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["adapter_owner"] = "Different Maintainers"
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("adapter_owner does not match recorded runner command", result.stderr)

    def test_v6_candidate_rejects_provenance_after_argument_terminator(self):
        self.make_active_fixture(summary_schema_version=5)
        command_path = self.run_dir / "command.txt"
        command_path.write_text(
            command_path.read_text(encoding="utf-8").replace(
                " --method-repository", " -- --method-repository", 1
            ),
            encoding="utf-8",
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("terminator or shell operator", result.stderr)

    def test_v6_candidate_rejects_follow_on_shell_provenance(self):
        self.make_active_fixture(summary_schema_version=5)
        command_path = self.run_dir / "command.txt"
        command_path.write_text(
            command_path.read_text(encoding="utf-8").replace(
                " --method-repository", " ; echo --method-repository", 1
            ),
            encoding="utf-8",
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("terminator or shell operator", result.stderr)

    def test_v6_candidate_keeps_target_accommodation_in_hash_bound_command(self):
        self.make_active_fixture(summary_schema_version=5)

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads(
            (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
        )["candidate_scope"]
        self.assertNotIn("target_accommodation", scope)
        self.assertIn("--mcp-http-session-header Example-Session", scope["command"])

    def test_v5_bundle_rejects_missing_result_state(self):
        self.make_active_fixture(summary_schema_version=5)
        rows = [
            json.loads(line)
            for line in (self.run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        del rows[0]["evidence"]["result_state"]
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid or missing evidence.result_state", result.stderr)

    def test_v5_bundle_rejects_exercised_coverage_not_derived_from_observed_rows(self):
        self.make_active_fixture(summary_schema_version=5)
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["exercised"]["capability_tags"] = []
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "exercised coverage does not match observed result evidence", result.stderr
        )

    def test_v5_bundle_rejects_exercised_coverage_wider_than_the_observed_rows(self):
        # The companion test above shrinks the claim. Inflation is the direction
        # that matters for a published result: a summary naming a transport no
        # row drove would advertise a tested surface that was never tested.
        self.make_active_fixture(summary_schema_version=5)
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["exercised"]["transports"] = ["fetch_proxy", "mcp_http"]
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "exercised coverage does not match observed result evidence", result.stderr
        )

    def test_active_summary_without_manifest_digest_is_rejected(self):
        self.make_active_fixture(summary_schema_version=5)
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        del summary["benchmark_manifest_sha256"]
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("benchmark_manifest_sha256 must be 64 lower-case hex characters", result.stderr)

    def test_v5_rejects_retired_score_fields_before_they_enter_a_bundle(self):
        for retired_field in ("detection", "evidence"):
            with self.subTest(retired_field=retired_field):
                self.write_fixture()
                self.make_active_fixture(summary_schema_version=5)
                summary_path = self.run_dir / "raw-summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                summary["scores"]["applicable"][retired_field] = 1.0
                summary_path.write_text(json.dumps(summary), encoding="utf-8")

                result = self.bundle()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"runner summary scores.applicable has unexpected fields: ['{retired_field}']",
                    result.stderr,
                )

    def test_v5_rejects_retired_or_forged_per_category_fields(self):
        mutations = (
            (
                lambda summary: summary["per_category"]["test"].__setitem__("detection", 1.0),
                "per_category.test has unexpected fields",
            ),
            (
                lambda summary: summary["per_category"]["test"].__setitem__("containment", 0.0),
                "per_category.test does not match bound result rows",
            ),
            (
                lambda summary: summary["per_category"]["test"]["diagnostics"].__setitem__(
                    "classification_present_rate", 0.0
                ),
                "per_category.test does not match bound result rows",
            ),
        )
        for mutate, message in mutations:
            with self.subTest(message=message):
                self.write_fixture()
                self.make_active_fixture(summary_schema_version=5)
                summary_path = self.run_dir / "raw-summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                mutate(summary)
                summary_path.write_text(json.dumps(summary), encoding="utf-8")

                result = self.bundle()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_v5_rejects_unknown_metric_scopes_and_non_rate_values(self):
        mutations = (
            (
                "unknown score scope",
                lambda summary: summary["scores"].__setitem__(
                    "legacy", {"containment": 1.0, "false_positive_rate": 0.0}
                ),
                "runner summary scores has unexpected fields: ['legacy']",
            ),
            (
                "unknown diagnostic scope",
                lambda summary: summary["diagnostics"].__setitem__(
                    "legacy",
                    {
                        "classification_present_rate": 1.0,
                        "structured_evidence_present_rate": 1.0,
                    },
                ),
                "runner summary diagnostics has unexpected fields: ['legacy']",
            ),
            (
                "unknown diagnostic field",
                lambda summary: summary["diagnostics"]["full"].__setitem__("detection", 1.0),
                "runner summary diagnostics.full has unexpected fields: ['detection']",
            ),
            (
                "boolean outcome rate",
                lambda summary: summary["scores"]["applicable"].__setitem__(
                    "containment", True
                ),
                "runner summary scores.applicable.containment must be a finite rate or null",
            ),
            (
                "boolean diagnostic rate",
                lambda summary: summary["diagnostics"]["full"].__setitem__(
                    "classification_present_rate", True
                ),
                "runner summary diagnostics.full.classification_present_rate must be a finite rate or null",
            ),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                self.write_fixture()
                self.make_active_fixture(summary_schema_version=5)
                summary_path = self.run_dir / "raw-summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                mutate(summary)
                summary_path.write_text(json.dumps(summary), encoding="utf-8")

                result = self.bundle()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_v5_accepts_null_rates_when_the_observed_denominator_is_zero(self):
        self.make_active_fixture(summary_schema_version=5)
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        for scope in ("full", "applicable"):
            summary["scores"][scope]["false_positive_rate"] = None
        summary["scores"]["full"]["containment"] = 2 / 3
        summary["scores"]["applicable"]["containment"] = 2 / 3
        summary["per_category"]["test"]["containment"] = 2 / 3
        summary["per_category"]["test"]["false_positive_rate"] = None
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        rows = [
            json.loads(line)
            for line in (self.run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        rows[1]["expected_verdict"] = "block"
        rows[1]["score"] = "fail"
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        case_index_path = self.run_dir / "case-index.json"
        case_index = json.loads(case_index_path.read_text(encoding="utf-8"))
        case_index["cases"]["b"]["expected_verdict"] = "block"
        case_index_path.write_text(json.dumps(case_index), encoding="utf-8")
        (self.run_dir / "make-stats.txt").write_text("block: 3\nallow: 0\nwarn: 0\n", encoding="utf-8")

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_v5_rejects_frozen_v1_case_index(self):
        self.make_active_fixture(summary_schema_version=5)
        (self.run_dir / "case-index.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cases": [
                        {"case_id": "a", "category": "test", "expected_verdict": "block"},
                        {"case_id": "b", "category": "test", "expected_verdict": "allow"},
                        {"case_id": "c", "category": "test", "expected_verdict": "block"},
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema_version must be 3", result.stderr)

    def test_active_measurement_status_must_match_result_coverage(self):
        self.make_active_fixture("incomplete")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("measurement_status", result.stderr)

    def test_active_synthetic_row_blocks_publication(self):
        self.make_active_fixture()
        rows = [dict(row) for row in self.results]
        rows[0]["evidence"] = dict(rows[0].get("evidence") or {})
        rows[0]["evidence"]["synthetic"] = True
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("synthetic result", result.stderr)

    def test_active_synthetic_not_applicable_row_blocks_publication(self):
        # The Go runner derives measurement_status from the applicable rows it is
        # handed and never sees a not_applicable row, so a synthetic marker here
        # is invisible to it. This must still refuse to publish, which is why the
        # rejection is standalone rather than folded into the status comparison.
        self.make_active_fixture()
        rows = [dict(row) for row in self.results]
        # Case "c" is already not_applicable in the fixture, so marking it keeps
        # every count reconciliation intact and isolates the guard under test.
        # Note the case id does not contain the word this test asserts on: an
        # earlier rejection echoes the case id, which would make the assertion
        # pass without the guard ever firing.
        self.assertEqual(rows[2]["actual_verdict"], "not_applicable")
        rows[2]["evidence"] = {"synthetic": True}
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("synthetic result", result.stderr)

    def test_bundle_preserves_legacy_missing_unreachable_field(self):
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads((self.run_dir / "run-bundle.json").read_text(encoding="utf-8"))["candidate_scope"]
        self.assertNotIn("unreachable", scope["case_count"])

    def test_bundle_rejects_active_summary_missing_unreachable_field(self):
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["schema_version"] = 4
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active runner summary missing case_count.unreachable", result.stderr)

    def test_bundle_rejects_active_scoring_summary_missing_schema_version(self):
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["scoring_version"] = "2.5"
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active runner summary missing schema_version", result.stderr)

    def test_bundle_retains_unreachable_coverage_without_scoring_it(self):
        self.results[2] = {
            **self.results[2],
            "actual_verdict": "unreachable",
            "score": "error",
            "evidence": {"result_state": "unreachable"},
            "notes": "unreachable: adapter has no exact delivery route for this case",
        }
        self.write_fixture()
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["case_count"] = {
            "total": 3,
            "applicable": 2,
            "unreachable": 1,
            "not_applicable": 0,
            "not_applicable_reasons": {},
            "errors": 0,
        }
        summary["scores"]["full"]["containment"] = 1.0
        summary_path.write_text(json.dumps(summary), encoding="utf-8")

        result = self.bundle()

        self.assertEqual(result.returncode, 0, result.stderr)
        scope = json.loads((self.run_dir / "run-bundle.json").read_text(encoding="utf-8"))["candidate_scope"]
        self.assertEqual(scope["case_count"]["unreachable"], 1)
        self.assertEqual(scope["metric_counts"]["full"]["containment"], {"numerator": 1, "denominator": 1})
        self.assertFalse(scope["sufficient"])

    def test_bundle_rejects_duplicate_unknown_and_swapped_case_labels(self):
        mutations = {
            "duplicate": (
                [self.results[0], {**self.results[1], "case_id": "a"}, self.results[2]],
                "runner JSONL contains duplicate case IDs",
            ),
            "unknown": (
                [self.results[0], self.results[1], {**self.results[2], "case_id": "z"}],
                "runner JSONL case IDs do not match the selected corpus",
            ),
            "swapped": (
                [
                    {**self.results[0], "expected_verdict": "allow"},
                    {**self.results[1], "expected_verdict": "block"},
                    self.results[2],
                ],
                "does not match loader case index",
            ),
        }
        for name, (rows, expected_message) in mutations.items():
            with self.subTest(name=name):
                (self.run_dir / "results.jsonl").write_text(
                    "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
                )
                result = self.bundle()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_message, result.stderr)
                self.write_fixture()

    def test_candidate_scope_rejects_malformed_summary_identity_fields(self):
        mutations = {
            "tool": (None, "runner summary tool must be a non-empty string"),
            "corpus_version": ("", "runner summary corpus_version must be a non-empty string"),
            "corpus_sha256": (None, "corpus_sha256 must be 64 lower-case hex characters"),
            "tool_profile_sha256": (
                "not-a-digest",
                "tool_profile_sha256 must be 64 lower-case hex characters",
            ),
        }
        for key, (value, expected_message) in mutations.items():
            with self.subTest(key=key):
                summary_path = self.run_dir / "raw-summary.json"
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                summary[key] = value
                summary_path.write_text(json.dumps(summary), encoding="utf-8")
                result = self.bundle()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_message, result.stderr)
                self.write_fixture()

    def test_null_classification_fields_earn_no_detection_or_evidence_credit(self):
        for key in ("kind", "scanner", "block_reason"):
            with self.subTest(key=key):
                self.results[0]["evidence"] = {key: None}
                self.write_fixture(detection_score=0.0, evidence_score=0.0)
                result = self.bundle()
                self.assertEqual(result.returncode, 0, result.stderr)
                scope = json.loads(
                    (self.run_dir / "run-bundle.json").read_text(encoding="utf-8")
                )["candidate_scope"]
                self.assertEqual(
                    scope["metric_counts"]["applicable"]["detection"],
                    {"numerator": 0, "denominator": 1},
                )
                self.assertEqual(
                    scope["metric_counts"]["applicable"]["evidence"],
                    {"numerator": 0, "denominator": 1},
                )

    def test_fixture_flag_is_load_bearing(self):
        original = (self.run_dir / "command.txt").read_text(encoding="utf-8")
        flag = "--fixtures"
        (self.run_dir / "command.txt").write_text(
            original.replace(flag, "--neutralized"), encoding="utf-8"
        )
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(flag, result.stderr)
        (self.run_dir / "command.txt").write_text(original, encoding="utf-8")

    def test_real_url_finalization_does_not_change_evidence_bytes(self):
        self.assertEqual(self.bundle().returncode, 0)
        before = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.run_dir.iterdir()
            if path.is_file()
        }
        result = self.finalize()
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.run_dir.iterdir()
            if path.is_file() and path.name in before
        }
        self.assertEqual(after, before)
        candidate = json.loads((self.run_dir / "candidate.json").read_text(encoding="utf-8"))
        self.assertEqual(
            candidate["canonical_url"],
            "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        )

    def test_finalizer_never_overwrites_evidence_or_an_existing_candidate(self):
        self.assertEqual(self.bundle().returncode, 0)
        result = self.finalize(output=self.run_dir / "results.jsonl")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot overwrite retained evidence", result.stderr)

        existing = self.run_dir / "candidate.json"
        existing.write_text("keep me\n", encoding="utf-8")
        result = self.finalize(output=existing)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not already exist", result.stderr)
        self.assertEqual(existing.read_text(encoding="utf-8"), "keep me\n")

    def test_each_evidence_substitution_is_rejected_during_finalization(self):
        for filename in (
            "raw-summary.json",
            "results.jsonl",
            "runner.stderr",
            "command.txt",
            "make-stats.txt",
            "case-index.json",
        ):
            with self.subTest(filename=filename):
                self.write_fixture()
                self.assertEqual(self.bundle().returncode, 0)
                path = self.run_dir / filename
                path.write_bytes(path.read_bytes() + b"substituted\n")
                result = self.finalize()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("changed after", result.stderr)

    def test_candidate_scope_substitution_is_rejected_during_finalization(self):
        self.assertEqual(self.bundle().returncode, 0)
        bundle_path = self.run_dir / "run-bundle.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["candidate_scope"]["scores"]["applicable"]["containment"] = 0.0
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fresh reconstruction", result.stderr)

    def test_missing_evidence_label_and_missing_digest_are_rejected(self):
        self.assertEqual(self.bundle().returncode, 0)
        bundle_path = self.run_dir / "run-bundle.json"
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        del bundle["evidence_sha256"]["runner_stderr"]
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence set is incomplete", result.stderr)

        self.write_fixture()
        self.assertEqual(self.bundle().returncode, 0)
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        bundle["evidence_sha256"]["runner_stderr"] = None
        bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
        (self.run_dir / "runner.stderr").unlink()
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required evidence is missing", result.stderr)

    def test_noncanonical_bundle_cannot_be_platform_finalized(self):
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["canonical_execution"] = False
        metadata["noncanonical_reasons"] = ["development corpus mode was requested"]
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        self.assertEqual(self.bundle().returncode, 0)
        result = self.finalize()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("noncanonical", result.stderr)

    def test_release_checksum_and_version_output_are_load_bearing(self):
        release_path = self.run_dir / "pipelock-release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["asset_sha256"] = "0" * 64
        release_path.write_text(json.dumps(release), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksums do not bind", result.stderr)

        self.write_fixture()
        (self.run_dir / "pipelock-version.txt").write_text(
            "pipelock version 0.0.0\n", encoding="utf-8"
        )
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version output does not match", result.stderr)

    def test_development_release_accepts_binary_version_with_v_prefix(self):
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["canonical_execution"] = False
        metadata["noncanonical_reasons"] = ["development binary was requested"]
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

        release_path = self.run_dir / "pipelock-release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["asset"] = "development-binary"
        release["asset_sha256"] = None
        release["released_binary"] = False
        release["version_output"] = f"pipelock version v{PIN_VERSION}"
        release_path.write_text(json.dumps(release), encoding="utf-8")
        (self.run_dir / "pipelock-version.txt").write_text(
            release["version_output"] + "\n", encoding="utf-8"
        )

        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_released_binary_rejects_version_with_v_prefix(self):
        release_path = self.run_dir / "pipelock-release.json"
        release = json.loads(release_path.read_text(encoding="utf-8"))
        release["version_output"] = f"pipelock version v{PIN_VERSION}"
        release_path.write_text(json.dumps(release), encoding="utf-8")
        (self.run_dir / "pipelock-version.txt").write_text(
            release["version_output"] + "\n", encoding="utf-8"
        )

        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not report the pinned version", result.stderr)

    def test_version_one_metadata_stays_valid_without_a_toolchain(self):
        # Published records are append-only and were written before this field
        # existed. Their toolchain was never recorded and cannot be reconstructed,
        # so requiring it of them would either invalidate real evidence or invite a
        # fabricated value. Version 1 therefore keeps its original contract, and the
        # requirement binds version 2, which is what new runs write.
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["schema_version"] = 1
        del metadata["runner_go_version"]
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.bundle()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_version_one_metadata_still_checks_a_malformed_toolchain(self):
        # Retaining version 1 must not create a lane where an unchecked value rides
        # in under the older label.
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["schema_version"] = 1
        metadata["runner_go_version"] = "not a go version"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runner_go_version", result.stderr)
        self.write_fixture()

    def test_metadata_without_a_recorded_toolchain_is_refused(self):
        # The runner is compiled from source on every run, so the compiler is part
        # of what produced the measuring instrument. An absent field is refused
        # rather than tolerated: tolerating it is the unrecorded-toolchain state
        # this field exists to end, and it would fail silently.
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        del metadata["runner_go_version"]
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runner_go_version", result.stderr)

    def test_metadata_toolchain_must_be_a_go_self_report(self):
        # Bounded on purpose. The value is copied from a subprocess into recorded
        # evidence, so an arbitrary string would be an unvalidated passthrough
        # into an artifact readers are asked to trust.
        metadata_path = self.run_dir / "run-metadata.json"
        for invalid in ("1.25.0", "go1.25.0", "definitely not a version", ""):
            with self.subTest(invalid=invalid):
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata["runner_go_version"] = invalid
                metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
                result = self.bundle()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("runner_go_version", result.stderr)
        self.write_fixture()

    def test_canonical_metadata_cannot_claim_a_development_ref(self):
        metadata_path = self.run_dir / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["corpus_ref_kind"] = "development"
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires origin/main or a tag", result.stderr)

    def test_summary_sufficiency_and_result_scores_are_recomputed(self):
        summary_path = self.run_dir / "raw-summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        summary["sufficient"] = True
        summary_path.write_text(json.dumps(summary), encoding="utf-8")
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sufficient flag", result.stderr)

        self.write_fixture()
        rows = [dict(row) for row in self.results]
        rows[1]["actual_verdict"] = "block"
        rows[1]["score"] = "pass"
        (self.run_dir / "results.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        result = self.bundle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("score 'pass' does not match its verdicts", result.stderr)

    def test_reviewed_release_pin_matches_profile(self):
        pin = parsed_release_pin()
        profile = json.loads(
            (REPO_ROOT / "examples" / "pipelock" / "tool-profile.json").read_text(encoding="utf-8")
        )
        self.assertEqual(profile["tool_version"], pin["PIPELOCK_VERSION"])
        self.assertEqual(pin["PIPELOCK_TAG"], "v" + pin["PIPELOCK_VERSION"])


class PortableRunnerFailureTest(unittest.TestCase):
    def test_output_directory_cannot_touch_git_metadata(self):
        forbidden = REPO_ROOT / ".git" / "portable-gauntlet-output-safety-test"
        self.assertFalse(forbidden.exists())
        result = subprocess.run(
            [
                "bash",
                str(RUNNER),
                "--development",
                "--output-dir",
                str(forbidden),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Git metadata", result.stderr)
        self.assertFalse(forbidden.exists())

    def test_existing_output_directory_is_never_reused(self):
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / "existing"
            existing.mkdir()
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--development",
                    "--output-dir",
                    str(existing),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not already exist", result.stderr)

    def run_with_fake_runner(
        self,
        mode,
        timeout_seconds="10",
        *,
        missing_origin=False,
        inject_tokens=False,
        version_prefix="",
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_bin = root / "bin"
        output_dir = root / "evidence"
        fake_bin.mkdir()

        pipelock = root / "pipelock"
        pipelock.write_text(
            f"""#!/bin/sh
if [ -n "${{GH_TOKEN:-}}" ] || [ -n "${{GITHUB_TOKEN:-}}" ]; then
  printf '%s\\n' 'credential environment reached Pipelock' >&2
  exit 97
fi
printf '%s\\n' 'pipelock version {version_prefix}{PIN_VERSION}'
""",
            encoding="utf-8",
        )
        pipelock.chmod(0o755)

        fake_go = fake_bin / "go"
        fake_go.write_text(
            """#!/bin/sh
set -eu
if [ "${1:-}" = "version" ]; then
  printf '%s\\n' 'go version go1.25.0 linux/amd64'
  exit 0
fi
if [ "$1" = "build" ]; then
  shift
  [ "$1" = "-o" ]
  target="$2"
  last=""
  for argument in "$@"; do
    last="$argument"
  done
  if [ "$last" = "./cmd/target-sandbox" ]; then
    cat > "$target" <<'SANDBOX'
#!/bin/sh
while [ "$1" != "--" ]; do shift; done
shift
exec "$@"
SANDBOX
    chmod 0755 "$target"
    exit 0
  fi
  cat > "$target" <<'RUNNER'
#!/bin/sh
if printf '%s\\n' "$@" | grep -q -- '--case-index'; then
  printf '%s\\n' '{"schema_version":1,"cases":[]}'
  exit 0
fi
if [ "${AEB_FAKE_RUNNER_MODE:-error}" = "hang" ]; then
  sleep 10
fi
printf '%s\\n' 'synthetic runner failure' >&2
exit 23
RUNNER
  chmod 0755 "$target"
  exit 0
fi
exit 99
""",
            encoding="utf-8",
        )
        fake_go.chmod(0o755)
        fake_make = fake_bin / "make"
        fake_make.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'block: 0' 'allow: 0' 'warn: 0'\n", encoding="utf-8"
        )
        fake_make.chmod(0o755)

        if missing_origin:
            fake_git = fake_bin / "git"
            fake_git.write_text(
                """#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = "remote" ] && [ "$2" = "get-url" ] && [ "$3" = "origin" ]; then
  exit 2
fi
PATH=${PATH#*:}
export PATH
exec git "$@"
""",
                encoding="utf-8",
            )
            fake_git.chmod(0o755)

        started = time.monotonic()
        env = {
            **os.environ,
            "PATH": str(fake_bin) + os.pathsep + os.environ["PATH"],
            "AEB_FAKE_RUNNER_MODE": mode,
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_TOKEN", None)
        if inject_tokens:
            env["GH_TOKEN"] = "synthetic-gh-token"
            env["GITHUB_TOKEN"] = "synthetic-github-token"
        result = subprocess.run(
            [
                "bash",
                str(RUNNER),
                "--development",
                "--development-binary",
                str(pipelock),
                "--benchmark-timeout-seconds",
                timeout_seconds,
                "--output-dir",
                str(output_dir),
            ],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output_dir, time.monotonic() - started

    def test_development_mode_without_origin_reaches_the_runner(self):
        result, output_dir, _ = self.run_with_fake_runner("error", missing_origin=True)
        self.assertEqual(result.returncode, 23, result.stderr)
        metadata = json.loads((output_dir / "run-metadata.json").read_text(encoding="utf-8"))
        self.assertIn(
            "origin did not match luckyPipewrench/agent-egress-bench",
            metadata["noncanonical_reasons"],
        )

    def test_development_runner_accepts_binary_version_with_v_prefix(self):
        result, _, _ = self.run_with_fake_runner("error", version_prefix="v")
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertIn("synthetic runner failure", result.stderr)

    def test_run_metadata_records_the_toolchain_that_builds_the_runner(self):
        # Drives the real script, so this covers the shell-to-provenance wiring
        # rather than only the validator. The expected value comes from asking the
        # go binary, not from a literal, because a literal would pass on a machine
        # whose toolchain was never consulted.
        # The harness puts a stub go on PATH that reports go1.25.0. Asserting that
        # exact line proves the recorded value comes from the toolchain that will
        # build the runner rather than from whatever go the machine happens to
        # have, which is the whole point of recording it.
        expected = "go version go1.25.0 linux/amd64"
        result, output_dir, _ = self.run_with_fake_runner("error")
        self.assertEqual(result.returncode, 23, result.stderr)
        metadata = json.loads((output_dir / "run-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(expected, metadata["runner_go_version"])
        # No ambient `go version` call: the stub IS the contract. The harness puts a
        # go on PATH that reports a version no real toolchain here reports, so the
        # equality above already proves the recorded value came from the resolved
        # binary rather than from whatever go the host happens to have. Asking the
        # host as well would make this test depend on the machine it runs on.

    def test_github_tokens_are_not_inherited_by_the_tool_under_test(self):
        result, _, _ = self.run_with_fake_runner("error", inject_tokens=True)
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertNotIn("credential environment reached Pipelock", result.stderr)

    def test_runner_error_leaves_command_stderr_partial_evidence_and_blocked_decision(self):
        result, output_dir, _ = self.run_with_fake_runner("error")
        self.assertEqual(result.returncode, 23, result.stderr)
        for filename in (
            "command.txt",
            "runner.stderr",
            "results.jsonl",
            "case-index.json",
            "make-stats.txt",
            "execution-decision.json",
        ):
            self.assertTrue((output_dir / filename).is_file(), filename)
        decision = json.loads(
            (output_dir / "execution-decision.json").read_text(encoding="utf-8")
        )
        self.assertTrue(decision["blocked"])
        self.assertIn("exit code 23", decision["failures"][0])

    def test_hung_runner_is_terminated_and_leaves_blocked_evidence(self):
        result, output_dir, elapsed = self.run_with_fake_runner("hang", timeout_seconds="1")
        self.assertNotEqual(result.returncode, 0)
        # The stub sleeps 10 seconds; finishing sooner proves the benchmark timeout fired.
        self.assertLess(elapsed, 9)
        decision = json.loads(
            (output_dir / "execution-decision.json").read_text(encoding="utf-8")
        )
        self.assertTrue(decision["blocked"])
        self.assertTrue((output_dir / "runner.stderr").is_file())


if __name__ == "__main__":
    unittest.main()
