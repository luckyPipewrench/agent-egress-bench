#!/usr/bin/env python3
"""Tests for reviewed append-only Gauntlet result promotion."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "promote_gauntlet_candidate.py"


def load_module(name):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


provenance = load_module("build_gauntlet_provenance")
evaluator = load_module("evaluate_gauntlet_candidate")
promotion = load_module("promote_gauntlet_candidate")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def baseline():
    return {
        "_comment": "Reviewed baseline for the continuous Gauntlet lane.",
        "schema_version": 1,
        "summary_schema_version": 5,
        "benchmark_manifest_sha256": "3" * 64,
        "recorded_on": "2026-08-01",
        "verified_candidate_sha256": "a" * 64,
        "verified_artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:122",
        "pipelock_version": "3.3.0",
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "corpus_version": "v2.3.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
        "observed_case_count": {
            "total": 2,
            "applicable": 2,
            "unreachable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
        },
        "score_floors": {
            "full": {"containment": 1.0},
            "applicable": {"containment": 1.0},
        },
        "score_ceilings": {"applicable": {"false_positive_rate": 0.0}},
    }


def candidate(run_id="123", run_attempt=None, generated_at="2026-08-05T00:10:08Z"):
    artifact_suffix = run_id if run_attempt is None else f"{run_id}:{run_attempt}"
    return {
        "schema_version": 2,
        "artifact_id": f"github-actions:luckyPipewrench/agent-egress-bench:{artifact_suffix}",
        "canonical_url": (
            "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/" + run_id
        ),
        "generated_at": generated_at,
        "tool": "pipelock",
        "tool_version": "3.3.0",
        "pipelock_version": "3.3.0",
        "corpus_git_sha": "b" * 40,
        "corpus_sha256": "c" * 64,
        "corpus_manifest_sha256": "d" * 64,
        "corpus_version": "v2.3.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
        "logical_case_count": 213,
        "case_count": {
            "total": 213,
            "applicable": 212,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
            "errors": 0,
        },
        "metric_counts": {
            "full": {
                "containment": {"numerator": 157, "denominator": 158},
                "detection": {"numerator": 157, "denominator": 157},
                "evidence": {"numerator": 157, "denominator": 157},
                "false_positive_rate": {"numerator": 0, "denominator": 55},
            },
            "applicable": {
                "containment": {"numerator": 158, "denominator": 158},
                "detection": {"numerator": 157, "denominator": 157},
                "evidence": {"numerator": 157, "denominator": 157},
                "false_positive_rate": {"numerator": 0, "denominator": 54},
            },
        },
        "scores": {
            "full": {
                "containment": 157 / 158,
                "detection": 1.0,
                "evidence": 1.0,
                "false_positive_rate": 0.0,
            },
            "applicable": {
                "containment": 1.0,
                "detection": 1.0,
                "evidence": 1.0,
                "false_positive_rate": 0.0,
            },
        },
        "sufficient": True,
    }


def v6_candidate(
    run_id="123",
    run_attempt=None,
    generated_at="2026-08-05T00:10:08Z",
    attempt_url=False,
):
    artifact_suffix = run_id if run_attempt is None else f"{run_id}:{run_attempt}"
    value = {
        "schema_version": 6,
        "artifact_id": f"github-actions:luckyPipewrench/agent-egress-bench:{artifact_suffix}",
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/"
        + run_id
        + (f"/attempts/{run_attempt}" if attempt_url and run_attempt is not None else ""),
        "local_run_id": "local:test:1",
        "generated_at": generated_at,
        "corpus_ref_kind": "origin/main",
        "corpus_git_sha": "b" * 40,
        "corpus_commit_url": "https://github.com/luckyPipewrench/agent-egress-bench/commit/" + "b" * 40,
        "dirty": False,
        "pipelock_tag": "v3.3.0",
        "pipelock_version": "3.3.0",
        "pipelock_asset": "pipelock_3.3.0_linux_amd64.tar.gz",
        "pipelock_asset_sha256": "1" * 64,
        "pipelock_binary_sha256": "2" * 64,
        "pipelock_release_url": "https://github.com/luckyPipewrench/pipelock/releases/tag/v3.3.0",
        "gauntlet_version": "1.0",
        "scoring_version": "2.4",
        "runner_version": "0.4.2",
        "tool": "pipelock",
        "tool_version": "3.3.0",
        "corpus_version": "v2.3.0",
        "corpus_sha256": "c" * 64,
        "corpus_manifest_sha256": "d" * 64,
        "case_index_sha256": "e" * 64,
        "logical_case_count": 2,
        "tool_profile_sha256": "f" * 64,
        "case_count": {
            "total": 2,
            "applicable": 2,
            "unreachable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
            "errors": 0,
        },
        "scores": {
            scope: {"containment": 1.0, "false_positive_rate": 0.0}
            for scope in ("full", "applicable")
        },
        "metric_counts": {
            scope: {
                "containment": {"numerator": 1, "denominator": 1},
                "false_positive_rate": {"numerator": 0, "denominator": 1},
            }
            for scope in ("full", "applicable")
        },
        "fixtures": True,
        "multifile_cases": True,
        "command": "aeb-gauntlet --fixtures",
        "make_stats": "block: 1\nallow: 1\nwarn: 0\n",
        "evidence_sha256": {label: "a" * 64 for label in provenance.RAW_EVIDENCE | provenance.V4_RAW_EVIDENCE},
        "measurement_status": "measured",
        "benchmark_manifest_sha256": "3" * 64,
        "diagnostics": {
            scope: {
                "classification_present_rate": 1.0,
                "structured_evidence_present_rate": 1.0,
            }
            for scope in ("full", "applicable")
        },
        "diagnostic_counts": {
            scope: {
                "classification_present_rate": {"numerator": 1, "denominator": 1},
                "structured_evidence_present_rate": {"numerator": 1, "denominator": 1},
            }
            for scope in ("full", "applicable")
        },
        "capability_registry": {
        "id": "aeb.core-capabilities",
        "format": 1,
        "revision": 1,
        "sha256": "f" * 64,
        },
        "reported_claims": [],
        # Exactly the coverage the pinned case index and raw rows below support.
        "exercised": {
            "transports": ["fetch_proxy"],
            "categories": ["test"],
            "capability_tags": ["url_dlp"],
        },
        "portable_bundle_sha256": "4" * 64,
        "method_repository": "luckyPipewrench/agent-egress-bench",
        "method_commit": "b" * 40,
        "adapter_id": "proxy",
        "adapter_owner": "Example Maintainers",
        "target_config_ref": "examples/pipelock/pipelock-benchmark.yaml",
        "target_config_sha256": "9" * 64,
    }
    return value


class PromotionFixture:
    def __init__(self, root, candidate_value=None, baseline_value=None):
        self.root = root
        self.artifact_dir = root / "artifact"
        self.artifact_dir.mkdir(parents=True)
        self.store_root = root / "site" / "results"
        self.latest = root / "site" / "latest-verified.json"
        self.baseline_path = root / "baseline.json"
        self.source_baseline_path = root / "source-baseline.json"
        self.summary = root / "promotion-summary.md"
        write_json(self.baseline_path, baseline_value or baseline())
        write_json(self.source_baseline_path, baseline_value or baseline())
        self.source_baseline_origin_path = root / "source-baseline-origin.json"
        self.write_source_baseline_origin()

        value = dict(candidate_value or v6_candidate())
        publication_fields = (
            "method_repository",
            "method_commit",
            "adapter_id",
            "adapter_owner",
            "target_config_ref",
            "target_config_sha256",
        )
        self.evidence = {}
        for label, filename in promotion.evidence_files_for(value).items():
            path = self.artifact_dir / filename
            if label == "execution_decision":
                write_json(
                    path,
                    {
                        "schema_version": 1,
                        "execution_status": "complete",
                        "blocked": False,
                        "publication_eligible": True,
                        "failures": [],
                    },
                )
            elif label == "raw_summary":
                write_json(
                    path,
                    {
                        "schema_version": 5,
                        **{field: value[field] for field in publication_fields if field in value},
                    },
                )
            elif label == "run_metadata":
                write_json(
                    path,
                    {
                        "corpus_repository": value.get("method_repository"),
                        "corpus_git_sha": value.get("method_commit"),
                    },
                )
            elif label == "command":
                path.write_text(
                    "timeout --signal=TERM --kill-after=30s 10s aeb-gauntlet "
                    f"--adapter {value.get('adapter_id', 'proxy')} --fixtures "
                    f"--method-repository {value.get('method_repository', '')} "
                    f"--method-commit {value.get('method_commit', '')} "
                    f"--adapter-owner '{value.get('adapter_owner', '')}' "
                    f"--target-config {value.get('target_config_ref', '')}\n",
                    encoding="utf-8",
                )
            elif label == "run_bundle":
                write_json(
                    path,
                    {
                        "schema_version": 1,
                        "bundle_status": "complete",
                        "candidate_scope": {
                            field: value[field] for field in publication_fields if field in value
                        },
                    },
                )
            elif label == "case_index":
                write_json(
                    path,
                    {
                        "schema_version": 3,
                        "cases": {
                            "attack-1": {
                                "category": "test",
                                "expected_verdict": "block",
                                "transport": "fetch_proxy",
                                "capability_tags": ["url_dlp"],
                            },
                            "benign-1": {
                                "category": "test",
                                "expected_verdict": "allow",
                                "transport": "fetch_proxy",
                                "capability_tags": ["url_dlp"],
                            },
                        },
                    },
                )
            elif label == "results":
                result_identity = {"schema_version": 5}
                if value.get("schema_version") == 6:
                    result_identity = {
                        "schema_version": 6,
                        "scoring_version": value["scoring_version"],
                    }
                containment_passes = (
                    value.get("metric_counts", {})
                    .get("applicable", {})
                    .get("containment", {})
                    .get("numerator")
                    == 1
                )
                benign_blocked = (
                    value.get("metric_counts", {})
                    .get("applicable", {})
                    .get("false_positive_rate", {})
                    .get("numerator")
                    == 1
                )
                path.write_text(
                    "".join(
                        json.dumps(row) + "\n"
                        for row in (
                            {
                                **result_identity,
                                "case_id": "attack-1",
                                "expected_verdict": "block",
                                "actual_verdict": "block" if containment_passes else "allow",
                                "score": "pass" if containment_passes else "fail",
                                "evidence": (
                                    {"scanner": "example", "result_state": "observed"}
                                    if containment_passes
                                    else {"result_state": "observed"}
                                ),
                                "notes": "",
                            },
                            {
                                **result_identity,
                                "case_id": "benign-1",
                                "expected_verdict": "allow",
                                "actual_verdict": "block" if benign_blocked else "allow",
                                "score": "fail" if benign_blocked else "pass",
                                "evidence": {"result_state": "observed"},
                                "notes": "",
                            },
                        )
                    ),
                    encoding="utf-8",
                )
            else:
                path.write_text(f"{label}\n", encoding="utf-8")
            self.evidence[label] = path

        self.candidate_value = value
        self.candidate_path = self.artifact_dir / promotion.CANDIDATE_FILENAME
        self.refresh_candidate_integrity()

    def refresh_candidate_integrity(self):
        self.candidate_value["case_index_sha256"] = hashlib.sha256(
            self.evidence["case_index"].read_bytes()
        ).hexdigest()
        self.candidate_value["portable_bundle_sha256"] = hashlib.sha256(
            self.evidence["run_bundle"].read_bytes()
        ).hexdigest()
        if self.candidate_value.get("schema_version") == 6:
            self.candidate_value["evidence_sha256"] = {
                label: hashlib.sha256(self.evidence[label].read_bytes()).hexdigest()
                for label in self.candidate_value["evidence_sha256"]
            }
        write_json(self.candidate_path, self.candidate_value)
        self.write_source_decision()

    def write_source_baseline_origin(self):
        """Describe the retained policy so the promoter can bind it to an owner."""
        write_json(
            self.source_baseline_origin_path,
            {
                "schema_version": 1,
                "repository": "luckyPipewrench/example-product",
                "commit": "c" * 40,
                "path": "benchmark/gauntlet-baseline.json",
                "sha256": hashlib.sha256(
                    self.source_baseline_path.read_bytes()
                ).hexdigest(),
            },
        )

    def write_source_decision(self):
        decision = evaluator.evaluate(self.candidate_path, self.source_baseline_path, self.evidence)
        write_json(self.artifact_dir / promotion.SOURCE_DECISION_FILENAME, decision)

    def command(self, accept_policy_change=False):
        artifact_parts = self.candidate_value["artifact_id"].split(":")
        expected_run_id = artifact_parts[-2] if len(artifact_parts) == 4 else artifact_parts[-1]
        command = [
            sys.executable,
            str(SCRIPT),
            "--artifact-dir",
            str(self.artifact_dir),
            "--baseline",
            str(self.baseline_path),
            "--source-baseline",
            str(self.source_baseline_path),
            "--source-baseline-origin",
            str(self.source_baseline_origin_path),
            "--store-root",
            str(self.store_root),
            "--latest",
            str(self.latest),
            "--summary",
            str(self.summary),
            "--expected-run-id",
            expected_run_id,
        ]
        if len(artifact_parts) == 4:
            command.extend(["--expected-run-attempt", artifact_parts[-1]])
        if accept_policy_change:
            command.append("--accept-policy-change")
        return command

    def run(self, accept_policy_change=False):
        return subprocess.run(
            self.command(accept_policy_change),
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )


class PromoteGauntletCandidateTest(unittest.TestCase):
    def fixture(self, candidate_value=None, baseline_value=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return PromotionFixture(Path(temporary.name), candidate_value, baseline_value)

    def test_v5_baseline_contract_change_requires_explicit_review(self):
        self.assertTrue(
            promotion.reviewable_policy_failure(
                "v5 candidate requires a reviewed baseline with summary_schema_version=5"
            )
        )
        self.assertTrue(
            promotion.reviewable_policy_failure(
                "v6 candidate requires a reviewed baseline with summary_schema_version=5"
            )
        )

    def test_v6_promotion_rejects_each_missing_publication_fact_by_name(self):
        for field in (
            "method_repository",
            "method_commit",
            "adapter_id",
            "adapter_owner",
            "target_config_ref",
            "target_config_sha256",
        ):
            with self.subTest(field=field):
                value = v6_candidate()
                del value[field]
                fixture = self.fixture(value)

                result = fixture.run()

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stdout + result.stderr)

    def test_v6_reference_guard_names_missing_adapter_owner(self):
        value = v6_candidate()
        del value["adapter_owner"]

        with self.assertRaisesRegex(ValueError, "adapter_owner"):
            promotion.validate_reference_candidate(value)

    def test_v6_reference_guard_consumes_validated_candidate(self):
        value = v6_candidate()
        normalized = dict(value)
        normalized["tool"] = "unexpected"

        with mock.patch.object(
            promotion.artifact_schema, "validate_file", return_value=normalized
        ):
            with self.assertRaisesRegex(ValueError, "tool must be pipelock"):
                promotion.validate_reference_candidate(value)

    def test_v6_promotion_rebinds_candidate_to_raw_summary(self):
        fixture = self.fixture()
        fixture.candidate_value["adapter_owner"] = "Different Maintainers"
        write_json(fixture.candidate_path, fixture.candidate_value)
        fixture.write_source_decision()

        result = fixture.run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate adapter_owner does not match retained run evidence", result.stdout)

    def test_v6_promotion_rebinds_every_advertised_evidence_digest(self):
        fixture = self.fixture()
        fixture.candidate_value["evidence_sha256"]["command"] = "0" * 64
        write_json(fixture.candidate_path, fixture.candidate_value)
        fixture.write_source_decision()

        result = fixture.run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "candidate evidence_sha256.command does not match retained evidence", result.stdout
        )

    def test_v6_promotion_rebinds_run_bundle_scope(self):
        fixture = self.fixture()
        bundle = evaluator.load_object(fixture.evidence["run_bundle"])
        bundle["candidate_scope"]["adapter_owner"] = "Different Maintainers"
        write_json(fixture.evidence["run_bundle"], bundle)
        fixture.refresh_candidate_integrity()

        result = fixture.run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run bundle adapter_owner does not match retained run evidence", result.stdout)

    def test_legacy_candidate_baseline_round_trips_through_evaluation(self):
        fixture = self.fixture(candidate())
        generated = promotion.proposed_baseline(
            fixture.candidate_value, evaluator.file_sha256(fixture.candidate_path)
        )
        generated_path = fixture.root / "generated-legacy-baseline.json"
        write_json(generated_path, generated)

        decision = evaluator.evaluate(fixture.candidate_path, generated_path, fixture.evidence)

        self.assertNotIn("summary_schema_version", generated)
        self.assertEqual(
            set(generated["score_floors"]["applicable"]),
            {"containment", "detection", "evidence"},
        )
        self.assertFalse(decision["blocked"], decision["failures"])

    def test_v5_baseline_retains_framed_manifest_identity(self):
        value = candidate()
        value["schema_version"] = 5
        value["benchmark_manifest_sha256"] = "e" * 64

        generated = promotion.proposed_baseline(value, "f" * 64)

        self.assertEqual(generated["schema_version"], 1)
        self.assertEqual(generated["summary_schema_version"], 5)
        self.assertEqual(generated["benchmark_manifest_sha256"], "e" * 64)

    def test_v6_candidate_keeps_the_v5_summary_baseline_generation(self):
        value = v6_candidate()

        generated = promotion.proposed_baseline(value, "f" * 64)

        self.assertEqual(generated["schema_version"], 1)
        self.assertEqual(generated["summary_schema_version"], 5)

    def test_clean_candidate_creates_append_only_record_pointer_and_baseline(self):
        fixture = self.fixture()
        original_candidate = fixture.candidate_path.read_bytes()
        original_source_baseline = fixture.source_baseline_path.read_bytes()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        pointer = evaluator.load_object(fixture.latest)
        self.assertEqual(pointer["assurances"], ["self-run", "artifact-validated"])
        digest = pointer["candidate_sha256"]
        record = fixture.store_root / "pipelock" / digest
        self.assertEqual((record / promotion.CANDIDATE_FILENAME).read_bytes(), original_candidate)
        self.assertEqual(
            (record / promotion.SOURCE_BASELINE_FILENAME).read_bytes(),
            original_source_baseline,
        )
        self.assertEqual(
            evaluator.file_sha256(record / promotion.RECORD_MANIFEST_FILENAME),
            pointer["record_manifest_sha256"],
        )
        promoted_baseline = evaluator.load_object(fixture.baseline_path)
        self.assertEqual(promoted_baseline["verified_candidate_sha256"], digest)
        reviewed = evaluator.load_object(record / promotion.PUBLISHED_DECISION_FILENAME)
        self.assertFalse(reviewed["blocked"])
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("Scope: `2 / 2` routed", summary)
        self.assertIn("Reviewed policy change proposed: `no`", summary)

    def test_source_decision_and_destination_policy_use_separate_baselines(self):
        fixture = self.fixture()
        destination = evaluator.load_object(fixture.baseline_path)
        destination["pipelock_version"] = "3.2.0"
        write_json(fixture.baseline_path, destination)

        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)

        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("Reviewed policy change proposed: `yes`", fixture.summary.read_text())
        fixture.summary.unlink()
        repeated = fixture.run(accept_policy_change=True)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertIn("Reviewed policy change proposed: `yes`", fixture.summary.read_text())

    def test_mismatched_source_decision_is_rejected(self):
        fixture = self.fixture()
        decision_path = fixture.artifact_dir / promotion.SOURCE_DECISION_FILENAME
        decision = evaluator.load_object(decision_path)
        decision["blocked"] = not decision["blocked"]
        write_json(decision_path, decision)

        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("fresh evaluation against the source baseline", result.stdout)

    def test_baselines_are_snapshotted_before_evaluation(self):
        fixture = self.fixture()
        source_bytes = fixture.source_baseline_path.read_bytes()
        destination_bytes = fixture.baseline_path.read_bytes()
        original_evaluate = evaluator.evaluate
        changed = False

        def mutate_inputs_after_snapshot(*args, **kwargs):
            nonlocal changed
            if not changed:
                changed = True
                fixture.source_baseline_path.write_text("{}\n", encoding="utf-8")
                fixture.baseline_path.write_text("{}\n", encoding="utf-8")
            return original_evaluate(*args, **kwargs)

        artifact_parts = fixture.candidate_value["artifact_id"].split(":")
        args = SimpleNamespace(
            artifact_dir=fixture.artifact_dir,
            baseline=fixture.baseline_path,
            source_baseline=fixture.source_baseline_path,
            source_baseline_origin=fixture.source_baseline_origin_path,
            store_root=fixture.store_root,
            latest=fixture.latest,
            summary=None,
            artifact_prefix=promotion.DEFAULT_ARTIFACT_PREFIX,
            url_prefix=promotion.DEFAULT_URL_PREFIX,
            expected_run_id=artifact_parts[-1],
            expected_run_attempt=None,
            accept_policy_change=False,
        )
        with mock.patch.object(evaluator, "evaluate", side_effect=mutate_inputs_after_snapshot):
            record = promotion.promote(args)

        self.assertEqual(
            (record / promotion.SOURCE_BASELINE_FILENAME).read_bytes(), source_bytes
        )
        self.assertEqual(
            (record / promotion.DESTINATION_BASELINE_FILENAME).read_bytes(),
            destination_bytes,
        )

    def test_archived_origin_is_the_bytes_that_were_validated(self):
        """Swapping the origin file after validation must not reach the record.

        The promoter used to validate the path and then read it again for
        archival, so a concurrent producer could replace the file between those
        two reads and the record would carry origin bytes nothing checked.
        """
        fixture = self.fixture()
        validated = fixture.source_baseline_origin_path.read_bytes()
        forged = json.dumps(
            {
                "schema_version": 1,
                "repository": "attacker/friendly-policy",
                "commit": "d" * 40,
                "path": "benchmark/gauntlet-baseline.json",
                "sha256": "0" * 64,
            }
        ).encode()
        self.assertNotEqual(validated, forged)

        original_read = Path.read_bytes
        state = {"calls": 0}

        def swapping_read(self_path, *args, **kwargs):
            data = original_read(self_path, *args, **kwargs)
            if self_path == fixture.source_baseline_origin_path:
                state["calls"] += 1
                # Replace the file the instant it is first read, which is what a
                # concurrent producer does.
                original_write = Path.write_bytes
                original_write(self_path, forged)
            return data

        with mock.patch.object(Path, "read_bytes", swapping_read):
            archived = promotion.load_source_baseline_origin(
                fixture.source_baseline_origin_path,
                fixture.source_baseline_path.read_bytes(),
            )
        self.assertGreaterEqual(state["calls"], 1)
        self.assertEqual(archived, validated)
        self.assertNotEqual(archived, forged)

    def test_blocked_source_decision_requires_explicit_review(self):
        fixture = self.fixture()
        source = evaluator.load_object(fixture.source_baseline_path)
        source["pipelock_version"] = "3.2.0"
        write_json(fixture.source_baseline_path, source)
        # A changed policy needs a matching origin, exactly as a real producer
        # would rewrite both. Leaving the origin behind would fail on the digest
        # first and this test would stop exercising the policy-change gate.
        fixture.write_source_baseline_origin()
        fixture.write_source_decision()

        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_new_legacy_candidate_is_rejected_before_publication(self):
        fixture = self.fixture(candidate())

        result = fixture.run()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("new promotions require active provenance candidate schema_version 6", result.stdout)

    def test_exact_legacy_promotion_repeat_remains_idempotent(self):
        fixture = self.fixture(candidate())
        digest = evaluator.file_sha256(fixture.candidate_path)
        record = fixture.store_root / "pipelock" / digest
        record.mkdir(parents=True)
        baseline_snapshot = record / promotion.BASELINE_SNAPSHOT_FILENAME
        baseline_snapshot.write_bytes(fixture.baseline_path.read_bytes())
        args = SimpleNamespace(
            artifact_dir=fixture.artifact_dir,
            baseline=fixture.baseline_path,
            source_baseline=None,
            source_baseline_origin=fixture.source_baseline_origin_path,
            store_root=fixture.store_root,
            latest=fixture.latest,
            summary=None,
            artifact_prefix=promotion.DEFAULT_ARTIFACT_PREFIX,
            url_prefix=promotion.DEFAULT_URL_PREFIX,
            expected_run_id="123",
            expected_run_attempt=None,
            accept_policy_change=False,
        )

        with mock.patch.object(promotion, "existing_promotion_is_complete", return_value=True):
            promoted = promotion.promote(args)

        self.assertEqual(promoted, record)

    def test_same_promotion_is_idempotent(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        fixture.summary.unlink()
        second = fixture.run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertIn("already complete", second.stdout)
        self.assertTrue(fixture.summary.is_file())

    def test_score_regression_needs_explicit_policy_change(self):
        value = v6_candidate()
        for scope in ("full", "applicable"):
            value["metric_counts"][scope]["containment"]["numerator"] = 0
            value["scores"][scope]["containment"] = 0.0
            for diagnostic in (
                "classification_present_rate",
                "structured_evidence_present_rate",
            ):
                value["diagnostic_counts"][scope][diagnostic] = {
                    "numerator": 0,
                    "denominator": 0,
                }
                value["diagnostics"][scope][diagnostic] = None
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual(
            evaluator.load_object(fixture.baseline_path)["score_floors"]["full"]["containment"],
            0.0,
        )

    def test_false_positive_regression_needs_explicit_policy_change(self):
        value = v6_candidate()
        for scope in ("full", "applicable"):
            value["metric_counts"][scope]["false_positive_rate"]["numerator"] = 1
            value["scores"][scope]["false_positive_rate"] = 1.0
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn("above baseline ceiling", fixture.summary.read_text(encoding="utf-8"))

    def test_pinned_version_move_needs_explicit_policy_change(self):
        value = v6_candidate()
        value["pipelock_version"] = "3.4.0"
        value["tool_version"] = "3.4.0"
        fixture = self.fixture(value)
        self.assertNotEqual(fixture.run().returncode, 0)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertEqual(
            evaluator.load_object(fixture.baseline_path)["pipelock_version"], "3.4.0"
        )

    def test_scope_identity_move_needs_explicit_policy_change(self):
        value = v6_candidate()
        value["corpus_sha256"] = "a" * 64
        fixture = self.fixture(value)
        blocked = fixture.run()
        self.assertNotEqual(blocked.returncode, 0)
        self.assertIn("explicit reviewed policy-change", blocked.stdout)
        accepted = fixture.run(accept_policy_change=True)
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("Reviewed policy change proposed: `yes`", summary)

    def test_summary_names_nonpassing_case_and_boundary_timing(self):
        value = v6_candidate()
        for scope in ("full", "applicable"):
            value["metric_counts"][scope]["containment"]["numerator"] = 0
            value["scores"][scope]["containment"] = 0.0
            for diagnostic in (
                "classification_present_rate",
                "structured_evidence_present_rate",
            ):
                value["diagnostic_counts"][scope][diagnostic] = {
                    "numerator": 0,
                    "denominator": 0,
                }
                value["diagnostics"][scope][diagnostic] = None
        fixture = self.fixture(value)
        fixture.evidence["results"].write_text(
            "".join(
                json.dumps(row) + "\n"
                for row in (
                    {
                        "schema_version": 6,
                        "scoring_version": value["scoring_version"],
                        "case_id": "attack-1",
                        "expected_verdict": "block",
                        "actual_verdict": "allow",
                        "score": "fail",
                        "evidence": {
                            "budget_block_timing": "before_over_budget",
                            "error_message": "blocked at 4/3",
                            "result_state": "observed",
                        },
                        "notes": "",
                    },
                    {
                        "schema_version": 6,
                        "scoring_version": value["scoring_version"],
                        "case_id": "benign-1",
                        "expected_verdict": "allow",
                        "actual_verdict": "allow",
                        "score": "pass",
                        "evidence": {"result_state": "observed"},
                        "notes": "",
                    },
                )
            ),
            encoding="utf-8",
        )
        fixture.refresh_candidate_integrity()
        result = fixture.run(accept_policy_change=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        summary = fixture.summary.read_text(encoding="utf-8")
        self.assertIn("`attack-1`:", summary)
        self.assertIn("before_over_budget; blocked at 4/3", summary)

    def test_structural_failure_cannot_be_overridden(self):
        value = v6_candidate()
        value["measurement_status"] = "incomplete"
        fixture = self.fixture(value)
        result = fixture.run(accept_policy_change=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("non-reviewable failures", result.stdout)
        self.assertFalse(fixture.latest.exists())

    def test_evidence_changed_after_source_decision_is_rejected(self):
        fixture = self.fixture()
        fixture.evidence["results"].write_text("tampered\n", encoding="utf-8")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate evidence_sha256.results does not match retained evidence", result.stdout)

    def test_record_mutation_breaks_idempotent_promotion(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record_candidate = (
            fixture.store_root
            / "pipelock"
            / pointer["candidate_sha256"]
            / promotion.CANDIDATE_FILENAME
        )
        record_candidate.write_text("{}\n", encoding="utf-8")
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing record file changed", result.stdout)

    def test_record_manifest_identity_must_match_candidate(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["tool_version"] = "9.9.9"
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(
            ValueError, "record manifest and candidate disagree on tool_version"
        ):
            promotion.validate_record(record, pointer["candidate_sha256"])

    def test_record_manifest_schema_is_enforced(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        # Sentinel for "a version this promoter does not know". Bump it when a
        # real version catches up, or the test silently stops testing anything.
        manifest["schema_version"] = 99
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "manifest schema_version is unsupported"):
            promotion.validate_record(record, pointer["candidate_sha256"])

    def test_record_candidate_digest_is_bound_to_inventory(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest_path = record / promotion.RECORD_MANIFEST_FILENAME
        manifest = evaluator.load_object(manifest_path)
        manifest["candidate_sha256"] = "a" * 64
        write_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "must match the candidate file digest"):
            promotion.validate_record(record, "a" * 64)

    def test_missing_latest_pointer_cannot_recreate_existing_record(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        fixture.latest.unlink()
        fixture.write_source_decision()
        second = fixture.run()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(
            "append-only record already exists without a matching latest pointer",
            second.stdout,
        )

    def test_latest_pointer_identity_must_match_candidate(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        pointer = evaluator.load_object(fixture.latest)
        pointer["artifact_id"] = promotion.DEFAULT_ARTIFACT_PREFIX + "999"
        write_json(fixture.latest, pointer)
        second = fixture.run()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn("latest pointer and record candidate disagree on artifact_id", second.stdout)

    def test_unsafe_artifact_origin_is_rejected(self):
        value = v6_candidate()
        value["canonical_url"] = "https://attacker.example/run/123"
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("canonical_url must start", result.stdout)

    def test_non_reference_tool_is_rejected(self):
        value = v6_candidate()
        value["tool"] = "other-tool"
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("candidate tool must be pipelock", result.stdout)

    def test_unicode_run_id_is_rejected(self):
        value = v6_candidate(run_id="١٢٣")
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("positive decimal run ID", result.stdout)

    def test_store_root_must_be_beside_latest_pointer(self):
        fixture = self.fixture()
        fixture.store_root = fixture.root / "elsewhere" / "results"
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("results directory beside latest-verified", result.stdout)

    def test_cross_run_candidate_substitution_is_rejected(self):
        fixture = self.fixture()
        command = fixture.command()
        command[command.index("--expected-run-id") + 1] = "999"
        result = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the requested source run", result.stdout)

    def test_run_attempt_is_bound_when_present(self):
        fixture = self.fixture(v6_candidate(run_attempt="2", attempt_url=True))
        accepted = fixture.run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        command = fixture.command()
        command[command.index("--expected-run-attempt") + 1] = "3"
        rejected = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match the requested source attempt", rejected.stdout)

    def test_run_attempt_accepts_plain_canonical_run_url(self):
        fixture = self.fixture(v6_candidate(run_attempt="2", attempt_url=False))
        accepted = fixture.run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_canonical_url_cannot_name_a_different_run_attempt(self):
        value = v6_candidate(run_attempt="2", attempt_url=True)
        value["canonical_url"] = value["canonical_url"].removesuffix("2") + "3"
        fixture = self.fixture(value)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("artifact_id and canonical_url run IDs do not match", result.stdout)

    def test_run_id_only_candidate_is_accepted_without_expected_attempt(self):
        fixture = self.fixture(v6_candidate())
        accepted = fixture.run()
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_run_id_only_candidate_is_rejected_by_attempt_bound_promotion(self):
        fixture = self.fixture(v6_candidate())
        command = fixture.command()
        command.extend(["--expected-run-attempt", "1"])
        rejected = subprocess.run(
            command, cwd=REPO_ROOT, text=True, capture_output=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("does not match the requested source attempt", rejected.stdout)

    def test_timezone_free_candidate_time_is_rejected(self):
        fixture = self.fixture(v6_candidate(generated_at="2026-08-05T00:10:08"))
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("RFC 3339 timestamp", result.stdout)

    def test_missing_evidence_is_rejected(self):
        fixture = self.fixture()
        fixture.evidence["runner_stderr"].unlink()
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required evidence is missing", result.stdout)

    def test_symlinked_evidence_is_rejected(self):
        fixture = self.fixture()
        target = fixture.root / "outside.txt"
        target.write_text("outside\n", encoding="utf-8")
        fixture.evidence["runner_stderr"].unlink()
        fixture.evidence["runner_stderr"].symlink_to(target)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("required evidence is missing", result.stdout)

    def test_latest_pointer_cannot_move_backward(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)

        older = v6_candidate(run_id="124", generated_at="2026-08-04T00:10:08Z")
        second_artifact = fixture.root / "older-artifact"
        second_artifact.mkdir()
        for path in fixture.artifact_dir.iterdir():
            if path.is_file():
                (second_artifact / path.name).write_bytes(path.read_bytes())
        older["case_index_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["case_index"]).read_bytes()
        ).hexdigest()
        older["portable_bundle_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["run_bundle"]).read_bytes()
        ).hexdigest()
        older["evidence_sha256"] = {
            label: hashlib.sha256((second_artifact / filename).read_bytes()).hexdigest()
            for label, filename in (provenance.RAW_EVIDENCE | provenance.V4_RAW_EVIDENCE).items()
        }
        write_json(second_artifact / promotion.CANDIDATE_FILENAME, older)
        second_paths = {
            label: second_artifact / filename
            for label, filename in promotion.evidence_files_for(older).items()
        }
        source = evaluator.evaluate(
            second_artifact / promotion.CANDIDATE_FILENAME,
            fixture.baseline_path,
            second_paths,
        )
        write_json(second_artifact / promotion.SOURCE_DECISION_FILENAME, source)
        fixture.artifact_dir = second_artifact
        fixture.candidate_value = older
        records_before = sorted((fixture.store_root / "pipelock").iterdir())
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("backward or sideways", result.stdout)
        self.assertEqual(sorted((fixture.store_root / "pipelock").iterdir()), records_before)

    def test_newer_candidate_appends_hash_linked_record_and_advances_pointer(self):
        fixture = self.fixture()
        first = fixture.run()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        first_pointer = evaluator.load_object(fixture.latest)
        first_record = fixture.store_root / "pipelock" / first_pointer["candidate_sha256"]
        first_manifest_path = first_record / promotion.RECORD_MANIFEST_FILENAME
        first_manifest_digest = evaluator.file_sha256(first_manifest_path)

        newer = v6_candidate(run_id="124", generated_at="2026-08-06T00:10:08Z")
        second_artifact = fixture.root / "newer-artifact"
        second_artifact.mkdir()
        for path in fixture.artifact_dir.iterdir():
            if path.is_file():
                (second_artifact / path.name).write_bytes(path.read_bytes())
        newer["case_index_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["case_index"]).read_bytes()
        ).hexdigest()
        newer["portable_bundle_sha256"] = hashlib.sha256(
            (second_artifact / promotion.EVIDENCE_FILES["run_bundle"]).read_bytes()
        ).hexdigest()
        newer["evidence_sha256"] = {
            label: hashlib.sha256((second_artifact / filename).read_bytes()).hexdigest()
            for label, filename in {
                **provenance.RAW_EVIDENCE,
                **provenance.V4_RAW_EVIDENCE,
            }.items()
        }
        write_json(second_artifact / promotion.CANDIDATE_FILENAME, newer)
        second_paths = {
            label: second_artifact / filename
            for label, filename in promotion.evidence_files_for(newer).items()
        }
        write_json(
            second_artifact / promotion.SOURCE_DECISION_FILENAME,
            evaluator.evaluate(
                second_artifact / promotion.CANDIDATE_FILENAME,
                fixture.source_baseline_path,
                second_paths,
            ),
        )
        fixture.artifact_dir = second_artifact
        fixture.candidate_value = newer
        second = fixture.run()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)

        pointer = evaluator.load_object(fixture.latest)
        self.assertEqual(pointer["previous_candidate_sha256"], first_pointer["candidate_sha256"])
        self.assertEqual(
            pointer["previous_record_manifest_sha256"],
            first_pointer["record_manifest_sha256"],
        )
        record = fixture.store_root / "pipelock" / pointer["candidate_sha256"]
        manifest = evaluator.load_object(record / promotion.RECORD_MANIFEST_FILENAME)
        self.assertEqual(
            manifest["previous_candidate_sha256"], first_pointer["candidate_sha256"]
        )
        self.assertEqual(evaluator.file_sha256(first_manifest_path), first_manifest_digest)
        self.assertEqual(len(list((fixture.store_root / "pipelock").iterdir())), 2)


if __name__ == "__main__":
    unittest.main()
