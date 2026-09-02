#!/usr/bin/env python3
"""Tests for the fail-safe provenance scope validator."""

import json
import hashlib
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_gauntlet_scope.py"
MANIFEST = REPO_ROOT / "cases" / "MANIFEST.txt"
FROZEN_RECORD = (
    REPO_ROOT
    / "gauntlet-site"
    / "results"
    / "pipelock"
    / "5869b18cf5027d502bc5d0fd8b8f6899872a8b379137226c617670a295222886"
)


def load_scope_validator_module():
    spec = importlib.util.spec_from_file_location("validate_gauntlet_scope", VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


scope_validator = load_scope_validator_module()


class RenderVersionOptionsTests(unittest.TestCase):
    def test_renders_all_supported_cardinalities(self):
        cases = (
            ([], "no accepted versions"),
            ([4], "4"),
            ([4, 1], "1 or 4"),
            ([4, 1, 3], "1, 3, or 4"),
        )
        for versions, expected in cases:
            with self.subTest(versions=versions):
                self.assertEqual(scope_validator.render_version_options(versions), expected)


def corpus_manifest_sha256():
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def logical_case_count():
    return len({line.strip() for line in MANIFEST.read_text(encoding="utf-8").splitlines() if line.strip()})


def write_active_authority_root(root):
    manifest = b"a\nb\nc\n"
    (root / "cases").mkdir(parents=True)
    (root / "cases" / "MANIFEST.txt").write_bytes(manifest)
    (root / "cases" / "CORPUS_VERSION").write_text("v9.9.9\n", encoding="utf-8")
    active_set_path = root / "corpora" / "active-sets" / "v1" / "v9.9.9.json"
    active_set_path.parent.mkdir(parents=True)
    active_set = {
        "schema_version": 1,
        "corpus_version": "v9.9.9",
        "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "excluded_case_ids": ["c"],
        "case_count": 2,
    }
    active_set_path.write_text(json.dumps(active_set), encoding="utf-8")
    ledger_path = root / "ci" / "corpus-versions.json"
    ledger_path.parent.mkdir()
    ledger_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "versions": [
                    {
                        "corpus_version": "v9.9.9",
                        "case_count": 2,
                        "active_set_sha256": hashlib.sha256(active_set_path.read_bytes()).hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return hashlib.sha256(manifest).hexdigest(), {"a", "b", "c"}, active_set_path, ledger_path


def complete_artifact():
    total = logical_case_count()
    full_benign = 55
    full_malicious = total - full_benign
    blocked_malicious = full_malicious - 1
    return {
        "schema_version": 2,
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
        "corpus_manifest_sha256": corpus_manifest_sha256(),
        "case_index_sha256": "c" * 64,
        "logical_case_count": logical_case_count(),
        "runner_version": "0.4.0",
        "scoring_version": "2.2",
        "case_count": {
            "total": total,
            "applicable": total - 1,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
            "errors": 0,
        },
        "scores": {
            "full": {
                "containment": blocked_malicious / full_malicious,
                "false_positive_rate": 0.0,
                "detection": 1.0,
                "evidence": 1.0,
            },
            "applicable": {
                "containment": 1.0,
                "false_positive_rate": 0.0,
                "detection": 1.0,
                "evidence": 1.0,
            },
        },
        "metric_counts": {
            "applicable": {
                "containment": {"numerator": blocked_malicious, "denominator": blocked_malicious},
                "false_positive_rate": {"numerator": 0, "denominator": full_benign},
                "detection": {"numerator": blocked_malicious, "denominator": blocked_malicious},
                "evidence": {"numerator": blocked_malicious, "denominator": blocked_malicious},
            },
            "full": {
                "containment": {"numerator": blocked_malicious, "denominator": full_malicious},
                "false_positive_rate": {"numerator": 0, "denominator": full_benign},
                "detection": {"numerator": blocked_malicious, "denominator": blocked_malicious},
                "evidence": {"numerator": blocked_malicious, "denominator": blocked_malicious},
            },
        },
    }


def complete_v5_artifact():
    artifact = complete_artifact()
    artifact["schema_version"] = 5
    artifact["runner_version"] = "0.4.3"
    artifact["scoring_version"] = "2.8"
    artifact["benchmark_manifest_sha256"] = "e" * 64
    artifact["measurement_status"] = "measured"
    artifact["case_count"]["unreachable"] = 0
    artifact["capability_registry"] = {
        "id": "aeb.core-capabilities",
        "format": 1,
        "revision": 1,
        "sha256": "d" * 64,
    }
    artifact["diagnostics"] = {}
    artifact["diagnostic_counts"] = {}
    for scope in ("full", "applicable"):
        scores = artifact["scores"][scope]
        counts = artifact["metric_counts"][scope]
        artifact["diagnostics"][scope] = {
            "classification_present_rate": scores.pop("detection"),
            "structured_evidence_present_rate": scores.pop("evidence"),
        }
        artifact["diagnostic_counts"][scope] = {
            "classification_present_rate": counts.pop("detection"),
            "structured_evidence_present_rate": counts.pop("evidence"),
        }
    artifact.update(
        {
            "local_run_id": "run-123",
            "generated_at": "2026-08-05T10:33:23Z",
            "corpus_ref_kind": "origin/main",
            "corpus_git_sha": "a" * 40,
            "corpus_commit_url": "https://github.com/luckyPipewrench/agent-egress-bench/commit/" + "a" * 40,
            "dirty": False,
            "pipelock_tag": "v3.3.0",
            "pipelock_version": "3.3.0",
            "pipelock_asset": "pipelock_3.3.0_linux_amd64.tar.gz",
            "pipelock_asset_sha256": "a" * 64,
            "pipelock_binary_sha256": "b" * 64,
            "pipelock_release_url": "https://github.com/luckyPipewrench/pipelock/releases/tag/v3.3.0",
            "gauntlet_version": "0.4.3",
            "tool": "pipelock",
            "tool_version": "3.3.0",
            "corpus_version": "v2.3.0",
            "corpus_sha256": "a" * 64,
            "tool_profile_sha256": "a" * 64,
            "fixtures": True,
            "multifile_cases": True,
            "command": "aeb-gauntlet",
            "make_stats": "complete",
            "evidence_sha256": {label: "a" * 64 for label in (
                "capability_registry", "case_index", "command", "corpus_manifest",
                "entrypoint_command", "pipelock_release", "pipelock_version_output",
                "raw_summary", "receipt_profile", "release_checksums", "results",
                "run_metadata", "runner_stderr", "stats", "tool_profile",
            )},
            "reported_claims": [],
            "exercised": {"transports": ["stdio"], "categories": ["prompt-injection"], "capability_tags": []},
            "portable_bundle_sha256": "a" * 64,
        }
    )
    return artifact


def complete_current_active_set_artifact():
    artifact = complete_v5_artifact()
    corpus_version = (REPO_ROOT / "cases" / "CORPUS_VERSION").read_text(encoding="utf-8").strip()
    active_set = json.loads(
        (REPO_ROOT / "corpora" / "active-sets" / "v1" / f"{corpus_version}.json").read_text(
            encoding="utf-8"
        )
    )
    selected_count = active_set["case_count"]
    if selected_count >= logical_case_count():
        raise ValueError("active-set fixture must select fewer cases than the source catalog")
    benign_count = 1
    malicious_count = selected_count - benign_count
    blocked_malicious = malicious_count
    artifact["corpus_version"] = corpus_version
    artifact["logical_case_count"] = selected_count
    artifact["case_count"] = {
        "total": selected_count,
        "applicable": selected_count,
        "unreachable": 0,
        "not_applicable": 0,
        "not_applicable_reasons": {},
        "errors": 0,
    }
    for scope in ("full", "applicable"):
        artifact["scores"][scope] = {
            "containment": 1.0,
            "false_positive_rate": 0.0,
        }
        artifact["metric_counts"][scope] = {
            "containment": {
                "numerator": blocked_malicious,
                "denominator": malicious_count,
            },
            "false_positive_rate": {"numerator": 0, "denominator": benign_count},
        }
        artifact["diagnostics"][scope] = {
            "classification_present_rate": 1.0,
            "structured_evidence_present_rate": 1.0,
        }
        artifact["diagnostic_counts"][scope] = {
            "classification_present_rate": {
                "numerator": blocked_malicious,
                "denominator": blocked_malicious,
            },
            "structured_evidence_present_rate": {
                "numerator": blocked_malicious,
                "denominator": blocked_malicious,
            },
        }
    return artifact


def all_na_artifact():
    artifact = complete_artifact()
    artifact["case_count"] = {
        "total": logical_case_count(),
        "applicable": 0,
        "not_applicable": logical_case_count(),
        "not_applicable_reasons": {"missing_requires": logical_case_count()},
        "errors": 0,
    }
    artifact["scores"]["applicable"] = {metric: None for metric in ("containment", "false_positive_rate", "detection", "evidence")}
    artifact["metric_counts"]["applicable"] = {
        metric: {"numerator": 0, "denominator": 0}
        for metric in ("containment", "false_positive_rate", "detection", "evidence")
    }
    artifact["scores"]["full"] = {
        "containment": 0.0,
        "false_positive_rate": None,
        "detection": None,
        "evidence": None,
    }
    artifact["metric_counts"]["full"] = {
        "containment": {"numerator": 0, "denominator": logical_case_count()},
        "false_positive_rate": {"numerator": 0, "denominator": 0},
        "detection": {"numerator": 0, "denominator": 0},
        "evidence": {"numerator": 0, "denominator": 0},
    }
    return artifact


def minimal_v1_artifact(manifest):
    ids = [line.strip() for line in manifest.decode("utf-8").splitlines() if line.strip()]
    total = len(ids)
    return {
        "schema_version": 1,
        "canonical_url": "https://github.com/luckyPipewrench/agent-egress-bench/actions/runs/123",
        "artifact_id": "github-actions:luckyPipewrench/agent-egress-bench:123",
        "corpus_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "logical_case_count": total,
        "runner_version": "0.4.0",
        "scoring_version": "2.2",
        "case_count": {
            "total": total,
            "applicable": total,
            "not_applicable": 0,
            "not_applicable_reasons": {},
        },
        "scores": {
            "applicable": {
                "containment": 1.0,
                "false_positive_rate": None,
            },
        },
        "metric_counts": {
            "applicable": {
                "containment": {"numerator": total, "denominator": total},
                "false_positive_rate": {"numerator": 0, "denominator": 0},
            },
        },
    }


class ValidateGauntletScopeTest(unittest.TestCase):
    def run_validator(self, artifact, manifest=None, args=(), write_sidecar=True):
        if manifest is None:
            manifest = MANIFEST.read_bytes()
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact_path = Path(temp_dir) / "artifact.json"
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            if write_sidecar:
                (artifact_path.parent / "corpus-manifest.txt").write_bytes(manifest)
            return subprocess.run(
                [sys.executable, str(VALIDATOR), *args, str(artifact_path)],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_complete_artifact_passes(self):
        result = self.run_validator(complete_artifact())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_complete_v5_active_set_artifact_passes_with_presence_diagnostics(self):
        artifact = complete_current_active_set_artifact()
        self.assertLess(artifact["logical_case_count"], logical_case_count())
        result = self.run_validator(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_current_active_set_artifact_rejects_unselected_case_count(self):
        artifact = complete_current_active_set_artifact()
        artifact["logical_case_count"] += 1

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checked-out active set", result.stderr)

    def test_current_candidate_rejects_a_different_declared_corpus_version(self):
        artifact = complete_current_active_set_artifact()
        artifact["corpus_version"] = "v2.6.0"

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the checked-out corpus version", result.stderr)

    def test_current_candidate_rejects_a_symlinked_corpus_version_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_digest, _, _, _ = write_active_authority_root(root)
            marker = root / "cases" / "CORPUS_VERSION"
            marker.unlink()
            marker.symlink_to(REPO_ROOT / "cases" / "CORPUS_VERSION")
            artifact = complete_current_active_set_artifact()
            with mock.patch.object(scope_validator, "REPO_ROOT", root), mock.patch.object(
                scope_validator, "MANIFEST_PATH", root / "cases" / "MANIFEST.txt"
            ):
                with self.assertRaisesRegex(ValueError, "must be a regular file"):
                    scope_validator.checked_out_corpus_authority(
                        artifact, root / "cases" / "MANIFEST.txt"
                    )

    def test_current_candidate_rejects_a_symlinked_checked_out_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_active_authority_root(root)
            manifest = root / "cases" / "MANIFEST.txt"
            manifest.unlink()
            manifest.symlink_to(MANIFEST)
            artifact = complete_current_active_set_artifact()
            with mock.patch.object(scope_validator, "REPO_ROOT", root), mock.patch.object(
                scope_validator, "MANIFEST_PATH", manifest
            ):
                with self.assertRaisesRegex(ValueError, "must be a regular file"):
                    scope_validator.checked_out_corpus_authority(artifact, manifest)

    def test_current_candidate_rejects_a_symlinked_active_set(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_digest, source_ids, active_set, _ = write_active_authority_root(root)
            active_set.unlink()
            active_set.symlink_to(REPO_ROOT / "corpora" / "active-sets" / "v1" / "v2.7.0.json")
            with mock.patch.object(scope_validator, "REPO_ROOT", root):
                with self.assertRaisesRegex(ValueError, "must be a regular file"):
                    scope_validator.checked_out_active_set_count(
                        source_digest, source_ids, "v9.9.9"
                    )

    def test_checked_out_active_set_rejects_invalid_contract_branches(self):
        cases = (
            (
                "source manifest mismatch",
                lambda active, ledger: active.update(source_manifest_sha256="0" * 64),
                "does not bind the checked-out corpus version and source manifest",
            ),
            (
                "unknown exclusion",
                lambda active, ledger: active.update(excluded_case_ids=["missing"]),
                "excludes unknown case IDs",
            ),
            (
                "active set count mismatch",
                lambda active, ledger: active.update(case_count=1),
                "active set case_count does not match",
            ),
            (
                "active set boolean count",
                lambda active, ledger: active.update(case_count=True),
                "active set case_count does not match",
            ),
            (
                "active set float count",
                lambda active, ledger: active.update(case_count=2.0),
                "active set case_count does not match",
            ),
            (
                "ledger active set mismatch",
                lambda active, ledger: ledger["versions"][0].update(active_set_sha256="0" * 64),
                "does not bind the active set bytes",
            ),
            (
                "ledger count mismatch",
                lambda active, ledger: ledger["versions"][0].update(case_count=1),
                "ledger case_count does not match",
            ),
            (
                "ledger boolean count",
                lambda active, ledger: ledger["versions"][0].update(case_count=True),
                "ledger case_count does not match",
            ),
            (
                "ledger float count",
                lambda active, ledger: ledger["versions"][0].update(case_count=2.0),
                "ledger case_count does not match",
            ),
            (
                "duplicate active version",
                lambda active, ledger: ledger["versions"].append(dict(ledger["versions"][0])),
                "appear once as the final ledger entry",
            ),
            (
                "active version is not final",
                lambda active, ledger: ledger["versions"].append({"corpus_version": "v10.0.0"}),
                "appear once as the final ledger entry",
            ),
            (
                "malformed ledger versions",
                lambda active, ledger: ledger.update(versions={}),
                "appear once as the final ledger entry",
            ),
        )
        for name, mutate, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_digest, source_ids, active_set_path, ledger_path = write_active_authority_root(root)
                active_set = json.loads(active_set_path.read_text(encoding="utf-8"))
                ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
                mutate(active_set, ledger)
                active_set_path.write_text(json.dumps(active_set), encoding="utf-8")
                if ledger.get("versions") and ledger["versions"][0].get("active_set_sha256") != "0" * 64:
                    ledger["versions"][0]["active_set_sha256"] = hashlib.sha256(
                        active_set_path.read_bytes()
                    ).hexdigest()
                ledger_path.write_text(json.dumps(ledger), encoding="utf-8")
                with mock.patch.object(scope_validator, "REPO_ROOT", root):
                    with self.assertRaisesRegex(ValueError, expected_error):
                        scope_validator.checked_out_active_set_count(
                            source_digest, source_ids, "v9.9.9"
                        )

    def test_repo_anchored_authority_reader_rejects_parent_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            outside = Path(directory) / "outside"
            root.mkdir()
            (outside / "cases").mkdir(parents=True)
            (outside / "cases" / "CORPUS_VERSION").write_text("v9.9.9\n", encoding="utf-8")
            (root / "cases").symlink_to(outside / "cases", target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "parent path for corpus version must contain only directories"):
                scope_validator.read_repo_regular_bytes(
                    root, Path("cases") / "CORPUS_VERSION", "corpus version"
                )

    def test_v5_rejects_legacy_presence_metric_names_in_scores(self):
        artifact = complete_current_active_set_artifact()
        artifact["scores"]["applicable"]["detection"] = 1.0

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("scores.applicable", result.stderr)
        self.assertIn("unexpected keys", result.stderr)

    def test_v5_rejects_unexpected_outer_metric_scopes(self):
        for field in ("scores", "diagnostics", "metric_counts", "diagnostic_counts"):
            with self.subTest(field=field):
                artifact = complete_current_active_set_artifact()
                artifact[field]["legacy"] = {}

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(field, result.stderr)
                self.assertIn("unexpected keys", result.stderr)

    def test_candidate_rejects_reduced_sidecar_that_self_asserts_match(self):
        # An attacker can make a reduced corpus self-consistent by controlling
        # both the sibling manifest and every denominator in the candidate.
        # Candidate validation must anchor to the checked-out manifest instead.
        reduced_manifest = b"url-attack-001\nurl-benign-002\n"
        result = self.run_validator(minimal_v1_artifact(reduced_manifest), reduced_manifest)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checked-out cases/MANIFEST.txt", result.stderr)

    def test_existing_schema_versions_remain_standalone_in_candidate_mode(self):
        v1 = minimal_v1_artifact(MANIFEST.read_bytes())
        v2 = complete_artifact()
        v4 = complete_artifact()
        v4["schema_version"] = 4
        v4["capability_registry"] = {
            "id": "aeb.core-capabilities",
            "format": 1,
            "revision": 1,
            "sha256": "d" * 64,
        }

        for name, artifact in (("v1", v1), ("v2", v2), ("v4", v4)):
            with self.subTest(schema=name):
                result = self.run_validator(artifact, write_sidecar=False)

                self.assertEqual(result.returncode, 0, result.stderr)

    def test_frozen_record_requires_explicit_authenticated_archive_mode(self):
        record_manifest = FROZEN_RECORD / "record-manifest.json"
        expected_manifest_digest = hashlib.sha256(record_manifest.read_bytes()).hexdigest()
        artifact_path = FROZEN_RECORD / "continuous-gauntlet-pipelock.json"
        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--archive-record",
                str(FROZEN_RECORD),
                "--expected-record-manifest-sha256",
                expected_manifest_digest,
                str(artifact_path),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_promoted_record_v2_is_accepted_in_archive_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / FROZEN_RECORD.name
            shutil.copytree(FROZEN_RECORD, record)
            manifest_path = record / "record-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema_version"] = 2
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            expected_manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--archive-record",
                    str(record),
                    "--expected-record-manifest-sha256",
                    expected_manifest_digest,
                    str(record / "continuous-gauntlet-pipelock.json"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_archive_record_refusal_names_all_accepted_record_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            record = Path(directory) / FROZEN_RECORD.name
            shutil.copytree(FROZEN_RECORD, record)
            manifest_path = record / "record-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["schema_version"] = 99
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            expected_manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            result = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATOR),
                    "--archive-record",
                    str(record),
                    "--expected-record-manifest-sha256",
                    expected_manifest_digest,
                    str(record / "continuous-gauntlet-pipelock.json"),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("schema_version must be 1, 2, or 3", result.stderr)

    def test_archive_record_rejects_an_untrusted_record_manifest_digest(self):
        artifact_path = FROZEN_RECORD / "continuous-gauntlet-pipelock.json"
        result = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--archive-record",
                str(FROZEN_RECORD),
                "--expected-record-manifest-sha256",
                "0" * 64,
                str(artifact_path),
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted expected digest", result.stderr)

    def test_duplicate_retained_manifest_ids_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = Path(temp_dir) / "corpus-manifest.txt"
            manifest.write_text("url-attack-001\nurl-attack-001\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate"):
                scope_validator.corpus_manifest_identity(manifest)

    def test_unreachable_coverage_is_visible_but_outside_full_denominator(self):
        artifact = complete_artifact()
        total = artifact["case_count"]["total"]
        artifact["case_count"]["applicable"] = total - 2
        artifact["case_count"]["unreachable"] = 1
        artifact["metric_counts"]["applicable"]["false_positive_rate"]["denominator"] -= 1
        artifact["metric_counts"]["full"]["false_positive_rate"]["denominator"] -= 1

        result = self.run_validator(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_required_scope_field_fails_when_missing(self):
        required_paths = [
            ("schema_version",),
            ("case_count", "applicable"),
            ("case_count", "total"),
            ("case_count", "not_applicable"),
            ("case_count", "not_applicable_reasons"),
            ("case_count", "errors"),
            ("canonical_url",),
            ("artifact_id",),
            ("corpus_manifest_sha256",),
            ("case_index_sha256",),
            ("logical_case_count",),
            ("runner_version",),
            ("scoring_version",),
        ]
        for scope in ("applicable", "full"):
            for metric in ("containment", "false_positive_rate", "detection", "evidence"):
                required_paths.extend(
                    [
                        ("scores", scope, metric),
                        ("metric_counts", scope, metric, "numerator"),
                        ("metric_counts", scope, metric, "denominator"),
                    ]
                )

        for path in required_paths:
            with self.subTest(path=".".join(path)):
                artifact = complete_artifact()
                target = artifact
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(".".join(path), result.stderr)

    def test_original_v1_artifact_remains_verifiable(self):
        artifact = complete_artifact()
        artifact["schema_version"] = 1
        artifact.pop("case_index_sha256")
        artifact["case_count"].pop("errors")
        artifact["scores"].pop("full")
        artifact["metric_counts"].pop("full")
        for metric in ("detection", "evidence"):
            artifact["scores"]["applicable"].pop(metric)
            artifact["metric_counts"]["applicable"].pop(metric)

        result = self.run_validator(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unknown_schema_version_fails(self):
        artifact = complete_artifact()
        artifact["schema_version"] = 99

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported schema_version", result.stderr)

    def test_missing_corpus_digest_fails(self):
        artifact = complete_artifact()
        del artifact["corpus_manifest_sha256"]

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corpus_manifest_sha256", result.stderr)

    def test_corpus_digest_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["corpus_manifest_sha256"] = "0" * 64

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("corpus_manifest_sha256", result.stderr)

    def test_logical_case_count_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["logical_case_count"] -= 1

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("logical_case_count", result.stderr)

    def test_case_count_total_must_match_checked_out_manifest(self):
        artifact = complete_artifact()
        artifact["case_count"] = {
            "total": logical_case_count() - 1,
            "applicable": logical_case_count() - 2,
            "not_applicable": 1,
            "not_applicable_reasons": {"missing_requires": 1},
            "errors": 0,
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("case_count.total", result.stderr)

    def test_score_must_equal_metric_numerator_over_denominator(self):
        for metric in ("containment", "false_positive_rate"):
            with self.subTest(metric=metric):
                artifact = complete_artifact()
                artifact["scores"]["applicable"][metric] = 0.5

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(metric, result.stderr)

    def test_full_and_applicable_numerators_cannot_diverge(self):
        artifact = complete_artifact()
        artifact["metric_counts"]["full"]["detection"]["numerator"] -= 1
        artifact["scores"]["full"]["detection"] = (
            artifact["metric_counts"]["full"]["detection"]["numerator"]
            / artifact["metric_counts"]["full"]["detection"]["denominator"]
        )

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("applicable numerator", result.stderr)

    def test_full_metric_denominators_must_partition_total(self):
        artifact = complete_artifact()
        artifact["metric_counts"]["full"]["false_positive_rate"]["denominator"] -= 1

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full metric denominators must partition", result.stderr)

    def test_metric_denominator_cannot_exceed_applicable_cases(self):
        artifact = complete_artifact()
        artifact["metric_counts"]["applicable"]["containment"] = {
            "numerator": logical_case_count(),
            "denominator": logical_case_count(),
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("metric denominator", result.stderr)

    def test_inconsistent_na_breakdown_fails(self):
        artifact = complete_artifact()
        artifact["case_count"]["not_applicable_reasons"] = {"missing_requires": 0}

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not_applicable_reasons must sum", result.stderr)

    def test_null_false_positive_rate_passes_as_na(self):
        artifact = complete_artifact()
        total = logical_case_count()
        artifact["case_count"] = {
            "total": total,
            "applicable": total,
            "not_applicable": 0,
            "not_applicable_reasons": {},
            "errors": 0,
        }
        for scope in ("applicable", "full"):
            artifact["scores"][scope]["containment"] = 1.0
            artifact["metric_counts"][scope]["containment"] = {
                "numerator": total,
                "denominator": total,
            }
        artifact["scores"]["applicable"]["false_positive_rate"] = None
        artifact["metric_counts"]["applicable"]["false_positive_rate"] = {
            "numerator": 0,
            "denominator": 0,
        }
        artifact["scores"]["full"]["false_positive_rate"] = None
        artifact["metric_counts"]["full"]["false_positive_rate"] = {
            "numerator": 0,
            "denominator": 0,
        }
        for scope in ("applicable", "full"):
            for metric in ("detection", "evidence"):
                artifact["scores"][scope][metric] = 1.0
                artifact["metric_counts"][scope][metric] = {
                    "numerator": total,
                    "denominator": total,
                }

        result = self.run_validator(artifact)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_containment_is_na_only_when_no_cases_are_applicable(self):
        all_na_result = self.run_validator(all_na_artifact())
        self.assertEqual(all_na_result.returncode, 0, all_na_result.stderr)

        all_na_with_score = all_na_artifact()
        all_na_with_score["scores"]["applicable"]["containment"] = 0.0
        all_na_with_score_result = self.run_validator(all_na_with_score)
        self.assertNotEqual(all_na_with_score_result.returncode, 0)
        self.assertIn("containment", all_na_with_score_result.stderr)

        applicable_with_na = complete_artifact()
        applicable_with_na["scores"]["applicable"]["containment"] = None
        applicable_with_na_result = self.run_validator(applicable_with_na)
        self.assertNotEqual(applicable_with_na_result.returncode, 0)
        self.assertIn("containment", applicable_with_na_result.stderr)

        # Likewise, a null score with a zero denominator is internally
        # well-formed but cannot represent containment when cases applied.
        applicable_with_zero_denominator = complete_artifact()
        applicable_with_zero_denominator["scores"]["applicable"]["containment"] = None
        applicable_with_zero_denominator["metric_counts"]["applicable"]["containment"] = {
            "numerator": 0,
            "denominator": 0,
        }
        applicable_with_zero_denominator_result = self.run_validator(applicable_with_zero_denominator)
        self.assertNotEqual(applicable_with_zero_denominator_result.returncode, 0)
        self.assertIn("containment", applicable_with_zero_denominator_result.stderr)

        applicable_with_score_result = self.run_validator(complete_artifact())
        self.assertEqual(applicable_with_score_result.returncode, 0, applicable_with_score_result.stderr)

    def test_invalid_containment_values_fail(self):
        # For runs with applicable cases, containment is the published headline.
        # A string or out-of-range number must fail rather than render a
        # misleading score.
        for bad in ("100%", 2, -1):
            with self.subTest(value=bad):
                artifact = complete_artifact()
                artifact["scores"]["applicable"]["containment"] = bad

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("containment", result.stderr)
    def test_zero_total_fails(self):
        artifact = complete_artifact()
        artifact["case_count"] = {
            "total": 0,
            "applicable": 0,
            "not_applicable": 0,
            "not_applicable_reasons": {},
            "errors": 0,
        }

        result = self.run_validator(artifact)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("greater than zero", result.stderr)

    def test_unsafe_canonical_url_fails(self):
        # A non-https or non-absolute canonical_url must fail: it is rendered as
        # a link, so a javascript:/relative/http value is a real safety gap.
        for bad in ("javascript:alert(1)", "not-a-url", "http://example.com/x", "//example.com/x"):
            with self.subTest(value=bad):
                artifact = complete_artifact()
                artifact["canonical_url"] = bad

                result = self.run_validator(artifact)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("canonical_url", result.stderr)


if __name__ == "__main__":
    unittest.main()
