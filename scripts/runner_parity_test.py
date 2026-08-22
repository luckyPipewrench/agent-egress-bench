import contextlib
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from scripts import runner_parity


class RunnerParityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.results = self.root / "results.jsonl"
        self.manifest = self.root / "benchmark-manifest.txt"
        self.manifest.write_text("a\nb\n", encoding="utf-8")
        rows = [
            {"schema_version": 5, "case_id": "b", "tool": "tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "allow", "score": "pass", "evidence": {"result_state": "observed"}},
            {"schema_version": 5, "case_id": "a", "tool": "tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "error", "score": "error", "evidence": {"result_state": "delivery_unavailable"}},
        ]
        self.results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def args(self, output, **updates):
        values = dict(
            results=self.results, output=output, corpus_sha256="a" * 64,
            comparison_id="round-2026-08-10-a",
            benchmark_manifest=self.manifest, tool="tool", tool_version="1.2.3",
            tool_profile_sha256="c" * 64, runner="aeb-gauntlet", runner_version="4",
            runtime="go1.25.10", os_name="linux", arch="amd64", concurrency=1,
            timeout_seconds=15.0, fixture_mode="local", network_mode="contained",
        )
        values.update(updates)
        return Namespace(**values)

    def prepare(self, name="reveal.json", **updates):
        path = self.root / name
        nonce = updates.pop("nonce_hex", "e" * 32 if name != "reveal.json" else "d" * 32)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner_parity.prepare_with_nonce(self.args(path, **updates), nonce)
        return path, output.getvalue().strip()

    def test_prepare_verify_and_compare(self):
        left, digest = self.prepare()
        reveal = json.loads(left.read_text(encoding="utf-8"))
        self.assertEqual(["a", "b"], [row["case_id"] for row in reveal["normalized_results"]])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner_parity.verify(Namespace(reveal=left, commitment_sha256=digest, benchmark_manifest=self.manifest))
        self.assertEqual(digest, output.getvalue().strip())
        right, _ = self.prepare("right.json", runner="independent-runner")
        with contextlib.redirect_stdout(io.StringIO()):
            runner_parity.compare(Namespace(left=left, right=right, benchmark_manifest=self.manifest))

    def test_environment_is_committed_but_excluded_from_result_parity(self):
        left, left_digest = self.prepare()
        right, right_digest = self.prepare("right.json", os_name="darwin", arch="arm64")
        self.assertNotEqual(left_digest, right_digest)
        left_value = json.loads(left.read_text(encoding="utf-8"))
        right_value = json.loads(right.read_text(encoding="utf-8"))
        self.assertEqual(
            left_value["commitment"]["results"]["normalized_vector_sha256"],
            right_value["commitment"]["results"]["normalized_vector_sha256"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            runner_parity.compare(Namespace(left=left, right=right, benchmark_manifest=self.manifest))

    def test_mutating_result_after_commit_fails_closed(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["case_id"] = "aa"
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest, benchmark_manifest=self.manifest))

    def test_mutating_environment_breaks_published_commitment(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["commitment"]["environment"]["concurrency"] = 8
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest, benchmark_manifest=self.manifest))

    def test_missing_result_state_is_rejected(self):
        row = json.loads(self.results.read_text(encoding="utf-8").splitlines()[0])
        del row["evidence"]["result_state"]
        self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "result_state"):
            runner_parity.load_results(self.results)

    def test_inconsistent_result_state_is_rejected(self):
        row = json.loads(self.results.read_text(encoding="utf-8").splitlines()[0])
        row["actual_verdict"] = "error"
        row["score"] = "error"
        self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "observed result"):
            runner_parity.load_results(self.results)

    def test_result_v5_conformance_vectors(self):
        path = Path(__file__).resolve().parents[1] / "validate" / "testdata" / "result-v5-conformance.json"
        corpus = json.loads(path.read_text(encoding="utf-8"))
        for vector in corpus["accepted"]:
            with self.subTest(kind="accepted", name=vector["name"]):
                self.results.write_text(json.dumps(vector["row"]) + "\n", encoding="utf-8")
                self.assertEqual(1, len(runner_parity.load_results(self.results)))
        for vector in corpus["rejected"]:
            with self.subTest(kind="rejected", name=vector["name"]):
                self.results.write_text(json.dumps(vector["row"]) + "\n", encoding="utf-8")
                with self.assertRaises(ValueError):
                    runner_parity.load_results(self.results)

    def test_v6_scoring_version_is_normalized_and_bound(self):
        row = json.loads(self.results.read_text(encoding="utf-8").splitlines()[0])
        row["schema_version"] = 6
        row["scoring_version"] = runner_parity.SCORING_VERSION
        self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
        normalized = runner_parity.load_results(self.results)
        self.assertEqual(runner_parity.SCORING_VERSION, normalized[0]["scoring_version"])
        row["scoring_version"] = ""
        self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "scoring_version"):
            runner_parity.load_results(self.results)
        row["scoring_version"] = "2.9"
        self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
        normalized = runner_parity.load_results(self.results)
        self.assertEqual("2.9", normalized[0]["scoring_version"])

    def test_v6_rows_cannot_share_a_file_with_v5_rows_in_either_order(self):
        rows = [json.loads(line) for line in self.results.read_text(encoding="utf-8").splitlines()]
        active = dict(rows[0], schema_version=6, scoring_version="2.8")
        frozen = rows[1]
        for ordered_rows in ((active, frozen), (frozen, active)):
            with self.subTest(active_first=ordered_rows[0]["schema_version"] == 6):
                self.results.write_text(
                    "".join(json.dumps(row) + "\n" for row in ordered_rows), encoding="utf-8"
                )
                with self.assertRaisesRegex(ValueError, "frozen result rows cannot share a file"):
                    runner_parity.load_results(self.results)

    def test_validate_reveal_rejects_mixed_legacy_and_scorer_bound_rows(self):
        path, _ = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["scoring_version"] = runner_parity.SCORING_VERSION
        reveal["commitment"]["results"]["normalized_vector_sha256"] = runner_parity.sha256(
            reveal["normalized_results"]
        )
        with self.assertRaisesRegex(ValueError, "cannot mix frozen and scorer-bound rows"):
            runner_parity.validate_reveal(reveal)

    def test_v5_rows_must_omit_declared_scoring_version(self):
        row = json.loads(self.results.read_text(encoding="utf-8").splitlines()[0])
        for scoring_version in (None, "", "2.8"):
            with self.subTest(scoring_version=scoring_version):
                row["scoring_version"] = scoring_version
                self.results.write_text(json.dumps(row) + "\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "must not declare scoring_version"):
                    runner_parity.load_results(self.results)

    def test_v6_scoring_version_changes_commitment(self):
        rows = [json.loads(line) for line in self.results.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            row["schema_version"] = 6
            row["scoring_version"] = runner_parity.SCORING_VERSION
        self.results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        left, left_digest = self.prepare()
        reveal = json.loads(left.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["scoring_version"] = "3.0"
        left.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match"):
            runner_parity.verify(
                Namespace(reveal=left, commitment_sha256=left_digest, benchmark_manifest=self.manifest)
            )

    def test_compare_rejects_independently_committed_scorer_mismatch(self):
        rows = [json.loads(line) for line in self.results.read_text(encoding="utf-8").splitlines()]
        for row in rows:
            row["schema_version"] = 6
            row["scoring_version"] = runner_parity.SCORING_VERSION
        self.results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        left, _ = self.prepare()
        for row in rows:
            row["scoring_version"] = "2.9"
        self.results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        right, _ = self.prepare("right.json")
        with self.assertRaisesRegex(ValueError, "vectors differ"):
            runner_parity.compare(Namespace(left=left, right=right, benchmark_manifest=self.manifest))

    def test_tool_identity_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "tool does not match"):
            runner_parity.load_results(self.results, "different-tool", "1.2.3")

    # NaN fails every comparison and Infinity is positive, so a bare
    # "timeout <= 0" bound accepted both. Neither is JSON, so a reveal carrying
    # one could not be parsed by an independent verifier. prepare must refuse
    # before it writes, not after.
    def test_prepare_rejects_non_finite_timeout_before_writing(self):
        with self.assertRaisesRegex(ValueError, "positive finite"):
            self.prepare("not-a-number.json", timeout_seconds=float("nan"))
        self.assertFalse((self.root / "not-a-number.json").exists())

    def test_verify_rejects_non_finite_timeout_in_a_hand_written_reveal(self):
        path, _ = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["commitment"]["environment"]["timeout_seconds"] = float("inf")
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "positive finite"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256="0" * 64, benchmark_manifest=self.manifest))

    def test_compare_rejects_different_vectors(self):
        left, _ = self.prepare()
        rows = self.results.read_text(encoding="utf-8").replace('"actual_verdict": "allow", "score": "pass"', '"actual_verdict": "block", "score": "fail"')
        self.results.write_text(rows, encoding="utf-8")
        right, _ = self.prepare("right.json")
        with self.assertRaisesRegex(ValueError, "vectors differ"):
            runner_parity.compare(Namespace(left=left, right=right, benchmark_manifest=self.manifest))

    def test_compare_rejects_same_reveal_or_nonce(self):
        left, _ = self.prepare()
        with self.assertRaisesRegex(ValueError, "distinct nonces"):
            runner_parity.compare(Namespace(left=left, right=left, benchmark_manifest=self.manifest))

    def test_compare_rejects_different_rounds(self):
        left, _ = self.prepare()
        right, _ = self.prepare("right.json", comparison_id="another-round")
        with self.assertRaisesRegex(ValueError, "same comparison round"):
            runner_parity.compare(Namespace(left=left, right=right, benchmark_manifest=self.manifest))

    def test_verify_rejects_laundered_result_semantics(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["result_state"] = "observed"
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inconsistent observed"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest, benchmark_manifest=self.manifest))

    def test_prepare_rejects_omitted_manifest_case(self):
        rows = self.results.read_text(encoding="utf-8").splitlines()
        self.results.write_text(rows[0] + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "missing=\\['a'\\]"):
            self.prepare("omitted.json")

    def test_prepare_rejects_unexpected_result_case(self):
        row = json.loads(self.results.read_text(encoding="utf-8").splitlines()[0])
        row["case_id"] = "c"
        with self.results.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        with self.assertRaisesRegex(ValueError, "unexpected=\\['c'\\]"):
            self.prepare("unexpected.json")

    def test_verify_rejects_different_manifest_bytes(self):
        path, digest = self.prepare()
        self.manifest.write_text("a\nb\nc\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest, benchmark_manifest=self.manifest))


if __name__ == "__main__":
    unittest.main()
