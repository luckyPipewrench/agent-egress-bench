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
        rows = [
            {"schema_version": 4, "case_id": "b", "tool": "tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "allow", "score": "pass", "evidence": {"result_state": "observed"}},
            {"schema_version": 4, "case_id": "a", "tool": "tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "error", "score": "error", "evidence": {"result_state": "delivery_unavailable"}},
        ]
        self.results.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def args(self, output, **updates):
        values = dict(
            results=self.results, output=output, corpus_sha256="a" * 64,
            comparison_id="round-2026-08-10-a",
            benchmark_manifest_sha256="b" * 64, tool="tool", tool_version="1.2.3",
            tool_profile_sha256="c" * 64, runner="aeb-gauntlet", runner_version="4",
            runtime="go1.25.10", os_name="linux", arch="amd64", concurrency=1,
            timeout_seconds=15.0, fixture_mode="local", network_mode="contained",
            nonce_hex="d" * 32,
        )
        values.update(updates)
        return Namespace(**values)

    def prepare(self, name="reveal.json", **updates):
        path = self.root / name
        if name != "reveal.json" and "nonce_hex" not in updates:
            updates["nonce_hex"] = "e" * 32
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner_parity.prepare(self.args(path, **updates))
        return path, output.getvalue().strip()

    def test_prepare_verify_and_compare(self):
        left, digest = self.prepare()
        reveal = json.loads(left.read_text(encoding="utf-8"))
        self.assertEqual(["a", "b"], [row["case_id"] for row in reveal["normalized_results"]])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner_parity.verify(Namespace(reveal=left, commitment_sha256=digest))
        self.assertEqual(digest, output.getvalue().strip())
        right, _ = self.prepare("right.json", runner="independent-runner")
        with contextlib.redirect_stdout(io.StringIO()):
            runner_parity.compare(Namespace(left=left, right=right))

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
            runner_parity.compare(Namespace(left=left, right=right))

    def test_mutating_result_after_commit_fails_closed(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["case_id"] = "aa"
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "does not match"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest))

    def test_mutating_environment_breaks_published_commitment(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["commitment"]["environment"]["concurrency"] = 8
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest))

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
            runner_parity.verify(Namespace(reveal=path, commitment_sha256="0" * 64))

    def test_compare_rejects_different_vectors(self):
        left, _ = self.prepare()
        rows = self.results.read_text(encoding="utf-8").replace('"actual_verdict": "allow", "score": "pass"', '"actual_verdict": "block", "score": "fail"')
        self.results.write_text(rows, encoding="utf-8")
        right, _ = self.prepare("right.json")
        with self.assertRaisesRegex(ValueError, "vectors differ"):
            runner_parity.compare(Namespace(left=left, right=right))

    def test_compare_rejects_same_reveal_or_nonce(self):
        left, _ = self.prepare()
        with self.assertRaisesRegex(ValueError, "distinct nonces"):
            runner_parity.compare(Namespace(left=left, right=left))

    def test_compare_rejects_different_rounds(self):
        left, _ = self.prepare()
        right, _ = self.prepare("right.json", comparison_id="another-round")
        with self.assertRaisesRegex(ValueError, "same comparison round"):
            runner_parity.compare(Namespace(left=left, right=right))

    def test_verify_rejects_laundered_result_semantics(self):
        path, digest = self.prepare()
        reveal = json.loads(path.read_text(encoding="utf-8"))
        reveal["normalized_results"][0]["result_state"] = "observed"
        path.write_text(json.dumps(reveal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inconsistent observed"):
            runner_parity.verify(Namespace(reveal=path, commitment_sha256=digest))


if __name__ == "__main__":
    unittest.main()
