import importlib.util
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("check_case_immutability.py")
SPEC = importlib.util.spec_from_file_location("case_immutability", MODULE_PATH)
case_immutability = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(case_immutability)


class CaseImmutabilityTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.case_path = self.repo / "cases" / "url" / "immutable-case.json"
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://example.invalid"}})
        self.add_drift_case("mcp-drift-immutable")
        self.git("add", "cases")
        self.git("commit", "-qm", "base cases")
        self.base = self.git("rev-parse", "HEAD").decode().strip()

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, *args):
        environment = {
            **os.environ,
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
        }
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, env=environment
        ).stdout

    def write_json(self, path, value):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def add_drift_case(self, case_id):
        directory = self.repo / "cases" / "mcp-drift" / case_id
        directory.mkdir(parents=True)
        (directory / "case.yaml").write_text("schema_version: 1\n", encoding="utf-8")
        self.write_json(directory / "before.json", {"tools": []})
        self.write_json(directory / "after.json", {"tools": []})
        self.write_json(directory / "expected.json", {"version": 1})
        (directory / "notes.md").write_text("immutable notes\n", encoding="utf-8")

    def add_repair_record(self, case_id, path, base_raw, repaired_raw):
        digest = hashlib.sha256(repaired_raw).hexdigest()
        self.write_json(
            self.repo / "governance" / "case-repairs" / f"{case_id}-{digest[:12]}.repair.json",
            {
                "schema_version": 1,
                "case_id": case_id,
                "reason": "Correct the case transport without changing its security meaning.",
                "files": [
                    {
                        "path": path,
                        "base_sha256": hashlib.sha256(base_raw).hexdigest(),
                        "repaired_sha256": digest,
                    }
                ],
            },
        )

    def test_allows_unchanged_base_cases_and_new_ids(self):
        self.write_json(
            self.repo / "cases" / "url" / "new-case.json",
            {"id": "new-case", "payload": {"url": "https://new.example.invalid"}},
        )
        base, count, changed = case_immutability.check(self.repo, self.base)
        self.assertEqual(base, self.base)
        self.assertEqual(count, 2)
        self.assertEqual(changed, [])

    def test_rejects_rewritten_existing_case_bytes(self):
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://changed.example.invalid"}})
        with self.assertRaisesRegex(ValueError, "immutable-case: bytes changed"):
            case_immutability.check(self.repo, self.base)

    def test_rejects_added_file_inside_existing_mcp_drift_case(self):
        path = self.repo / "cases" / "mcp-drift" / "mcp-drift-immutable" / "added.json"
        self.write_json(path, {"unexpected": True})
        with self.assertRaisesRegex(ValueError, "mcp-drift-immutable: file inventory changed"):
            case_immutability.check(self.repo, self.base)

    def test_repair_override_is_deliberate_and_visible_to_the_caller(self):
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://changed.example.invalid"}})
        base, count, changed = case_immutability.check(self.repo, self.base, "repair: documented fixture correction")
        self.assertEqual(base, self.base)
        self.assertEqual(count, 2)
        self.assertEqual(len(changed), 1)
        with mock.patch.dict(
            os.environ,
            {
                case_immutability.OVERRIDE_ENV: case_immutability.OVERRIDE_TOKEN,
                case_immutability.OVERRIDE_REASON_ENV: "repair: documented fixture correction",
            },
            clear=True,
        ):
            self.assertEqual(
                case_immutability.override_from_environment(),
                "repair: documented fixture correction",
            )

    def test_accepts_new_hash_bound_repair_record(self):
        base_raw = self.case_path.read_bytes()
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://changed.example.invalid"}})
        self.add_repair_record(
            "immutable-case",
            "cases/url/immutable-case.json",
            base_raw,
            self.case_path.read_bytes(),
        )
        base, count, changed = case_immutability.check(self.repo, self.base)
        self.assertEqual(base, self.base)
        self.assertEqual(count, 2)
        self.assertEqual(len(changed), 1)

    def test_rejects_repair_record_when_repaired_hash_does_not_match(self):
        base_raw = self.case_path.read_bytes()
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://changed.example.invalid"}})
        self.add_repair_record(
            "immutable-case",
            "cases/url/immutable-case.json",
            base_raw,
            b"different repaired bytes",
        )
        with self.assertRaisesRegex(ValueError, "repair record hashes do not match"):
            case_immutability.check(self.repo, self.base)

    def test_cannot_reuse_a_repair_record_from_the_base(self):
        base_raw = self.case_path.read_bytes()
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://first-repair.example.invalid"}})
        self.add_repair_record(
            "immutable-case",
            "cases/url/immutable-case.json",
            base_raw,
            self.case_path.read_bytes(),
        )
        self.git("add", "cases", "governance")
        self.git("commit", "-qm", "first repair")
        repaired_base = self.git("rev-parse", "HEAD").decode().strip()
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://second-repair.example.invalid"}})
        with self.assertRaisesRegex(ValueError, "immutable case bytes changed"):
            case_immutability.check(self.repo, repaired_base)

    def test_rejects_symlinked_repair_record(self):
        base_raw = self.case_path.read_bytes()
        self.write_json(self.case_path, {"id": "immutable-case", "payload": {"url": "https://changed.example.invalid"}})
        self.add_repair_record(
            "immutable-case",
            "cases/url/immutable-case.json",
            base_raw,
            self.case_path.read_bytes(),
        )
        record = next((self.repo / "governance" / "case-repairs").iterdir())
        target = self.repo / "repair-target.json"
        record.rename(target)
        record.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "repair record must be a regular file"):
            case_immutability.check(self.repo, self.base)

    def test_override_requires_acknowledgement_and_reason(self):
        with mock.patch.dict(os.environ, {case_immutability.OVERRIDE_ENV: "yes"}, clear=True):
            with self.assertRaisesRegex(ValueError, "acknowledgement token"):
                case_immutability.override_from_environment()
        with mock.patch.dict(
            os.environ,
            {case_immutability.OVERRIDE_ENV: case_immutability.OVERRIDE_TOKEN},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "must name the documented repair"):
                case_immutability.override_from_environment()

    def test_rejects_missing_base_instead_of_passing(self):
        with self.assertRaisesRegex(ValueError, "base revision is required"):
            case_immutability.check(self.repo, "")

    def test_accepts_non_ascii_base_path(self):
        self.write_json(
            self.repo / "cases" / "url" / "caf\u00e9-case.json",
            {"id": "unicode-case", "payload": {"url": "https://unicode.example.invalid"}},
        )
        self.git("add", "cases")
        self.git("commit", "-qm", "add unicode fixture")
        base = self.git("rev-parse", "HEAD").decode().strip()

        resolved, count, changed = case_immutability.check(self.repo, base)
        self.assertEqual(base, resolved)
        self.assertEqual(3, count)
        self.assertEqual([], changed)


if __name__ == "__main__":
    unittest.main()
