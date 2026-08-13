#!/usr/bin/env python3
"""Tests for the historical Pipelock result migration inventory."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("validate_pipelock_result_inventory.py")
SPEC = importlib.util.spec_from_file_location("inventory", MODULE_PATH)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pipelock-result-inventory-")
        self.root = Path(self.temporary.name)
        paths = [
            Path("gauntlet-site/gauntlet-results.json"),
            Path("gauntlet-site/latest-verified.json"),
            Path("gauntlet-site/results/pipelock/digest/record-manifest.json"),
        ]
        for index, path in enumerate(paths):
            absolute = self.root / path
            absolute.parent.mkdir(parents=True, exist_ok=True)
            absolute.write_text(json.dumps({"value": index}) + "\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Test"], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.email", "test@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "fixture"], check=True)
        self.inventory_path = self.root / "migration/inventory.json"
        self.inventory_path.parent.mkdir()
        self.write_inventory(inventory.build_inventory(self.root))

    def tearDown(self):
        self.temporary.cleanup()

    def write_inventory(self, value):
        self.inventory_path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def load_inventory(self):
        return json.loads(self.inventory_path.read_text(encoding="utf-8"))

    def validate(self):
        inventory.validate(self.root, self.inventory_path, verify_records=False)

    def test_accepts_complete_inventory(self):
        self.validate()

    def test_rejects_changed_source_bytes(self):
        original = self.load_inventory()
        source = self.root / "gauntlet-site/latest-verified.json"
        source.write_text('{"changed":true}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", source.relative_to(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "change bytes"], check=True)
        value = inventory.build_inventory(self.root)
        stale = next(
            entry
            for entry in original["entries"]
            if entry["source_path"] == source.relative_to(self.root).as_posix()
        )
        value["entries"] = [
            stale if entry["source_path"] == stale["source_path"] else entry
            for entry in value["entries"]
        ]
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "drifted from source bytes"):
            self.validate()

    def test_rejects_unlisted_record_file(self):
        extra = self.root / "gauntlet-site/results/pipelock/digest/new-evidence.json"
        extra.write_text("{}\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", extra.relative_to(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "add evidence"], check=True)
        value = inventory.build_inventory(self.root)
        value["entries"] = [
            entry
            for entry in value["entries"]
            if entry["source_path"] != extra.relative_to(self.root).as_posix()
        ]
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "path set differs"):
            self.validate()

    def test_allows_newer_records_outside_the_historical_snapshot(self):
        extra = self.root / "gauntlet-site/results/pipelock/new-digest/record-manifest.json"
        extra.parent.mkdir()
        extra.write_text("{}\n", encoding="utf-8")
        self.validate()

    def test_allows_live_pointer_to_advance_after_the_snapshot(self):
        source = self.root / "gauntlet-site/latest-verified.json"
        source.write_text('{"new_pointer":true}\n', encoding="utf-8")
        self.validate()

    def test_rejects_entry_removed_from_inventory(self):
        value = self.load_inventory()
        value["entries"].pop()
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "path set differs"):
            self.validate()

    def test_rejects_source_commit_that_does_not_own_bytes(self):
        value = self.load_inventory()
        value["source_commit"] = "0" * 40
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "must resolve to a commit object"):
            self.validate()

    def test_rejects_tree_object_as_source_commit(self):
        value = self.load_inventory()
        value["source_commit"] = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD^{tree}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "must resolve to a commit object"):
            self.validate()

    def test_rejects_missing_result_tree_at_source_commit(self):
        value = self.load_inventory()
        record = self.root / "gauntlet-site/results/pipelock/digest/record-manifest.json"
        record.unlink()
        subprocess.run(["git", "-C", str(self.root), "add", "-u"], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "remove records"], check=True)
        value["source_commit"] = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "must resolve to a tree"):
            self.validate()

    def test_rejects_symlinked_record_in_source_commit(self):
        value = self.load_inventory()
        record = self.root / "gauntlet-site/results/pipelock/digest/record-manifest.json"
        record.unlink()
        record.symlink_to("../../../latest-verified.json")
        subprocess.run(["git", "-C", str(self.root), "add", record.relative_to(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "commit", "-qm", "replace with symlink"], check=True)
        value["source_commit"] = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "must be a regular file at source_commit"):
            self.validate()

    def test_rejects_non_hex_source_commit(self):
        value = self.load_inventory()
        value["source_commit"] = "z" * 40
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "full Git commit"):
            self.validate()

    def test_rejects_reordered_entries(self):
        value = self.load_inventory()
        value["entries"].reverse()
        self.write_inventory(value)
        with self.assertRaisesRegex(ValueError, "unique and sorted"):
            self.validate()

    def test_rejects_symlinked_record(self):
        source = self.root / "gauntlet-site/results/pipelock/digest/record-manifest.json"
        source.unlink()
        source.symlink_to(self.root / "gauntlet-site/latest-verified.json")
        with self.assertRaisesRegex(ValueError, "missing or not a regular file"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
