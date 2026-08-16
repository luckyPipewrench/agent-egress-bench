#!/usr/bin/env python3
"""Tests for generated result-state bindings."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "generate_result_state_bindings", ROOT / "scripts" / "generate_result_state_bindings.py"
)
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class ResultStateBindingsTest(unittest.TestCase):
    def test_generated_files_match_contract(self):
        document = json.loads(generator.CONTRACT.read_text(encoding="utf-8"))
        for path, expected in generator.render(document).items():
            with self.subTest(path=path):
                self.assertEqual(expected, path.read_text(encoding="utf-8"))

    def test_new_state_changes_every_language_binding(self):
        document = json.loads(generator.CONTRACT.read_text(encoding="utf-8"))
        changed = copy.deepcopy(document)
        changed["evidence_result_states"]["new_state"] = "Test state."
        original = generator.render(document)
        updated = generator.render(changed)
        self.assertEqual(set(original), set(updated))
        for path in original:
            with self.subTest(path=path):
                self.assertNotEqual(original[path], updated[path])
                self.assertIn("new_state", updated[path])


if __name__ == "__main__":
    unittest.main()
