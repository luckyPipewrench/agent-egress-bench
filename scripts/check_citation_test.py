#!/usr/bin/env python3
"""Regression tests for the citation author-identity check."""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent
spec = importlib.util.spec_from_file_location("check_citation", SCRIPTS / "check_citation.py")
check_citation = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["check_citation"] = check_citation
spec.loader.exec_module(check_citation)


PERSON = """cff-version: 1.2.0
title: fixture
message: "cite it"
type: dataset
authors:
  - given-names: Jane
    family-names: Doe
    alias: jdoe
"""

ENTITY = """cff-version: 1.2.0
title: fixture
message: "cite it"
type: dataset
authors:
  - name: Jane Doe
    alias: jdoe
"""


class CitationCheckTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, content):
        (self.root / "CITATION.cff").write_text(content, encoding="utf-8")

    def test_accepts_a_person(self):
        self.write(PERSON)
        self.assertEqual(1, check_citation.check(self.root))

    def test_rejects_the_entity_spelling_of_a_person(self):
        # The defect this exists for. Both spellings are valid CFF, so schema
        # validation passes either way and only this check tells them apart.
        self.write(ENTITY)
        with self.assertRaisesRegex(ValueError, "entity field 'name'"):
            check_citation.check(self.root)

    def test_rejects_an_author_without_family_names(self):
        self.write(
            "cff-version: 1.2.0\ntitle: fixture\nmessage: \"cite it\"\ntype: dataset\n"
            "authors:\n  - given-names: Jane\n"
        )
        with self.assertRaisesRegex(ValueError, "family-names"):
            check_citation.check(self.root)

    def test_rejects_a_file_with_no_authors(self):
        self.write("cff-version: 1.2.0\ntitle: fixture\nmessage: \"cite it\"\ntype: dataset\n")
        with self.assertRaisesRegex(ValueError, "no authors"):
            check_citation.check(self.root)

    def test_rejects_a_missing_file(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            check_citation.check(self.root)


if __name__ == "__main__":
    unittest.main()
