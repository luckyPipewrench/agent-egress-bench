#!/usr/bin/env python3
"""Structural tests for pointer-first Gauntlet result rendering."""

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX = REPO_ROOT / "gauntlet-site" / "index.html"


class GauntletSiteIndexTest(unittest.TestCase):
    def setUp(self):
        self.html = INDEX.read_text(encoding="utf-8")

    def test_verified_pointer_loads_before_legacy_result(self):
        latest = self.html.index("window.loadLatestVerifiedResult(")
        legacy = self.html.index("function loadLegacyResult()")
        self.assertLess(legacy, latest)
        self.assertIn(
            "if (err.status === 404 && err.resource === 'pointer') return loadLegacyResult();",
            self.html,
        )
        self.assertNotIn("catch(function() { return loadLegacyResult();", self.html)

    def test_verified_scope_is_rendered_as_one_validated_block(self):
        self.assertIn("card.appendChild(window.renderGauntletScope(r));", self.html)
        self.assertIn('<script src="./scope-render.js"></script>', self.html)
        self.assertIn('<script src="./latest-result.js"></script>', self.html)

    def test_diagnostic_scope_describes_observed_delivery_not_profile_claims(self):
        self.assertIn(
            "cases this adapter delivered and observed, not the complete corpus.",
            self.html,
        )
        self.assertNotIn("matching this tool\\u2019s declared capabilities", self.html)

    def test_current_scope_identity_matches_repository_versions(self):
        self.assertIn('data-corpus-version="v2.3.0"', self.html)
        self.assertIn('data-scoring-version="2.4"', self.html)


if __name__ == "__main__":
    unittest.main()
