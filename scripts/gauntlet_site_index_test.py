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
        self.assertIn("card.appendChild(window.renderGauntletFailures(r));", self.html)
        self.assertIn("card.appendChild(window.renderGauntletScope(r));", self.html)
        self.assertIn(
            "card.appendChild(window.renderGauntletControlCoverage(r));", self.html
        )
        self.assertIn('<script src="./scope-render.js"></script>', self.html)
        self.assertIn('<script src="./latest-result.js"></script>', self.html)
        self.assertNotIn("badge.textContent = 'verified';", self.html)

    def test_diagnostic_scope_describes_routed_cases_not_profile_claims(self):
        # The invariant is that scope comes from what the adapter did, never
        # from what the tool declared about itself. The wording says "routed"
        # rather than "delivered and observed" because case_count.applicable
        # includes rows that ended in error, which were routed but never
        # observed; describing those as observed overstates the exercised scope
        # in a buyer-facing report.
        self.assertIn(
            "cases this adapter routed, which includes any that ended in error",
            self.html,
        )
        self.assertNotIn("delivered and observed", self.html)
        self.assertNotIn("matching this tool\\u2019s declared capabilities", self.html)

    def test_current_scope_identity_matches_repository_versions(self):
        self.assertIn('data-corpus-version="v2.4.0"', self.html)
        self.assertIn('data-scoring-version="2.8"', self.html)


if __name__ == "__main__":
    unittest.main()
