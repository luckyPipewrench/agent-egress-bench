#!/usr/bin/env python3
"""Check the complete privileged caller shape and paired immutable source pins."""

import pathlib
import re
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/pr-review.yaml"
EXPECTED = """name: AI PR Review
on:
  issue_comment:
    types: [created]
permissions:
  contents: read
  issues: write
  pull-requests: write
jobs:
  review:
    if: >-
      github.actor == 'luckyPipewrench' &&
      github.triggering_actor == 'luckyPipewrench' &&
      github.event.comment.user.login == 'luckyPipewrench' &&
      github.event.comment.author_association == 'OWNER' &&
      github.event.issue.pull_request &&
      (github.event.comment.body == '/review' ||
       github.event.comment.body == '/review deep')
    uses: luckyPipewrench/pipelock/.github/workflows/pr-review-reusable.yaml@REVIEWER_SHA
    with:
      reviewer_sha: REVIEWER_SHA
      pr_number: ${{ github.event.issue.number }}
      review_mode: >-
        ${{ github.event.comment.body == '/review deep' && 'deep' ||
        'default' }}
    secrets:
      review_token: ${{ secrets.GITHUB_TOKEN }}
      openai_api_key: ${{ secrets.OPENAI_API_KEY }}"""


class ReviewCallerTest(unittest.TestCase):
    def test_caller_contract_and_matching_immutable_pins(self):
        """Reject caller structure drift and unequal or mutable source references."""
        text = WORKFLOW.read_text(encoding="utf-8")
        # Preserve indentation: changing YAML structure must not pass by
        # collapsing whitespace. Only empty lines and whole comments vary.
        text = "\n".join(
            line.rstrip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
        pins = re.findall(
            r"(?:pr-review-reusable\.yaml@|reviewer_sha: )([0-9a-f]{40})$", text, re.MULTILINE
        )
        self.assertEqual(len(pins), 2, "both source references must be full immutable SHAs")
        self.assertEqual(pins[0], pins[1], "workflow and checked-out source must agree")
        self.assertEqual(text.replace(pins[0], "REVIEWER_SHA"), EXPECTED)


if __name__ == "__main__":
    unittest.main()
