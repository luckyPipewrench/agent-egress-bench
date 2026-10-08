#!/usr/bin/env python3
"""Check the complete privileged caller shape and paired immutable source pins."""

import os
import pathlib
import re
import stat
import tempfile
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
        text = read_workflow(WORKFLOW)
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
        self.assertEqual(pins[0], REVIEWER_SHA, "caller must use the tested reviewer revision")
        self.assertEqual(text.replace(pins[0], "REVIEWER_SHA"), EXPECTED)

EXPECTED_CONTRACT = r"""name: Review caller contract

on:
  pull_request_target:
    types: [opened, synchronize, reopened]
    paths:
      - '.github/workflows/pr-review.yaml'
      - '.github/workflows/review-caller-contract.yaml'
      - 'scripts/test_pr_review_workflow.py'
  push:
    branches: [main]
    paths:
      - '.github/workflows/pr-review.yaml'
      - '.github/workflows/review-caller-contract.yaml'
      - 'scripts/test_pr_review_workflow.py'

permissions:
  contents: read

jobs:
  contract:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - name: Check out immutable caller validator
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: luckyPipewrench/agent-egress-bench
          ref: VALIDATOR_SHA
          path: trusted-validator
          persist-credentials: false
          sparse-checkout: scripts/test_pr_review_workflow.py
          sparse-checkout-cone-mode: false
      - name: Check out proposed caller as data
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name || github.repository }}
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
          # Proposed workflows are bounded data; no proposed code is executed.
          allow-unsafe-pr-checkout: true
          path: proposed
          persist-credentials: false
          filter: blob:none
          sparse-checkout: |
            .github/workflows/pr-review.yaml
            .github/workflows/review-caller-contract.yaml
          sparse-checkout-cone-mode: false
      - name: Validate proposed caller with immutable test code
        run: |
          python3 -I - <<'PY'
          import importlib.util
          import pathlib
          import subprocess
          import unittest

          validator = pathlib.Path("trusted-validator/scripts/test_pr_review_workflow.py")
          spec = importlib.util.spec_from_file_location("trusted_caller", validator)
          module = importlib.util.module_from_spec(spec)
          spec.loader.exec_module(module)
          validator_sha = subprocess.check_output(
              ["git", "-C", "trusted-validator", "rev-parse", "HEAD"], text=True
          ).strip()
          module.validate_contract(
              pathlib.Path("proposed/.github/workflows/review-caller-contract.yaml"),
              validator_sha,
          )
          module.WORKFLOW = pathlib.Path("proposed/.github/workflows/pr-review.yaml")
          suite = unittest.defaultTestLoader.loadTestsFromModule(module)
          result = unittest.TextTestRunner(verbosity=2).run(suite)
          raise SystemExit(not result.wasSuccessful())
          PY
      - name: Check out immutable reviewer and its security tests
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
        with:
          repository: luckyPipewrench/pipelock
          ref: 3e8534e0dd621c62879238cc01d56f7e58e9d096
          path: trusted-reviewer
          persist-credentials: false
      - name: Install pinned reviewer test dependencies
        working-directory: trusted-reviewer
        run: |
          python3 -m venv .review-test-venv
          .review-test-venv/bin/python -m pip install --require-hashes \
            -r .github/actions/pr-review/requirements.txt \
            -r .github/requirements-pr-review-test.txt
      - name: Verify shared reviewer workflow protections
        working-directory: trusted-reviewer
        run: >-
          .review-test-venv/bin/python -m unittest
          scripts.pr_review_test.WorkflowPackagingTest
          scripts.pr_review_test.FailureDirectionTest.test_review_job_timeout_exceeds_the_wall_clock_with_finalization_margin
"""

MAX_WORKFLOW_BYTES = 65536
REVIEWER_SHA = "3e8534e0dd621c62879238cc01d56f7e58e9d096"


def normalized(text):
    """Allow comments and empty lines without erasing YAML indentation."""
    return "\n".join(line.rstrip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


def read_workflow(path):
    """Read bounded UTF-8 data without following any path-component symlink."""
    path = pathlib.Path(path)
    if ".." in path.parts:
        raise ValueError("workflow path must not traverse parents")
    parts = path.parts[1:] if path.is_absolute() else path.parts
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor if path.is_absolute() else ".", directory_flags)
    try:
        for part in parts[:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_WORKFLOW_BYTES:
                raise ValueError("workflow must be a bounded regular file")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(MAX_WORKFLOW_BYTES + 1)
            if len(data) > MAX_WORKFLOW_BYTES:
                raise ValueError("workflow exceeds the data limit")
            return data.decode("utf-8")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def validate_contract(path, validator_sha):
    """Reject changes to the immutable contract except its approved source pin."""
    if not re.fullmatch(r"[0-9a-f]{40}", validator_sha):
        raise ValueError("validator must have an immutable revision")
    expected = EXPECTED_CONTRACT.replace("VALIDATOR_SHA", validator_sha)
    if normalized(read_workflow(path)) != normalized(expected):
        raise ValueError("proposed contract differs from its trusted definition")


class WorkflowInputTest(unittest.TestCase):
    def test_bounded_regular_utf8_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "caller.yaml"
            path.write_text("name: caller\n", encoding="utf-8")
            self.assertEqual(read_workflow(path), "name: caller\n")
            path.write_bytes(b"x" * (MAX_WORKFLOW_BYTES + 1))
            with self.assertRaises(ValueError):
                read_workflow(path)
            path.write_bytes(b"\xff")
            with self.assertRaises(UnicodeError):
                read_workflow(path)

    def test_symlink_and_symlink_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            directory = root / "outside"
            directory.mkdir()
            path = directory / "caller.yaml"
            path.write_text("outside sentinel", encoding="utf-8")
            link = root / "caller.yaml"
            link.symlink_to(path)
            parent = root / "proposed"
            parent.symlink_to(directory, target_is_directory=True)
            for candidate in [link, parent / "caller.yaml"]:
                with self.subTest(path=candidate), self.assertRaises(OSError):
                    read_workflow(candidate)

    def test_fifo_and_parent_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "caller.yaml"
            os.mkfifo(path)
            with self.assertRaises(ValueError):
                read_workflow(path)
            with self.assertRaises(ValueError):
                read_workflow(path.parent / ".." / "caller.yaml")

    def test_contract_changes_are_rejected(self):
        revision = "0123456789abcdef0123456789abcdef01234567"
        expected = EXPECTED_CONTRACT.replace("VALIDATOR_SHA", revision)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "contract.yaml"
            path.write_text(expected, encoding="utf-8")
            validate_contract(path, revision)
            mutations = [
                expected.replace("contents: read", "contents: write"),
                expected.replace("module.validate_contract(", "module.skip_contract("),
                expected.replace("--require-hashes", "--no-deps"),
                expected.replace("WorkflowPackagingTest", "MissingProtectionTest"),
                expected.replace(revision, "main"),
                expected.replace(REVIEWER_SHA, revision),
            ]
            for text in mutations:
                with self.subTest(text=text[:30]):
                    self.assertNotEqual(text, expected)
                    path.write_text(text, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        validate_contract(path, revision)


if __name__ == "__main__":
    unittest.main()
