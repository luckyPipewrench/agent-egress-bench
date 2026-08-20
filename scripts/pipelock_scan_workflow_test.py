#!/usr/bin/env python3
"""Structural tests for the Pipelock secret-scan workflow.

Each assertion corresponds to a defect caught by a human reviewer rather than by
any check, which is why they are tests and not comments.

The scan workflow was rewritten on 2026-08-10 because the published Pipelock
action installs the latest RELEASE, and a scanner fix on Pipelock's default
branch does not reach a release for weeks. Whole-file-deletion hunk parsing was
fixed in pipelock#1145, which was absent from v3.3.0, so every pull request that
deleted a file failed with "unverifiable input: content outside unified diff
hunks" and the action surfaced that as "Secrets detected in PR diff" with no
secret present. That blocked #157 for a day.

These assertions target the EXECUTABLE path, never workflow prose. An earlier
version of this file searched the raw workflow text, which meant a file with two
no-op steps and the pinned revision sitting inside a COMMENT would have passed
every check while invoking no scanner at all. Review caught that. Matching on
step display names or on any occurrence of a command in the file is decoration:
the contract is the command that actually runs, reached through the parsed
event condition.
"""

import re
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "pipelock.yaml"

FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
SCAN_COMMAND = "pipelock git scan-diff"

# The two events that must each reach a scan, keyed by the condition the step
# is actually gated on rather than by its display name.
REQUIRED_EVENTS = {
    "pull_request": "github.event_name == 'pull_request'",
    "workflow_dispatch": "github.event_name == 'workflow_dispatch'",
}


def load_workflow():
    return yaml.safe_load(WORKFLOW.read_text())


def scan_job(workflow):
    jobs = workflow.get("jobs") or {}
    job = jobs.get("security-scan")
    if job is None:
        raise AssertionError(
            "no security-scan job; if the job was renamed, update this test rather than deleting it"
        )
    return job


def steps_running(job, needle):
    """Steps whose executed shell actually contains needle."""
    return [s for s in (job.get("steps") or []) if needle in (s.get("run") or "")]


class PipelockScanWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = load_workflow()
        self.job = scan_job(self.workflow)

    def test_both_events_reach_a_real_scan(self):
        """Each trigger must reach a step that actually runs the scanner.

        Promotion pull requests are created with GITHUB_TOKEN and do not emit a
        pull_request run, so the promotion workflow dispatches this one against
        the generated branch instead. Losing either path leaves a class of
        change entering main unscanned, and the loss is invisible because the
        surviving path still reports success.
        """
        triggers = self.workflow.get(True) or self.workflow.get("on") or {}
        for event in REQUIRED_EVENTS:
            self.assertIn(
                event,
                triggers,
                f"{event} trigger removed; that class of change would go unscanned",
            )

        scanning = steps_running(self.job, SCAN_COMMAND)
        self.assertTrue(
            scanning,
            f"no step actually runs {SCAN_COMMAND!r}; the job may look intact while scanning nothing",
        )

        conditions = [str(s.get("if") or "") for s in scanning]
        for event, condition in REQUIRED_EVENTS.items():
            self.assertTrue(
                any(condition in c for c in conditions),
                f"no scanning step is gated on {condition!r}; {event} would run the job without scanning",
            )

    def test_scanner_is_built_from_an_immutable_pinned_revision(self):
        """The executed install command must consume a pinned commit.

        Asserting that a 40-character SHA appears somewhere in the file is not
        enough: the real install could use a moving ref while an unrelated or
        commented value satisfies the pattern. The pin only counts if the
        command that installs the scanner consumes it.
        """
        installing = steps_running(self.job, "go install")
        self.assertTrue(installing, "no step installs the scanner")

        for step in installing:
            run = step["run"]
            env = step.get("env") or {}

            module_refs = re.findall(r"cmd/pipelock@(\S+)", run)
            self.assertTrue(
                module_refs,
                f"install command does not name a pipelock revision:\n  {run.strip()}",
            )

            for ref in module_refs:
                ref = ref.strip('"').strip("'")
                # The ref is normally an env expansion; resolve it before judging.
                expansion = re.fullmatch(r"\$\{?(\w+)\}?", ref)
                if expansion:
                    key = expansion.group(1)
                    self.assertIn(
                        key,
                        env,
                        f"install consumes ${key} but the step does not define it, so the pinned "
                        "revision cannot be verified here",
                    )
                    resolved = str(env[key]).strip()
                else:
                    resolved = ref

                self.assertRegex(
                    resolved,
                    FULL_SHA,
                    f"scanner installed from {resolved!r}; pin a full 40-character commit so a later "
                    "upstream commit cannot silently change or disable this gate",
                )

    def test_audit_config_producer_is_version_pinned(self):
        """The audit config must not drift ahead of the pinned scanner."""
        action_steps = [
            step
            for step in (self.job.get("steps") or [])
            if str(step.get("uses") or "").startswith("luckyPipewrench/pipelock@")
        ]
        self.assertEqual(1, len(action_steps), "expected one Pipelock action step")
        version = str((action_steps[0].get("with") or {}).get("version") or "")
        self.assertRegex(version, r"^\d+\.\d+\.\d+$", "pin the audit config producer to a stable release")
        self.assertNotEqual("latest", version, "a moving release can produce config the pinned scanner cannot parse")

    def test_scanned_diff_is_generated_with_text(self):
        """The diff feeding the scanner must be generated with --text.

        Without it a path marked binary by an in-repo .gitattributes reduces to
        a "Binary files differ" marker and its content is never scanned, so a
        credential can be added behind a one-line attributes rule.

        Only the diff that actually feeds the scanner is checked. Requiring
        every git diff in the file to carry --text would reject legitimate
        non-scanning uses such as `git diff --quiet`.
        """
        scanning = steps_running(self.job, SCAN_COMMAND)
        self.assertTrue(scanning, "no scanning step to check")

        for step in scanning:
            # Join continuations so a multi-line command is judged whole.
            run = re.sub(r"\\\s*\n\s*", " ", step["run"])
            diff_commands = [
                line.strip()
                for line in run.splitlines()
                if "git diff" in line and ">" in line
            ]
            self.assertTrue(
                diff_commands,
                f"scanning step {step.get('name')!r} does not generate a diff file it then scans",
            )
            for command in diff_commands:
                self.assertIn(
                    "--text",
                    command,
                    f"diff feeding the scanner is generated without --text:\n  {command}\n"
                    "an in-repo .gitattributes rule could hide added content from the scanner",
                )


if __name__ == "__main__":
    unittest.main()
