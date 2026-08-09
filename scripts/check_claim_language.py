#!/usr/bin/env python3
"""Fail the build when documentation makes a claim the method cannot support.

Three checks run together:

1. Banned claim terms. Certification, ranking, and absolute-security language
   must not appear in contributor-facing documentation. A line that needs the
   term (usually to forbid it) carries an inline ``<!-- claim-ok: reason -->``
   marker, so every exception is visible in review.
2. The definitions document. ``docs/RESULTS-USE.md`` must keep defining every
   assurance label and must keep granting permission to publish adverse
   results. Deleting either is the failure mode this check exists to catch.
3. Target review stays public and limited to setup. Documentation must not
   promise private notice or a prepublication result preview to a target.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# The definitions document names the terms it forbids, so the banned-term scan
# skips it. Its own required content is asserted separately below.
DEFINITIONS_DOC = Path("docs/RESULTS-USE.md")

SCAN_ROOTS = (
    Path("README.md"),
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("docs"),
    Path("examples"),
    Path("profiles"),
)

# CHANGELOG.md records history that predates this policy. Result records under
# gauntlet-site and the control-evidence conformance corpora are immutable
# evidence bytes and are never edited to satisfy a lint.
SKIP_PARTS = ("gauntlet-site", "control-evidence", "node_modules")

MARKER = re.compile(r"<!--\s*claim-ok:\s*\S+.*?-->")

BANNED = (
    (r"leaderboards?", "this repository publishes no ranking; describe the actual page"),
    (r"certif(?:ied|ication|ications|ies|y)", "a Gauntlet result is not a certification"),
    (r"proofstamp", "no third-party mark is required for a result to count"),
    (r"neutral benchmark", "say tool-neutral corpus; neutrality is a governance claim"),
    (r"proven secure", "a corpus proves containment of the cases it ran, nothing more"),
    (r"no bypass(?:es)?\b", "absence of bypasses is not observable from a passing run"),
    (r"unbypassable", "absence of bypasses is not observable from a passing run"),
    (r"insurance discount", "no insurer has priced this evidence"),
    (r"\bFIPS\b", "no module here is FIPS validated"),
    (r"all prox(?:y|ies)[- ]based", "proxy shapes differ; scope the claim to the profile"),
    (
        r"\bgive\s+(?:the\s+)?(?:maintainer|target|vendor)\s+notice\b",
        "publish setup for public correction; do not promise target-specific notice",
    ),
    (
        r"\b(?:offer|provide|grant|give)(?:ed|s)?\b[^\n]{0,80}"
        r"\b(?:private|pre[- ]publication)\b[^\n]{0,40}"
        r"\b(?:preview|review|notice)\b",
        "targets get no private or prepublication result review",
    ),
    (
        r"\b(?:private|pre[- ]publication)\b[^\n]{0,40}"
        r"\b(?:preview|review|notice)\b[^\n]{0,60}"
        r"\b(?:offered|provided|granted|given)\b",
        "targets get no private or prepublication result review",
    ),
    # The two patterns above only fire when the sentence's subject is the giver.
    # The prohibition is about a private preview EXISTING, so the same grant
    # written from the recipient's side slipped through: "A target may receive a
    # private prepublication result preview" passed clean. These cover that
    # direction. Verb enumeration is inherently incomplete, so a reviewer should
    # still read the section rather than trusting a green check here.
    (
        r"\b(?:receive|get|obtain|access|see|preview)(?:s|d|ed)?\b[^\n]{0,80}"
        r"\b(?:private|pre[- ]publication)\b[^\n]{0,40}"
        r"\b(?:preview|review|notice)\b",
        "targets get no private or prepublication result review",
    ),
    (
        r"\b(?:entitled\s+to|allowed\s+to|permitted\s+to|able\s+to|may|can)\b[^\n]{0,40}"
        r"\b(?:review|preview|see|inspect)\b[^\n]{0,60}"
        r"\bbefore\s+publication\b",
        "targets get no private or prepublication result review",
    ),
    (
        r"\b(?:private|pre[- ]publication)\b[^\n]{0,40}"
        r"\b(?:preview|review|notice)\b[^\n]{0,60}"
        r"\b(?:received|obtained|accessed)\b",
        "targets get no private or prepublication result review",
    ),
)

COMPILED = tuple((re.compile(pattern, re.IGNORECASE), reason) for pattern, reason in BANNED)

ADVERSE_SECTION = "Adverse results"
CONFIGURATION_SECTION = "Configuration verification"

REQUIRED_DEFINITIONS = (
    "Self-run",
    "Artifact-validated",
    "Independently executed",
    "Transparency-registered",
    "Challenge-verified",
)


def markdown_files(root: Path):
    """Yield markdown files under a configured scan root."""
    target = REPO_ROOT / root
    if target.is_file():
        candidates = [target]
    elif target.is_dir():
        candidates = sorted(target.rglob("*.md"))
    else:
        candidates = []
    for path in candidates:
        relative = path.relative_to(REPO_ROOT)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        if relative == DEFINITIONS_DOC:
            continue
        yield path


def scan_text(relative: Path, text: str):
    """Report banned claim terms in one document."""
    findings = []
    for number, line in enumerate(text.splitlines(), start=1):
        if MARKER.search(line):
            continue
        for pattern, reason in COMPILED:
            match = pattern.search(line)
            if match:
                findings.append(f"{relative}:{number}: {match.group(0)!r} {reason}")
    return findings


def section_text(text: str, heading: str):
    """Return the body of one level-two section, or None when it is absent."""
    body = []
    inside = False
    for line in text.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = line[3:].strip().lower() == heading.lower()
            continue
        if inside:
            body.append(line)
    return "\n".join(body) if inside or body else None


def check_definitions(text: str):
    """Report missing required content in the definitions document."""
    findings = []
    for label in REQUIRED_DEFINITIONS:
        if label not in text:
            findings.append(f"{DEFINITIONS_DOC}: missing the {label} assurance label")

    # The permission has to live in its own section. Matching the phrase anywhere
    # in the document would pass while the adverse-results section itself said
    # the opposite, which is the failure this gate exists to prevent.
    adverse = section_text(text, ADVERSE_SECTION)
    if adverse is None:
        findings.append(f"{DEFINITIONS_DOC}: missing the '{ADVERSE_SECTION}' section")
    else:
        collapsed = " ".join(adverse.split()).lower()
        granted = "may publish" in collapsed and "without notice, approval" in collapsed
        if not granted:
            findings.append(
                f"{DEFINITIONS_DOC}: the '{ADVERSE_SECTION}' section no longer grants "
                "permission to publish an adverse result without notice or approval"
            )

    configuration = section_text(text, CONFIGURATION_SECTION)
    if configuration is None:
        findings.append(f"{DEFINITIONS_DOC}: missing the '{CONFIGURATION_SECTION}' section")
    else:
        collapsed = " ".join(configuration.split()).lower()
        required = (
            "in public",
            "does not include case outcomes",
            "no private notice period",
            "no veto",
        )
        if any(phrase not in collapsed for phrase in required):
            findings.append(
                f"{DEFINITIONS_DOC}: the '{CONFIGURATION_SECTION}' section must keep "
                "setup review public, exclude outcomes, and deny private notice and veto rights"
            )
    return findings


def main():
    findings = []
    for root in SCAN_ROOTS:
        for path in markdown_files(root):
            findings.extend(
                scan_text(path.relative_to(REPO_ROOT), path.read_text(encoding="utf-8"))
            )

    definitions_path = REPO_ROOT / DEFINITIONS_DOC
    if not definitions_path.is_file():
        findings.append(f"{DEFINITIONS_DOC}: missing")
    else:
        findings.extend(check_definitions(definitions_path.read_text(encoding="utf-8")))

    if findings:
        print("check-claim-language: FAIL")
        for finding in findings:
            print(f"  {finding}")
        print("  fix the wording, or add an inline '<!-- claim-ok: reason -->' marker")
        return 1

    print("check-claim-language: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
