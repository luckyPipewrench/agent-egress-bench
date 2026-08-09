# Continuous Gauntlet Results

The Pipelock reference lane separates execution, review, and publication.

1. The read-only `Continuous Gauntlet` workflow runs the portable benchmark and retains a candidate evidence bundle.
2. A maintainer chooses a completed run in the `Prepare Gauntlet result promotion` workflow.
3. The promotion workflow downloads that exact bundle, recomputes its decision, and opens a pull request.
4. Merging the pull request is the repository publication approval. It adds an immutable record and advances `latest-verified`.

The scheduled workflow cannot write repository contents or open a pull request. A raw run never moves the committed pointer by itself. Candidate Actions artifacts are retained for 14 days, so a maintainer must prepare the promotion before that download window closes.

Daily runs do not create pull requests. The workflow summary says **PASS — NO ACTION REQUIRED** when the candidate matches the approved scope. Owner action is needed only when it says **REVIEW REQUIRED** for a scope or policy change, or **BLOCKED** for an incomplete or failed run.

Clean runs finish green. Review-required and blocked runs finish red so the Actions badge and normal failed-workflow notifications surface the action; the first line of the run summary distinguishes a review from a broken run. Email delivery still depends on the owner's GitHub notification settings.

## Append-only layout

Each approved candidate is stored at a digest-addressed path:

```text
gauntlet-site/results/pipelock/<candidate-sha256>/
```

The directory retains the exact finalized candidate, raw summary, per-case results, stderr, command, case index, corpus manifest, release identity, execution decision, source promotion decision, reviewed promotion decision, and a manifest that hashes every retained file.

`gauntlet-site/latest-verified.json` contains no score. It only identifies the selected immutable record and its digest. The repository includes a reference renderer that fetches the record manifest and candidate, verifies both SHA-256 digests in the browser, and renders containment together with applicable/total scope, N/A reasons, false-positive rate, and the original canonical run URL. The reference renderer is not the published pipelab.org page that carries the same first-party history. If the committed pointer exists but its manifest or record is missing, malformed, or digest-mismatched, the renderer fails closed instead of silently showing the legacy result.

Each record manifest hash-links its predecessor, and the selected pointer binds the head of that chain. Required validation checks the current chain and compares every previously committed record byte-for-byte with the pull request base, rejecting deletion, mutation, cycles, or unlinked records. The promotion command also refuses:

- a missing, partial, or publication-ineligible execution;
- evidence changed after the source decision;
- a source run from a different repository or workflow;
- a noncanonical pointer path;
- overwrite of an existing record;
- movement of `latest-verified` to an equal or older run;
- structural failures such as errors, incomplete measurement, or malformed provenance.

## Reviewable policy changes

A normal successful run can prepare a promotion pull request directly. A run that changed a score floor, false-positive ceiling, pinned Pipelock version, corpus identity, runner identity, or applicable/N/A scope remains blocked until the maintainer explicitly selects `accept_policy_change` in the manual promotion workflow.

That option does not change an incomplete execution into a measured one. It only permits the workflow to propose the exact score, version, identity, or scope change in a pull request. The candidate must still be fully measured, error-free, origin-bound, and hash-consistent. The pull request body lists the old-policy failures and the full new scope. Reviewers can merge or reject the proposal without changing the selected repository record.

Promotion branches are created with GitHub's workflow token, so the promotion workflow explicitly dispatches the repository's required validation workflows against the branch. Re-running a candidate that is already selected on `main` exits successfully without creating another branch or dispatching unnecessary checks. A second unmerged promotion may conflict with the first at the baseline and pointer. It must be regenerated from the newly merged baseline rather than bypassing the up-to-date branch requirement.

## Independent operators

The portable command is not tied to GitHub Actions:

```bash
./scripts/run-pipelock-gauntlet.sh
```

An independent lab can repeat that command with its own scheduler and retain the same portable bundle. Its platform supplies its own real artifact ID and HTTPS URL during finalization. Its publication policy remains independent from this repository's self-operated Pipelock lane. Matching the Pipelock release, corpus commit and digest, runner version, fixtures, and applicable/N/A denominator makes the two results directly reconcilable without pretending they share an operator.
