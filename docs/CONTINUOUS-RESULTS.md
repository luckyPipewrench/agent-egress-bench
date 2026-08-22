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

`gauntlet-site/latest-verified.json` contains no score. It identifies the selected immutable record, its digest, and the publisher-declared `self-run` and `artifact-validated` assurances. The reference renderer hash-checks the record, per-case rows, case index, and corpus manifest in the browser. It shows failed case IDs and their expected and observed verdicts before containment, applicable/total scope, N/A reasons, false-positive rate, and the original canonical run URL. The reference renderer is not the published pipelab.org page that carries the same first-party history. If a required file is missing, malformed, or digest-mismatched, the renderer fails closed instead of silently showing the legacy result.

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

## Promotion operator checklist

Treat the generated pull request as a proposal that still needs proof before merge.

1. Confirm the source run used the intended release and finished with a measured result, zero execution errors, and the expected corpus scope.
2. Read the generated baseline, reviewed decision, record manifest, and `latest-verified` change. Their candidate digest, artifact identity, tool version, corpus commit, and case counts must agree.
3. Check every dispatched validation workflow. GitHub may mark pull-request workflows as `action_required` when a workflow-token branch needs approval, so inspect the separately dispatched runs too. A failed dispatched run still blocks the promotion even when the pull request shows only the checks GitHub attached to it.
4. Run `make preflight` from the promotion branch. A new retained evidence bundle may introduce schema versions that aren't listed under `retained_public_records.frozen_readers` in `contracts/artifacts.json`. Add a reader only after the named validators accept that version. Tests for versioned promoted records must resolve the schema through `scripts/artifact_contracts.py`; they must not hardcode the oldest schema.
5. Merge only after the append-only record checks, compatibility checks, and review are clean. Record the resulting `main` commit because downstream consumers must pin the merged commit, not the source-run commit or the promotion branch head.

After merge, any Pipelock-hosted rerun and the pipelab.org importer must use that exact benchmark commit. The hosted workflow must fetch `origin/main` before running the pinned detached commit so the benchmark can prove the commit belongs to the canonical history. The website can publish the result only after its importer verifies the same benchmark commit, candidate digest, and hosted-run identity.

## Independent operators

The portable command is not tied to GitHub Actions:

```bash
./scripts/run-pipelock-gauntlet.sh
```

An independent lab can repeat that command with its own scheduler and retain the same portable bundle. Its platform supplies its own real artifact ID and HTTPS URL during finalization. Its publication policy remains independent from this repository's self-operated Pipelock lane. Matching the Pipelock release, corpus commit and digest, runner version, fixtures, and applicable/N/A denominator makes the two results directly reconcilable without pretending they share an operator.

An operator calling its program continuous declares the publication selection rule before execution, keeps each completed scored result in scope, and shows the run date beside every displayed score. Superseding records link to retained predecessors. An error, incomplete measurement, or unknown state stays visibly non-successful instead of leaving the last successful result looking current. The neutral publication lockup described in [RESULTS-USE.md](RESULTS-USE.md) makes the reproducibility facts portable across the operator's report, badge data, website, and social presentation without transferring ownership of the method or the operator's brand.
