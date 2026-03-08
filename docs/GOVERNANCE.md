# Governance

How this corpus is maintained, how decisions are made, and how conflicts are handled.

## Neutrality

This corpus is tool-neutral. It was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author, but it is designed for any agent egress security tool. The repo does not produce rankings, leaderboards, scores, or "certified" badges. Each tool publishes its own results independently.

No case is written to favor or penalize a specific tool. Cases test observable behavior on the wire (did the request get blocked?), not implementation internals.

## Case ID immutability

Once a case ID is merged to `main`, it never changes. No renaming. No reassignment. A case ID is a permanent identifier. If a case needs to be superseded, create a new case with a new ID.

## Semantic stability

Existing case semantics do not change silently. This includes the expected verdict, capability tags, payload content, and the meaning of a case. If the attack surface evolves in a way that changes what the correct verdict should be, create a new case. If a verdict was wrong from the start, open an issue and discuss before changing it. Unannounced semantic changes break reproducibility for every tool that has already run against the corpus.

## Versioning

The spec uses `schema_version`. v1 is the current schema. Future versions are additive where possible: new fields are optional, new enum values extend existing lists. Breaking changes (removing fields, changing field semantics, altering scoring rules) increment the schema version. The validator enforces the active schema version.

## Contribution acceptance

Cases from any vendor, researcher, or individual are welcome. Every submitted case must include:

- **Rationale:** why this attack pattern matters
- **Expected verdict:** `block` or `allow`, with a `why_expected` explanation
- **Source:** where the attack pattern comes from (real-world incident, research paper, original creation)
- **False positive assessment:** likelihood of benign traffic matching this pattern

The [validator](../validate/) enforces structural correctness (valid JSON, required fields, correct enums, ID matching filename). Semantic review (is the expected verdict correct? is the attack realistic?) is manual and happens during PR review.

## Conflict of interest

The corpus maintainer also builds a competing tool ([Pipelock](https://github.com/luckyPipewrench/pipelock)). This is disclosed here and in the [README](../README.md). It is handled by:

1. **Tool-neutral case design.** Cases test observable behavior, not implementation details. A case asks "was this secret in the query string blocked?" not "did the tool use regex pattern X?"
2. **Reference, not privilege.** The [Pipelock runner](../examples/pipelock/) is a reference example showing how to build a runner. It has no special status. Any vendor can add a runner in `examples/`.
3. **Open contribution.** Any vendor or individual can submit cases, runners, or spec changes through the normal PR process.

## Appeals

If you disagree with a case's expected verdict, open a GitHub issue. Include:

- The case ID
- Your reasoning (why the verdict should be different)
- Evidence if available (real-world traffic patterns, false positive data, attack feasibility analysis)

Verdict changes require community discussion. They are not made unilaterally.

## Spec changes

Changes to [SPEC.md](SPEC.md), [SCORING.md](SCORING.md), or [RUNNER.md](RUNNER.md) require a PR with rationale explaining the change. The validator must be updated to match any spec changes. Discussion happens in the PR before merge. These documents define the contract between the corpus and every runner, so changes affect all downstream tools.
