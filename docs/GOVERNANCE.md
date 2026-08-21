# Governance

How this corpus is maintained, how decisions are made, and how conflicts are handled.

## Neutrality

This corpus is tool-neutral. It was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author, but it is designed for any agent egress security tool. This repository publishes no ranking, leaderboard, or cross-tool comparison table, awards no badge, and certifies nothing. <!-- claim-ok: states the non-claim -->
Optional receipt profiles under `profiles/` are maintainer-published evidence artifacts, not corpus-issued endorsements. [RESULTS-USE.md](RESULTS-USE.md) defines the labels a publisher may use, the facts that travel with a public result, and the limits this policy places on the maintainer.

No case is written to favor or penalize a specific tool. Cases test observable behavior on the wire (did the request get blocked?), not implementation internals.

## Case ID immutability

Once a case ID is merged to `main`, it never changes. No renaming. No reassignment. A case ID is a permanent identifier. If a case needs to be superseded, create a new case with a new ID.

CI compares every file belonging to an existing case ID with the pull request merge base. It rejects changed, removed, or added files belonging to every existing case ID, including multi-file cases. New case IDs remain allowed, along with the generated manifest and stats changes that follow from adding them.

Only a genuine repository repair may bypass this check. A pull request must add a new record under `governance/case-repairs/` that names the case, explains the repair, and binds every changed file to its exact base and repaired SHA-256 digests. CI accepts the change only when that new record matches the complete case inventory and both versions of the bytes.

A maintainer may verify the same repair locally before its record exists by running the exact command below with a visible reason:

```bash
AEB_CASE_IMMUTABILITY_REPAIR=I_UNDERSTAND_CASE_IMMUTABILITY_REPAIR AEB_CASE_IMMUTABILITY_REASON='repair: exact fixture correction' make check-case-immutability
```

The gate prints `OVERRIDE ACTIVE` when it accepts the local override and `REPAIR RECORD ACTIVE` when it verifies a tracked record. CI must never set the environment override.

## Semantic stability

Existing case semantics do not change silently. This includes the expected verdict, capability tags, payload content, and the meaning of a case. If the attack surface evolves in a way that changes what the correct verdict should be, create a new case. If a verdict was wrong from the start, open an issue and discuss before changing it. Unannounced semantic changes break reproducibility for every tool that has already run against the corpus.

## Supersession

The optional `supersedes` field records that one case replaces another case's semantics. It is
relationship metadata, not a loader instruction. The original case remains in the corpus and the
runner executes both cases.

Removing a superseded case from an active score would change the denominator. No mutable skip list
may do that. A future active-set mechanism must be immutable, versioned, and bound to the release it
changes before a runner may exclude any case.

## Per-case governance decision records

Each logical case has one decision record at `governance/case-decisions/<case-id>.decision.json`, validated against [`case-governance-decision-v1`](../schemas/case-governance-decision-v1.schema.json). It binds the exact immutable case source files to the case ID and copies the existing description, expected verdict, `why_expected`, source, false-positive assessment, and supersession state. Its contents don't create new rationale or alter a case.

`make check-case-governance` requires one valid record for every logical case and rejects missing, malformed, extra, unreadable, or case-inconsistent records, along with a case that supersedes itself, supersedes an unknown case, or takes part in a supersession cycle.

## Versioning and compatibility

### The short version

Ask one question about any proposed change:

> Could an artifact someone already saved still be read, verified, and scored the same way afterward?

Yes, so amend that family in place and leave its version alone. No, so bump that one family and keep its old reader working. The rest of this section is that question stated precisely, plus what freezing means.

Two things follow that are easy to get backwards. A version number belongs to ONE family, so bumping result rows does not move cases, profiles, or anything else; the writer constants are per family and `runner/schema_version_contract_test.go` fails if any of them disagrees with the manifest. And a high version number is not evidence of churn, because these numbers were assigned when versioned filenames were adopted rather than earned one release at a time.

Each artifact family has its own version. Cases, result rows, tool profiles, receipt profiles, summaries, provenance candidates, case indexes, promotion records, baselines, and Control Evidence documents do not become compatible because two version numbers happen to match. The machine-readable [`contracts/artifacts.json`](../contracts/artifacts.json) manifest names each active writer, accepted reader, frozen version, schema, and gate.

An active schema may change in place only when every existing artifact that declares that version remains valid with the same meaning and score. Clarifications, schema corrections that change no accepted instance, and optional fields with a documented behavior-preserving default can qualify. This rule never permits a change to an existing case ID, payload, expected verdict, capability tags, or semantics.

A version bump is required if a change does any of the following:

- rejects a previously valid artifact or accepts it with a different meaning
- changes a result, denominator, security interpretation, provenance interpretation, required field after an artifact declares that version, enum meaning, delivery rule, observation rule, or published-record verification rule

Internal code changes still require a bump when they produce one of those effects.

A version freezes when the repository commits an immutable public record that declares it. Frozen readers keep that version's exact behavior. A new reader may support a new version, but it must not normalize old bytes into the new definition. Case semantics freeze per case when the case reaches `main`, independent of the artifact-family version.

Retained v1 and v2 evidence records are frozen. The v4 case and tool-profile formats remain active. Receipt profiles write v5 and retain v1, v3, and v4 readers. Result rows and summaries write v5 and retain their frozen v4 readers. Provenance candidates write v6 while retaining their v5 reader. A local v5 summary may omit publication provenance, but a v6 provenance candidate can't cross the promotion boundary without the method repository and commit, adapter identity and owner, and target configuration reference and digest. Promotion baselines remain on v1 because v6 candidates still carry v5 summary and scoring semantics.

Every active profile and result binds an immutable capability-registry snapshot by ID, format, revision, and raw-byte SHA-256. Adding or deprecating a reporting label creates a registry revision, not an artifact schema bump.

### Compatibility matrix

The table summarizes the manifest. `make check-contracts` checks the full machine-readable inventory against schema files, `$id` values, Go constants, and retained public records.

| Family | Active writer | Accepted readers | Frozen | Canonical schema |
| --- | ---: | --- | --- | --- |
| Case and multi-file case | 4 | 4 | none | [`case-v4.schema.json`](../schemas/case-v4.schema.json), with the multi-file shape enforced in Go |
| Case governance decision | 1 | 1 | none | [`case-governance-decision-v1.schema.json`](../schemas/case-governance-decision-v1.schema.json) |
| Result row | 5 | 4, 5 | 4 | [`result-v5.schema.json`](../schemas/result-v5.schema.json) |
| Tool profile | 4 | 1, 3, 4 | 1, 3 | [`tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json) |
| Receipt-scoring profile | 5 | 1, 3, 4, 5 | 1, 3, 4 | [`receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json) |
| Summary | 5 | 4, 5 | 4 | [`summary-v5.schema.json`](../schemas/summary-v5.schema.json) |
| Provenance candidate | 6 | 1, 2, 4, 5, 6 | 1, 2, 5 | [`provenance-candidate-v6.schema.json`](../schemas/provenance-candidate-v6.schema.json) |
| Case index | 3 | 1, 2, 3 | 1, 2 | [`case-index-v3.schema.json`](../schemas/case-index-v3.schema.json) |
| Promoted record | 2 | 1, 2 | 1 | [`promoted-record-v2.schema.json`](../schemas/promoted-record-v2.schema.json) |
| Promotion baseline | 1 | 1 | 1 | [`promotion-baseline-v1.schema.json`](../schemas/promotion-baseline-v1.schema.json) |

Every versioned schema has an explicit `-vN` filename and matching `$id`. Result rows and summaries retain frozen v4 beside active v5. Provenance candidates retain every accepted version beside active v6. A path can't silently retarget a historical contract, and the repository provides no unsuffixed compatibility aliases.

The summary stays on v5 because it already has optional fields for the publication facts. Provenance candidate v6 makes those fields mandatory and verifies them before publication. Keeping the requirement in that artifact family avoids changing the local-run summary or the promotion baseline when their meaning hasn't changed.

## Contribution acceptance

Cases from any vendor, researcher, or individual are welcome. Every submitted case must include:

- **Rationale:** why this attack pattern matters
- **Expected verdict:** `block` or `allow`, with a `why_expected` explanation
- **Source:** where the attack pattern comes from (real-world incident, research paper, original creation)
- **False positive assessment:** likelihood of benign traffic matching this pattern
- **Synthetic fixtures:** credentials and secrets must be fake and unmistakably test-only

The [validator](../validate/) enforces structural correctness (valid JSON, required fields, correct enums, ID matching filename). Semantic review (is the expected verdict correct? is the attack realistic?) is manual and happens during PR review.

## Conflict of interest

The corpus maintainer also builds a competing tool ([Pipelock](https://github.com/luckyPipewrench/pipelock)). This is disclosed here and in the [README](../README.md). It is handled by:

1. **Tool-neutral case design.** Cases test observable behavior, not implementation details. A case asks "was this secret in the query string blocked?" not "did the tool use regex pattern X?"
2. **Reference, not privilege.** The [Pipelock runner](../examples/pipelock/) is a reference example showing how to build a runner. It has no special status. Any vendor can add a runner in `examples/`.
3. **Open contribution.** Any vendor or individual can submit cases, runners, or spec changes through the normal PR process.

## Appeals

If you disagree with a case's expected verdict, open a GitHub Issue. Include:

- The case ID
- Your reasoning (why the verdict should be different)
- Evidence if available (real-world traffic patterns, false positive data, attack feasibility analysis)

Verdict changes require community discussion. They are not made unilaterally.

Use a GitHub Discussion instead when the disagreement is about scoring, adapter or method application, or a published result that appears to misstate the method. [`RESULTS-USE.md`](RESULTS-USE.md) defines that result-correction path.

## Spec changes

Changes to [SPEC.md](SPEC.md), [gauntlet.md](gauntlet.md), or [RUNNER.md](RUNNER.md) require a PR with rationale explaining the change. The validator must be updated to match any spec changes. Discussion happens in the PR before merge. These documents define the contract between the corpus and every runner, so changes affect all downstream tools.
