# Governance

How this corpus is maintained, how decisions are made, and how conflicts are handled.

## Neutrality

This corpus is tool-neutral. It was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author, but it is designed for any agent egress security tool. This repository publishes no ranking, leaderboard, or cross-tool comparison table, awards no badge, and certifies nothing. <!-- claim-ok: states the non-claim -->
Optional receipt profiles under `profiles/` are maintainer-published evidence artifacts, not corpus-issued endorsements. [RESULTS-USE.md](RESULTS-USE.md) defines the labels a publisher may use, the facts that travel with a public result, and the limits this policy places on the maintainer.

No case is written to favor or penalize a specific tool. Cases test observable behavior on the wire (did the request get blocked?), not implementation internals.

## Case ID immutability

Once a case ID is merged to `main`, it never changes. No renaming. No reassignment. A case ID is a permanent identifier. If a case needs to be superseded, create a new case with a new ID.

## Semantic stability

Existing case semantics do not change silently. This includes the expected verdict, capability tags, payload content, and the meaning of a case. If the attack surface evolves in a way that changes what the correct verdict should be, create a new case. If a verdict was wrong from the start, open an issue and discuss before changing it. Unannounced semantic changes break reproducibility for every tool that has already run against the corpus.

## Supersession

The optional `supersedes` field records that one case replaces another case's semantics. It is
relationship metadata, not a loader instruction. The original case remains in the corpus and the
runner executes both cases.

Removing a superseded case from an active score would change the denominator. No mutable skip list
may do that. A future active-set mechanism must be immutable, versioned, and bound to the release it
changes before a runner may exclude any case.

## Versioning and compatibility

Each artifact family has its own version. Cases, result rows, tool profiles, receipt profiles, summaries, provenance candidates, case indexes, promotion records, baselines, and Control Evidence documents do not become compatible because two version numbers happen to match. The machine-readable [`contracts/artifacts.json`](../contracts/artifacts.json) manifest names each active writer, accepted reader, frozen version, schema, and gate.

An active schema may change in place only when every existing artifact that declares that version remains valid with the same meaning and score. Clarifications, schema corrections that change no accepted instance, and optional fields with a documented behavior-preserving default can qualify. This rule never permits a change to an existing case ID, payload, expected verdict, capability tags, or semantics.

A version bump is required if a change does any of the following:

- rejects a previously valid artifact or accepts it with a different meaning
- changes a result, denominator, security interpretation, provenance interpretation, required field, enum meaning, delivery rule, observation rule, or published-record verification rule

Internal code changes still require a bump when they produce one of those effects.

A version freezes when the repository commits an immutable public record that declares it. Frozen readers keep that version's exact behavior. A new reader may support a new version, but it must not normalize old bytes into the new definition. Case semantics freeze per case when the case reaches `main`, independent of the artifact-family version.

Retained v1 and v2 evidence records are frozen. The v4 case, profile, result-row, and receipt-profile formats and the v5 summary and provenance formats are active. No promoted record uses the v4 or v5 formats yet. The first promoted record in either active generation freezes the contracts it carries.

Every active profile and result binds an immutable capability-registry snapshot by ID, format, revision, and raw-byte SHA-256. Adding or deprecating a reporting label creates a registry revision, not an artifact schema bump.

### Compatibility matrix

The table summarizes the manifest. `make check-contracts` checks the full machine-readable inventory against schema files, `$id` values, Go constants, and retained public records.

| Family | Active writer | Accepted readers | Frozen | Canonical schema |
| --- | ---: | --- | --- | --- |
| Case and multi-file case | 4 | 4 | none | [`case.schema.json`](../schemas/case.schema.json), with the multi-file shape enforced in Go |
| Result row | 4 | 4 | none | [`result.schema.json`](../schemas/result.schema.json) |
| Tool profile | 4 | 1, 3, 4 | 1, 3 | [`tool-profile.schema.json`](../schemas/tool-profile.schema.json) |
| Receipt-scoring profile | 4 | 1, 4 | 1 | [`receipt-scoring-profile.schema.json`](../schemas/receipt-scoring-profile.schema.json) |
| Summary | 5 | 4, 5 | 4 | [`summary-v5.schema.json`](../schemas/summary-v5.schema.json) |
| Provenance candidate | 5 | 1, 2, 4, 5 | 1, 2 | Python reader, no JSON Schema |
| Case index, promoted record, baseline | 1 | 1 | 1 | Go or Python reader, no JSON Schema |

The current schema filenames are transitional. The summary family uses an unsuffixed frozen v4 file while the tool-profile family uses an unsuffixed active v4 file. The manifest records those paths so edits cannot land on the wrong generation without failing the gate. Schema renames and `$id` changes remain deferred until the owner decides whether unsuffixed public URLs become compatibility aliases.

A proposed change to the active v5 summary, including the work tracked in pull request 153, may amend v5 only if every existing v5 artifact keeps the same accepted meaning, score, and verification result. Any change to those outcomes requires a new version. The owner must classify that change before publication; this policy does not decide the facts of that pull request.

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

If you disagree with a case's expected verdict, open a GitHub issue. Include:

- The case ID
- Your reasoning (why the verdict should be different)
- Evidence if available (real-world traffic patterns, false positive data, attack feasibility analysis)

Verdict changes require community discussion. They are not made unilaterally.

## Spec changes

Changes to [SPEC.md](SPEC.md), [gauntlet.md](gauntlet.md), or [RUNNER.md](RUNNER.md) require a PR with rationale explaining the change. The validator must be updated to match any spec changes. Discussion happens in the PR before merge. These documents define the contract between the corpus and every runner, so changes affect all downstream tools.
