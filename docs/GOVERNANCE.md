# Governance

How this corpus is maintained, how decisions are made, and how conflicts are handled.

## Neutrality

Case design is tool-neutral: no case targets a product. The project itself is not independent yet. PipeLab maintains the corpus and holds decision rights over case semantics and scoring, and says so rather than calling itself neutral. It was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author and is designed for any agent egress security tool. This repository publishes no ranking, leaderboard, or cross-tool comparison table, awards no badge, and certifies nothing. <!-- claim-ok: states the non-claim -->
Optional receipt profiles under `profiles/` are maintainer-published evidence artifacts, not corpus-issued endorsements. [RESULTS-USE.md](RESULTS-USE.md) defines the labels a publisher may use, the facts that travel with a public result, and the limits this policy places on the maintainer.

This repository's own continuous integration runs the maintainer's product against this repository's files to check for committed secrets. That is repository hygiene and a self-run check, not a security audit, not an endorsement, and not evidence about that product or any other. It gates changes to this repository only, it awards nothing, and no result it produces may be cited as a corpus outcome. <!-- claim-ok: states the non-claim -->

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

Removing a retained case from an active score changes the denominator. The complete source catalog
remains `cases/MANIFEST.txt`. No mutable skip list may redefine it. An active score may instead use
an immutable `corpora/active-sets/v1/<corpus-version>.json` artifact that names the corpus version,
binds the exact source-manifest digest, records its exclusions and selected count, and is itself bound
by the append-only corpus-version ledger. `cases/CORPUS_VERSION` makes the active-set requirement
travel with an official corpus copy, so losing the selection artifact fails before a score runs.

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

Retained v1 and v2 evidence records are frozen. The v4 case and tool-profile formats remain active. Receipt profiles write v5 and retain v1, v3, and v4 readers. Result rows write v6 and retain frozen v4 and v5 readers; summaries still write v5 and retain their frozen v4 reader. Provenance candidates write v6 while retaining their v5 reader. A local v5 summary may omit publication provenance, but a v6 provenance candidate can't cross the promotion boundary without the method repository and commit, adapter identity and owner, and target configuration reference and digest. Promotion baselines remain on v1 because v6 candidates still carry v5 summary and scoring semantics.

Every active profile and result binds an immutable capability-registry snapshot by ID, format, revision, and raw-byte SHA-256. Adding or deprecating a reporting label creates a registry revision, not an artifact schema bump.

### Release tag identity

The release tag versions one thing: the release bundle. That bundle is the public API this
repository promises against, and it is the archive layout, the `aeb-gauntlet` and `aeb-validate`
command behavior, the `release-identity.json` format, the reusable Action interface, and the
verification procedure in [RELEASES.md](RELEASES.md). Tags are `vMAJOR.MINOR.PATCH` under
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html), validated on the release path,
and a tag that is not a valid version, or that does not resolve to the release commit, fails the
build before anything is produced.

The tag is not a summary of the per-family versions above and cannot be read as one. Those answer
whether a saved artifact still opens; the tag answers what an installable package is and whether a
cited result came from a package anyone can rebuild. A release may bump the tag's MINOR while every
artifact family holds its version, and a family may bump while the tag takes a PATCH, because they
measure different things. Ask the compatibility question of the family manifest, never of the tag.

Tags are immutable once published. A published tag is never moved, deleted, or reinterpreted, since
results cite it and the verification procedure resolves it.

### Corpus version identity

`corpus_version` names one exact corpus and is bound to it. [`ci/corpus-versions.json`](../ci/corpus-versions.json) records, for each label, the scored case count and the `benchmark_manifest_sha256` of the corpus that label names, and `runner/corpus_version_test.go` fails when the corpus on disk is not the corpus the current label names. An active-set entry also records the SHA-256 of its versioned selection artifact. Adding, removing, or re-expecting a scored case therefore requires a new label and a new ledger entry in the same change. The current label must be the ledger's final entry.

Ledger entries are append-only. Published results carry the label, so rewriting an entry retroactively changes what an already-published number was measured over. Documentation and unreferenced files are excluded from the digest, so editorial work on the corpus does not force a bump.

The requirement exists because a label that does not move is indistinguishable from a corpus that did not change. Four scored cases were added on 2026-08-24 without a bump, so one label named both a 242-case and a 246-case corpus while every check that compared labels reported agreement.

### Compatibility matrix

The table summarizes the manifest. `make check-contracts` checks the full machine-readable inventory against schema files, `$id` values, Go constants, and retained public records.

| Family | Active writer | Accepted readers | Frozen | Canonical schema |
| --- | ---: | --- | --- | --- |
| Case and multi-file case | 4 | 4 | none | [`case-v4.schema.json`](../schemas/case-v4.schema.json), with the multi-file shape enforced in Go |
| Case governance decision | 1 | 1 | none | [`case-governance-decision-v1.schema.json`](../schemas/case-governance-decision-v1.schema.json) |
| Result row | 6 | 4, 5, 6 | 4, 5 | [`result-v6.schema.json`](../schemas/result-v6.schema.json) |
| Tool profile | 4 | 1, 3, 4 | 1, 3 | [`tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json) |
| Receipt-scoring profile | 5 | 1, 3, 4, 5 | 1, 3, 4 | [`receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json) |
| Summary | 5 | 4, 5 | 4 | [`summary-v5.schema.json`](../schemas/summary-v5.schema.json) |
| Provenance candidate | 6 | 1, 2, 4, 5, 6 | 1, 2, 5 | [`provenance-candidate-v6.schema.json`](../schemas/provenance-candidate-v6.schema.json) |
| Case index | 3 | 1, 2, 3 | 1, 2 | [`case-index-v3.schema.json`](../schemas/case-index-v3.schema.json) |
| Promoted record | 4 | 1, 2, 3, 4 | 1, 2, 3 | [`promoted-record-v4.schema.json`](../schemas/promoted-record-v4.schema.json) |
| Promotion baseline | 1 | 1 | 1 | [`promotion-baseline-v1.schema.json`](../schemas/promotion-baseline-v1.schema.json) |
| Result pointer | 1 | 1 | none | [`result-pointer-v1.schema.json`](../schemas/result-pointer-v1.schema.json) |

Every versioned schema has an explicit `-vN` filename and matching `$id`. Result rows retain frozen v4 and v5 beside active v6; summaries retain frozen v4 beside active v5. Provenance candidates retain every accepted version beside active v6. A path can't silently retarget a historical contract, and the repository provides no unsuffixed compatibility aliases.

Tool-profile reader support depends on the consumer. Scoring readers refuse profiles outside their declared contract with `incompatible_schema_version`; retained-evidence readers preserve only the historical formats they explicitly implement. `contracts/artifacts.json` is the authority for the consumer map and its accepted-version union.

The summary stays on v5 because it already has optional fields for the publication facts. Provenance candidate v6 makes those fields mandatory and verifies them before publication. Keeping the requirement in that artifact family avoids changing the local-run summary or the promotion baseline when their meaning hasn't changed.

### Mixed-release readers

A lab that keeps an artifact from tagged release N-1 and later opens it with a reader from N should expect the behavior below. These are the current readers, not a promise that a future bump will keep every listed version.

Verify a downloaded release package against the tag that produced it. `python3 scripts/release_build.py verify --release-dir DIR --repo-root .` rebuilds `release-identity.json` from the checked-out tree and refuses a mismatch with `release identity disagrees with the checked-out source tree`. Pointing an N checkout at N-1 archives fails that check. It is not a schema-family read.

Saved run artifacts are per family, and the accepted version list for every family is owned by [`contracts/artifacts.json`](../contracts/artifacts.json), not this page. The behavior is uniform: a reader either accepts the versions that manifest declares for it or refuses with a `schema_version` error that names the accepted versions and the value it got. Copying those version lists here has already drifted once, so this page states only the behaviors that are version-free:

- Frozen result rows cannot share a file with rows of the active result schema; the validator refuses the mixed file with `frozen result rows cannot share a file with active schema_version 6 rows` style errors that name both sides.
- Control Evidence v0 and v1 are separate verifiers. A v1 verifier given a v0 requirement envelope fails closed with `requirement_payload_type_mismatch`, and historical v0 packages cannot be normalized into v1; use the v0 verifier for v0 packages.
- Retained historical schemas keep validating the packages recorded under them, but a retained schema is never a scoring input.

If release N does not bump a family, an N-1 artifact of that family still verifies under the same reader. If it does bump a family, keep the frozen reader that the current program actually implements, or expect the refusal error above.

## Contribution acceptance

Cases from any vendor, researcher, or individual are welcome. Every submitted case must include:

- **Rationale:** why this attack pattern matters
- **Expected verdict:** `block` or `allow`, with a `why_expected` explanation
- **Source:** where the attack pattern comes from (real-world incident, research paper, original creation)
- **False positive assessment:** likelihood of benign traffic matching this pattern
- **Synthetic fixtures:** credentials and secrets must be fake and unmistakably test-only
- **Threat model, multi-file cases only:** the trust assumption the case is written under, in prose

The [validator](../validate/) enforces structural correctness (valid JSON, required fields, correct enums, ID matching filename). Semantic review (is the expected verdict correct? is the attack realistic?) is manual and happens during PR review.

### Why `threat_model` is required on multi-file cases and absent from single-file cases

The multi-file schema requires a `threat_model` paragraph and the single-file schema has no such field. That asymmetry is deliberate, and it survives because of what the two case shapes can honestly answer rather than because one shape is better documented.

A multi-file case is a temporal sequence: the same tool inventory observed across sessions. Its verdict depends on a trust assumption that no other field records, because identical bytes can be an approved vendor update or a post-approval mutation. Stating that assumption in prose is what makes the expected verdict reviewable, so a reviewer reads it during semantic review and a case that omits it cannot be assessed.

A single-file case usually cannot answer the same question. Most of the corpus observes an outbound request at the egress boundary: a credential leaves in a query string, a header, a body, or a subdomain label. A poisoned page, a malicious operator, a compromised peer agent, or an ordinary bug in the agent all produce the same observable bytes, and the case deliberately does not choose between them, because containment is expected either way. Requiring an attacker's position on those cases would ask authors to assert a cause the case does not establish, which reads as documentation while adding no reviewable fact.

`threat_model` is prose for human review and is not machine-readable. It does not reach the scorer, it does not affect a verdict, and no published number is derived from it. A structured attacker-position vocabulary was evaluated as a replacement and rejected. Independent classification passes over the corpus agreed that most attack cases name no upstream attacker, and disagreed with each other about whether the acting agent counts as the hostile party in the rest. A field whose value depends on which reasonable reading a rater applies cannot carry a stable public claim.

## Conflict of interest

The corpus maintainer also builds a competing tool ([Pipelock](https://github.com/luckyPipewrench/pipelock)). This is disclosed here and in the [README](../README.md). It is handled by:

1. **Tool-neutral case design.** Cases test observable behavior, not implementation details. A case asks "was this secret in the query string blocked?" not "did the tool use regex pattern X?"
2. **Reference, not privilege.** The [Pipelock runner](../examples/pipelock/) is a reference example showing how to build a runner. It has no special status. Any vendor can add a runner in `examples/`.
3. **Open contribution.** Any vendor or individual can submit cases, runners, or spec changes through the normal PR process.

Mandatory repository validation checks the shared corpus, evidence, runner, and scoring contracts. It doesn't run a named product or decide which scores and failed cases are acceptable for that product. Product repositories own their continuous runs and release acceptance policy.

Reference adapters and manual examples may show how a product implements the shared contract, but they don't get a product into Bench's required preflight or release gate. `check-neutrality-boundary` follows mandatory validation dependencies and rejects product runner or product acceptance policy paths.

Bench may verify a retained published result against the baseline archived with that result. That preserves public evidence history; it doesn't approve a product release or set the score required for one.

## Appeals

If you disagree with a case's expected verdict, open a GitHub Issue. Include:

- The case ID
- Your reasoning (why the verdict should be different)
- Evidence if available (real-world traffic patterns, false positive data, attack feasibility analysis)

Verdict changes require community discussion. They are not made unilaterally.

Use a GitHub Discussion instead when the disagreement is about scoring, adapter or method application, or a published result that appears to misstate the method. [`RESULTS-USE.md`](RESULTS-USE.md) defines that result-correction path.

## Spec changes

Changes to [SPEC.md](SPEC.md), [gauntlet.md](gauntlet.md), or [RUNNER.md](RUNNER.md) require a PR with rationale explaining the change. The validator must be updated to match any spec changes. Discussion happens in the PR before merge. These documents define the contract between the corpus and every runner, so changes affect all downstream tools.
