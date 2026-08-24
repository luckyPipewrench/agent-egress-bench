# Results Use and Attribution

This policy defines the words used beside a public Agent Egress Bench result, and the facts that
must travel with one. It is a disclosure vocabulary. It is not a permission regime, and it does not
add conditions to the Apache 2.0 license that covers this repository.

Nobody needs approval from the maintainer to run the corpus, publish a result, or say what they
found. The point of writing the vocabulary down is that two people using the same word should mean
the same thing.

The released method also has no target-vendor co-owner, proprietary verifier dependency, mandatory
vendor registry, or mandatory transparency chain. A lab controls its own name and schedule. These
release invariants are machine-readable in `contracts/method-independence-v1.json`, bound into the
release identity, shipped in the data bundle, and checked by the downloaded-release verifier.

## Scope

Agent Egress Bench evaluates products that mediate the outbound traffic this corpus defines and
expose an observable decision. A result is scoped to the exact product, version, configuration,
adapter, capability profile, capability-registry snapshot, corpus, and scoring version that produced it.

The corpus does not evaluate every security product, and a result never generalizes past the
capability profile that produced it. See [RUNNER.md](RUNNER.md) for the tool shapes the shipped
adapters can drive today.

## Assurance labels

Use the label that matches how the run happened. Each label answers one question and leaves the
others open.

| Label | What it means | What it does not mean |
|---|---|---|
| **Self-run** | The vendor, customer, or maintainer ran the public method against their own target. | Nothing about who controlled the host or preserved the artifacts. |
| **Artifact-validated** | The result and manifest structure, digests, and declared bindings reconcile under the shipped validator. | Nothing about who executed the run, or when. |
| **Independently executed** | A separate operator controlled the execution host and retained the artifacts. Guided setup is still independent execution, and saying so is accurate. | Independent custody of the clock, independent case selection, or a certification. |
| **Transparency-registered** | A start commitment was published before execution, and the completed bundle root was appended to a log operated by neither the target vendor nor the executing lab. | That the log operator reviewed the result. Offline verification stays complete without the log. |
| **Challenge-verified** | Predeclared holdout cases outside the public corpus were applied under a published selection and retirement rule. | A general claim about cases nobody has run. |

A run may carry more than one label. A run carries none of them by default.

`transparency-registered` requires the commitment to come first. An authenticated timestamp
obtained after execution proves the timestamp exists. It does not prove when the run happened.

## Facts that travel with a public result

Publish these next to any score, or the number is not reproducible.

| Fact | Why |
|---|---|
| Method identity: repository and exact commit | The corpus and scoring change over time. |
| Corpus and scoring version, plus `benchmark_manifest_sha256` | Pins the case surface that ran. Active records carry both digests; frozen legacy records may carry only `corpus_sha256` and cannot carry the newer manifest digest. |
| Capability profile, `tool_profile_sha256`, and exact registry reference | Preserves the profile's reporting labels and the raw registry snapshot that defined them. |
| Exercised-control coverage: the transports, categories, and capability tags backed by observed result rows | The runner derives this separately from outcome scores. Publication re-derives it from `evidence.result_state=observed` rows and the pinned case index. Profile claims and framework mappings aren't execution evidence. |
| Adapter identity and owner | A vendor-authored adapter is normal. Hiding who wrote it is not. |
| Target product, version, and configuration | A score against an unnamed configuration cannot be repeated. |
| Applicable, unreachable, historical not-applicable, and error counts, with N/A reasons | An N/A case that silently leaves the denominator inflates the score; an unreachable row exposes an adapter coverage gap without pretending it was a measurement. |
| Every failed case ID, a commit-pinned link, and the expected and observed verdicts | An aggregate score without its losses makes a concentrated product gap look like unexplained weakness. |
| Containment and false-positive rate, reported separately | There is no composite score in this corpus. V5 field-presence diagnostics are non-scoring observations, not detection or proof claims. |
| The non-claims that apply | See below. |

The runner writes these into the v5 summary JSON. The corpus-derived facts come from the run itself; repository and commit, adapter owner, and target configuration are operator declarations supplied with `--method-repository`, `--method-commit`, `--adapter-owner`, and `--target-config`. A local summary may omit a declaration rather than guess it. The v6 provenance candidate requires every declaration before promotion, and the buyer report names anything absent from older or local artifacts. Reproduction instructions belong beside a public result too, so a reader can run it rather than believe it.

The released runner can render a neutral, copy-ready lockup from a complete publication-eligible artifact directory:

```bash
./aeb-gauntlet \
  --publication-lockup artifacts \
  --publication-assurance self-run \
  --publication-evidence-url https://publisher.example/results/run-123 \
  --publication-lockup-output artifacts/result-lockup.md
```

The lockup lists each failed case before the aggregate scores, with a stable link and the expected and observed verdicts. It also carries the method identity, scope, configuration identity, exercised coverage, publisher-declared assurance label, evidence URL, and non-claims. The `self-run`, `independently-executed`, `transparency-registered`, and `challenge-verified` labels validate the target-neutral summary, result rows, profile, registry, receipt profile, and declared method identity without requiring Pipelock-specific release files or an AEB-Go bundle. The first-party Pipelock lane may also declare `artifact-validated` after its complete AEB bundle passes the stricter retained-decision checks. A lab or vendor may style the surrounding presentation, but wherever a score appears these facts must remain adjacent to it. Putting them only in a methodology page does not make a detached screenshot, badge, or sales slide reproducible.

## Verify a public result

The public result must include the score, its exact scope and pinned inputs, the reproduction commands, the raw evidence, the normalized decisions, and a verification path. Those categories bind any publisher. The exact filenames do not: they belong to the lane that produced the result. The [public result contract](../contracts/public-result-v1.json) names the files the first-party Pipelock lane retains, and the [Pipelock result inventory](../migration/pipelock-result-inventory-v1.json) gives each of those files a commit-pinned public URL and digest. Run `python3 scripts/validate_gauntlet_records.py` from a checkout of this repository to verify that lane's retained chain and reconstruct its decisions from the raw evidence.

Paid reports may add analysis or convenience. They can't gate the score, scope, evidence, or verification needed to check a public result. A private engagement may remain private and be priced however its parties agree, but it cannot support a public claim while its underlying result remains unavailable.

## Non-claims

A result does not establish any of the following, and no publisher should imply otherwise:

- certification, accreditation, or a pass mark of any kind;
- legal or regulatory compliance;
- insurance eligibility or pricing;
- security of a product outside the exercised capability profile;
- absence of bypasses, including bypasses of the same class the corpus tests.

Words to avoid beside a result until the underlying protocol exists: certified, accredited, audited, approved, assured, attested, endorsed, graded, rated, sealed, stamped, witnessed, passed, neutral benchmark, proven secure, no bypass, any product, all proxies. `artifact-validated` is the defined self-consistency label above; bare `validated` must not be used as a substitute for certification or endorsement. <!-- claim-ok: names the terms it forbids -->

## Adverse results

Anyone may publish a result that reflects badly on Pipelock, or on any other target, without
notice, approval, embargo, or prior review by the maintainer. That permission is stated here so it
cannot be quietly withdrawn later.

The maintainer may respond in public with a factual correction. A correction is an argument, not a
veto, and the original result stays published.

A continuous or version-tracking public campaign states its selection rule before it runs and keeps every completed scored result in that declared scope, including adverse results. A correction or rerun receives a new permanent record and links back to the earlier result; it does not replace it. Every displayed score carries its run date. An error, incomplete measurement, or unknown state must remain visibly non-successful and must not leave an older successful score looking current.

## Configuration verification

Before a run, a publisher may put the adapter, capability profile, pinned target version, target
configuration, and exact command in public. The target and anyone else may point out a factual setup
error in that same public record. Corrections stay visible and the publisher records the final setup
used for the run.

This review covers setup only. It does not include case outcomes, scores, or result artifacts. The
target receives no private notice period, embargo, approval right, or prepublication result preview.
It has no veto over execution or publication.

## Corrections and disputes

Open a GitHub Issue for a disputed case verdict or other case-semantics question. Open a GitHub Discussion for a scoring question, adapter or method application, or a result that appears to misstate the method. Include the case IDs when applicable, the exact commit, and the artifacts.

The maintainer answers in the thread. A case that changes semantics becomes a new case, since case
IDs are immutable. See [GOVERNANCE.md](GOVERNANCE.md) for the case and supersession rules.

No party gets a private review window before someone else publishes, and that includes the
maintainer.

## Using the name

The benchmark name identifies the method. Two rules keep it meaningful:

1. A result presented as an Agent Egress Bench result runs this corpus and this scoring model, at a
   stated commit. Renaming the method, or relabeling a modified corpus under the same name without
   saying so, makes results that do not reconcile.
2. Forks are allowed under the license and are a reasonable way to develop an adapter. A public
   result meant to be compared with another public result should pin the canonical upstream commit,
   or state exactly how it diverges.

A lab may brand its own program, environment, campaign, and report. Name and version-pin each
component method inside it, so a reader can tell which instrument produced which number.

Suggested sentence for an independently executed run:

> `<lab>` independently executed Agent Egress Bench at commit `<sha>` against `<product>`
> `<version>` under the declared `<capability-profile>` and published the resulting artifact.

## What the maintainer will not do

These constraints bind this repository and its maintainer, not just outside publishers:

- no ranking, leaderboard, or cross-tool comparison table in this repository;
- no maintainer-awarded verification mark, badge, or pass label attached to somebody else's result;
- no private preview of an adverse result to the affected vendor before publication;
- no retroactive scoring change to move a published number. Scoring changes get a version.

The maintainer builds Pipelock. Retained Pipelock records under
`gauntlet-site/results/pipelock/` are archived first-party regression evidence. They are not the
live product schedule or public score, and they carry no independence claim.

See [GOVERNANCE.md](GOVERNANCE.md) for neutrality and contribution rules, and
[gauntlet.md](gauntlet.md) for how results are produced and published.
