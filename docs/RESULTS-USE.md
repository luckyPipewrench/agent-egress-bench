# Results Use and Attribution

This policy defines the words used beside a public Agent Egress Bench result, and the facts that
must travel with one. It is a disclosure vocabulary. It is not a permission regime, and it does not
add conditions to the Apache 2.0 license that covers this repository.

Nobody needs approval from the maintainer to run the corpus, publish a result, or say what they
found. The point of writing the vocabulary down is that two people using the same word should mean
the same thing.

## Scope

Agent Egress Bench evaluates products that mediate the outbound traffic this corpus defines and
expose an observable decision. A result is scoped to the exact product, version, configuration,
adapter, capability profile, corpus, and scoring version that produced it.

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
| Corpus and scoring version, plus `corpus_sha256` | Pins the case surface that ran. |
| Capability profile and `tool_profile_sha256` | Declares what the target claims to support. |
| Exercised profile: the transports, categories, and capability tags the run actually drove | The declared profile is a claim; the exercised profile is what was tested. A result covers only the surface it drove. |
| Adapter identity and owner | A vendor-authored adapter is normal. Hiding who wrote it is not. |
| Target product, version, and configuration | A score against an unnamed configuration cannot be repeated. |
| Applicable, unreachable, historical not-applicable, and error counts, with N/A reasons | An N/A case that silently leaves the denominator inflates the score; an unreachable row exposes an adapter coverage gap without pretending it was a measurement. |
| Containment, detection, evidence, and false-positive rate, reported separately | There is no composite score in this corpus. |
| The non-claims that apply | See below. |

The runner writes these into the summary JSON. The corpus-derived facts come from the run itself; repository and commit, adapter owner, and the target configuration are operator declarations, supplied with `--method-repository`, `--method-commit`, `--adapter-owner`, and `--target-config`. A fact you do not declare is omitted rather than guessed, and the buyer report names it as absent. Reproduction instructions belong
beside a public result too, so a reader can run it rather than believe it.

## Non-claims

A result does not establish any of the following, and no publisher should imply otherwise:

- certification, accreditation, or a pass mark of any kind;
- legal or regulatory compliance;
- insurance eligibility or pricing;
- security of a product outside the exercised capability profile;
- absence of bypasses, including bypasses of the same class the corpus tests.

Words to avoid beside a result until the underlying protocol exists: certified, sealed, witnessed,
neutral benchmark, proven secure, no bypass, any product, all proxies. <!-- claim-ok: names the terms it forbids -->

## Adverse results

Anyone may publish a result that reflects badly on Pipelock, or on any other target, without
notice, approval, embargo, or prior review by the maintainer. That permission is stated here so it
cannot be quietly withdrawn later.

The maintainer may respond in public with a factual correction. A correction is an argument, not a
veto, and the original result stays published.

## Corrections and disputes

Open a GitHub Discussion for a disputed case verdict, a scoring question, or a result that appears
to misstate the method. Include the case IDs, the exact commit, and the artifacts.

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

The maintainer builds Pipelock, and the Pipelock reference lane in this repository publishes
first-party regression evidence under `gauntlet-site/results/pipelock/`. That lane is disclosed
self-run and artifact-validated evidence. It carries no independence claim.

See [GOVERNANCE.md](GOVERNANCE.md) for neutrality and contribution rules, and
[methodology.md](methodology.md) for how results are produced and published.
