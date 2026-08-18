# Detection metric replacement

## Decision

Don't replace the retired detection metric in this corpus. Close BENCH-025 with the current outcome vector: containment, false-positive rate, and measurement status. Keep the two field-presence values as diagnostics only.

The runner can prove that a control stopped or allowed the exact case input. It can't prove that a tool's finding named the right underlying threat without a separate correctness oracle. An earlier experiment on an unmerged branch explored a public static finding oracle scored with precision, recall, and one-to-one label matching; it was never merged, and no `oracles/` directory exists on `main`. The v5 retirement in `ab1ebcb` removed field presence from scored metrics because a field can be constant or unrelated to the case and still look good. The current contract says a future detection score needs an edition-owned taxonomy, implication rules, and a correctness oracle [docs/gauntlet.md:140-146]. This memo assumes the stated constraint that this repository won't publish a static label oracle.

This is a negative result. The corpus doesn't have the independent facts needed to measure detection with independent evidence.

## What the runner can observe today

The corpus defines a malicious case as `expected_verdict: block` and a benign case as `expected_verdict: allow`. Those are deterministic wire-outcome rubrics, not labels for the reason a tool acted [docs/gauntlet.md:31-35]. A row becomes scoreable only after the adapter proves delivery of the exact wire input and observes a request-correlated allow or block verdict [docs/gauntlet.md:107-116]. The result matrix then treats a malicious block as a pass and a benign block as a fail [docs/gauntlet.md:61-70].

That gives one defensible outcome rubric that people sometimes call "detection": **observed intervention at the required boundary**. It means the tool blocked the malicious test input, not that it recognized the attack family. In this benchmark it's already containment: correctly blocked malicious cases divided by the malicious denominator [docs/gauntlet.md:80-87]. Renaming it would double-count one fact and mislead a reader into believing the benchmark checked diagnosis.

The runner also observes the opposite availability outcome. A block of a benign case is a failure and contributes to false-positive rate [docs/gauntlet.md:61-70, 80-87]. This matters because a control that denies every request can stop every malicious case without remaining usable.

The existing output-field diagnostics are weaker observables. They report that a correctly blocked malicious row included one of several fields, such as `scanner`, `block_reason`, `decision`, or `findings` [docs/gauntlet.md:140-143]. They don't establish that the field describes the case. A universal `block_reason: "policy"` and an incorrect SSRF label both count [docs/gauntlet.md:146]. They must remain diagnostics, not a replacement for detection.

## Required observables and current schema coverage

An oracle-free *outcome* calculation needs the following per-case facts:

| Fact | Current field | Present now? | Limit |
| --- | --- | --- | --- |
| Stable test identity | `case_id` | Yes | Identifies the case, not a hidden attack class. |
| Corpus expectation | `expected_verdict` | Yes | Says block or allow at the wire boundary. |
| Observed target behavior | `actual_verdict` | Yes | Distinguishes `allow`, `block`, `error`, and `unreachable`. |
| Whether the row is a real measurement | `evidence.result_state` plus `score` | Yes | Delivery and verdict observation must have occurred before scoring. |
| Tool and corpus provenance | tool/version, registry reference, summary corpus and manifest digests | Yes | Supports reproduction, not diagnosis correctness. |

The active row schema requires the first four inputs and permits other tool-specific evidence [schemas/result-v5.schema.json:7-19, 52-78]. The summary records the two outcome scores, diagnostics, exercised surface, and `measurement_status` [schemas/summary-v5.schema.json:7-37, 73-137]. The runner emits one JSONL object for every case [docs/RUNNER.md:37-43] and rejects a row as a measurement when delivery or verdict observation is missing [docs/RUNNER.md:195-205]. Therefore no new fields are needed to compute the existing outcome vector.

A genuine detection metric needs more facts that the schema intentionally doesn't supply: a normalized tool-emitted finding, a versioned taxonomy, the expected finding set for the case, and matching rules that define correct, over-broad, and missing findings. The schema's open `evidence` object can carry a vendor-specific finding, but it neither requires nor interprets one [schemas/result-v5.schema.json:67-78]. Adding those fields without an independent expected finding set would only make a more elaborate field-presence rate. This is speculation about a future edition design, not a capability of the active contract.

## Composite signals

Don't publish a single replacement number. The current methodology chooses separate outcome metrics so readers can see the security and availability trade-off [docs/gauntlet.md:78-87]. A weighted score would hide a choice about how many benign denials should buy one blocked attack. This corpus has no universal answer to that product decision.

The recommended composite is a displayed vector, not an arithmetic composite:

| Component | Meaning on its own | Why it can't substitute for another component |
| --- | --- | --- |
| Containment | Fraction of measured malicious cases stopped | It says nothing about benign traffic or why the tool acted. |
| False-positive rate | Fraction of measured benign cases blocked | It detects indiscriminate denial, but says nothing about attacks that escaped. |
| Measurement status | Whether every applicable case obtained an observed outcome | It prevents partial coverage from looking like a complete result, but isn't a quality score. |
| Field-presence diagnostics | Whether blocked rows carried named output fields | They describe observability only and can't establish accurate detection. |
| Label informativeness (oracle-free, diagnostic only) | Whether a tool's own emitted label carries information about the corpus's own category partition | It shows a label is not a constant. It cannot show the label is CORRECT, and it is gameable by cardinality, so it must never become a score. |

That last row is the one honest step beyond presence, and it would need no external taxonomy, no expected-finding set, and no new schema field: the runner already loads `Case.Category` and already keys a scored breakdown on it, and adapters already record varying threat labels in evidence.

**Nothing in this repository computes it today, and nothing consumes it.** No runner code emits a label informativeness value, no schema field carries one, and no published artifact contains one. The figures below were computed ad hoc while writing this memo, by reading the retained `gauntlet-site/results/pipelock/5869b18c.../results.jsonl` and grouping the recorded evidence label against each case's own category. They are offered as evidence that the question is answerable, not as a runner capability or a reproducible published metric. Implementing it would require defining canonical label extraction from an evidence object the schema deliberately leaves unstructured, deciding how a missing or malformed label counts, and naming where the value is emitted and read.

On that ad hoc reading of 154 correctly-blocked malicious rows, the conditional entropy of category given label gives homogeneity 0.745, where a constant `block_reason: "policy"` scores 0.000 and both score an identical 1.0 on the current presence rate. That gap is the operator question presence cannot answer.

It stays a diagnostic because it fails its own gaming test. A tool emitting a unique string per case scores homogeneity 1.000 and beats the honest labeler on V-measure, 0.702 against 0.678. Bounded label cardinality would be a precondition for any scored version, and this corpus cannot enforce one. Any such diagnostic also inherits the existing denominator caveat: it is computed over correctly-blocked malicious rows only, so it says nothing about what escaped.

This is already how the repository models the data: `measurement_status` is `incomplete` for errors, unreachable cases, or synthetic evidence, and it doesn't judge containment [docs/gauntlet.md:95-101]. A single number would also contradict the current public result policy, which doesn't rank tools or issue any form of approval for them [docs/GOVERNANCE.md:5-10].

## Held-out cases in a public corpus

Holding back corpus cases isn't workable as a public benchmark control. Every merged case is visible in Git history, and the repository promises that its ID, payload, expected verdict, and semantics never silently change [docs/GOVERNANCE.md:12-38]. A vendor can tune to every released case, including a case removed from the current presentation but still present in history. A newly published "holdout" becomes available for the next run. The same visibility also prevents treating an unreviewed vendor-supplied label as an independent oracle.

Two substitutes are useful, but neither creates a corpus-issued detection score:

1. An independent lab can run a time-bounded, private evaluation with cases and a finding taxonomy controlled outside this repository, then publish its method, target configuration, and evidence after the result. This can test generalization if the lab keeps the material private until execution. It must be presented as that lab's evaluation, not as an Agent Egress Bench score. This follows the repository's distinction between tool-neutral corpus contracts and externally published comparisons [docs/GOVERNANCE.md:5-10].

2. Maintainers and contributors can add fresh public cases over time. This raises the cost of case-text memorization and tests whether a released tool handles newly disclosed variants. It doesn't prove generalization, because the case is visible before any later result and its expected wire verdict is public. This is corpus maintenance, not a holdout.

## Attack the proposal

### Memorization

Containment can still be gamed by a tool that recognizes public payloads or case-shaped fixtures. The asymmetry with a label metric is deliberate and is worth stating: gaming containment requires actually blocking the request at the wire boundary, which is the operationally valuable behavior being measured, while gaming a label costs a string. Applied without that distinction, the memorization argument here would retire containment too. The existing runner reduces a separate, narrower fraud class by requiring exact transport, delivery proof, and a request-correlated verdict [docs/gauntlet.md:107-124], but it can't tell whether a correct block came from general security logic or a case-text lookup. A public finding score would be worse: a vendor could emit the expected label from the same lookup. No formula over public rows repairs that. Independent private evaluation is the only listed substitute that can test this property.

### Shotgun findings and denial

Any label-presence score rewards a tool that emits every finding on every block. The abandoned oracle experiment tried precision, recall, and one-to-one label matching, but that mechanism depended on a public static expected label set and is excluded by this row's premise. It was never merged, so it is prior art rather than a shipped feature that was withdrawn. The active diagnostics openly accept this limitation [docs/gauntlet.md:142-146].

Shotgun denial also can't score well under the outcome vector: it raises containment and false-positive rate together. Keeping those two values separate makes the trade visible instead of letting a weighted composite hide it. A tool that blocks every request has a false-positive rate of 1.0 over measured benign cases, so it can't claim a clean result.

### Over-strict denial of correct tools

The false-positive suite exists for benign traffic that must remain allowed [docs/gauntlet.md:39-55]. Its failure direction is already wired into the per-case contract: `expected_verdict: allow` with `actual_verdict: block` is a failed row [docs/gauntlet.md:61-70]. Don't introduce a detection score whose denominator contains only correctly blocked malicious cases. That shape would reward a control for denying more aggressively while leaving the availability cost in a separate number that a headline score could drown out.

## Recommendation and falsifier

**Recommendation:** close BENCH-025 with no replacement metric. Retain containment, false-positive rate, measurement status, and the two explicitly non-scoring diagnostics. Don't add a "detection" label to outcome containment or turn field presence into a score.

The strongest argument against this decision is that operators need to know whether a tool explains its blocks. That need is real, and the present diagnostics only tell them a field existed. It doesn't justify calling an unchecked explanation correct.

This recommendation has two reopening conditions, and the first is deliberately not meetable here.

The first is a full correctness oracle: an independent, versioned finding taxonomy whose expected findings aren't available to the evaluated tool before the run, plus a reproducible method for binding tool-emitted findings to it. State plainly what that means: NO artifact governed by this repository can ever satisfy it, because governance makes every merged case ID, payload, and expected verdict permanent and public, so a newly published holdout is available for the next run. It is meetable only by a separately governed private edition, and such an edition should be designed as its own evaluation rather than as a mutation of the public corpus score. Written without that sentence, this condition would read as live and would keep the row nominally open forever.

The second is reachable and is the reason closing this row must not foreclose it: an oracle-free diagnostic that distinguishes a constant label from an informative one, published as a diagnostic and never as a score, with label cardinality bounded or the gaming result above restated beside it. That work needs no oracle and no schema change. Until then, a claimed detection metric would measure either containment again or a vendor-controlled string.
