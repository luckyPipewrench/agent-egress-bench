# Scoring

## Per-Case Verdicts

Each case produces one of five result outcomes:

The table lists result outcomes, not the `score` field alone. `pass`, `fail`, and `error` appear in both `actual_verdict` and `score`; `unreachable` and `not_applicable` are `actual_verdict` values whose `score` is `error` and `not_applicable` respectively.

| Result outcome | Meaning |
|----------------|---------|
| `pass` | Tool produced the expected verdict |
| `fail` | Tool produced the wrong verdict |
| `not_applicable` | Historical v3 N/A evidence, retained without reinterpretation |
| `unreachable` | Adapter has no exact delivery route; visible coverage gap, not a measurement |
| `error` | Runner or tool failure prevented a verdict |

## Applicability

A case is scoreable only when its adapter proves delivery of the exact declared wire input and observes a request-correlated `allow` or `block` verdict. `claims`, `requires`, and `capability_tags` do not select cases. Claims and tags are registry-backed reporting labels. They never alter a score, denominator, measurement-status decision, or publication decision.

An adapter that declares no exact route emits `actual_verdict: "unreachable"` with `score: "error"`. It is neither a scored runner error nor N/A: it is excluded from score denominators and makes the measurement incomplete. A routed case without delivery proof or a trustworthy verdict is an `error`, which is treated the same way for the same reason: it was not measured, so it is excluded from the denominators and it also makes the measurement incomplete.

`requires` lists only what the runner needs to deliver the input to the tool and observe a trustworthy verdict: the transport, genuine runtime fixtures (e.g. `tls_interception`, `dns_rebinding_fixture`), and the base surface or detector family the tool must inspect. It must never contain an attack-difficulty or evasion-technique flag (e.g. `encoding_evasion_scanning`, `ssrf_bypass_scanning`); those are `capability_tags` for reporting. This holds for malicious `block` cases and benign `allow` cases alike: a tool must not dodge a hard variant of a surface it already inspects by declining a difficulty claim. The runner resolves every tag from the exact registry snapshot bound to the profile before it emits a score.

## Summary Format

Runners print a summary to stderr after all cases:

```
results: 22 passed, 3 failed, 0 unreachable, 10 not_applicable, 0 errors (35 total)
```

Pass, fail, unreachable, not-applicable, and error result counters must sum to the total
number of cases processed. In Gauntlet summary JSON, `case_count.applicable` is
the retained name for the routed-case partition. It includes routed cases that
ended in `error`, while `case_count.errors` reports that unobserved subset
explicitly. It is not an observed-measurement count.

## What Scoring Is NOT

This corpus does not produce rankings, percentages, or letter grades. Each tool can publish its own results. Cross-tool comparison tables are not part of this repo.

A route the adapter cannot prove is not a meaningful measurement. That is why
unreachable coverage stays separate from both scores and historical N/A rows.

## Error Handling

A runner error (tool crash, timeout, transport failure) is scored as `error`, not `fail`. This prevents infrastructure problems from being counted as detection failures.

If any case produces `error`, or any case is unreachable, or any row carries synthetic calibration evidence, `measurement_status` is `incomplete` and the results should not be published. An error and an unreachable case both mean a case was not measured, and neither describes the target's behaviour, so both are excluded from every score denominator and both block publication. Synthetic evidence is different in one respect worth stating separately: those rows are asserted by a calibration adapter rather than observed from a target, so they may still land in a denominator while publication stays blocked. That symmetry is deliberate: because errors are excluded from the denominator, tolerating them would raise the reported score while hiding the fact that part of the corpus was never measured. An error is this harness or the adapter failing, so the fix belongs there rather than in a scoring allowance.

The runner records this in `summary.measurement_status`; the separate case/result validator does not decide whether a complete run is publishable.

## Authoritative Validation

The Go validator (`validate/`) is the authoritative tool for checking case files, result lines, and tool profiles. The JSON Schemas provide structural validation. Cross-field constraints (score consistency, category/input_type mapping, category/transport mapping) are enforced by the Go validator only.
