# Scoring

## Per-Case Verdicts

Each case produces one of four scores:

| Score | Meaning |
|-------|---------|
| `pass` | Tool produced the expected verdict |
| `fail` | Tool produced the wrong verdict |
| `not_applicable` | Case does not apply to this tool (missing capability or prerequisite) |
| `error` | Runner or tool failure prevented a verdict |

## Applicability

A case is `not_applicable` if either:

1. Any `requires` value is not in the tool profile's `supports`
2. The case `transport` is not in the tool profile's `supports`

This is checked before running the case. Not-applicable cases are never executed.

`requires` lists only what the runner needs to deliver the input to the tool and observe a trustworthy verdict: the transport, genuine runtime fixtures (e.g. `tls_interception`, `dns_rebinding_fixture`), and the base surface or detector family the tool must inspect. It must never contain an attack-difficulty or evasion-technique flag (e.g. `encoding_evasion_scanning`, `ssrf_bypass_scanning`); those are `capability_tags` for reporting. This holds for malicious `block` cases and benign `allow` cases alike: a tool must not dodge a hard variant of a surface it already inspects by declining a difficulty claim. Use `capability_tags` to report which detector family a control belongs to.

## Summary Format

Runners print a summary to stderr after all cases:

```
results: 22 passed, 3 failed, 10 not_applicable, 0 errors (35 total)
```

Pass, fail, not-applicable, and error result counters must sum to the total
number of cases processed. In Gauntlet summary JSON, `case_count.applicable`
includes applicable cases that ended in `error`, while `case_count.errors`
reports that subset explicitly.

## What Scoring Is NOT

This corpus does not produce rankings, percentages, or letter grades. Each tool can publish its own results. Cross-tool comparison tables are not part of this repo.

A tool failing a case it was never designed to handle is not a meaningful signal. That's why applicability exists.

## Error Handling

A runner error (tool crash, timeout, transport failure) is scored as `error`, not `fail`. This prevents infrastructure problems from being counted as detection failures.

If a tool produces `error` on more than 20% of applicable cases, the run is insufficient and the results should not be published. The runner enforces this in `summary.sufficient`; the separate case/result validator does not decide whether a complete run is publishable.

## Authoritative Validation

The Go validator (`validate/`) is the authoritative tool for checking case files, result lines, and tool profiles. The JSON Schemas provide structural validation. Cross-field constraints (score consistency, category/input_type mapping, category/transport mapping) are enforced by the Go validator only.
