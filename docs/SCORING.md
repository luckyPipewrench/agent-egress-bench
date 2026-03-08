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

1. Any `capability_tags` value is not in the tool profile's `claims`
2. Any `requires` value is not in the tool profile's `supports`

This is checked before running the case. Not-applicable cases are never executed.

## Summary Format

Runners print a summary to stderr after all cases:

```
results: 22 passed, 3 failed, 10 not_applicable, 0 errors (35 total)
```

The four counters must sum to the total number of cases processed.

## What Scoring Is NOT

This corpus does not produce rankings, percentages, or letter grades. Each tool can publish its own results. Cross-tool comparison tables are not part of this repo.

A tool failing a case it was never designed to handle is not a meaningful signal. That's why applicability exists.

## Error Handling

A runner error (tool crash, timeout, transport failure) is scored as `error`, not `fail`. This prevents infrastructure problems from being counted as detection failures.

If a tool produces `error` on more than 20% of applicable cases, the run should be considered invalid and the results should not be published. This threshold is a guideline for result publishers; the Go validator does not enforce it automatically.

## Authoritative Validation

The Go validator (`validate/`) is the authoritative tool for checking case files, result lines, and tool profiles. The JSON Schemas provide structural validation. Cross-field constraints (score consistency, category/input_type mapping, category/transport mapping) are enforced by the Go validator only.
