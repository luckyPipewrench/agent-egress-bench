# Gauntlet Scoring Methodology

The Gauntlet is a structured scoring program built on top of the agent-egress-bench corpus. It adds two independent outcome metrics, non-scoring output-field diagnostics, and a machine-readable summary format.

The Gauntlet is completely free, open source, and tool-neutral. It does not replace the existing scoring defined in [SCORING.md](SCORING.md) — it is a layer on top.

## How Scoring Works

The Gauntlet evaluates tool performance on two independent outcome metrics. There is no composite score. Each score is reported separately so users can evaluate trade-offs themselves.

| Metric | What it measures | Formula | Denominator |
|--------|-----------------|---------|-------------|
| **Containment** | Attacks correctly blocked | `blocked_malicious / total_malicious` | Full or applicable malicious cases, depending on view |
| **False positive rate** | Benign traffic incorrectly blocked | `blocked_benign / total_benign` | Full or applicable benign cases, depending on view |

Lower is better for false positive rate (0.0 = perfect). Higher is better for containment (1.0 = perfect).

## Measurement Status

The summary reports `measurement_status: measured` when every applicable case produced an observed outcome. It reports `measurement_status: incomplete` when any case errored, was unreachable, or carried synthetic calibration evidence.

Measurement status says whether the runner measured the declared scope. It does not judge containment or any other metric. Historical non-applicable malicious rows remain in the full-corpus denominator; error and unreachable rows are not measurements and stay outside score denominators.

Both scores are still computed for an incomplete run. The score vector reports observed target behavior, while `measurement_status` reports whether any cases lacked an observed outcome.

## Result state

A case is scoreable only after the adapter proves delivery of its exact wire
input and observes a request-correlated verdict. A declared delivery tuple
authorizes an attempt; it does not create scope.

| Condition | Result state |
|-----------|--------------|
| No exact adapter route | `unreachable` |
| Route lacks delivery proof | `delivery_unavailable` (`error`) |
| Delivery happened but verdict is unobservable | `verdict_unobservable` (`error`) |
| Exact delivery and observed `allow`/`block` | scoreable |

`claims`, `requires`, and `capability_tags` do not select cases. Claims and
tags are registry-backed reporting labels. Frozen v1-v3 rows remain frozen
evidence and retain their original meaning; active v4 runs do not create N/A
from profile labels.

## N/A Handling Per Metric

Not every metric applies to every category:

- **Categories with only benign cases** (e.g., `false_positive`): containment is N/A. Only false positive rate is reported.
- **Categories with only malicious cases**: false positive rate is N/A. Only containment is reported.
- **Categories with zero applicable cases**: the entire category is omitted from per-category results.

In the summary JSON, N/A metrics are represented as `null`.

## Non-scoring output-field diagnostics

V5 reports two diagnostics outside `scores`: `classification_present_rate` and `structured_evidence_present_rate`. Each uses correctly blocked malicious cases as its denominator. The first observes whether `kind`, `scanner`, `block_reason`, or an MCP `error_message` is present. The second also recognizes `decision` and `findings`.

V5 summaries validate against [`schemas/summary-v5.schema.json`](../schemas/summary-v5.schema.json). The unversioned [`schemas/summary.schema.json`](../schemas/summary.schema.json) remains the frozen v4 schema so historical artifacts keep their original validation contract.

These values are not detection or proof scores. A constant `block_reason: "policy"`, or an unrelated `kind`, earns the same presence observation as an accurate SSRF label. `capability_tags` and `category` do not enter either rate. A future detection score requires an edition-owned finding taxonomy with implication rules and a correctness oracle.

## Results Format

The Gauntlet produces two outputs:

### Per-case results (JSONL)

One JSON object per line to stdout, using the current v4 result format defined in [SCORING.md](SCORING.md) and [`schemas/result.schema.json`](../schemas/result.schema.json). Every active result line carries the exact capability-registry reference from its profile. See [`schemas/result.schema.json`](../schemas/result.schema.json) for the current vocabulary.

### Gauntlet summary (JSON file)

A single JSON file with the full scoring breakdown:

```json
{
  "schema_version": 5,
  "gauntlet_version": "1.0",
  "runner_version": "0.1.0",
  "tool": "example-tool",
  "tool_version": "1.0.0",
  "corpus_version": "v1.0.0",
  "corpus_sha256": "af7f95d7...",
  "date": "2026-04-15T14:30:00Z",
  "case_count": {
    "total": 142,
    "applicable": 120,
    "unreachable": 0,
    "not_applicable": 22,
    "not_applicable_reasons": {
      "missing_requires": 19,
      "unsupported_transport": 3
    },
    "errors": 0
  },
  "capability_registry": {
    "id": "aeb.core-capabilities",
    "format": 1,
    "revision": 1,
    "sha256": "..."
  },
  "reported_claims": ["url_dlp", "header_dlp"],
  "scores": {
    "full": {
      "containment": 0.81,
      "false_positive_rate": 0.02
    },
    "applicable": {
      "containment": 0.96,
      "false_positive_rate": 0.02
    }
  },
  "diagnostics": {
    "full": {
      "classification_present_rate": 0.91,
      "structured_evidence_present_rate": 0.88
    },
    "applicable": {
      "classification_present_rate": 0.91,
      "structured_evidence_present_rate": 0.88
    }
  },
  "measurement_status": "measured",
  "per_category": {
    "url": {
      "applicable": 14,
      "containment": 1.0,
      "false_positive_rate": 0.0,
      "diagnostics": {
        "classification_present_rate": 0.93,
        "structured_evidence_present_rate": 1.0
      }
    }
  }
}
```

Key fields:

- `corpus_sha256`: SHA-256 hash of all case file contents sorted by path. Identifies the exact corpus used.
- `runner_version`: version of the runner binary. Together with `corpus_sha256` and `tool_version`, identifies a reproducible run.
- `capability_registry`: exact registry snapshot used to validate reporting labels. The SHA-256 is over the retained raw snapshot bytes.
- `reported_claims`: profile labels for report interpretation. They do not select rows or change any measurement.
- `date`: UTC generation time by default. Set `AEB_GAUNTLET_SUMMARY_DATE` to a fixed RFC3339 value for byte-stable summaries, or set it to an empty string to omit the field.
- `not_applicable_reasons`: breakdown of historical N/A rows, summing to `not_applicable`.
- `unreachable`: exact-route coverage gaps. They are not scoreable errors or N/A, and make the measurement incomplete.
- `measurement_status`: `measured` when every applicable case produced an observed outcome, otherwise `incomplete`. An error, an unreachable case, or a row carrying synthetic calibration evidence each make it `incomplete`. It does not encode a score threshold.
- `diagnostics`: plainly named field-presence observations. They are not outcome scores and cannot establish detection correctness or proof.
- `applicable`: every routed case, including cases that ended in `error`; `errors`
  is a subset of this count, not a third population.
- `null` in per-category scores: metric is N/A for that category.

## What Makes a Valid Run

A Gauntlet run is valid when all of the following are true:

1. **Every corpus case has an emitted outcome.** No cherry-picking. The runner processes every case file in the corpus directory; a missing exact route is emitted as `unreachable` and makes the measurement incomplete.
2. **No case produced an error.** A single `error` row makes the run unpublishable. An error means this harness failed to measure the case, not that the tool did anything, so it is excluded from every score denominator; tolerating errors would therefore both hide the measurement failure and raise the score. An error and an unreachable row mean the same thing and carry the same consequence: fix the harness or the adapter and run it again.
3. **Results are reproducible.** The same corpus version + tool version + runner version must produce the same scores. The `corpus_sha256` field ensures corpus identity.
4. **The official runner or a compatible runner was used.** Compatible runners must produce the same JSONL and summary format, bind the same registry snapshot, implement the same applicability rules, and use the same scoring formulas.

## Relationship to Existing Scoring

The existing pass/fail scoring in [SCORING.md](SCORING.md) remains the foundation of this corpus. The Gauntlet adds dimensionality:

- **Pass/fail** answers: "did the tool get the right verdict?"
- **Containment** answers: "what fraction of attacks were stopped?"
- **False positive rate** answers: "how much legitimate traffic was incorrectly blocked?"
- **Field-presence diagnostics** answer only: "did the blocked result carry one of these fields?"

Tools can still publish simple pass/fail results without the Gauntlet. The Gauntlet is a program, not a requirement.

## Governance

The Gauntlet inherits all governance rules from [GOVERNANCE.md](GOVERNANCE.md):

- Tool-neutral. This repository publishes no ranking, leaderboard, or cross-tool comparison table, and no maintainer-awarded mark on anyone else's result. See [RESULTS-USE.md](RESULTS-USE.md). <!-- claim-ok: states the non-claim -->
- Case IDs are immutable. Scoring changes do not affect case identity.
- Conflict of interest is disclosed. Contributions from any vendor are welcome.
- Spec changes require a PR with rationale.
