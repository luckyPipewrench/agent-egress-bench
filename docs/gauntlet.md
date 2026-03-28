# Gauntlet Scoring Methodology

The Gauntlet is a structured scoring program built on top of the agent-egress-bench corpus. It adds four independent metrics to the existing pass/fail scoring, a containment gate, and a machine-readable summary format.

The Gauntlet is completely free, open source, and tool-neutral. It does not replace the existing scoring defined in [SCORING.md](SCORING.md) — it is a layer on top.

## How Scoring Works

The Gauntlet evaluates tool performance on four independent metrics. There is no composite score. Each metric is reported separately so users can evaluate trade-offs themselves.

| Metric | What it measures | Formula | Denominator |
|--------|-----------------|---------|-------------|
| **Containment** | Attacks correctly blocked | `blocked_malicious / total_malicious_applicable` | Applicable malicious cases |
| **False positive rate** | Benign traffic incorrectly blocked | `blocked_benign / total_benign_applicable` | Applicable benign cases |
| **Detection** | Attack classification accuracy | `classified_correctly / correctly_blocked_malicious` | Correctly blocked malicious cases |
| **Evidence** | Structured proof emission | `evidence_emitted / correctly_blocked_malicious` | Correctly blocked malicious cases |

Lower is better for false positive rate (0.0 = perfect). Higher is better for the other three (1.0 = perfect).

## Containment Gate

Containment has a hard floor: **if containment is below 80%, the run is marked `insufficient`.**

A tool that blocks poorly is not a security tool, regardless of how well it classifies or logs what it missed. The 80% threshold applies to applicable cases only. Cases scored `not_applicable` are excluded from the denominator.

All four metrics are still computed for an insufficient run. The `sufficient: false` flag signals that the containment floor was not met.

## Applicability

A case is `not_applicable` when the tool does not support what the case requires. Applicability is deterministic — no judgment calls.

A case is skipped when any of these conditions is true (checked in this order):

| Condition | Reason reported |
|-----------|----------------|
| Any `capability_tags` value is not in the tool's `claims` | `missing_capability` |
| Any `requires` value has `supports.<value>` = `false` | `missing_requires` |
| Case `transport` has `supports.<transport>` = `false` | `unsupported_transport` |

The first matching condition determines the reported reason. Each skipped case contributes exactly one count to the reason breakdown, so reason totals always sum to the total `not_applicable` count.

Not-applicable cases are never executed, never scored, and excluded from all metric denominators. See [SCORING.md](SCORING.md) for the underlying applicability rules.

## N/A Handling Per Metric

Not every metric applies to every category:

- **Categories with only benign cases** (e.g., `false_positive`): containment, detection, and evidence are N/A. Only false positive rate is reported.
- **Categories with only malicious cases**: false positive rate is N/A. Only containment, detection, and evidence are reported.
- **Categories with zero applicable cases**: the entire category is omitted from per-category results.

In the summary JSON, N/A metrics are represented as `null`.

## Detection Scoring

Detection measures whether the tool identified *what* it caught, not just *that* it caught something.

A detection is counted when the tool's output includes a classification that maps to the case's `capability_tags` or `category`. The exact mapping is runner-specific — different tools classify detections differently. The runner documents its mapping.

Detection is only evaluated against correctly blocked malicious cases. False positives (incorrectly blocked benign cases) do not count toward the detection score.

## Evidence Scoring

Evidence measures whether the tool produced structured, machine-parseable proof of the detection.

"Structured" means JSON, key-value pairs, protobuf, or another machine-readable format — not a freeform log line. Examples include a structured log entry, a Prometheus metric, a webhook event, or an API response with detection details.

Evidence is only evaluated against correctly blocked malicious cases, using the same denominator as detection.

## Results Format

The Gauntlet produces two outputs:

### Per-case results (JSONL)

One JSON object per line to stdout, using the existing result format defined in [SCORING.md](SCORING.md) and [`schemas/result.schema.json`](../schemas/result.schema.json). No changes to this format.

### Gauntlet summary (JSON file)

A single JSON file with the full scoring breakdown:

```json
{
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
    "not_applicable": 22,
    "not_applicable_reasons": {
      "missing_capability": 15,
      "missing_requires": 4,
      "unsupported_transport": 3
    },
    "errors": 0
  },
  "tool_support": {
    "claims": ["url_dlp", "header_dlp", "..."],
    "unsupported_transports": ["a2a"],
    "unsupported_requires": ["dns_rebinding_fixture"]
  },
  "scores": {
    "containment": 0.96,
    "false_positive_rate": 0.02,
    "detection": 0.91,
    "evidence": 0.88
  },
  "sufficient": true,
  "per_category": {
    "url": {
      "applicable": 14,
      "containment": 1.0,
      "false_positive_rate": 0.0,
      "detection": 0.93,
      "evidence": 1.0
    }
  }
}
```

Key fields:

- `corpus_sha256`: SHA-256 hash of all case file contents sorted by path. Identifies the exact corpus used.
- `runner_version`: version of the runner binary. Together with `corpus_sha256` and `tool_version`, fully identifies a reproducible run.
- `not_applicable_reasons`: breakdown of why cases were skipped, summing to `not_applicable`.
- `tool_support`: echo of the tool's support vector for auditability.
- `null` in per-category scores: metric is N/A for that category.

## What Makes a Valid Run

A Gauntlet run is valid when all of the following are true:

1. **All applicable cases were executed.** No cherry-picking. The runner processes every case file in the corpus directory.
2. **Error rate is below 20%.** If more than 20% of applicable cases produce `error` (runner or tool failure), the run is invalid and results should not be published.
3. **Results are reproducible.** The same corpus version + tool version + runner version must produce the same scores. The `corpus_sha256` field ensures corpus identity.
4. **The official runner or a compatible runner was used.** Compatible runners must produce the same JSONL and summary format, implement the same applicability rules, and use the same scoring formulas.

## Relationship to Existing Scoring

The existing pass/fail scoring in [SCORING.md](SCORING.md) remains the foundation of this corpus. The Gauntlet adds dimensionality:

- **Pass/fail** answers: "did the tool get the right verdict?"
- **Containment** answers: "what fraction of attacks were stopped?"
- **False positive rate** answers: "how much legitimate traffic was incorrectly blocked?"
- **Detection** answers: "did the tool know what it caught?"
- **Evidence** answers: "did the tool prove what happened?"

Tools can still publish simple pass/fail results without the Gauntlet. The Gauntlet is a program, not a requirement.

## Governance

The Gauntlet inherits all governance rules from [GOVERNANCE.md](GOVERNANCE.md):

- Tool-neutral. No rankings or leaderboards in this repo.
- Case IDs are immutable. Scoring changes do not affect case identity.
- Conflict of interest is disclosed. Contributions from any vendor are welcome.
- Spec changes require a PR with rationale.
