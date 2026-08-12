# Gauntlet Methodology

The Gauntlet tests the security tool between an AI agent and the network. It does not test whether the model refuses harmful instructions. A runner sends each case through a proxy, firewall, MCP wrapper, or similar control and records the observed result.

```text
Agent (secrets, tools) --> Security tool (proxy/firewall) --> Internet
                                    ^
                           Gauntlet tests this
```

The Gauntlet is free, open source, and tool-neutral. It defines per-case result states, two independent outcome metrics, non-scoring output-field diagnostics, and a machine-readable summary format.

## Scope

### In scope

- Secret exfiltration through URL query strings, request bodies, HTTP headers, WebSocket frames, MCP arguments, A2A messages, and hostname labels
- Prompt injection in HTTP responses, MCP tool results, and A2A messages
- SSRF through private addresses, cloud metadata endpoints, encoded addresses, and DNS rebinding
- MCP tool poisoning, schema injection, drift, and multi-step exfiltration chains
- A2A Agent Card poisoning and drift
- Encoding evasion, shell obfuscation, crypto and financial data, and false-positive controls

### Out of scope

- Timing, header-ordering, HTTP/2, steganographic, and other covert channels
- Model alignment, refusal behavior, semantic manipulation, and multi-turn context poisoning
- Inbound traffic filtering
- Authentication and authorization

## Case design

Cases depend on observable wire behavior, produce deterministic expected verdicts, and remain tool-neutral. Severity and false-positive risk are informational metadata and do not affect scoring.

A logical case is either one JSON file or one MCP drift directory containing `case.yaml` plus its named snapshots. Both shapes count as one case. [`cases/MANIFEST.txt`](../cases/MANIFEST.txt) pins the loaded IDs, and [`cases/STATS.md`](../cases/STATS.md) reports loader-backed counts. [`SPEC.md`](SPEC.md) owns both case formats.

## Categories

| Category | Directory | What it tests |
| --- | --- | --- |
| URL DLP | `cases/url/` | Secrets in query strings, encoded paths, high-entropy subdomains |
| Request body DLP | `cases/request-body/` | Secrets in POST bodies |
| Header DLP | `cases/headers/` | API keys and tokens in HTTP headers |
| Response injection | `cases/response-fetch/`, `cases/response-mitm/` | Prompt injection in fetched or intercepted content |
| MCP input and tools | `cases/mcp-input/`, `cases/mcp-tool/` | Tool-call DLP, poisoned definitions, and schema injection |
| MCP chains and drift | `cases/mcp-chain/`, `cases/mcp-drift/` | Multi-step sequences and tool-definition changes |
| A2A | `cases/a2a-message/`, `cases/a2a-agent-card/` | Message scanning, Agent Card poisoning, and drift |
| WebSocket DLP | `cases/websocket-dlp/` | Frame scanning and fragment evasion |
| SSRF bypass | `cases/ssrf-bypass/` | Private addresses, cloud metadata, and encoded forms |
| Encoding and shell evasion | `cases/encoding-evasion/`, `cases/shell-obfuscation/` | Multi-layer encodings and obfuscated commands |
| Crypto and financial DLP | `cases/crypto-financial/` | Wallets, keys, seed phrases, cards, and IBANs |
| Hostname exfiltration | `cases/hostname-exfiltration/` | Data encoded in DNS hostname labels |
| False-positive suite | `cases/false-positive/` | Benign traffic that must remain allowed |

Current counts belong in [`cases/STATS.md`](../cases/STATS.md), not in this document.

## Per-case results

An active result row separates the observed verdict from the score. `actual_verdict` is `block`, `allow`, `unreachable`, or `error`. `score` is `pass`, `fail`, or `error`. Frozen historical rows can also carry `not_applicable` under their original reader.

| Result outcome | Meaning |
| --- | --- |
| `pass` | An observed `block` or `allow` satisfied the case contract |
| `fail` | An observed `block` or `allow` violated the case contract |
| `not_applicable` | Frozen historical N/A evidence, retained without reinterpretation |
| `unreachable` | The adapter has no exact route, so no measurement occurred |
| `error` | The runner, tool, delivery proof, or verdict observation failed |

## How Scoring Works

The Gauntlet evaluates tool performance on two independent outcome metrics. There is no composite score. Each score is reported separately so users can evaluate trade-offs themselves.

| Metric | What it measures | Formula | Denominator |
|--------|-----------------|---------|-------------|
| **Containment** | Attacks correctly blocked | `blocked_malicious / total_malicious` | Full or applicable malicious cases, depending on view |
| **False positive rate** | Benign traffic incorrectly blocked | `blocked_benign / total_benign` | Full or applicable benign cases, depending on view |

Lower is better for false positive rate (0.0 = perfect). Higher is better for containment (1.0 = perfect).

### Score views

The full-corpus view is primary. It keeps measured cases in the denominator and preserves frozen historical N/A treatment. An unreachable case is not a measurement and remains visible outside the denominator.

The applicable view is diagnostic. It contains cases with adapter-proven delivery and an observed verdict. A tool's declarations cannot select this view or remove a case from it.

## Measurement Status

The summary reports `measurement_status: measured` when every applicable case produced an observed outcome. It reports `measurement_status: incomplete` when any case errored, was unreachable, or carried synthetic calibration evidence.

Measurement status says whether the runner measured the declared scope. It does not judge containment or any other metric. Historical non-applicable malicious rows remain in the full-corpus denominator; error and unreachable rows are not measurements and stay outside score denominators.

Both scores are still computed for an incomplete run. The score vector reports observed target behavior, while `measurement_status` reports whether any cases lacked an observed outcome.

## Result state

An active tool profile declares registry-backed reporting claims and binds the exact capability-registry snapshot that defines them. [`RUNNER.md`](RUNNER.md) owns the profile shape. Claims report the surface a tool names; they do not decide which cases count.

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

`requires` names only what the runner needs to deliver the input and observe a trustworthy verdict: transport, runtime fixtures, and the base surface the tool must inspect. It must not carry attack-difficulty, evasion-technique, or enforcement-claim flags. Those belong in registry-backed reporting labels. This applies to malicious and benign cases alike.

### Adapter transport integrity

An adapter must execute the case's declared transport. A scan API response does not prove that a fetch proxy, forward proxy, WebSocket, MCP, or A2A transport enforced the same payload. An adapter declaration authorizes an attempt; delivery proof and a request-correlated verdict authorize scoring.

`mcp_http` cases target the tool's MCP HTTP listener. They do not prove HTTP forward-proxy enforcement. A local WebSocket fixture can also trigger SSRF protection before frame scanning, so evidence should name the enforcement layer the runner observed.

## N/A Handling Per Metric

Not every metric applies to every category:

| Category contents | Result |
| --- | --- |
| Only benign cases | Containment is N/A; only false positive rate is reported |
| Only malicious cases | False positive rate is N/A; only containment is reported |
| Zero applicable cases | The category is omitted from per-category results |

In the summary JSON, N/A metrics are represented as `null`.

## Non-scoring output-field diagnostics

V5 reports two diagnostics outside `scores`: `classification_present_rate` and `structured_evidence_present_rate`. Each uses correctly blocked malicious cases as its denominator. The first observes whether `kind`, `scanner`, `block_reason`, or an MCP `error_message` is present. The second also recognizes `decision` and `findings`.

V5 summaries validate against [`schemas/summary-v5.schema.json`](../schemas/summary-v5.schema.json). The unversioned [`schemas/summary-v4.schema.json`](../schemas/summary-v4.schema.json) remains the frozen v4 schema so historical artifacts keep their original validation contract.

These values are not detection or proof scores. A constant `block_reason: "policy"`, or an unrelated `kind`, earns the same presence observation as an accurate SSRF label. `capability_tags` and `category` do not enter either rate. A future detection score requires an edition-owned finding taxonomy with implication rules and a correctness oracle.

## Results Format

The Gauntlet produces two outputs:

### Per-case results (JSONL)

One JSON object per line goes to stdout, using the current v4 result format in [`schemas/result-v4.schema.json`](../schemas/result-v4.schema.json). Every active result line carries the exact capability-registry reference from its profile. [`RUNNER.md`](RUNNER.md) owns the delivery and output protocol.

### Gauntlet summary (JSON file)

A single JSON file with the full scoring breakdown:

```json
{
  "schema_version": 5,
  "gauntlet_version": "1.0",
  "scoring_version": "2.8",
  "runner_version": "0.4.3",
  "tool": "example-tool",
  "tool_version": "1.0.0",
  "corpus_version": "v1.0.0",
  "corpus_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "benchmark_manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "tool_profile_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
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
    "revision": 2,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "reported_claims": ["url_dlp", "header_dlp"],
  "exercised": {
    "transports": ["fetch_proxy"],
    "categories": ["url"],
    "capability_tags": ["url_dlp"]
  },
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

- `corpus_sha256`: retained SHA-256 hash of case-file contents sorted by path. It detects content changes but cannot identify file boundaries or membership.
- `benchmark_manifest_sha256`: SHA-256 over lexicographically ordered manifest entries. For each entry, write the unsigned LEB128 varint byte length of its UTF-8 key, the key bytes, the unsigned LEB128 varint byte length of its raw file bytes, then those file bytes. Keys are `cases/<relative-path>` for single-file cases and `multifile/<registered-family>/<relative-path>` for multi-file cases, with `/` separators. It identifies the exact corpus that ran.
- `runner_version`: version of the runner binary. Together with `benchmark_manifest_sha256` and `tool_version`, identifies a reproducible run.
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

The runner also prints result counters to stderr. This independent 35-case
example is not the 142-case summary above:

```text
results: 22 passed, 3 failed, 0 unreachable, 10 not_applicable, 0 errors (35 total)
```

Pass, fail, unreachable, not-applicable, and error counters must sum to the number of processed cases. In summary JSON, `case_count.applicable` is the retained name for the routed-case partition: it includes routed cases that ended in `error`, and `case_count.errors` reports that unobserved subset explicitly. It is not an observed-measurement count.

## What Makes a Valid Run

A Gauntlet run is valid when all of the following are true:

1. **Every corpus case has an emitted outcome.** No cherry-picking. The runner processes every case file in the corpus directory; a missing exact route is emitted as `unreachable` and makes the measurement incomplete.
2. **No case produced an error.** A single `error` row makes the run unpublishable. An error means this harness failed to measure the case, not that the tool did anything, so it is excluded from every score denominator; tolerating errors would therefore both hide the measurement failure and raise the score. An error and an unreachable row mean the same thing and carry the same consequence: fix the harness or the adapter and run it again.
3. **Results are reproducible.** The same corpus version + tool version + runner version must produce the same scores. The `benchmark_manifest_sha256` field ensures corpus identity.
4. **The official runner or a compatible runner was used.** Compatible runners must produce the same JSONL and summary format, bind the same registry snapshot, implement the same applicability rules, and use the same scoring formulas.

## Interpreting outputs

Per-case results and aggregate metrics answer different questions:

- **Pass/fail** answers: "did the tool get the right verdict?"
- **Containment** answers: "what fraction of attacks were stopped?"
- **False positive rate** answers: "how much legitimate traffic was incorrectly blocked?"
- **Field-presence diagnostics** answer only: "did the blocked result carry one of these fields?"

Tools can still publish simple pass/fail results without the Gauntlet. The Gauntlet is a program, not a requirement.

## Error handling and validation

A tool crash, timeout, transport failure, missing delivery proof, or unobservable verdict produces `error`, not `fail`. These states describe a failure to measure, so they stay outside score denominators and make `measurement_status` incomplete. Counting them as detection failures would misstate the target's behavior. Tolerating them would also raise a reported score by shrinking its denominator.

Synthetic calibration evidence also blocks publication. A synthetic row can remain in a denominator because the adapter asserted an outcome, but it is not an observation from the target.

The Go validator in `validate/` is the authoritative checker for active case files, result rows, and tool profiles. It enforces structural and cross-field rules. The JSON Schemas declare public interchange shapes, while [`contracts/artifacts.json`](../contracts/artifacts.json) and `make check-contracts` bind their versions and identities to source. The active Go paths do not compile those schemas yet, so a schema file alone is not proof that the runner enforces its full shape.

## Versions and reproducibility

[`GOVERNANCE.md`](GOVERNANCE.md) owns artifact versioning and compatibility. Seven fields identify an active run:

| Field | What it tracks | Source |
| --- | --- | --- |
| `corpus_version` | Tag or commit of the case corpus | Repository tag or commit |
| `scoring_version` | Scoring, applicability, and publication rules | Runner constant |
| `corpus_sha256` | Retained legacy content digest; not exact corpus identity | Computed at runtime |
| `benchmark_manifest_sha256` | Exact loaded case paths, boundaries, and bytes | Computed at runtime |
| `runner_version` | Runner binary generation | Runner constant |
| `tool_profile_sha256` | Exact tool profile | Computed at runtime |
| `capability_registry` | Exact reporting-label registry snapshot | Profile and active results |

`corpus_version` and `scoring_version` decide whether a result is stale. The remaining fields make a run reproducible and auditable.

Scoring version 2.8 moves classification and evidence field-presence rates out of `scores` and into non-scoring diagnostics. Scoring version 2.7 removed the hidden containment threshold from publication decisions. Scoring version 2.6 moved applicability from profile claims to adapter-proven delivery and verdict observation. Results on opposite sides of those boundaries remain records of their own rules, but they are not interchangeable.

Historical N/A rows keep their frozen meaning. Active execution represents a missing route as `unreachable`, leaves it outside score denominators, and marks the measurement incomplete.

## Running the Gauntlet

For the reviewed Pipelock release, use the portable entry point from a clean Linux clone:

```bash
./scripts/run-pipelock-gauntlet.sh
```

The entry point pins the released binary, supplies managed commands, enables local fixtures, includes the multi-file corpus, validates result rows, and retains hash-bound evidence. A plain proxy run without the required fixtures can score fixture failures as security outcomes, so it is not a substitute.

For another tool or adapter development, use the Go runner. It writes JSONL results to stdout and a summary to the path passed through `--output`. [`RUNNER.md`](RUNNER.md) defines the commands, adapters, delivery proof, and output protocol.

## Publishing a result

Each vendor, lab, or customer runs the Gauntlet against its own target and owns the result it publishes. This repository stores no third-party result and awards no verification mark. [`RESULTS-USE.md`](RESULTS-USE.md) defines the permitted assurance labels and the identifying facts that must travel with a public result.

The maintainer-operated Pipelock records under `gauntlet-site/results/pipelock/` are disclosed first-party regression evidence. The append-only record chain and `latest-verified` pointer do not create an independence claim.

## Disputes and supersession

Open a GitHub Discussion to dispute a case verdict. Name the case ID, proposed change, and supporting evidence. If the proposal is accepted, add a new case with `supersedes` pointing to the original. The original stays in the corpus and the runner executes both. [`GOVERNANCE.md`](GOVERNANCE.md) owns case immutability and supersession.

## Neutrality

The Pipelock author created this corpus and maintains its first-party reference lane. Cases test observable behavior rather than implementation choices. Third parties own their results, and anyone may publish an adverse Pipelock result without notice or approval. This repository publishes no ranking, leaderboard, or cross-tool comparison table. <!-- claim-ok: states the non-claim -->

[`GOVERNANCE.md`](GOVERNANCE.md) owns neutrality and contribution policy. [`ADOPTION.md`](ADOPTION.md) explains how to build a runner and publish results.
