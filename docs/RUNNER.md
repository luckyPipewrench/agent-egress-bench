# Runner Contract

A runner connects a specific tool to the benchmark corpus. This document defines the contract every runner must satisfy.

**JSON Schemas:** [`schemas/result.schema.json`](../schemas/result.schema.json) (result lines), [`schemas/tool-profile.schema.json`](../schemas/tool-profile.schema.json) (tool profiles)

**Starter template:** [`examples/runner-template/`](../examples/runner-template/)

## Input

1. A directory of case JSON files
2. A tool profile JSON file

## Output

One JSON object per case, written to stdout (one per line, JSONL):

```json
{
  "case_id": "url-dlp-aws-key-001",
  "tool": "pipelock",
  "tool_version": "0.3.6",
  "expected_verdict": "block",
  "actual_verdict": "block",
  "score": "pass",
  "evidence": {
    "http_status": 403,
    "matched_signal": "blocked_http_status"
  },
  "notes": ""
}
```

### Required output fields

| Field | Type | Description |
|-------|------|-------------|
| `case_id` | string | The case ID |
| `tool` | string | Tool name from profile |
| `tool_version` | string | Tool version from profile |
| `expected_verdict` | string | From the case file |
| `actual_verdict` | string | `block`, `allow`, `not_applicable`, or `error` |
| `score` | string | `pass`, `fail`, `not_applicable`, or `error` |
| `evidence` | object | Tool-specific evidence (freeform) |
| `notes` | string | Optional context |

## Runner Setup

Some cases require tool-specific configuration before running. These requirements are documented in each case's `notes` field and in this section.

### Domain blocklist seeding

Cases with `capability_tags: ["domain_blocklist"]` require the runner to configure the tool's blocklist with benchmark-specific test domains before running. The current test domain is:

- `exfil-collector.example.net` (IANA-reserved, no real DNS resolution)

If your tool does not support domain blocklisting, set `supports.domain_blocklist` to `false` and these cases will be scored `not_applicable`.

### Budget enforcement

Cases with `requires: ["budget_enforcement"]` require the runner or tool under test to enforce the budget metadata carried in the case payload. The current single-session cases use MCP `mcp_tool_sequence` payloads with neutral fields such as `budget_scope`, `budget_limit_units`, per-call `cost_units`, and `over_budget_call_id`. A conforming runner must treat the named over-budget call as the action that should be blocked, while earlier in-budget calls should be allowed.

## Applicability Check

Before running a case, the runner must check applicability:

1. Every `requires` value must be satisfied by the tool profile's `supports`
2. The case `transport` must be satisfied by the tool profile's `supports`

If either check fails, emit `score: "not_applicable"` and `actual_verdict: "not_applicable"` without running the case.

Do not use detector-specific `requires` to skip benign `allow` controls. Those cases measure false positives and should run whenever the transport and any true runtime prerequisites are available.

## Observable Verdict Rules

### HTTP and fetch cases

| Observation | Verdict |
|-------------|---------|
| Explicit deny status (e.g. 403, 502 with block marker) | `block` |
| Deny marker in response body (tool-specific) | `block` |
| Successful upstream response without deny marker | `allow` |
| Runner or tool failure | `error` |

### MCP cases

| Observation | Verdict |
|-------------|---------|
| Request or result withheld | `block` |
| Explicit policy deny in response | `block` |
| Process exits with deny semantics | `block` |
| Structured block signal | `block` |
| Message forwarded without block signal | `allow` |
| Transport or runner failure | `error` |

## Verdict Mapping

Tools may use different mechanisms to express blocking. Runners must document their mapping. For example, Pipelock returns HTTP 403 for blocked proxy requests and a JSON-RPC error for blocked MCP calls.

Not all tools will use the same signals. The runner is responsible for normalizing tool-specific behavior into the `actual_verdict` enum.

## Summary Output

After all cases, the runner should print a summary line to stderr:

```
results: 22 passed, 3 failed, 10 not_applicable, 0 errors (35 total)
```

## Validating Output

The validator can check your runner's JSONL output and tool profile:

```bash
cd validate && go build -o aeb-validate .
./aeb-validate results path/to/results.jsonl
./aeb-validate profile path/to/tool-profile.json
```

This checks field presence, enum validity, and score consistency (e.g., `actual_verdict == expected_verdict` should produce `score: "pass"`).

## Receipt-Scoring Profile (optional)

The reference runner can emit a [receipt-scoring profile](RECEIPT-SCORING.md) alongside the Gauntlet summary. The profile records, per applicable case, whether the tool blocked the action, explained it, produced a signed receipt, produced one that is independently verifiable, and whether it blocked a benign baseline. Output validates against [`schemas/receipt-scoring-profile.schema.json`](../schemas/receipt-scoring-profile.schema.json).

Flags:

- `--emit-receipt-profile <path>`: write the profile JSON to `<path>`. Default off.
- `--receipt-verifier-file <path>`: optional JSON file describing the tool's receipt verifier (shape: the `verifier` object in the receipt-scoring schema). Omitted means "no verifier shipped" and the runner emits a degraded honest verifier block.
- `--multifile-cases <dir>`: optional directory of multi-file MCP-drift cases. The reference profile uses `cases/mcp-drift`; omitting this flag runs only the single-file JSON corpus.

Reproducibility:

- Per-case rows are sorted by `case_id` and the runner emits no timestamps in the profile. Repeated runs against the same corpus and tool profile produce byte-identical output. A relying party can reproduce a published profile by running the same command and `sha256sum`-comparing the result.
- The Gauntlet summary includes a `date` by default. For byte-stable summary JSON, set `AEB_GAUNTLET_SUMMARY_DATE` to a fixed RFC3339 value, or set it to an empty string to omit the field.

Example shape for a tool-specific benchmark run:

```bash
cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
export PIPELOCK_BIN=/path/to/pipelock
export PIPELOCK_BENCH_CONFIG="$PWD/examples/pipelock/pipelock-benchmark.yaml"
/tmp/aeb-gauntlet \
  --adapter proxy \
  --scan-token bench-test-token \
  --mcp-cmd "\"$PIPELOCK_BIN\" mcp proxy --config \"$PIPELOCK_BENCH_CONFIG\" -- cat" \
  --managed-proxy-cmd './examples/pipelock/start-proxy-for-benchmark.sh "$PIPELOCK_BIN"' \
  --managed-mcp-http-cmd './examples/pipelock/start-mcp-http-for-benchmark.sh "$PIPELOCK_BIN"' \
  --fixtures \
  --cases ./cases \
  --multifile-cases ./cases/mcp-drift \
  --profile examples/pipelock/tool-profile.json \
  --output /tmp/gauntlet.json \
  --emit-receipt-profile /tmp/pipelock.json \
  --receipt-verifier-file examples/pipelock/receipt-verifier.json \
  --timeout 15s

# 3. Compare byte-for-byte with the committed artifact.
sha256sum /tmp/pipelock.json profiles/pipelock.json
diff -q /tmp/pipelock.json profiles/pipelock.json
```

Published profile reproduction should name the exact tool binary and corpus commit
used for the run. A mismatch means the corpus drifted, the tool drifted, or the
runner changed. A relying party reproducing a profile should treat a mismatch as a
signal to investigate, not to trust either side blindly.
