# Runner Contract

A runner connects a specific tool to the benchmark corpus. This document defines the contract every runner must satisfy.

**JSON Schemas:** [`schemas/result.schema.json`](../schemas/result.schema.json) (result lines), [`schemas/tool-profile.schema.json`](../schemas/tool-profile.schema.json) (tool profiles)

**Starter template:** [`examples/runner-template/`](../examples/runner-template/)

## Can my tool be integrated?

The built-in proxy adapter can drive a tool only when the tool exposes one of
the transport shapes the runner knows how to exercise. A custom runner can
support other shapes, but it must still produce the same JSONL output and must
not substitute one transport for another.

| Tool shape | Current status | What the runner can prove |
|------------|----------------|---------------------------|
| Forward proxy with a fetch endpoint such as `/fetch?url=...` | Supported by the proxy adapter as `fetch_proxy` | URL, request-body, header, response-content, and fetch-routed cases when the tool exposes the expected endpoint, accepts the case method/body/headers, and returns an observable block signal |
| CONNECT-capable forward proxy | Supported by the proxy adapter as `http_proxy` | HTTP CONNECT and TLS-interception cases when the tool can be configured as an HTTPS forward proxy |
| Reverse proxy or API gateway with `listen` and `upstream` routing semantics | Not supported by the proxy adapter today | A custom runner is required; the current adapter cannot route arbitrary case URLs through this shape |
| In-process SDK or library | Not supported by the proxy adapter today | A custom runner or wrapper service is required, and the result should declare only the transports it can actually exercise |
| MCP gateway | Not supported by a generic adapter today | Tool-specific MCP stdio or MCP HTTP commands can be driven now; a protocol-first MCP gateway adapter is planned |

If none of the supported shapes match your architecture, mark the unmatched
transports as unsupported in `supports` or write a tool-specific runner. Do not
force a tool through the wrong shape just to get a numeric result.

## Input

1. A directory of case JSON files
2. A tool profile JSON file

## Output

One JSON object per case, written to stdout (one per line, JSONL):

> `--stats` is the one exception to this contract. It reports the loaded corpus rather than running it, so it writes a human-readable Markdown snapshot to stdout and exits without producing JSONL or a summary. It requires `--cases` and ignores the tool-profile and adapter flags. `make stats`, `make stats-update` and `make check-stats` are its only intended callers.

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

### Managed command hooks

The Go runner can either target already-running endpoints or start
operator-provided commands with managed command hooks. Managed commands receive
endpoint and fixture values through environment variables. The runner does not
parse or mutate tool configuration.

Available managed-command environment variables:

| Variable | Meaning |
| --- | --- |
| `AEB_PROXY_ADDR` | Host:port the managed forward/fetch proxy command should listen on |
| `AEB_SCAN_ADDR` | Host:port the managed scan API command should listen on |
| `AEB_MCP_HTTP_ADDR` | Host:port the managed MCP HTTP command should listen on |
| `AEB_MCP_HTTP_URL` | URL corresponding to `AEB_MCP_HTTP_ADDR` |
| `AEB_HTTP_FIXTURE_ADDR` | HTTP fixture address |
| `AEB_TLS_FIXTURE_ADDR` | HTTPS fixture address for intercepted request/response cases |
| `AEB_TLS_CA_FILE` | Fixture CA certificate path |
| `AEB_TLS_CA_KEY_FILE` | Fixture CA private-key path |
| `AEB_WS_FIXTURE_ADDR` | WebSocket fixture address |
| `AEB_DNS_FIXTURE_ADDR` | DNS fixture address |
| `AEB_MCP_HTTP_FIXTURE_URL` | MCP HTTP upstream fixture URL |

### MCP stdio upstream observation

Some `mcp_stdio` cases need a controlled upstream response, and every MCP
stdio allow needs independent proof that the request reached upstream. For
those cases the runner opens a loopback TCP listener that speaks one
line-delimited JSON-RPC message per line and sets this environment variable on
the evaluated `--mcp-cmd` process:

| Variable | Meaning |
| --- | --- |
| `AEB_MCP_STDIO_UPSTREAM_ADDR` | Host:port of the runner-owned line-delimited JSON-RPC upstream for this case |

This is an explicit, tool-neutral opt-in contract. Configure the evaluated
tool's own command or configuration to use that address as its MCP stdio
upstream; for example, a tool with a TCP-upstream option could be launched as
`my-mcp-proxy --upstream-tcp "$AEB_MCP_STDIO_UPSTREAM_ADDR"`. The runner never
parses a separator in `--mcp-cmd`, appends a backend command, modifies the
command string, or passes a proof file descriptor/token to the tool.

The listener records matching JSON-RPC requests itself. An allow is credited
only when every required request arrives at that listener in order (including
every call in an under-budget sequence). A block requires a structured,
verifiable deny signal, such as an MCP JSON-RPC policy error; a bare clean exit
with no output and no runner-owned upstream observation is unprovable and
therefore returns adapter verdict `skip`. For client-only cases, a complete
runner-owned upstream observation can still prove `allow` even when a
pipelining proxy exits before reading or emitting a response.
Structured policy denies remain `block` even when they deliberately do not
reach that listener. A command that completes without either a structured block
signal or the required observation returns adapter verdict `skip`; for an otherwise-applicable case,
the Gauntlet runner records that as `actual_verdict: "error"`, `score: "error"`,
and notes `adapter skip: mcp_stdio_upstream_observation_missing`. A command
failure is an adapter error, not an observation skip. This means an integration
must expose a compatible upstream surface to score allow outcomes; it must not
rely on runner-side command rewriting.

### Domain blocklist seeding

Cases with `capability_tags: ["domain_blocklist"]` require the runner to configure the tool's blocklist with benchmark-specific test domains before running. The current test domain is:

- `exfil-collector.example.net` (IANA-reserved, no real DNS resolution)

If your tool does not support domain blocklisting, set `supports.domain_blocklist` to `false` and these cases will be scored `not_applicable`.

### Budget enforcement

Cases with `requires: ["budget_enforcement"]` require the runner or tool under test to enforce the call-count budget metadata carried in the case payload. The current single-session cases use MCP `mcp_tool_sequence` payloads with neutral fields:

- `budget_scope: "per_subject"`
- `subject_id`
- `budget_limit_calls`
- `over_budget_call_id` for block-expected cases

The scoring boundary is off-by-one sensitive: a limit of `N` must allow the first `N` subject calls and block the `N+1` call. A conforming runner must drive the MCP sequence to the tool's MCP proxy in order and score the block case as detected only when the first block occurs at or after `over_budget_call_id`. A block before `over_budget_call_id` is a failure for the budget case because another policy or an incorrect budget boundary blocked too early. Benign controls that make exactly `budget_limit_calls` calls must not be blocked.

Weighted fields such as `cost_units` and `budget_limit_units` are intentionally not part of the contract because call-count budget tools cannot score them.

### Reserved untrusted sinks

Some opaque-entropy cases must be sent to a reachable destination that is not in
the tool's trusted-destination set. The corpus reserves these synthetic hosts for
that purpose:

- `ws-exfil-sink.test` for WebSocket frame cases
- `a2a-exfil-sink.test` for A2A message cases using `payload.target_url`

A runner should route these hosts deterministically to a local or otherwise
controlled sink, but the routing mechanism must not make the hostname trusted.
For tools with an SSRF floor, use an IP-scoped reachability exception or
equivalent local fixture route rather than adding the sink hostname to trusted
domains. This keeps benign trusted-fixture controls allowed while still scoring
whether opaque high-entropy content is blocked when sent to an untrusted sink.

## Applicability Check

Before running a case, the runner must check applicability:

1. Every `requires` value must be satisfied by the tool profile's `supports`
2. The case `transport` must be satisfied by the tool profile's `supports`

If either check fails, emit `score: "not_applicable"` and `actual_verdict: "not_applicable"` without running the case.

Do not use detector-specific `requires` to skip benign `allow` controls. Those cases measure false positives and should run whenever the transport and any true runtime prerequisites are available.

A tool is scored only on capabilities it claims through `supports`. Cases outside
that declared surface are `not_applicable`, not failures. A mostly
`not_applicable` result is a statement about the integration and tool scope that
was measured, not a statement about the tool's overall quality.

## Observable Verdict Rules

### HTTP-shaped cases

HTTP-facing tools can expose several different shapes. They are not
interchangeable:

| Shape | Corpus transport | Current runner support |
|-------|------------------|------------------------|
| Fetch-style endpoint | `fetch_proxy` | Supported by the proxy adapter as an HTTP request to `/fetch?url=...` on the configured proxy address |
| CONNECT forward proxy | `http_proxy` | Supported by the proxy adapter through HTTPS proxy settings and runner-managed fixtures |
| Reverse proxy or API gateway | No generic transport today | Not supported by the proxy adapter; write a custom runner or mark the unmatched transports unsupported |

For supported HTTP-shaped cases, map observations to verdicts this way:

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
| Structured, verifiable block signal | `block` |
| Bare clean exit with no structured deny signal or upstream proof | `skip` |
| Message forwarded without block signal and observed at the runner-owned upstream | `allow` |
| Transport or runner failure | `error` |

For budget-enforcement MCP sequences, runners should include evidence fields such as `budget_limit_calls`, `blocked_call_id`, `blocked_call_index`, and `over_budget_call_id` when a block is observed. When a budget block is observed, the runner must include `budget_block_timing` (`at_or_after_over_budget` or `before_over_budget`); a budget-block case scores `pass` only when the timing is `at_or_after_over_budget`, so a block that cannot prove it allowed the first `budget_limit_calls` calls does not pass.

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

This checks field presence, enum validity, and score consistency. Most cases pass when `actual_verdict == expected_verdict`; sequence-boundary cases such as budget enforcement may still fail when evidence shows the tool blocked at the wrong step.

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
