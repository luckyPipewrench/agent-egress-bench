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
| MCP gateway | Narrow generic support today via `--adapter mcp-gateway` with a gateway plugin | Streamable HTTP only. An `mcp_http` case drives an ordered `tools/call` sequence (one or more messages, blocked at the first denied call), the `tools/list` tool-definition path, or the `mcp_tool_result` path that scans what a tool returns. The adapter does not claim an `mcp_stdio` case merely because it can send similar semantics over HTTP. When the plugin declares a `start_command`, the runner starts the gateway, waits for its ready address, and runs the fixture-registration command to wire it to the runner-owned upstream; the managed path is proven end-to-end only against an in-repo synthetic gateway. The adapter binds an `Mcp-Session-Id` when the gateway assigns one on initialize and replays it on the case's later requests. Resources, prompts, multi-server topologies, and a run against an unrelated third-party gateway are still out of scope. Tool-specific MCP stdio or MCP HTTP commands remain the fuller path. See [GATEWAY-ADAPTER.md](GATEWAY-ADAPTER.md) |

If none of the supported shapes match your architecture, retain an honest
`supports` declaration for v3 publication and write a tool-specific runner.
The declaration does not select cases. Do not force a tool through the wrong
shape just to get a numeric result.

## Input

1. A directory of case JSON files
2. A tool profile JSON file

## Output

One JSON object per case, written to stdout (one per line, JSONL):

> `--stats` and `--report` are the exceptions to this contract. It reports the loaded corpus rather than running it, so it writes a human-readable Markdown snapshot to stdout and exits without producing JSONL or a summary. It requires `--cases` and ignores the tool-profile and adapter flags. `make stats`, `make stats-update` and `make check-stats` are its only intended callers. `--report` likewise runs no cases: it reads an artifact directory an earlier run left behind and writes Markdown to the path given by `--report-output`, or to stdout when that is `-`.

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
| `actual_verdict` | string | `block`, `allow`, `not_applicable`, `unreachable`, or `error` |
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
tool's own command or configuration to make that address its MCP stdio
upstream; for example, a tool with a TCP-upstream option could be launched as
`my-mcp-proxy --upstream-tcp "$AEB_MCP_STDIO_UPSTREAM_ADDR"`. A stdio-only
backend can satisfy the same contract with a transparent stdio-to-TCP bridge;
the bridge must pass the line-delimited JSON-RPC stream in both directions, not
merely consume its input. The runner never parses a separator in `--mcp-cmd`,
appends a backend command, modifies the command string, or passes a proof file
descriptor/token to the tool.

This runner-owned observation is a **versioned runner-contract change**. To
have MCP stdio cases scored, an evaluated tool must route its MCP stdio
upstream to `$AEB_MCP_STDIO_UPSTREAM_ADDR`, either natively or through the
documented stdio-to-TCP bridge (or any equivalent forwarding proxy). A tool
that does not satisfy the contract receives adapter verdict `skip` because its
allow outcome is unprovable; it is never credited as a silent false allow.

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

If your tool does not support domain blocklisting, retain that fact in
`supports.domain_blocklist` and implement an adapter route that proves the
input and verdict. The declaration alone never skips these cases.

### Budget enforcement

Cases carrying the `denial_of_wallet` capability tag exercise the call-count budget metadata in the case payload. They gate on `mcp_chain_memory`, the surface the runner needs in order to deliver the sequence and observe a verdict, and never on `budget_enforcement` itself. A tool that does not enforce budgets is still measured on these cases and is expected to miss the malicious ones; that miss is the finding, not a reason to skip the case. The current single-session cases use MCP `mcp_tool_sequence` payloads with neutral fields:

- `budget_scope: "per_subject"`
- `subject_id`
- `budget_limit_calls`
- `over_budget_call_id` for block-expected cases

The scoring boundary is off-by-one sensitive: a limit of `N` must allow the first `N` subject calls and block the `N+1` call. A conforming runner must drive the MCP sequence to the tool's MCP proxy in order and score the block case as detected only when the first block occurs exactly at `over_budget_call_id`. A block before `over_budget_call_id` is a failure because another policy or an incorrect budget boundary blocked too early. A block after `over_budget_call_id` is also a failure because the first forbidden call already reached the target. Benign controls that make exactly `budget_limit_calls` calls must not be blocked.

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

## Result State Check

Before scoring a case, the runner must establish all of the following:

1. The adapter has an exact route for the declared wire transport, semantic surface, and lifecycle.
2. The adapter proves it delivered that exact input.
3. The adapter observes a request-correlated `allow` or `block` verdict.

A missing exact route emits `actual_verdict: "unreachable"` and `score: "error"`.
It is visible in `case_count.unreachable`, excluded from measurement denominators,
and makes the run insufficient. A routed case lacking delivery proof or verdict
observation emits `actual_verdict: "error"`. A tuple declaration alone never
creates N/A.

`claims`, `supports`, `requires`, and `capability_tags` do not select cases.
The v3 profile remains in output as publication metadata. This applies to hard
variants and benign controls alike.

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

For budget-enforcement MCP sequences, runners should include evidence fields such as `budget_limit_calls`, `blocked_call_id`, `blocked_call_index`, and `over_budget_call_id` when a block is observed. When a budget block is observed, the runner must include `budget_block_timing` (`before_over_budget`, `at_over_budget`, or `after_over_budget`); a budget-block case scores `pass` only when the timing is `at_over_budget`. Earlier blocks over-enforce, while later blocks have already allowed a forbidden call to reach the target. The block response ID must match the designated request, and runner-owned observation must prove the complete ordered message prefix before that request, including calls for other subjects that are interleaved in the sequence.

## Verdict Mapping

Tools may use different mechanisms to express blocking. Runners must document their mapping. For example, Pipelock returns HTTP 403 for blocked proxy requests and a JSON-RPC error for blocked MCP calls.

Not all tools will use the same signals. The runner is responsible for normalizing tool-specific behavior into the `actual_verdict` enum.

## Summary Output

After all cases, the runner should print a summary line to stderr:

```
results: 22 passed, 3 failed, 0 unreachable, 10 not_applicable, 0 errors (35 total)
```

## Buyer-readable report

The Go runner can render a Markdown report from an artifact directory left by an existing run. Report mode does not execute cases or recalculate scores. It reads the retained facts and shows missing or malformed inputs in place.

From the repository root:

```bash
(cd runner && go run . \
  --report ../continuous-gauntlet-artifacts \
  --report-output ../continuous-gauntlet-artifacts/run-report.md)
```

Use `--report-output -` to write the report to standard output.

The renderer reads these artifacts when present:

| Artifact | Report content |
|---|---|
| `raw-summary.json` | Method versions, target product and version, profile digest, declared capabilities, scope counts, and the four metric vectors |
| `results.jsonl` | Every historical not-applicable or unreachable case ID and its recorded reason |
| `run-metadata.json` | Repository and exact method commit |
| `run-bundle.json` | Bundle status, publication eligibility, retained material digests, and candidate bindings |
| `execution-decision.json` | Execution status, failures, review notes, and publication eligibility |
| `entrypoint-command.txt` and `command.txt` | The retained reproduction commands |

The report checks every digest declared by the run bundle, checks the candidate bindings against the summary and run metadata, and checks the execution decision against the bundle. It reports these checks separately from the four metrics.

Missing facts render as `Absent from run artifacts`. Wrong types and contradictory bindings render as invalid. A malformed JSON or JSONL input leaves the rest of the report readable and marks the affected section. A partial, blocked, errored, or publication-ineligible run still produces a report with that state visible.

The summary carries `target_config_ref`, `target_config_sha256`, and `adapter_owner` when the operator declares them with `--target-config` and `--adapter-owner`, and `adapter_id` for the adapter that was selected. Adapter identity comes from that recorded field rather than from the runner command line. Anything the operator does not declare is omitted from the summary and the report names it absent, so an undeclared fact never reads as a blank the renderer failed to fill.

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

> For the pinned Pipelock release, `./scripts/run-pipelock-gauntlet.sh` is the normal operator command. The long form below is an advanced reference for adapter and receipt-profile development.

```bash
cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
export PIPELOCK_BIN=/path/to/pipelock
export PIPELOCK_BENCH_CONFIG="$PWD/examples/pipelock/pipelock-benchmark.yaml"
/tmp/aeb-gauntlet \
  --adapter proxy \
  --scan-token bench-test-token \
  --mcp-cmd "\"$PIPELOCK_BIN\" mcp proxy --config \"$PIPELOCK_BENCH_CONFIG\" --env AEB_MCP_STDIO_UPSTREAM_ADDR -- sh ./examples/pipelock/mcp-stdio-upstream-bridge.sh" \
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

# Compare byte-for-byte with the committed artifact.
sha256sum /tmp/pipelock.json profiles/pipelock.json
diff -q /tmp/pipelock.json profiles/pipelock.json
```

Published profile reproduction should name the exact tool binary and corpus commit
used for the run. A mismatch means the corpus drifted, the tool drifted, or the
runner changed. A relying party reproducing a profile should treat a mismatch as a
signal to investigate, not to trust either side blindly.
