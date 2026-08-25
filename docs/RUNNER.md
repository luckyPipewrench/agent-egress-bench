# Runner Contract

A runner connects a specific tool to the benchmark corpus. This document defines the contract every runner must satisfy.

**JSON Schemas:** [`schemas/result-v6.schema.json`](../schemas/result-v6.schema.json) (active result lines), [`schemas/result-v4.schema.json`](../schemas/result-v4.schema.json) and [`schemas/result-v5.schema.json`](../schemas/result-v5.schema.json) (frozen result lines), and [`schemas/tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json) (tool profiles). [SCHEMAS.md](SCHEMAS.md) explains schema identifiers, the discovery catalog, and adapter quickstarts.

**Cross-field result contract:** [`contracts/result-states-v6.json`](../contracts/result-states-v6.json). [`gauntlet.md`](gauntlet.md) explains the same matrix and owns its scoring meaning.

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
| MCP Streamable HTTP listener | Supported by the proxy adapter with `--mcp-http-url` and `--fixtures` | Request-shaped cases plus fixture-proven tool definitions, tool results, and single-server temporal inventory changes. Temporal runs negotiate and reuse one live `Mcp-Session-Id`; exact upstream identity, method, and payload fingerprints prevent local responses, mutation, or replay from proving delivery. |
| Reverse proxy or API gateway with `listen` and `upstream` routing semantics | Not supported by the proxy adapter today | A custom runner is required; the current adapter cannot route arbitrary case URLs through this shape |
| In-process SDK or library | Not supported by the proxy adapter today | A custom runner or wrapper service is required, and the result should declare only the transports it can actually exercise |
| MCP gateway | Narrow generic support today via `--adapter mcp-gateway` with a gateway plugin | Streamable HTTP only. A native `mcp_http` case can drive one tool call, a dependent call sequence with final-sink proof, one tool result, one tool inventory via the `tools/list` tool-definition path, or a single-server post-approval inventory change. The adapter does not claim an `mcp_stdio` case merely because it can send similar semantics over HTTP: applicability comes from delivering the case's exact wire input, so a transport substitution is a different measurement wearing the same name. Temporal stdio and multi-server drift are likewise out of scope, so a result cannot mislabel the transport or topology it was taken on. When the plugin declares a `start_command`, the runner starts the gateway, waits for its ready address, and runs the fixture-registration command to wire it to the runner-owned upstream; the managed path is proven end-to-end only against an in-repo synthetic gateway. The adapter binds an `Mcp-Session-Id` from a validated initialize response and rejects static session headers. Resources, prompts, multi-server topologies, and a run against an unrelated third-party gateway are still out of scope. Tool-specific MCP stdio or MCP HTTP commands remain the fuller path. See [GATEWAY-ADAPTER.md](GATEWAY-ADAPTER.md) |

If none of the supported shapes match your architecture, write a tool-specific
runner. Active v4 profiles use registry-bound reporting labels, not a `supports`
map. Labels do not select cases. Do not force a tool through the wrong shape
just to get a numeric result.

## Input

1. A directory of case JSON files
2. A tool profile JSON file

## Output

One JSON object per case, written to stdout (one per line, JSONL):

> `--stats` and `--report` are the exceptions to this contract. It reports the loaded corpus rather than running it, so it writes a human-readable Markdown snapshot to stdout and exits without producing JSONL or a summary. It requires `--cases` and ignores the tool-profile and adapter flags. `make stats`, `make stats-update` and `make check-stats` are its only intended callers. `--report` likewise runs no cases: it reads an artifact directory an earlier run left behind and writes Markdown to the path given by `--report-output`, or to stdout when that is `-`.

`--require-complete` keeps the JSONL rows, summary, and optional receipt profile, then exits nonzero when `measurement_status` is `incomplete`. Use it in automation and offline runs so a partial measurement can't produce a green job. A complete measurement can still contain ordinary pass and fail outcomes; the flag rejects missing measurement, not an unfavorable score.

```json
{
  "schema_version": 6,
  "scoring_version": "2.8",
  "case_id": "url-dlp-aws-key-001",
  "tool": "pipelock",
  "tool_version": "0.3.6",
  "capability_registry": {
    "id": "aeb.core-capabilities",
    "format": 1,
    "revision": 2,
    "sha256": "..."
  },
  "expected_verdict": "block",
  "actual_verdict": "block",
  "score": "pass",
  "evidence": {
    "result_state": "observed",
    "http_status": 403,
    "matched_signal": "blocked_http_status"
  },
  "notes": ""
}
```

### Required output fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Active result schema version, currently `6` |
| `scoring_version` | string | Exact scoring rules used for this row, currently `2.8` |
| `case_id` | string | The case ID |
| `tool` | string | Tool name from profile |
| `tool_version` | string | Tool version from profile |
| `capability_registry` | object | Exact registry reference from the profile |
| `expected_verdict` | string | From the case file |
| `actual_verdict` | string | `block`, `allow`, `unreachable`, or `error` |
| `score` | string | `pass`, `fail`, or `error` |
| `evidence` | object | Evidence with required `result_state`; other fields are tool-specific |
| `notes` | string | Optional context |

### Returned-content diagnostics

When an adapter receives bytes on a content-bearing MCP response path, its row
may include `returned_content_sha256`, `returned_content_bytes`,
`returned_content_media_type`, and `returned_content_path`. The digest covers
the original received bytes, before any JSON decoding or text conversion.
`returned_content_path` is one of `mcp_tools_list`,
`mcp_tools_call_result`, `mcp_initialize_instructions`, or
`mcp_stdio_result`. Adapters may also report bounded shape facts such as a tool
count or the presence of `instructions`, `title`, `inputSchema`,
`outputSchema`, or `annotations`.

These are diagnostics only. They never enter the score or change what
`block` means. The runner still scores the channel decision using the existing
case contract. The proxy HTTP listener-session initialize is transport setup,
not case input, and is not retained.

`--retain-returned-content DIR` is an explicit local-only opt-in. It stores
the original bytes and a per-response manifest in `DIR` with private file
permissions. It is off by default. The Action publisher copies a closed list
of public artifacts and does not include that directory, even when it sits
beside a run. Public JSONL, summaries, reports, provenance, candidate
evaluation, and buyer reports receive no payload snippets from this feature.

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

A case requiring a blocklist needs the operator to configure the tool with that
exact host before running, and to say so with `--seeded-blocklist-domain`. The
runner configures nothing itself. The case does not have to declare the host, and the
current corpus ones do not, because case bytes are fixed once a case ships. A
runner resolves the requirement from both sources and acts on their union:

- Declared: a `blocklist_domain` prerequisite naming the host.
- Derived: `requires` containing `domain_blocklist`, with the host taken from
  `payload.url` or `payload.target_url`.

Acting on the union matters. Preferring declarations would let a case that
declares some other prerequisite suppress a derived blocklist requirement and
score a detection result with nothing seeded. A declared value must equal the
payload host, so the two describe one requirement rather than two.

The current corpus host is:

- `exfil-collector.example.net` (IANA-reserved, no real DNS resolution)

The built-in runner cannot see the tool's blocklist, so it treats the domain as
unsatisfied until the operator passes `--seeded-blocklist-domain` with that
host. An unsatisfied `blocklist_domain` records `actual_verdict: "error"` and
`score: "error"`. It never becomes a containment miss.

Because the runner cannot read the tool's blocklist, a seeded domain is an
operator claim rather than a verified fact. Any row scored while relying on one
carries `setup_asserted_by_operator` in its evidence, listing the domains that
were asserted. A reserved sink route is absent from that list on purpose: the
runner holds that route itself, so it is proven rather than claimed.

If your tool does not support domain blocklisting, implement an adapter route
that proves the input and verdict. A reporting label alone never skips these
cases.

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

A case needing this routing may declare a `reserved_sink_route` prerequisite
with that host, and a runner derives the same requirement when the payload host
is one of the two reserved names above, so an undeclared case is covered. The built-in proxy adapter satisfies it when `--fixtures` is on,
because the fixture manager then has a reachable route that keeps the reserved
hostname. Without that route the runner records `actual_verdict: "error"` and
`score: "error"` instead of a miss.

A runner should route these hosts deterministically to a local or otherwise
controlled sink, but the routing mechanism must not make the hostname trusted.
For tools with an SSRF floor, use an IP-scoped reachability exception or
equivalent local fixture route rather than adding the sink hostname to trusted
domains. This keeps benign trusted-fixture controls allowed while still scoring
whether opaque high-entropy content is blocked when sent to an untrusted sink.

### Frame reassembly and cross-message correlation

Two different obligations sit behind multi-frame cases, and conflating them makes one look
unbounded when it is not.

**Fragment reassembly is protocol-defined and mandatory.** A frame carrying `fin: false` followed by
`continuation` frames is one logical message under RFC 6455, and the message ends at the frame with
`fin: true`. A runner reassembles that message and scans the reassembled content. The boundary comes
from the wire, so this needs no window, no timer, and no eviction policy. Three corpus cases have this
shape, including a benign one.

**Cross-message correlation is a policy, and the corpus states its bound.** Separate complete
messages, each with `fin: true`, are distinct messages that a tool may nonetheless correlate to catch
a credential split across them. A conforming runner MUST correlate at least **two consecutive
complete messages within a single connection**. That is the widest span any current corpus case
requires, and a runner correlating less will report a miss that is a configuration gap rather than a
detection failure.

Beyond that minimum a runner MAY correlate further, subject to two bounds it must be able to state:

- **Eviction.** Correlation state is per connection and ends when the connection closes. A runner
  that retains it across connections is answering for traffic the case never sent.
- **Overflow.** A correlation buffer is attacker-influenced, so it must have a fixed ceiling on
  retained bytes or messages. On reaching it, a runner evicts oldest-first and continues scanning.
  Growing without limit turns a detection feature into a memory-exhaustion path, which is a failure
  direction, not a thoroughness setting.

**The availability direction is scored.** `fp-ws-clean-multiframe-016` is a benign three-fragment
message that must be ALLOWED after reassembly. A tool that treats any multi-frame sequence as
suspicious fails that case. Correlating more aggressively is not free, and the corpus measures both
directions.

## Result State Check

Before scoring a case, the runner must establish all of the following:

1. The adapter has an exact route for the declared wire transport, semantic surface, and lifecycle.
2. The adapter proves it delivered that exact input.
3. The adapter observes a request-correlated `allow` or `block` verdict.

A missing exact route emits `actual_verdict: "unreachable"` and `score: "error"`. It is visible in `case_count.unreachable`, excluded from measurement denominators, and makes the measurement incomplete. A routed case lacking delivery proof or verdict observation emits `actual_verdict: "error"`. A tuple declaration alone never creates N/A.

`claims`, `requires`, and `capability_tags` do not select cases. In v4, claims and tags are validated against the profile's exact registry snapshot and remain reporting metadata. They cannot affect scope, denominators, scores, measurement status, or publication. This applies to hard variants and benign controls alike.

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
| Deny status carrying a deny marker in the body | `block` |
| Deny marker in response body (tool-specific) | `block` |
| Successful upstream response without deny marker | `allow` |
| Deny status with no deny marker, upstream confirmed answered | `allow` |
| Deny status with no deny marker, upstream not confirmed | `skip` |
| Runner or tool failure | `error` |

#### Make your denials attributable

A status code alone names no actor. An origin, a reverse proxy, a fixture, or the tool under test
can all return 400 or 403, so the runner will not credit containment to the tool on a status
alone: an unmarked denial scores `skip`, meaning unscorable, and counts toward neither containment
nor leakage.

This is a deliberate trade. Crediting every unmarked 4xx would inflate the score of whatever is
being measured, and a benchmark that flatters its subject is worth nothing. The cost is that a real
denial carrying no marker goes uncounted.

A tool makes its denials countable by emitting a positive marker in the response body. Any of
these is recognized:

```json
{"blocked": true}
{"block_reason": "DLP match"}
{"scanner": "prompt_injection"}
```

If your tool denies with an unmarked status and you cannot change that, say so when you publish a
result: report the `skip` count alongside the score rather than presenting the score as complete.

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
results: 22 passed, 3 failed, 0 unreachable, 0 errors (25 total)
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
| `raw-summary.json` | Method versions, target product and version, profile digest, exact registry reference, reporting labels, scope counts, two outcome metrics, and two diagnostic rates |
| `results.jsonl` | Every historical not-applicable or unreachable case ID and its recorded reason |
| `run-metadata.json` | Repository and exact method commit |
| `run-bundle.json` | Bundle status, publication eligibility, retained material digests, and candidate bindings |
| `execution-decision.json` | Execution status, failures, review notes, and publication eligibility |
| `entrypoint-command.txt` and `command.txt` | The retained reproduction commands |

The report checks every digest declared by the run bundle, checks the candidate bindings against the summary and run metadata, and checks the execution decision against the bundle. It reports these checks separately from the outcome metrics and non-scoring diagnostics.

Missing facts render as `Absent from run artifacts`. Wrong types and contradictory bindings render as invalid. A malformed JSON or JSONL input leaves the rest of the report readable and marks the affected section. A partial, blocked, errored, or publication-ineligible run still produces a report with that state visible.

For a public presentation, the runner can also render a compact neutral lockup from a complete, publication-eligible artifact directory:

```bash
(cd runner && go run . \
  --publication-lockup ../continuous-gauntlet-artifacts \
  --publication-assurance self-run \
  --publication-evidence-url https://publisher.example/results/run-123 \
  --publication-lockup-output ../continuous-gauntlet-artifacts/result-lockup.md)
```

Unlike the diagnostic report, lockup generation fails closed when retained decisions, bundle method identity, scope, configuration identity, registry/profile bindings, or measurement status are incomplete or invalid. It uses target-neutral runner outputs rather than Pipelock-specific release files. The lockup contains no publisher branding, badge, or pass/fail judgment; its assurance label is an explicit publisher declaration, not an award from the runner. Publishers add their own presentation around it without separating the displayed score from these reproducibility facts.

The summary schema owns the provenance-fact field list; declare those facts with `--method-repository`, `--method-commit`, `--target-config`, and `--adapter-owner`, and see [`contracts/`](../contracts/) for the authoritative fields per summary version. A local run may omit these declarations and still complete. A provenance candidate can't be finalized or promoted without every field, and the gate names each missing declaration. A submitted adapter or plugin must disclose its author. Adapters cannot tune applicability or scoring; [GATEWAY-ADAPTER.md](GATEWAY-ADAPTER.md#author-disclosure) records the compiled route boundary and the result-state ownership.

Target-specific accommodation stays in the retained `command.txt` evidence. The runner rejects accommodation flags when the selected adapter doesn't consume them, and the candidate binds the command by SHA-256. The publication schema doesn't turn one product's session-token behavior into a shared field.

## Validating Output

The validator can check your runner's JSONL output and tool profile:

```bash
cd validate && go build -o aeb-validate .
./aeb-validate results path/to/results.jsonl ../cases
./aeb-validate profile path/to/tool-profile.json
```

This checks field presence, enum validity, row-level scoring identity, and the active cross-field result rules defined by [Gauntlet Scoring](gauntlet.md#per-case-results) and the machine-readable [`result-states-v6.json`](../contracts/result-states-v6.json). The cases directory binds each row to canonical case metadata, including whether budget timing evidence is required. Omitting it performs structural checks only and cannot authenticate a result row's case-specific claims.

### Scope-artifact verification

Validate a candidate with the checked-out corpus manifest. This is the publish-path command. `cases/MANIFEST.txt` supplies the corpus authority. A sibling `corpus-manifest.txt` remains bundle evidence.

```bash
python3 scripts/validate_gauntlet_scope.py gauntlet-site/testdata/complete-provenance-artifact.json
```

An external verifier that already trusts a different manifest may pass it explicitly with `--expected-manifest`. Do not source that file from the candidate directory.

Historical records use archive mode. It requires the immutable record directory and an independently trusted SHA-256 for that directory's `record-manifest.json`. Archive mode verifies the record's file bindings and checks that its retained manifest matches the corpus commit recorded by the artifact before using it for scope checks.

```bash
python3 scripts/validate_gauntlet_scope.py \
  --archive-record gauntlet-site/results/pipelock/5869b18cf5027d502bc5d0fd8b8f6899872a8b379137226c617670a295222886 \
  --expected-record-manifest-sha256 17d069ecebe70f52413cd2509aa80c551d0a0e3703385471cc406088625fabb6 \
  gauntlet-site/results/pipelock/5869b18cf5027d502bc5d0fd8b8f6899872a8b379137226c617670a295222886/continuous-gauntlet-pipelock.json
```

The expected record-manifest digest must come from an authenticated immutable source, such as a verified append-only record chain. Reading it from the archive being checked would make the archive self-authenticating.

## Receipt-Scoring Profile (optional)

The reference runner can emit a [receipt-scoring profile](RECEIPT-SCORING.md) alongside the Gauntlet summary. The profile records, per applicable case, whether the tool blocked the action, explained it, produced a signed receipt, produced one that is independently verifiable, and whether it blocked a benign baseline. It also carries the exact manifest digest, an honest Git-checkout status, and a separate tool-version observation. Output validates against [`schemas/receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json).

Flags:

- `--emit-receipt-profile <path>`: write the profile JSON to `<path>`. Default off.
- `--receipt-verifier-file <path>`: optional JSON file describing the tool's receipt verifier (shape: the `verifier` object in the receipt-scoring schema). Omitted means "no verifier shipped" and the runner emits a degraded honest verifier block.
- `--tool-version-command <json-argv>`: optional JSON array of argv strings that asks the target tool to self-report a version, for example `["/opt/example-tool", "--version"]`. The runner executes it without a shell before the benchmark begins, stores bounded stdout only on success, and otherwise records an explicit unavailable status. It never substitutes the profile's declared `tool_version`.
- `--multifile-cases <dir>`: optional source-location override for the multi-file MCP-drift cases. By default the runner discovers registered multi-file families under `--cases`; an override must yield the same logical case IDs as that loader-backed corpus.
- `--seeded-blocklist-domain <host>`: repeatable. Declares that the operator already seeded this host in the tool blocklist. Required to score a `blocklist_domain` prerequisite; omitting it records an error instead of a miss.

### Multi-file MCP drift loader

By default, each immediate child directory under the registered
`cases/mcp-drift/` family is one logical case. An explicit
`--multifile-cases` path changes only the source location; it does not change
the required IDs or scoring contract.

The loader strictly decodes `case.yaml` against
[`multi-file-case-v4`](../schemas/multi-file-case-v4.schema.json), rejects
unknown or missing fields, requires the ID to equal the directory name, and
accepts only distinct safe case-relative `.json` component paths plus a safe
case-relative `.md` notes path. Nested paths remain confined to the case
directory. It then validates `before.json` and
`after.json` as MCP `tools/list` responses, either directly or in the
multi-server wrapper used by the cross-server fixture, and validates
`expected.json` against the case verdict, transport, and severity.

The runtime sends the before snapshot first to establish the baseline, then
the after snapshot through the same logical session. Array order is retained;
the loader does not sort tool definitions or server responses. Missing files,
malformed JSON/YAML, unsafe paths, duplicate server IDs, empty tool names, and
metadata disagreements fail the load rather than dropping the case.

Schema-v4 `warn` remains available for compatibility and maps to `allow` in the
binary result row because the active result schema has only block/allow
expectations. Current single-file cases use block/allow; multi-file drift cases
retain `warn` as the receipt-aware expectation in corpus metadata. For the generic adapter, a pass proves
only that the tool did not block the benign change. It does not prove that the
tool detected the change or emitted a warning. The runner validates the
normative `expected.json`, but an adapter must expose receipt comparison before
those fields become observed evidence.

Reproducibility:

- The receipt profile repeats the Gauntlet summary's `benchmark_manifest_sha256`, which is the exact loaded case identity. Its retained `corpus_sha256` is a legacy content digest and does not bind file boundaries or membership. The top-level summary contract is documented in [gauntlet.md](gauntlet.md#gauntlet-summary-json-file).
- Per-case rows are sorted by `case_id` and the runner emits no timestamps in the profile. A relying party can reproduce a published profile by running the same command and comparing the retained fields. Byte-for-byte equality also requires the corpus Git state and tool-version command output to match.
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
  --seeded-blocklist-domain exfil-collector.example.net \
  --cases ./cases \
  --profile examples/pipelock/tool-profile.json \
  --output /tmp/gauntlet.json \
  --emit-receipt-profile /tmp/pipelock.json \
  --receipt-verifier-file examples/pipelock/receipt-verifier.json \
  --timeout 15s

# Inspect the emitted profile.
sha256sum /tmp/pipelock.json
```

`profiles/pipelock.json` is a retained historical artifact from Pipelock 3.1.0 on
corpus v2.0.0, pinned by `profiles/retained-artifacts.json`. A run against a
current tool and corpus is EXPECTED to differ from it, so a byte-for-byte diff
against that file is not a reproduction check.

That retained declaration is an integrity pin, not a reproduction recipe. It
records the artifact's digest, its tool version, and its corpus version, but no
corpus or runner source revision and no tool binary digest, and the command above
runs whatever runner the current checkout contains. Reproducing this profile
byte-for-byte therefore needs provenance the repository does not carry for it.
Treat it as evidence of the run it names and verify it by its recorded digest.

Published profile reproduction should name the exact tool binary and corpus commit
used for the run. A mismatch means the corpus drifted, the tool drifted, or the
runner changed. A relying party reproducing a profile should treat a mismatch as a
signal to investigate, not to trust either side blindly.

Independent runner comparisons use the pre-reveal commitment protocol in
[`RUNNER-PARITY.md`](RUNNER-PARITY.md). It binds both the normalized decision
vector and the environment that produced it without treating different host
environments as different decisions.
