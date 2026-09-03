# Runner Template

A practical guide for building a runner that connects your security tool to the agent-egress-bench corpus. This is the "how to do it" guide. For the formal contract (required fields, scoring rules), see [docs/RUNNER.md](../../docs/RUNNER.md).

## What you need

- Your tool's binary or running service
- `jq` (for JSON processing)
- The `cases/` directory from this repo
- A `tool-profile.json` declaring your tool's capabilities
- `bash` (the skeleton is a bash script, but you can write your runner in any language)

## Can my tool be integrated?

Use this check before writing code:

| Tool shape | Current status | What to do |
|------------|----------------|------------|
| Forward proxy with a fetch endpoint such as `/fetch?url=...` | Yes | Prove your runner can call that endpoint with the case method/body/headers and observe block signals |
| CONNECT-capable forward proxy | Yes | Prove your runner can send requests through it as an HTTPS forward proxy |
| Reverse proxy or API gateway with `listen` and `upstream` routing | Not today | Write a custom runner or leave the unmatched transports unsupported |
| In-process SDK or library | Not today | Wrap it in a runner-owned service or leave the unmatched transports unsupported |
| MCP gateway | Not as a generic adapter today | Tool-specific MCP stdio or MCP HTTP commands can be driven now; a protocol-first MCP gateway adapter is planned |

A result is scoreable only when its adapter proves delivery of the exact wire
input and observes a verdict. Claims are registry-backed reporting labels. They
do not select cases or change a score, denominator, sufficiency decision, or
publication decision. No exact route is `unreachable`, not N/A, and makes the
run insufficient.

## Step 1: Create your tool profile

Copy `tool-profile-template.json` to your runner directory and fill it in.

```bash
cp tool-profile-template.json ../your-tool/tool-profile.json
```

Edit the file. Here is what each field means:

### Top-level fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Always `4` for active scoring |
| `tool` | string | Your tool's name (lowercase, no spaces) |
| `tool_version` | string | The version you are testing against |
| `runner_version` | string | Version of your runner script (use `v1` to start) |

### `claims` array

Reporting labels for what your tool detects. They do not control selection.
Pick them from the exact capability-registry snapshot named below:

| Claim | What it means |
|-------|---------------|
| `url_dlp` | Detect secrets in URLs (query strings, paths) |
| `request_body_dlp` | Detect secrets in POST/PUT bodies |
| `header_dlp` | Detect secrets in HTTP headers |
| `response_injection` | Detect prompt injection in fetched content |
| `mcp_input_scan` | Detect secrets/injection in MCP tool arguments |
| `mcp_session_binding` | Bind MCP state to the intended session |
| `mcp_tool_result_dlp_scanning` | Detect credential material in MCP tool results |
| `mcp_tool_poison` | Detect poisoned MCP tool descriptions |
| `mcp_chain` | Detect multi-step exfiltration sequences |
| `ssrf` | Detect SSRF attempts (private IPs, metadata endpoints) |
| `domain_blocklist` | Block known-bad domains |
| `entropy` | Detect high-entropy strings (potential encoded secrets) |
| `encoding_evasion` | Detect encoded/obfuscated secrets |
| `benign` | Required to run benign (false-positive) cases |
| `a2a_scan` | Detect attacks in A2A messages |
| `a2a_card_poison` | Detect poisoned A2A Agent Cards |
| `operation_policy` | Enforce method-aware policy on allowlisted hosts (for example, fetch-only registries refuse writes) |
| `websocket_dlp` | Detect secrets in WebSocket frames |
| `ssrf_bypass` | Detect alternate SSRF encodings and IP forms |
| `shell_obfuscation` | Detect obfuscated shell commands |
| `crypto_dlp` | Detect cryptocurrency, wallet, or financial material |
| `hostname_exfil` | Detect exfiltration encoded into hostnames |
| `denial_of_wallet` | Detect resource-abuse sequences that exceed a declared tool-call count budget |

Only claim what your tool actually does; these labels help readers interpret results.

### `capability_registry` object

Copy the exact `id`, `format`, `revision`, and `sha256` from the registry
snapshot you use. The SHA-256 is over the raw snapshot file, not re-serialized
JSON. The runner rejects an unknown label, missing snapshot, digest mismatch,
duplicate label, or unsupported format before it emits any score. Keep that raw
snapshot with every published profile and result.

## Step 2: Write the runner

Copy the skeleton script and fill in the TODOs:

```bash
cp skeleton.sh ../your-tool/run.sh
cp tool-profile-template.json ../your-tool/tool-profile.json
```

The skeleton handles:
- Reading the tool profile
- Declaring delivery routes and result-state proof
- Iterating over all case files
- Emitting JSONL results
- Printing a summary

You fill in:
- Starting your tool
- Feeding each case to your tool
- Observing whether your tool blocked or allowed the traffic

### The three parts you must implement

Look for `TODO` markers in `skeleton.sh`. There are three:

1. **Start your tool.** Launch your proxy/service, wait for it to be ready.
2. **Prove the route.** For every case, establish exact delivery and a request-correlated verdict. If no exact route exists, emit `unreachable`; do not emit N/A from a declaration.
3. **Feed and observe.** Send the case payload to your tool and determine the verdict.

The Go runner can start managed commands and pass runner-owned fixture addresses
through environment variables. The full managed-command contract is documented
in [docs/RUNNER.md](../../docs/RUNNER.md#managed-command-hooks).

## Step 3: Handle each transport

### Fetch endpoint cases (`fetch_proxy`)

`fetch_proxy` cases are for tools that expose a fetch-style endpoint. The
built-in proxy adapter calls `/fetch?url=...` on the configured proxy address
using the method, body, and headers from the case payload. These cases exercise
URL, request-body, header, response-content, and some blocklist or SSRF checks
when the runner can express the case through that endpoint.

The pattern is:

1. Start your tool on a local port
2. For each case, build the request expected by your fetch endpoint
3. Send it to your tool's fetch endpoint
4. Check the response status code and body for the tool's block signal

### CONNECT forward-proxy cases (`http_proxy`)

`http_proxy` cases are for CONNECT-capable forward proxies. The runner drives
these by configuring the tool as an HTTPS proxy and sending requests to
runner-managed fixtures. These cases exercise forward-proxy and TLS-intercepted
request/response paths. A reverse proxy or API gateway is not equivalent to this
shape because the runner cannot currently rewrite arbitrary case URLs into a
fixed upstream route.

The pattern is:

1. Start your forward proxy on a local port
2. Configure the client request to use that port as the HTTPS proxy
3. Send the case payload through the proxy to the runner fixture
4. Check the proxy response status code and body for the tool's block signal

Verdict mapping from HTTP status codes:

| Status | Verdict |
|--------|---------|
| 403 | `block` (explicit deny) |
| 502 with block marker | `block` (upstream denied) |
| 200, 301, 404, etc. | `allow` (request went through) |
| 000 (connection refused) | `error` |

Your tool might use different status codes. Document your mapping.

### MCP cases (mcp_stdio, mcp_http)

MCP cases provide `jsonrpc_messages` in the payload. Each message is a JSON-RPC 2.0 object. To test:

1. Start your tool in MCP proxy mode
2. Feed each JSON-RPC message through the proxy (write to stdin, read from stdout for stdio mode)
3. Check if the message was forwarded, modified, or blocked

Verdict mapping for MCP:

| Observation | Verdict |
|-------------|---------|
| Message not forwarded | `block` |
| JSON-RPC error response with deny code | `block` |
| Process exits with non-zero status | `block` |
| Message forwarded unchanged | `allow` |
| Transport failure | `error` |

### Response scanning cases

Response cases (`input_type: response_content`) include a `response_body` in the payload. These are harder to test because you need to simulate a server returning that content. Options:

- Start a local HTTP server that returns the `response_body`
- Use a tool-specific runner only if it can prove the case exercised the declared transport
- Emit `unreachable` until an exact delivery route exists

### Cases you cannot handle

If your runner does not support a transport or input type, emit `unreachable`
with route evidence. This is an explicit coverage gap, not a scored error or
N/A. A narrow runner can support one transport while still reporting the rest
honestly.

Do not fake results. If you cannot observe the verdict, say so.

## Step 4: Validate your output

### Check JSONL format

Each line of your runner's stdout must be valid JSON with the required fields:

```bash
# Run your runner, capture output
bash run.sh /path/to/your-tool > results.jsonl 2>summary.txt

# Verify every line is valid JSON
jq empty results.jsonl

# Check required fields exist on every line
jq -s -e 'if all(.[]; has("schema_version") and has("scoring_version") and has("case_id") and has("tool") and has("tool_version") and has("expected_verdict") and has("actual_verdict") and has("score") and has("evidence") and has("notes")) then true else error("missing required result field") end' results.jsonl > /dev/null
```

### Check verdicts are valid

```bash
# All actual_verdict values must be one of: block, allow, not_applicable, unreachable, error
jq -r '.actual_verdict' results.jsonl | sort -u
# Expected output: some subset of {allow, block, error, not_applicable, unreachable}

# All score values must be one of: pass, fail, not_applicable, error
jq -r '.score' results.jsonl | sort -u
```

### Check scoring is correct

```bash
# Every case where actual == expected should be "pass"
jq -r 'select(.actual_verdict == .expected_verdict and .score != "pass" and .score != "not_applicable") | .case_id' results.jsonl
# Should print nothing

# Every case where actual != expected (and neither is error/N/A/unreachable) should be "fail"
jq -r 'select(.actual_verdict != .expected_verdict and .actual_verdict != "error" and .actual_verdict != "not_applicable" and .actual_verdict != "unreachable" and .score != "fail") | .case_id' results.jsonl
# Should print nothing
```

### Check case coverage

```bash
# Total cases in corpus
find ../../cases -name '*.json' -type f | wc -l

# Total results emitted
wc -l < results.jsonl

# These should match
```

## Common mistakes

**Treating claims as proof.** A reporting label never proves a route. Validate
it against the profile's retained registry snapshot, then add delivery and
verdict observation before scoring.

**Hardcoding verdicts.** Every verdict must come from observing your tool's actual behavior. If you return `block` without sending the request through your tool, the result is meaningless.

**Mixing stdout and stderr.** JSONL goes to stdout. Status messages, progress, and summaries go to stderr. If you print status to stdout, the JSONL will be unparseable.

**Forgetting false-positive coverage.** Benign cases need the same delivery and
verdict proof as attacks. A profile declaration cannot remove them from scope.

## Reference

- [docs/RUNNER.md](../../docs/RUNNER.md): the formal runner contract
- [docs/SPEC.md](../../docs/SPEC.md): case schema and field definitions
- [docs/gauntlet.md](../../docs/gauntlet.md): result states and scoring method
- [examples/pipelock/](../pipelock/): reference runner implementation
