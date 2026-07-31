# Runner Template

A practical guide for building a runner that connects your security tool to the agent-egress-bench corpus. This is the "how to do it" guide. For the formal contract (required fields, scoring rules), see [docs/RUNNER.md](../../docs/RUNNER.md).

## What you need

- Your tool's binary or running service
- `jq` (for JSON processing)
- The `cases/` directory from this repo
- A `tool-profile.json` declaring your tool's capabilities
- `bash` (the skeleton is a bash script, but you can write your runner in any language)

## Step 1: Create your tool profile

Copy `tool-profile-template.json` to your runner directory and fill it in.

```bash
cp tool-profile-template.json ../your-tool/tool-profile.json
```

Edit the file. Here is what each field means:

### Top-level fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Always `1` for now |
| `tool` | string | Your tool's name (lowercase, no spaces) |
| `tool_version` | string | The version you are testing against |
| `runner_version` | string | Version of your runner script (use `v1` to start) |

### `claims` array

Reporting labels for what your tool detects. Applicability is controlled by `supports`, not by `claims`. Pick from:

| Claim | What it means |
|-------|---------------|
| `url_dlp` | Detect secrets in URLs (query strings, paths) |
| `request_body_dlp` | Detect secrets in POST/PUT bodies |
| `header_dlp` | Detect secrets in HTTP headers |
| `response_injection` | Detect prompt injection in fetched content |
| `mcp_input_scan` | Detect secrets/injection in MCP tool arguments |
| `mcp_tool_poison` | Detect poisoned MCP tool descriptions |
| `mcp_chain` | Detect multi-step exfiltration sequences |
| `ssrf` | Detect SSRF attempts (private IPs, metadata endpoints) |
| `domain_blocklist` | Block known-bad domains |
| `entropy` | Detect high-entropy strings (potential encoded secrets) |
| `encoding_evasion` | Detect encoded/obfuscated secrets |
| `benign` | Required to run benign (false-positive) cases |
| `a2a_scan` | Detect attacks in A2A messages |
| `a2a_card_poison` | Detect poisoned A2A Agent Cards |
| `websocket_dlp` | Detect secrets in WebSocket frames |
| `ssrf_bypass` | Detect alternate SSRF encodings and IP forms |
| `shell_obfuscation` | Detect obfuscated shell commands |
| `crypto_dlp` | Detect cryptocurrency, wallet, or financial material |
| `hostname_exfil` | Detect exfiltration encoded into hostnames |
| `denial_of_wallet` | Detect resource-abuse sequences that exceed a declared tool-call count budget |

Only claim what your tool actually does; these labels help readers interpret results.

### `supports` object

Which transport and scanning modes your tool supports. These map to the `requires` field in case files. If a case requires a capability you don't support, it is skipped.

| Key | What it means |
|-----|---------------|
| `fetch_proxy` | Tool provides an HTTP fetch endpoint (like `/fetch?url=...`) |
| `http_proxy` | Tool works as a CONNECT/forward proxy |
| `mcp_stdio` | Tool can wrap MCP servers via stdio |
| `mcp_http` | Tool can proxy MCP over HTTP |
| `websocket` | Tool can proxy WebSocket connections |
| `a2a` | Tool can inspect A2A protocol traffic |
| `tls_interception` | Tool can intercept and inspect TLS traffic |
| `url_dlp_scanning` | Tool detects secrets in URL components |
| `request_body_dlp_scanning` | Tool detects secrets in HTTP request bodies |
| `header_dlp_scanning` | Tool detects secrets in HTTP headers |
| `response_prompt_injection_scanning` | Tool detects prompt injection in response content |
| `mcp_input_dlp_scanning` | Tool detects secrets in MCP tool arguments |
| `mcp_input_prompt_injection_scanning` | Tool detects prompt injection in MCP tool arguments |
| `mcp_tool_policy` | Tool enforces policy on MCP tool names/actions |
| `mcp_tool_result_prompt_injection_scanning` | Tool detects prompt injection in MCP tool results |
| `mcp_tool_poison_scanning` | Tool detects poisoned MCP tool definitions |
| `mcp_tool_baseline` | Tool tracks MCP tool definitions over time (rug-pull detection) |
| `mcp_chain_memory` | Tool tracks sequences of MCP tool calls |
| `mcp_cross_server_chain_memory` | Tool correlates MCP chains across server sessions |
| `mcp_data_class_labels` | Tool tracks sensitivity labels on MCP tool outputs |
| `a2a_dlp_scanning` | Tool detects secrets in A2A messages |
| `a2a_prompt_injection_scanning` | Tool detects prompt injection in A2A messages |
| `a2a_card_prompt_injection_scanning` | Tool detects poisoned A2A Agent Cards |
| `a2a_card_drift_scanning` | Tool detects A2A Agent Card drift |
| `a2a_ssrf_scanning` | Tool detects SSRF-capable A2A URLs or file URIs |
| `websocket_dlp_scanning` | Tool detects secrets in WebSocket frames |
| `websocket_prompt_injection_scanning` | Tool detects prompt injection in WebSocket frames |
| `ssrf_scanning` | Tool detects direct SSRF attempts in URL requests |
| `ssrf_bypass_scanning` | Tool detects SSRF bypass encodings and alternate IP forms |
| `domain_blocklist` | Tool can block benchmark-configured known-bad domains |
| `entropy_scanning` | Tool detects high-entropy exfiltration strings |
| `encoding_evasion_scanning` | Tool decodes or normalizes encoded payloads before detection |
| `shell_analysis` | Tool detects obfuscated shell commands in tool arguments |
| `crypto_dlp_scanning` | Tool detects cryptocurrency, wallet, or financial material |
| `hostname_exfil_scanning` | Tool detects exfiltration encoded into DNS hostnames or labels |
| `dns_rebinding_fixture` | Runner provides controlled DNS for rebinding tests |
| `budget_enforcement` | Tool can enforce per-subject MCP tool-call count budgets during a run |

## Step 2: Write the runner

Copy the skeleton script and fill in the TODOs:

```bash
cp skeleton.sh ../your-tool/run.sh
cp tool-profile-template.json ../your-tool/tool-profile.json
```

The skeleton handles:
- Reading the tool profile
- Checking case applicability
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
2. **Check transport support.** Skip cases with transports your runner can't handle yet (even if your tool supports them in theory, your runner might not have the plumbing).
3. **Feed and observe.** Send the case payload to your tool and determine the verdict.

## Step 3: Handle each transport

### HTTP cases (fetch_proxy, http_proxy)

For tools that act as HTTP proxies, the pattern is:

1. Start your tool on a local port
2. For each case, build an HTTP request from the payload
3. Send it through your tool (via curl, wget, or direct HTTP)
4. Check the response status code and body

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
- Use your tool's API directly if it has a scan-content endpoint
- Mark as `not_applicable` in v1 and add support later

### Cases you cannot handle

If your runner does not support a transport or input type, emit `not_applicable` with a reason. This is normal. The Pipelock reference runner (v1) only supports `fetch_proxy` and marks everything else `not_applicable`.

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
jq -e 'has("case_id") and has("tool") and has("tool_version") and has("expected_verdict") and has("actual_verdict") and has("score") and has("evidence") and has("notes")' results.jsonl > /dev/null
```

### Check verdicts are valid

```bash
# All actual_verdict values must be one of: block, allow, not_applicable, error
jq -r '.actual_verdict' results.jsonl | sort -u
# Expected output: some subset of {allow, block, error, not_applicable}

# All score values must be one of: pass, fail, not_applicable, error
jq -r '.score' results.jsonl | sort -u
```

### Check scoring is correct

```bash
# Every case where actual == expected should be "pass"
jq -r 'select(.actual_verdict == .expected_verdict and .score != "pass" and .score != "not_applicable") | .case_id' results.jsonl
# Should print nothing

# Every case where actual != expected (and neither is error/na) should be "fail"
jq -r 'select(.actual_verdict != .expected_verdict and .actual_verdict != "error" and .actual_verdict != "not_applicable" and .score != "fail") | .case_id' results.jsonl
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

**Claiming supports you do not test.** If your profile sets `mcp_chain_memory` and `mcp_stdio` to `true`, those cases will run and produce `error` if your runner cannot actually test them. Set unsupported capabilities or transports to `false`.

**Hardcoding verdicts.** Every verdict must come from observing your tool's actual behavior. If you return `block` without sending the request through your tool, the result is meaningless.

**Mixing stdout and stderr.** JSONL goes to stdout. Status messages, progress, and summaries go to stderr. If you print status to stdout, the JSONL will be unparseable.

**Forgetting false-positive coverage.** Benign cases use the same `requires` taxonomy as attack cases. If you set the relevant supports to `false`, those false-positive cases are marked `not_applicable` and your results will not show whether your tool over-blocks.

## Reference

- [docs/RUNNER.md](../../docs/RUNNER.md): the formal runner contract
- [docs/SPEC.md](../../docs/SPEC.md): case schema and field definitions
- [docs/SCORING.md](../../docs/SCORING.md): scoring model
- [examples/pipelock/](../pipelock/): reference runner implementation
