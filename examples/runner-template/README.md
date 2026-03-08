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

Which attack categories your tool detects. Only cases matching your claims will run. Pick from:

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

Only claim what your tool actually does. Unclaimed cases are scored `not_applicable`, not `fail`.

### `supports` object

Which transport and scanning modes your tool supports. These map to the `requires` field in case files. If a case requires a capability you don't support, it is skipped.

| Key | What it means |
|-----|---------------|
| `fetch_proxy` | Tool provides an HTTP fetch endpoint (like `/fetch?url=...`) |
| `http_proxy` | Tool works as a CONNECT/forward proxy |
| `mcp_stdio` | Tool can wrap MCP servers via stdio |
| `mcp_http` | Tool can proxy MCP over HTTP |
| `websocket` | Tool can proxy WebSocket connections |
| `tls_interception` | Tool can intercept and inspect TLS traffic |
| `request_body_scanning` | Tool inspects HTTP request bodies |
| `header_scanning` | Tool inspects HTTP headers |
| `response_scanning` | Tool inspects HTTP response content |
| `mcp_tool_baseline` | Tool tracks MCP tool definitions over time (rug-pull detection) |
| `mcp_chain_memory` | Tool tracks sequences of MCP tool calls |

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

**Claiming capabilities you do not test.** If your tool claims `mcp_chain` but your runner does not support `mcp_stdio`, those cases will try to run and produce `error` instead of `not_applicable`. Either support the transport or remove the claim.

**Hardcoding verdicts.** Every verdict must come from observing your tool's actual behavior. If you return `block` without sending the request through your tool, the result is meaningless.

**Mixing stdout and stderr.** JSONL goes to stdout. Status messages, progress, and summaries go to stderr. If you print status to stdout, the JSONL will be unparseable.

**Forgetting benign cases.** Add `benign` to your `claims` array. If you skip it, all false-positive test cases are marked `not_applicable` and your results will not show whether your tool over-blocks.

## Reference

- [docs/RUNNER.md](../../docs/RUNNER.md): the formal runner contract
- [docs/SPEC.md](../../docs/SPEC.md): case schema and field definitions
- [docs/SCORING.md](../../docs/SCORING.md): scoring model
- [examples/pipelock/](../pipelock/): reference runner implementation
