# CLAUDE.md: agent-egress-bench Development Guide

agent-egress-bench is a tool-neutral attack corpus for evaluating AI agent egress security tools. 143 cases across 16 categories. JSON case files, a Go validator, a Gauntlet scoring runner, spec docs, and reference runners. This is NOT an application. The validator and runner are build tools, not the product.

## Hard Rules

- **Tool neutrality is sacred.** No case, doc, or design choice should favor any specific security tool. The pipelock runner in `examples/pipelock/` is a reference implementation, not a privileged position.
- **Case IDs are immutable.** Once published, an ID never changes. Semantic changes = new case with new ID.
- **No real secrets.** All credentials in cases must be obviously fake. Split at pattern boundaries if GitHub Push Protection blocks the push.
- **No cross-tool comparisons.** This repo contains attack patterns, not tool rankings.

## Quick Reference

| Item | Value |
|------|-------|
| Repo | `luckyPipewrench/agent-egress-bench` |
| License | Apache 2.0 |
| Go | 1.24+ (validator only) |
| Validator | stdlib-only Go, zero external deps |
| Spec | `docs/SPEC.md` (source of truth for case format) |
| Scoring | `docs/SCORING.md` (pass/fail) + `docs/gauntlet.md` (4-dimension scoring) |
| Runner contract | `docs/RUNNER.md` |
| Gauntlet runner | `runner/` (stdlib-only Go, zero deps) |
| OWASP mapping | `docs/OWASP-MAPPING.md` |

## Build, Test, Validate

```bash
cd validate && go test -race -count=1 ./...                    # Validator tests
cd validate && go build -o /tmp/aeb-validate .                 # Build validator
/tmp/aeb-validate ../cases                                     # Validate all cases
cd runner && go test -race -count=1 ./...                      # Runner tests
cd runner && go build -o /tmp/aeb-gauntlet .                   # Build runner
/tmp/aeb-gauntlet --cases ../cases --profile ../examples/pipelock/tool-profile.json --output /tmp/summary.json
```

## Project Structure

```
cases/
  url/              URL-based exfiltration (DLP, entropy, encoding evasion, SSRF)
  request-body/     Request body secret exfiltration
  headers/          Header-based secret leaks
  response-fetch/   Prompt injection in fetched response content
  response-mitm/    Prompt injection via TLS-intercepted responses
  mcp-input/        MCP tool call argument scanning (DLP, injection)
  mcp-tool/         MCP tool description poisoning and rug-pull
  mcp-chain/        Multi-step MCP tool call sequence detection
  a2a-message/      A2A protocol message scanning (DLP, injection)
  a2a-agent-card/   A2A Agent Card poisoning and drift
  websocket-dlp/    WebSocket frame DLP, fragment evasion
  ssrf-bypass/      SSRF via encoded IPs, cloud metadata
  encoding-evasion/ Multi-layer encoding chains, homoglyphs
  shell-obfuscation/ Obfuscated shell commands in tool args
  crypto-financial/ Wallet addresses, seed phrases, credit cards
  false-positive/   Benign traffic that must not be blocked
validate/           Go validator (stdlib-only, zero deps)
runner/             Gauntlet scoring runner CLI (stdlib-only, zero deps)
examples/           Reference runner implementations
  pipelock/         Pipelock reference runner (harness.sh, config, tool-profile)
docs/               Spec, scoring, Gauntlet methodology, runner contract, OWASP mapping
scripts/            CI tooling (pr-review.py)
```

## Case Format

Every case is a JSON file. Filename (minus `.json`) must match the `id` field exactly. Files live in category-specific directories under `cases/`.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | int | Must be `1` |
| `id` | string | Unique, immutable identifier |
| `category` | string | Attack surface category |
| `title` | string | Short human-readable title |
| `description` | string | What the case tests |
| `input_type` | string | Input format being tested |
| `transport` | string | Expected transport mechanism |
| `payload` | object | Test payload (shape varies by input_type) |
| `expected_verdict` | string | `block` or `allow` |
| `severity` | string | `critical`, `high`, `medium`, or `low` |
| `capability_tags` | array | What capabilities this exercises |
| `requires` | array | Runtime prerequisites (can be empty `[]`) |
| `false_positive_risk` | string | `low`, `medium`, or `high` |
| `why_expected` | string | Machine-readable reason for expected verdict |

### Conditional/Optional Fields

| Field | Type | Notes |
|-------|------|-------|
| `safe_example` | bool | **Required `true`** for benign cases (`expected_verdict: allow`) |
| `notes` | string | Required. Human-readable context (use `""` if none) |
| `source` | string | Required. Provenance: `"original"`, `"public: <url>"`, or `"synthetic: <desc>"`. Must be non-empty for Gauntlet categories. |

### Category/Input Type/Transport Consistency

The validator enforces these relationships:

| Category | Allowed Input Types | Allowed Transports |
|----------|--------------------|--------------------|
| `url` | `url` | `fetch_proxy`, `http_proxy`, `websocket` |
| `request_body` | `request_body` | `fetch_proxy`, `http_proxy`, `websocket` |
| `headers` | `header` | `fetch_proxy`, `http_proxy`, `websocket` |
| `response_fetch` | `response_content` | `fetch_proxy`, `http_proxy`, `websocket` |
| `response_mitm` | `response_content` | `http_proxy` only |
| `mcp_input` | `mcp_tool_call` | `mcp_stdio`, `mcp_http` |
| `mcp_tool` | `mcp_tool_result`, `mcp_tool_definition` | `mcp_stdio`, `mcp_http` |
| `mcp_chain` | `mcp_tool_sequence` | `mcp_stdio`, `mcp_http` |
| `a2a_message` | `a2a_message` | `a2a` |
| `a2a_agent_card` | `a2a_agent_card` | `a2a` |
| `websocket_dlp` | `websocket_frame` | `websocket` |
| `ssrf_bypass` | `url` | `fetch_proxy`, `http_proxy` |
| `encoding_evasion` | `url`, `request_body`, `mcp_tool_call` | `fetch_proxy`, `mcp_stdio` |
| `shell_obfuscation` | `mcp_tool_call` | `mcp_stdio`, `mcp_http` |
| `crypto_financial` | `url`, `request_body`, `header`, `mcp_tool_call` | `fetch_proxy`, `mcp_stdio` |
| `false_positive` | any | any |

### Payload Shape Per Input Type

| Input Type | Required Payload Keys |
|------------|----------------------|
| `url` | `method` (string), `url` (string) |
| `request_body` | `method`, `url`, `content_type`, `body` (all strings) |
| `header` | `method`, `url` (strings), `headers` (object) |
| `response_content` | `url`, `response_body` (strings) |
| `mcp_tool_call/result/definition/sequence` | `jsonrpc_messages` (non-empty array) |
| `a2a_message` | `jsonrpc_messages` (non-empty array, A2A methods) |
| `a2a_agent_card` | `agent_card` (object with `name` and `skills`) |
| `websocket_frame` | `url` (string), `frames` (non-empty array with `opcode` and `payload`) |

## Enum Values

**capability_tags:** `url_dlp`, `request_body_dlp`, `header_dlp`, `response_injection`, `mcp_input_scan`, `mcp_tool_poison`, `mcp_chain`, `ssrf`, `domain_blocklist`, `entropy`, `encoding_evasion`, `benign`, `a2a_scan`, `a2a_card_poison`, `websocket_dlp`, `ssrf_bypass`, `shell_obfuscation`, `crypto_dlp`

**requires:** `tls_interception`, `request_body_scanning`, `header_scanning`, `response_scanning`, `mcp_tool_baseline`, `mcp_chain_memory`, `websocket_frame_scanning`, `a2a_scanning`, `shell_analysis`, `dns_rebinding_fixture`

**transports:** `fetch_proxy`, `http_proxy`, `mcp_stdio`, `mcp_http`, `websocket`, `a2a`

## Common Development Tasks

### Adding a case

1. Pick category and directory (see table above)
2. Name: `{category}-{subcategory}-{NNN}.json`, must match `id` field
3. Copy an existing case in the same directory as a template
4. Benign cases (`expected_verdict: allow`) MUST have `"safe_example": true`
5. Validate: `cd validate && go build -o /tmp/aeb-validate . && /tmp/aeb-validate ../cases`

### Adding a validator rule

1. Update `validate/main.go` (add enum values, cross-field checks, payload validation)
2. Add tests in `validate/main_test.go`
3. Run: `cd validate && go test -race -count=1 ./...`
4. Validate all existing cases still pass

### Adding a runner

Create `examples/{tool-name}/` with:
- Runner script or binary
- `tool-profile.json` (capability claims and supports flags)
- `README.md` explaining usage

Output must follow `docs/RUNNER.md` (JSONL, one object per case).

## Fake Secrets

Cases contain intentionally fake secrets. GitHub Push Protection flags patterns like `AKIA`, `ghp_`, `xoxb-`, `sk-live_`.

- Use obviously synthetic values: `AKIAIOSFODNN7EXAMPLE`
- Split at pattern boundary if push is blocked: `"AKIA" + "IOSFODNN7EXAMPLE"` in code
- The `SG.FAKE_TEST_KEY` pattern works for SendGrid-style tokens
- Never use real secrets, even expired ones

## CI

The `validate` workflow runs on every push/PR to `main`:
1. Go tests for the validator (`go test -race -count=1 ./...`)
2. Build validator binary
3. Validate all cases against the corpus
4. Check case count is > 0

Branch protection requires passing CI. PRs required (no direct pushes to main).

## Governance

1. Case IDs are immutable forever. Never rename.
2. Existing case semantics don't change. Semantic changes = new case.
3. Corpus versions are additive.
4. No cross-tool leaderboard in this repo.
