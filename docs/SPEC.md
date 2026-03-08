# agent-egress-bench Specification

**Version:** 1
**Status:** Stable

**JSON Schema:** [`schemas/case.schema.json`](../schemas/case.schema.json)

## Overview

agent-egress-bench defines a standardized corpus of test cases for evaluating AI agent egress security tools. Each case specifies an input, the expected verdict (block or allow), and the capabilities required to evaluate it.

## Case Format

Each case is a single JSON file in the `cases/` directory tree. Files are named `{id}.json` where `id` matches the `id` field inside the document.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Must be `1` |
| `id` | string | Unique identifier. Immutable once published. |
| `category` | string | Attack surface category (see Enums) |
| `title` | string | Short human-readable title |
| `description` | string | What the case tests |
| `input_type` | string | Type of input being tested (see Enums) |
| `transport` | string | Expected transport mechanism (see Enums) |
| `payload` | object | Test payload (format varies by input_type) |
| `expected_verdict` | string | `block` or `allow` |
| `severity` | string | Impact severity (see Enums) |
| `capability_tags` | array of strings | What capabilities this case exercises |
| `requires` | array of strings | Runtime prerequisites |
| `false_positive_risk` | string | Likelihood of incorrect blocking (see Enums) |
| `why_expected` | string | Machine-readable reason for expected verdict |

### Additional Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `notes` | string | Human context (use empty string if none) |
| `source` | string | Reference or citation (use empty string if none) |

### Conditional Fields

| Field | Type | Description |
|-------|------|-------------|
| `safe_example` | boolean | Must be `true` for benign cases (`expected_verdict: allow`). Omit for malicious cases. |

## Enums

### category

`url`, `request_body`, `headers`, `response_fetch`, `response_mitm`, `mcp_input`, `mcp_tool`, `mcp_chain`

### input_type

`url`, `request_body`, `header`, `response_content`, `mcp_tool_call`, `mcp_tool_result`, `mcp_tool_definition`, `mcp_tool_sequence`

### transport

`fetch_proxy`, `http_proxy`, `mcp_stdio`, `mcp_http`, `websocket`

Note: `websocket` is a valid v1 transport for tools that proxy WebSocket connections. The v1.0 corpus does not yet include WebSocket-specific cases. Runners may declare `supports.websocket` in their profile; cases will be added in future corpus versions.

### expected_verdict

`block`, `allow`

v1 is binary. No `warn` in case expectations.

### severity

`critical`, `high`, `medium`, `low`

### false_positive_risk

`low`, `medium`, `high`

## capability_tags (v1)

`url_dlp`, `request_body_dlp`, `header_dlp`, `response_injection`, `mcp_input_scan`, `mcp_tool_poison`, `mcp_chain`, `ssrf`, `domain_blocklist`, `entropy`, `encoding_evasion`, `benign`

Tags describe what the case exercises. Used for reporting and applicability.

## requires (v1)

`tls_interception`, `request_body_scanning`, `header_scanning`, `response_scanning`, `mcp_tool_baseline`, `mcp_chain_memory`

Runtime prerequisites. If a tool's profile does not satisfy all `requires` entries, the case is `not_applicable`.

## Payload Formats

### URL cases (`input_type: url`)

```json
{
  "method": "GET",
  "url": "https://example.com/path?key=value"
}
```

### Request body cases (`input_type: request_body`)

```json
{
  "method": "POST",
  "url": "https://example.com/api",
  "content_type": "application/json",
  "body": "{\"key\": \"value\"}"
}
```

### Header cases (`input_type: header`)

```json
{
  "method": "GET",
  "url": "https://example.com/api",
  "headers": {
    "Authorization": "Bearer sk-..."
  }
}
```

### Response cases (`input_type: response_content`)

```json
{
  "url": "https://example.com/page",
  "response_body": "page content with injection attempt"
}
```

### MCP cases (`input_type: mcp_tool_call`, `mcp_tool_result`, `mcp_tool_definition`, `mcp_tool_sequence`)

```json
{
  "jsonrpc_messages": [
    {"jsonrpc": "2.0", "method": "tools/call", "params": {...}, "id": 1}
  ]
}
```

## Applicability

A case is `not_applicable` for a tool if either:

1. Any entry in `capability_tags` is not in the tool's `claims`, or
2. Any entry in `requires` is not supported by the tool's profile

This is deterministic. No judgment calls.

## Machine-Readable Schemas

JSON Schema files for programmatic validation:

- [`schemas/case.schema.json`](../schemas/case.schema.json): case file schema
- [`schemas/tool-profile.schema.json`](../schemas/tool-profile.schema.json): tool profile schema
- [`schemas/result.schema.json`](../schemas/result.schema.json): runner result line schema

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for full policy. Key rules:

1. Case IDs are immutable forever.
2. Existing case semantics do not change silently. Semantic changes require a new case.
3. New cases must include rationale, expected verdict, source or explanation, and false-positive assessment.
4. Corpus versions are additive where possible.
5. Author conflict is disclosed: created by the Pipelock author. Contributions from any vendor are welcome. No cross-tool leaderboard in this repo.
