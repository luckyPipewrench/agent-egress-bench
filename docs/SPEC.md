# agent-egress-bench Specification

**Active case contract:** schema version 4
**Status:** Active; merged case semantics are immutable

**JSON Schemas:** [`case-v4`](../schemas/case-v4.schema.json) and
[`multi-file-case-v4`](../schemas/multi-file-case-v4.schema.json)

## Overview

agent-egress-bench defines a standardized corpus of test cases for evaluating AI agent egress security tools. Each case specifies an input, the expected verdict (block or allow), and the capabilities required to evaluate it.

## Case Format

Each case is a single JSON file in the `cases/` directory tree. Files are named `{id}.json` where `id` matches the `id` field inside the document.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | integer | Must be `4` for active scoring. Earlier schemas are frozen readers only. |
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

`url`, `request_body`, `headers`, `hostname_exfiltration`, `response_fetch`, `response_mitm`, `mcp_input`, `mcp_tool`, `mcp_chain`, `mcp_drift`, `a2a_message`, `a2a_agent_card`, `websocket_dlp`, `ssrf_bypass`, `encoding_evasion`, `shell_obfuscation`, `crypto_financial`, `false_positive`

`mcp_drift` is carried only by multi-file cases under `cases/mcp-drift/`, so the single-file validator does not accept it; the multi-file loader requires it.

### input_type

`url`, `request_body`, `header`, `response_content`, `mcp_tool_call`, `mcp_tool_result`, `mcp_tool_definition`, `mcp_tool_sequence`, `a2a_message`, `a2a_agent_card`, `websocket_frame`

### transport

`fetch_proxy`, `http_proxy`, `mcp_stdio`, `mcp_http`, `websocket`, `a2a`

### Valid category, input, and transport combinations

[`contracts/case-shapes-v4.json`](../contracts/case-shapes-v4.json) is the
complete machine-readable matrix. `make check-public-contracts` compares it
with the case schemas and Go validator, so an undocumented combination
cannot enter through one reader.

| Category | Allowed input types | Allowed transports |
| --- | --- | --- |
| `url` | `url` | `fetch_proxy`, `http_proxy`, `websocket` |
| `request_body` | `request_body` | `fetch_proxy`, `http_proxy`, `websocket` |
| `headers` | `header` | `fetch_proxy`, `http_proxy`, `websocket` |
| `response_fetch` | `response_content` | `fetch_proxy`, `http_proxy`, `websocket` |
| `response_mitm` | `response_content` | `http_proxy` |
| `mcp_input` | `mcp_tool_call` | `mcp_stdio`, `mcp_http` |
| `mcp_tool` | `mcp_tool_result`, `mcp_tool_definition` | `mcp_stdio`, `mcp_http` |
| `mcp_chain` | `mcp_tool_sequence` | `mcp_stdio`, `mcp_http` |
| `a2a_message` | `a2a_message` | `a2a` |
| `a2a_agent_card` | `a2a_agent_card` | `a2a` |
| `websocket_dlp` | `websocket_frame` | `websocket` |
| `ssrf_bypass` | `url` | `fetch_proxy`, `http_proxy` |
| `encoding_evasion` | `url`, `request_body`, `mcp_tool_call` | `fetch_proxy`, `mcp_stdio` |
| `shell_obfuscation` | `mcp_tool_call` | `mcp_stdio`, `mcp_http` |
| `crypto_financial` | `url`, `request_body`, `header`, `mcp_tool_call` | `fetch_proxy`, `http_proxy`, `mcp_stdio` |
| `false_positive` | `url`, `request_body`, `header`, `response_content`, `mcp_tool_call`, `mcp_tool_result`, `mcp_tool_definition`, `websocket_frame`, `a2a_message` | `fetch_proxy`, `http_proxy`, `mcp_stdio`, `mcp_http`, `websocket`, `a2a` |
| `hostname_exfiltration` | `url` | `fetch_proxy`, `http_proxy` |
| `mcp_drift` (multi-file only) | `mcp_tool_sequence_temporal` | `mcp_stdio`, `mcp_http` |

### expected_verdict

`block`, `allow`

Single-file JSON v1 cases are binary. No `warn` appears in single-file JSON case expectations.
The multi-file MCP drift fixtures use a separate `case.yaml` contract documented in
[`cases/mcp-drift/README.md`](../cases/mcp-drift/README.md), where `warn` is allowed for
benign drift that should be surfaced for operator review without being blocked.
Its JSON Schema applies to the decoded YAML data model. The Go validator and
runner also enforce directory-name identity, distinct component filenames, and
the referenced tools/list and expected-receipt document contracts.

### severity

`critical`, `high`, `medium`, `low`

### false_positive_risk

`low`, `medium`, `high`

## capability_tags (registry-backed reporting labels)

`url_dlp`, `request_body_dlp`, `header_dlp`, `response_injection`, `mcp_input_scan`, `mcp_session_binding`, `mcp_tool_result_dlp_scanning`, `mcp_tool_poison`, `mcp_chain`, `ssrf`, `domain_blocklist`, `entropy`, `encoding_evasion`, `benign`, `a2a_scan`, `a2a_card_poison`, `websocket_dlp`, `ssrf_bypass`, `shell_obfuscation`, `crypto_dlp`, `hostname_exfil`, `denial_of_wallet`

Tags describe what the case exercises. They are validated against the immutable
capability-registry snapshot bound by the active profile and result. Tags are
reporting labels only. They never select cases, alter a denominator, affect
sufficiency, change a score, or gate publication.

## requires

`tls_interception`, `url_dlp_scanning`, `request_body_dlp_scanning`, `header_dlp_scanning`, `response_prompt_injection_scanning`, `mcp_input_dlp_scanning`, `mcp_input_prompt_injection_scanning`, `mcp_tool_policy`, `mcp_tool_result_prompt_injection_scanning`, `mcp_tool_poison_scanning`, `mcp_tool_baseline`, `mcp_chain_memory`, `mcp_cross_server_chain_memory`, `mcp_data_class_labels`, `a2a_dlp_scanning`, `a2a_prompt_injection_scanning`, `a2a_card_prompt_injection_scanning`, `a2a_card_drift_scanning`, `a2a_ssrf_scanning`, `websocket_dlp_scanning`, `websocket_prompt_injection_scanning`, `ssrf_scanning`, `domain_blocklist`, `entropy_scanning`, `shell_analysis`, `crypto_dlp_scanning`, `hostname_exfil_scanning`, `dns_rebinding_fixture`

Delivery, fixture, and base-observation prerequisites only. `requires` must never encode attack difficulty, evasion resistance, or an enforcement claim (for example `encoding_evasion_scanning`, `ssrf_bypass_scanning`, or `budget_enforcement`); those belong in `capability_tags` or result evidence. The validator rejects those tokens for both single-file and multi-file cases.

Live case, profile, result-row, and receipt artifacts use schema v4 together. The scorer rejects a mixed-version input set. The generated summary and its candidate provenance use schema v5 because their published metric contract changed, while the v4 inputs remain unchanged. Each active profile and result names the exact capability-registry snapshot by ID, format, revision, and raw-byte SHA-256. Historical artifacts are readable only through their frozen readers and are never normalized into active semantics. See [Capability Vocabulary and Profile Evolution](CAPABILITY-VOCABULARY.md).

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

Denial-of-wallet budget cases are MCP tool-call sequences that use a
scoreable call-count model. They carry the `denial_of_wallet` capability tag,
which is what selects them for the payload rules below, and they gate on the
observation surface (`mcp_chain_memory`) rather than on `budget_enforcement`.
`budget_enforcement` is not a scope declaration. It is rejected in `requires`:
gating a case on the feature it exists to test lets a tool delete the case, and
the benign control measuring its over-blocking, simply by not claiming it.

These cases carry the following payload fields alongside `jsonrpc_messages`:

| Field | Type | Description |
|-------|------|-------------|
| `budget_scope` | string | Must be `per_subject` for current budget cases. |
| `subject_id` | string | Neutral subject label used by the case payload. |
| `budget_limit_calls` | integer | Maximum allowed MCP tool calls for the subject in the benchmark window. |
| `over_budget_call_id` | integer | Required for `block` cases; identifies the first call that exceeds `budget_limit_calls`. Omit for `allow` controls. |

For a limit of `N`, the intended boundary is: calls `1..N` are allowed, and
call `N+1` is the first over-budget call. Do not use weighted `cost_units` or
`budget_limit_units`; those are not scoreable against call-count budget tools.

### A2A message cases (`input_type: a2a_message`)

```json
{
  "target_url": "http://a2a-exfil-sink.test/message:send",
  "jsonrpc_messages": [
    {"jsonrpc": "2.0", "method": "message/send", "params": {"message": {"parts": []}}, "id": 1}
  ]
}
```

`target_url` is optional. When present, it identifies the A2A HTTP endpoint the
runner should send the JSON-RPC message to, and its host must be the reserved
benchmark sink `a2a-exfil-sink.test`. The reserved host
`a2a-exfil-sink.test` is an untrusted benchmark sink for cases that must exercise
destination-sensitive detectors such as opaque entropy scanning. Runners may make
the sink reachable with local DNS or IP allowlisting, but must not treat the
hostname itself as trusted.

### A2A Agent Card cases (`input_type: a2a_agent_card`)

```json
{
  "agent_card": {
    "name": "example-agent",
    "skills": []
  }
}
```

### WebSocket frame cases (`input_type: websocket_frame`)

```json
{
  "url": "wss://example.com/socket",
  "frames": [
    {"opcode": "text", "payload": "message"}
  ]
}
```

The reserved host `ws-exfil-sink.test` is an untrusted benchmark sink for
WebSocket cases that must exercise destination-sensitive detectors such as opaque
entropy scanning. Runners may route it to a local reachable fixture, but must not
rewrite it to a trusted fixture hostname or add it to a trusted-destination list.

## Result state

[`gauntlet.md`](gauntlet.md) owns scoreability, result states, denominators, and historical N/A behavior. `requires` and `capability_tags` remain case metadata defined in this specification.

## Machine-Readable Schemas

JSON Schema files for programmatic validation:

- [`schemas/case-v4.schema.json`](../schemas/case-v4.schema.json): case file schema
- [`schemas/multi-file-case-v4.schema.json`](../schemas/multi-file-case-v4.schema.json): temporal MCP drift `case.yaml` schema
- [`schemas/tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json): tool profile schema
- [`schemas/result-v4.schema.json`](../schemas/result-v4.schema.json): runner result line schema

## Governance

[`GOVERNANCE.md`](GOVERNANCE.md) owns case immutability, semantic stability, versioning, neutrality, and contribution policy.
