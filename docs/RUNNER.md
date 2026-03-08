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

If your tool does not support domain blocklisting, omit `domain_blocklist` from your profile's `claims` and these cases will be scored `not_applicable`.

## Applicability Check

Before running a case, the runner must check applicability:

1. Every `capability_tags` value must be in the tool profile's `claims`
2. Every `requires` value must be satisfied by the tool profile's `supports`

If either check fails, emit `score: "not_applicable"` and `actual_verdict: "not_applicable"` without running the case.

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
