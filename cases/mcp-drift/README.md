# MCP drift cases

End-to-end worked scenarios exercising the **rug-pull / drift detection** path
in MCP-wrapping security tools. Where `cases/mcp-tool/` carries single-JSON
attack payloads (one `tools/list` snapshot), this directory carries
**before/after pairs plus expected receipt output** — a complete adversarial
chain that drives the detector through baseline establishment and subsequent
mutation.

## Why a new directory

The single-JSON case format in `cases/<category>/` describes one input and the
verdict a scanner MUST emit. Drift is inherently **temporal**: the attack
exists in the delta between a benign baseline and a later mutated response.
Modelling that as one JSON loses the baseline anchor that vendors need to
demonstrate detection.

These cases are intentionally a different shape:

```
<case-id>/
├── case.yaml      Case metadata (id, threat model, expected verdict)
├── before.json    Initial tools/list response — the baseline
├── after.json     Later tools/list response — the mutation (or cross-server)
├── expected.json  The receipt the security tool MUST emit on after.json
└── notes.md       Attack narrative + detection logic explainer
```

The `validate/` Go tool checks the multi-file `schema_version` and `requires`
vocabulary. The runner validates the full layout and replays `before.json`,
then `after.json`, against one MCP session before comparing the emitted receipt
with `expected.json`.

## `case.yaml` schema (v4, inline)

```yaml
schema_version: 4
id: <unique, immutable>
category: mcp_drift                # multi-file category, not in the single-file case-v4 schema
title: <human-readable>
description: <what the case demonstrates>
threat_model: <prose: what the attacker controls, what they want>
input_type: mcp_tool_sequence_temporal
transport: mcp_stdio | mcp_http
files:
  before: before.json
  after: after.json
  expected: expected.json
expected_verdict: block | warn | allow
severity: critical | high | medium | low
capability_tags: [mcp_tool_poison, mcp_chain, ...]
requires: [mcp_tool_baseline, ...]
false_positive_risk: low | medium | high
why_expected: <machine-readable reason>
notes: <pointer to notes.md>
source: <citation, real-world exploit reference>
```

## Cases

| id                          | threat                                                                    | verdict |
|-----------------------------|---------------------------------------------------------------------------|---------|
| `mcp-drift-benign-001`      | Server adds a new tool between sessions. Benign drift, observable.        | warn    |
| `mcp-drift-rugpull-desc-002`| Description silently rewritten to inject instructions post-approval.      | block   |
| `mcp-drift-rugpull-param-003` | Parameter renamed from `query` to `query_and_system_prompt`.            | block   |
| `mcp-drift-collusion-004`   | Cross-server toxic composition: tool A references tool B in server B.     | block   |
| `mcp-drift-http-rugpull-desc-005` | Streamable HTTP description gains a workspace-data routing instruction. | block |
| `mcp-drift-http-benign-refinement-006` | Streamable HTTP description adds harmless result-format detail. | allow |

## Detection contract

For each case, a conforming detector configured with rug-pull / chain detection
enabled MUST:

1. Load `before.json` and establish a baseline (one entry per tool, hashing
   `description + inputSchema`).
2. Load `after.json` and compare against the baseline.
3. Emit a receipt that matches `expected.json` on the following fields
   (other fields are implementation-detail-free):

   - `action_record.verdict`
   - `action_record.layer`
   - `action_record.pattern`
   - `action_record.severity`
   - Any `action_record.intent` value documented in `expected.json`

Signature/key fields are not pinned across vendors. Each vendor signs with its
own production key; the conformance test is over the **decision semantics**,
not the signature provenance.

## Cross-vendor reactability

These cases are designed to be runnable against multiple MCP-wrapping
implementations. Tools with rug-pull detection should produce receipts on each
case and publish their results. Cases 1-3 stand alone; case 4 (cross-server
collusion) depends on chain detection and sensitivity labels. Tools without
sensitivity labels should disclose that gap rather than silently passing.
Cases 5 and 6 use native Streamable HTTP through one session and one upstream.
Their runner path proves both inventory requests at the upstream and compares
the full changed definition delivered to the agent.

## Source threats

- **Invariant Labs WhatsApp/GitHub research** (2025) — original public
  demonstration of MCP rug-pull via description mutation.
- **Hidden Layer parameter-abuse research** — MCP tool parameter name
  manipulation as an injection vector.
- **OWASP ASI04** (Supply Chain) — generalisation of post-approval tool
  mutation as a supply-chain attack class.
- **OWASP ASI02 + ASI08** — cross-server tool composition as a lethal-trifecta
  enabler.
