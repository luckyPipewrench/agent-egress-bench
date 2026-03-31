# Gauntlet Methodology

## Purpose

The Gauntlet tests AI agent egress security tools: proxies, firewalls, MCP wrappers, and similar network-layer defenses. It does not test the LLM. Model benchmarks (AgentDojo, InjecAgent, AgentHarm) measure whether the agent refuses harmful instructions. The Gauntlet measures whether the security tool sitting between the agent and the network catches the attack.

```
Agent (secrets, tools) --> Security tool (proxy/firewall) --> Internet
                                    ^
                           Gauntlet tests THIS
```

The corpus is a set of JSON case files. Each case encodes an attack payload (or benign traffic), the expected verdict (`block` or `allow`), and the capabilities required to evaluate it. A runner feeds cases to the tool under test and records verdicts.

## Scope

### In scope

- Secret exfiltration: URL query strings, request bodies, HTTP headers, WebSocket frames, MCP tool arguments, A2A message parts, hostname labels (DNS-based exfil)
- Prompt injection: HTTP response content (fetched and MITM), MCP tool results, A2A messages
- SSRF: private IP detection, cloud metadata endpoints, encoded IP bypasses, DNS rebinding
- MCP attacks: tool description poisoning, schema injection, rug-pull (drift), multi-step exfiltration chains
- A2A attacks: Agent Card poisoning, skill description injection, card drift
- Encoding evasion: multi-layer encoding chains (URL, base64, hex), Unicode tricks, zero-width character insertion
- Shell obfuscation: backtick substitution, brace expansion, IFS manipulation, variable indirection
- Crypto and financial data: wallet addresses, seed phrases, credit card numbers, IBANs
- False positives: benign traffic patterns that naive scanners would incorrectly block

### Out of scope

- Timing side channels
- Header ordering covert channels
- HTTP/2 covert channels (PRIORITY, padding)
- Steganography (image/audio payloads)
- Semantic manipulation (persuading the model to reinterpret instructions)
- Multi-turn context poisoning
- Inbound traffic filtering
- Authentication and authorization
- Model alignment and refusal behavior

## Case Design Principles

Every case is **observable**: the verdict depends on what appears on the wire, not on tool internals. A case asks "was this secret in the query string blocked?" not "did the tool use regex pattern X?"

Every case is **deterministic**: given the same payload and tool configuration, the expected verdict is always the same. No judgment calls. No "it depends."

Every case is **tool-neutral**: no case is written to favor or penalize a specific tool. Cases test observable network behavior.

**Severity** (`critical`, `high`, `medium`, `low`) and **false positive risk** (`low`, `medium`, `high`) are informational metadata. They help operators prioritize but do not affect scoring.

## Categories

The corpus contains 17 categories across the `cases/` directory tree.

| # | Category | Directory | What it tests |
|---|----------|-----------|---------------|
| 1 | URL DLP | `cases/url/` | Secrets in query strings, encoded paths, high-entropy subdomains |
| 2 | Request body DLP | `cases/request-body/` | Secrets in POST bodies (JSON, YAML, CSV, multipart, base64, hex) |
| 3 | Header DLP | `cases/headers/` | API keys and tokens in HTTP headers |
| 4 | Response injection (fetch) | `cases/response-fetch/` | Prompt injection in fetched web content |
| 5 | Response injection (MITM) | `cases/response-mitm/` | Injection via TLS-intercepted responses |
| 6 | MCP input scanning | `cases/mcp-input/` | DLP and injection in MCP tool call arguments |
| 7 | MCP tool poisoning | `cases/mcp-tool/` | Poisoned tool descriptions, schema injection, rug-pull drift |
| 8 | MCP chain detection | `cases/mcp-chain/` | Multi-step exfiltration sequences (read-then-send, env-to-network) |
| 9 | A2A message scanning | `cases/a2a-message/` | Secrets and injection in A2A message parts |
| 10 | A2A Agent Card poisoning | `cases/a2a-agent-card/` | Injection in Agent Card skill descriptions, card drift |
| 11 | WebSocket DLP | `cases/websocket-dlp/` | Secrets in WebSocket frames, fragment reassembly evasion |
| 12 | SSRF bypass | `cases/ssrf-bypass/` | Private IP detection, cloud metadata, encoded IP bypasses |
| 13 | Encoding evasion | `cases/encoding-evasion/` | Multi-layer encoding chains, Unicode tricks, zero-width insertion |
| 14 | Shell obfuscation | `cases/shell-obfuscation/` | Backtick substitution, brace expansion, IFS manipulation |
| 15 | Crypto/financial DLP | `cases/crypto-financial/` | Wallet addresses, seed phrases, credit cards, IBANs |
| 16 | Hostname exfiltration | `cases/hostname-exfil/` | Secret data encoded in DNS hostname labels |
| 17 | False positive suite | `cases/false-positive/` | Benign traffic that must not be blocked |

Categories 1 through 16 contain malicious cases (expected verdict: `block`). Category 17 contains benign cases (expected verdict: `allow`). Some categories also include benign cases for category-specific false positive testing.

## Scoring

The Gauntlet evaluates four independent dimensions. There is no composite score. Each metric is reported separately so users can evaluate trade-offs on their own terms.

| Metric | What it measures | Formula | Better |
|--------|-----------------|---------|--------|
| **Containment** | Attacks correctly blocked | blocked_malicious / total_malicious_applicable | Higher (1.0 = perfect) |
| **False positive rate** | Benign traffic incorrectly blocked | blocked_benign / total_benign_applicable | Lower (0.0 = perfect) |
| **Detection** | Correct classification of blocked attacks | classified_correctly / correctly_blocked_malicious | Higher (1.0 = perfect) |
| **Evidence** | Structured proof emission | evidence_emitted / correctly_blocked_malicious | Higher (1.0 = perfect) |

### No composite score

Combining these into a single number would hide real trade-offs. A tool with 99% containment and 15% false positive rate is very different from one with 85% containment and 1% false positive rate. Both might produce the same composite number. Operators need to see each dimension.

### Two views

**Full corpus (primary).** All cases in the denominator. This is the procurement view. If a tool does not claim a capability, unclaimed cases count as failures. A tool that claims to handle 40% of attack surfaces gets scored on 100% of them.

**Applicable (diagnostic).** Only cases matching the tool's declared capabilities are in the denominator. This is the engineering view. Useful for understanding how well a tool performs within its stated scope. Not suitable for cross-tool procurement decisions because it hides coverage gaps.

The full corpus view is primary. Published results on pipelab.org use full corpus scoring. Applicable scoring is available in the summary JSON for diagnostic use.

### Containment floor

If containment falls below 80%, the run is marked `insufficient`. A tool that blocks poorly is not a security tool, regardless of classification or logging quality. All four metrics are still computed for an insufficient run. The `sufficient: false` flag signals that the floor was not met.

## Capability Profiles

Each tool declares a **tool profile** (`tool-profile.json`) with two sections:

- **claims**: which `capability_tags` the tool handles (e.g., `url_dlp`, `mcp_input_scan`, `ssrf`)
- **supports**: which transports and prerequisites the tool satisfies (e.g., `fetch_proxy: true`, `tls_interception: true`)

### Applicability filtering

A case is `not_applicable` when any of these conditions is true (checked in order, first match wins):

1. Any value in the case's `capability_tags` is absent from the tool's `claims`.
2. Any value in the case's `requires` has `supports.<value>` set to `false` in the profile.
3. The case's `transport` has `supports.<transport>` set to `false` in the profile.

Not-applicable cases are never executed, never scored, and excluded from all metric denominators. The applicability check is deterministic. No judgment calls.

## Versioning

Five provenance fields identify a Gauntlet run:

| Field | What it tracks | Source |
|-------|---------------|--------|
| `corpus_version` | Tag or commit of the case corpus | Repository tag |
| `scoring_version` | Version of the Gauntlet scoring rules | `gauntlet_version` in summary JSON |
| `corpus_sha256` | Hash of all case file contents (sorted by path) | Computed at runtime |
| `runner_version` | Version of the runner binary | Hardcoded in runner |
| `tool_profile_sha256` | Hash of the tool profile used | Computed at runtime |

**Staleness** is determined by `corpus_version` and `scoring_version` only. If either changes, previous results are stale and should be re-run. The other three fields are informational: they support reproducibility and audit trails but do not trigger staleness.

`corpus_sha256` proves which exact file contents were present at runtime. `runner_version` identifies the binary that produced the results. `tool_profile_sha256` proves which capability claims were active. Together, these five fields make any run fully reproducible.

## Running the Gauntlet

Build and run the Gauntlet runner:

```bash
cd runner && go build -o aeb-gauntlet .
./aeb-gauntlet \
  --cases ../cases \
  --profile ../examples/pipelock/tool-profile.json \
  --output summary.json
```

Per-case JSONL results are written to stdout. The summary JSON file is written to the path specified by `--output`. See [RUNNER.md](RUNNER.md) for the full runner contract and verdict mapping rules.

## Submission

Vendors run the Gauntlet locally against their own tool. Results are submitted to the [pipelab.org](https://pipelab.org) leaderboard.

Submitted results start as **self-reported**. A maintainer may verify results by re-running the Gauntlet against the same tool version. Verified results are marked accordingly on the leaderboard.

No results are stored in this repository. This repo contains attack cases and scoring methodology only. Each vendor owns their results.

## Dispute Resolution

To dispute a case verdict, open a **GitHub Discussion** with:

1. The case ID
2. The proposed change (new expected verdict, revised payload, or case removal)
3. Evidence supporting the change (real-world traffic data, false positive analysis, attack feasibility)

### If accepted

A new case is created with a `supersedes` field pointing to the original case ID. The original case remains byte-immutable (its ID, payload, and expected verdict never change). The supersession is tracked in [`data/supersessions.json`](../data/supersessions.json).

### If rejected

The maintainer posts an explanation in the discussion thread with reasoning.

Case IDs are permanent. Even superseded cases stay in the corpus as historical records. Runners skip superseded cases automatically when the supersessions manifest is loaded.

## Neutrality

This corpus was created by the author of [Pipelock](https://github.com/luckyPipewrench/pipelock), an agent egress security tool. That conflict of interest is disclosed here, in [GOVERNANCE.md](GOVERNANCE.md), and in the repository README.

Neutrality is maintained through design constraints:

- **Cases test observable behavior.** Every case asks "was this traffic blocked?" not "did the tool use this internal technique?" No case requires a specific implementation approach.
- **Pipelock runner is reference, not privileged.** The Pipelock runner in `examples/pipelock/` is a working example. It has no special status. Any vendor can add a runner in `examples/`.
- **Pipelock results live on pipelab.org, not in this repo.** No tool's scores are stored in the benchmark repository.
- **Methodology published before results.** The scoring rules, case corpus, and governance policy are public before any tool publishes Gauntlet results. No retroactive tuning.

Contributions from any vendor, researcher, or individual are welcome. See [GOVERNANCE.md](GOVERNANCE.md) for the full policy and [ADOPTION.md](ADOPTION.md) for how to build a runner and publish results.
