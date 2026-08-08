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

A logical case takes one of two fixture shapes. Most are a single JSON file in a category directory. MCP drift cases are a directory under `cases/mcp-drift/` holding `case.yaml` plus before, after and expected snapshots, replayed through one MCP session. Both shapes count as one case, both are pinned by `cases/MANIFEST.txt`, and the counts in [`cases/STATS.md`](../cases/STATS.md) are generated from what the runner loads rather than from a file count.

## Categories

The corpus categories across the `cases/` directory tree are listed below. Current counts are generated from the runner-loaded corpus in [`cases/STATS.md`](../cases/STATS.md).

| Category | Directory | What it tests |
|----------|-----------|---------------|
| URL DLP | `cases/url/` | Secrets in query strings, encoded paths, high-entropy subdomains |
| Request body DLP | `cases/request-body/` | Secrets in POST bodies (JSON, YAML, CSV, multipart, base64, hex) |
| Header DLP | `cases/headers/` | API keys and tokens in HTTP headers |
| Response injection (fetch) | `cases/response-fetch/` | Prompt injection in fetched web content |
| Response injection (MITM) | `cases/response-mitm/` | Injection via TLS-intercepted responses |
| MCP input scanning | `cases/mcp-input/` | DLP and injection in MCP tool call arguments |
| MCP tool poisoning | `cases/mcp-tool/` | Poisoned tool descriptions, schema injection, rug-pull drift |
| MCP chain detection | `cases/mcp-chain/` | Multi-step exfiltration sequences (read-then-send, env-to-network) |
| A2A message scanning | `cases/a2a-message/` | DLP and injection in A2A message parts |
| A2A Agent Card poisoning | `cases/a2a-agent-card/` | Injection in Agent Card skill descriptions, card drift |
| WebSocket DLP | `cases/websocket-dlp/` | Secrets in WebSocket frames, fragment reassembly evasion |
| SSRF bypass | `cases/ssrf-bypass/` | Private IP detection, cloud metadata, encoded IP bypasses |
| Encoding evasion | `cases/encoding-evasion/` | Multi-layer encoding chains, Unicode tricks, zero-width insertion |
| Shell obfuscation | `cases/shell-obfuscation/` | Backtick substitution, brace expansion, IFS manipulation |
| Crypto/financial DLP | `cases/crypto-financial/` | Wallet addresses, seed phrases, credit cards, IBANs |
| Hostname exfiltration | `cases/hostname-exfiltration/` | Secret data encoded in DNS hostname labels |
| MCP drift | `cases/mcp-drift/` | Multi-file MCP tool-definition changes, including benign drift guardrails |
| False positive suite | `cases/false-positive/` | Benign traffic that must not be blocked |

Categories can contain malicious (`block`), benign (`allow`), or drift-guardrail (`warn`) cases. Some attack-surface categories also include benign cases for category-specific false-positive testing.

## Scoring

The Gauntlet evaluates four independent dimensions. There is no composite score. Each metric is reported separately so users can evaluate trade-offs on their own terms.

| Metric | What it measures | Formula | Better |
|--------|-----------------|---------|--------|
| **Containment** | Attacks correctly blocked | blocked_malicious / malicious denominator for the selected view | Higher (1.0 = perfect) |
| **False positive rate** | Benign traffic incorrectly blocked | blocked_benign / benign denominator for the selected view | Lower (0.0 = perfect) |
| **Detection** | Correct classification of blocked attacks | classified_correctly / correctly_blocked_malicious | Higher (1.0 = perfect) |
| **Evidence** | Structured proof emission | evidence_emitted / correctly_blocked_malicious | Higher (1.0 = perfect) |

### No composite score

Combining these into a single number would hide real trade-offs. A tool with 99% containment and 15% false positive rate is very different from one with 85% containment and 1% false positive rate. Both might produce the same composite number. Operators need to see each dimension.

### Two views

**Full corpus (primary).** All cases in the denominator. This is the procurement view. If a tool does not claim a capability, unclaimed cases count as failures. A tool that claims to handle 40% of attack surfaces gets scored on 100% of them.

**Applicable (diagnostic).** Only cases matching the tool's declared `supports` map are in the denominator. This is the engineering view. Useful for understanding how well a tool performs within its stated scope. Not suitable for cross-tool procurement decisions because it hides coverage gaps.

The full corpus view is primary. Published results should use full corpus scoring. Applicable scoring is available in the summary JSON for diagnostic use.

### Containment floor

If full-corpus containment falls below 80%, the run is marked `insufficient`. A tool that blocks poorly or covers too little of the corpus is not sufficient for the primary procurement view. All four metrics are still computed. The `sufficient: false` flag signals that the floor was not met.

## Capability Profiles

Each tool declares a **tool profile** (`tool-profile.json`) with two sections:

- **claims**: reporting labels that help interpret results (e.g., `url_dlp`, `mcp_input_scan`, `ssrf`)
- **supports**: which transports and fine-grained prerequisites the tool satisfies (e.g., `fetch_proxy: true`, `url_dlp_scanning: true`, `tls_interception: true`)

### Applicability filtering

A case is `not_applicable` when any of these conditions is true (checked in order, first match wins):

1. Any value in the case's `requires` has `supports.<value>` set to `false` in the profile.
2. The case's `transport` has `supports.<transport>` set to `false` in the profile.

Not-applicable cases are never executed and are excluded from applicable-view denominators. In the primary full-corpus view, non-applicable malicious cases remain in the denominator as attacks not blocked. The applicability check is deterministic. No judgment calls.

### Adapter transport integrity

An adapter must execute the case's declared transport. A scan API result is not evidence that a fetch, forward-proxy, WebSocket, MCP, or A2A transport enforced the same payload. Adapters therefore must not substitute transports or fall back from one transport to another.

Applicability is decided before adapter execution. If an adapter cannot execute a case that the tool profile declared applicable, the result is `error`, not `not_applicable`. This makes missing fixtures visible and lets the error-rate gate invalidate incomplete runs.

`mcp_http` cases target the tool's MCP HTTP listener directly. They are a
distinct MCP ingress surface, not evidence for HTTP forward-proxy enforcement.

WebSocket cases also need careful interpretation when a fixture address is local: a proxy may block the loopback fixture as SSRF before any frame scan occurs. Such a result proves SSRF enforcement, not that the WebSocket frame scanner evaluated the payload. Evidence should identify the observed enforcement layer when possible.

## Versioning

Five provenance fields identify a Gauntlet run:

| Field | What it tracks | Source |
|-------|---------------|--------|
| `corpus_version` | Tag or commit of the case corpus | Repository tag |
| `scoring_version` | Version of the Gauntlet scoring and applicability rules | Runner constant emitted in summary JSON |
| `corpus_sha256` | Hash of all case file contents (sorted by path) | Computed at runtime |
| `runner_version` | Version of the runner binary | Hardcoded in runner |
| `tool_profile_sha256` | Hash of the tool profile used | Computed at runtime |

**Staleness** is determined by `corpus_version` and `scoring_version` only. If either changes, previous results are stale and should be re-run. The other three fields are informational: they support reproducibility and audit trails but do not trigger staleness.

Scoring version 2.5 gates applicability on observability: a case applies when the
runner can deliver its exact input to the tool and observe a trustworthy verdict.
Attack-difficulty and evasion-resistance flags (`encoding_evasion_scanning`,
`ssrf_bypass_scanning`) no longer gate applicability, so a tool cannot render a
hard variant `not_applicable` by declining a difficulty claim for a surface it
already inspects. Full-corpus scores remain primary and directly comparable across
this change (a malicious not-applicable case already counts as unblocked). Applicable-only
scores from before 2.5 are not comparable to those after it, because the closed loophole
inflated them. Full-corpus scores are treated as diagnostic-versus-primary as in 2.1, and
an adapter's inability to execute a declared applicable transport still counts as an error.

`corpus_sha256` proves which exact file contents were present at runtime. `runner_version` identifies the binary that produced the results. `tool_profile_sha256` proves which capability claims were active. Together, these five fields make any run fully reproducible.

## Running the Gauntlet

For the reviewed Pipelock release, run the portable entry point from a clean Linux clone:

```bash
./scripts/run-pipelock-gauntlet.sh
```

The entry point pins and verifies the released binary, supplies the required managed commands, enables the local fixtures, includes the multi-file MCP drift corpus, validates the result rows, and leaves a hash-bound evidence directory. It rejects a recorded command with the fixture or multi-file flags missing. Without fixtures, cases can fail because no local server exists rather than because policy blocked them, and the false-positive rate becomes meaningless. A plain listening proxy also scores response-interception cases incorrectly because it does not receive the runner's TLS fixture configuration.

The raw portable directory is the common execution layer. It has a local run ID but no invented public URL. GitHub Actions or another retaining platform supplies a real artifact ID and canonical HTTPS URL during a separate finalization step. The [Pipelock reference-runner guide](../examples/pipelock/README.md) documents every evidence file, explicit development mode, the underlying long-form command, and a Linux scheduling example. The [continuous-results contract](CONTINUOUS-RESULTS.md) documents the separate append-only review and publication step.

For other tools and adapter development, use the Go runner directly. Per-case JSONL results are written to stdout and the summary JSON file is written to the path specified by `--output`. See [RUNNER.md](RUNNER.md) for the full runner contract and verdict mapping rules.

## Publishing a result

Vendors, labs, and customers run the Gauntlet against their own target and publish the result themselves. This repository stores no third-party results and awards no verification mark to one. Whoever ran it owns it.

Label the run with the assurance labels in [Results Use and Attribution](RESULTS-USE.md), and publish every identifying fact in that policy's table. The table is the complete list; it covers exact method commit, corpus and scoring version with `corpus_sha256`, capability profile and its digest, adapter identity and owner, target version and configuration, the applicable, not-applicable, and error counts with N/A reasons, the metrics reported separately, and the instructions to reproduce the run. A number without those facts cannot be reproduced or disputed.

The maintainer-operated Pipelock lane is the one result set kept in this repository. Its records live under `gauntlet-site/results/pipelock/` as immutable evidence directories selected by a reviewed `latest-verified` pointer. That lane is disclosed self-run, artifact-validated regression evidence. It carries no independence claim, and the maintainer re-running somebody else's tool would not change that.

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
- **Third-party results live outside this repo.** The append-only Pipelock history is disclosed first-party regression evidence. Optional receipt profiles may live in `profiles/` as self-reported, reproducible evidence artifacts.
- **Methodology published before results.** The scoring rules, case corpus, and governance policy are public before any tool publishes Gauntlet results. No retroactive tuning.
- **The rules bind the maintainer too.** Anyone may publish an adverse Pipelock result with no notice or approval, and the maintainer awards nobody a verification mark. See [RESULTS-USE.md](RESULTS-USE.md).

Contributions from any vendor, researcher, or individual are welcome. See [GOVERNANCE.md](GOVERNANCE.md) for the full policy and [ADOPTION.md](ADOPTION.md) for how to build a runner and publish results.
