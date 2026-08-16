<p align="center">
  <img src="assets/social-preview.png" alt="agent-egress-bench: Open test corpus for AI agent egress security" width="640">
</p>

<p align="center">
  <a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/validate.yaml"><img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/validate.yaml/badge.svg" alt="Validate Cases"></a>
  <a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/security.yaml"><img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/security.yaml/badge.svg" alt="Security"></a>
  <a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml"><img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml/badge.svg" alt="Pipelock Scan"></a>
  <a href="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/continuous-gauntlet.yaml"><img src="https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/continuous-gauntlet.yaml/badge.svg" alt="Continuous Gauntlet"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/agent-egress-bench"><img src="https://api.scorecard.dev/projects/github.com/luckyPipewrench/agent-egress-bench/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://goreportcard.com/report/github.com/luckyPipewrench/agent-egress-bench"><img src="https://goreportcard.com/badge/github.com/luckyPipewrench/agent-egress-bench" alt="Go Report Card"></a>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="https://discord.gg/badNfhGKTc"><img alt="Discord" src="https://img.shields.io/badge/Discord-Join%20the%20community-5865F2?logo=discord&logoColor=white"></a>
</p>

A standardized test corpus for evaluating AI agent egress security tools, covering secret exfiltration, prompt injection, SSRF, hostname exfiltration, MCP tool poisoning, chain detection, MCP drift, A2A protocol scanning, WebSocket DLP, encoding evasion, shell obfuscation, and cryptocurrency/financial data protection. Current loader-backed counts are in [`cases/STATS.md`](cases/STATS.md).

**This tests the security tool, not the agent.** Most benchmarks in this space (AgentDojo, InjecAgent, CyberSecEval, AgentHarm) test whether the LLM behaves correctly. This one tests whether the firewall, proxy, or scanner sitting between the agent and the network catches the attack.

```
┌─────────────────────┐     ┌──────────────────────┐     ┌──────────┐
│  AI Agent           │     │  Security Tool        │     │          │
│  (has secrets,      │────▶│  (proxy / firewall /  │────▶│ Internet │
│   runs tools)       │     │   MCP wrapper)        │     │          │
└─────────────────────┘     └──────────────────────┘     └──────────┘
                                     ▲
                            agent-egress-bench
                            tests THIS layer
```

## Why this exists

AI agents that can browse the web, call APIs, and use MCP tools need network-layer security. An agent with access to secrets and an internet connection is an exfiltration risk, whether through prompt injection, tool poisoning, or simple misalignment.

Tools exist to sit between agents and the network (proxies, firewalls, MCP wrappers). But there was no standard way to test them. This corpus fills that gap: a shared set of attack cases that any security tool can run against.

## What's in the corpus

| Category | Directory | What it tests |
|----------|-----------|---------------|
| URL DLP | `cases/url/` | Secrets leaked via query strings, encoded paths, high-entropy subdomains, SSRF, domain blocklist |
| Request body DLP | `cases/request-body/` | Secrets in POST bodies (JSON, YAML, CSV, multipart, base64, hex, env dumps) |
| Header DLP | `cases/headers/` | API keys and tokens in HTTP headers (Bearer, JWT, AWS, multi-header) |
| Hostname exfiltration | `cases/hostname-exfiltration/` | Encoded secrets in DNS hostname labels before resolution |
| Response injection (fetch) | `cases/response-fetch/` | Prompt injection in fetched web content |
| Response injection (MITM) | `cases/response-mitm/` | Injection via tampered TLS-intercepted responses |
| MCP input scanning | `cases/mcp-input/` | DLP and injection in MCP tool arguments (base64, hex, scattered, SSH keys) |
| MCP tool poisoning | `cases/mcp-tool/` | Poisoned tool descriptions, schema injection, rug-pull changes |
| MCP chain detection | `cases/mcp-chain/` | Multi-step exfiltration sequences (read-then-send, env-to-network) |
| MCP drift | `cases/mcp-drift/` | Multi-file before/after tool snapshots for rug-pull and benign drift detection |
| A2A message scanning | `cases/a2a-message/` | Secrets and injection in A2A message parts |
| A2A Agent Card poisoning | `cases/a2a-agent-card/` | Injection in Agent Card skill descriptions, card drift |
| WebSocket DLP | `cases/websocket-dlp/` | Secrets in WebSocket frames, fragment reassembly evasion |
| SSRF bypass | `cases/ssrf-bypass/` | Private IP detection, cloud metadata, encoded IPs |
| Encoding evasion | `cases/encoding-evasion/` | Multi-layer encoding chains, Unicode tricks, zero-width insertion |
| Shell obfuscation | `cases/shell-obfuscation/` | Backtick substitution, brace expansion, IFS manipulation |
| Crypto/financial DLP | `cases/crypto-financial/` | Wallet addresses, seed phrases, credit cards, IBANs |
| False positive suite | `cases/false-positive/` | Benign traffic that must not be blocked |

Counts are logical cases, not fixture files. Most cases are single JSON files; MCP drift cases are multi-file before/after snapshots, and each drift directory counts as one case.

The [loader-backed statistics](cases/STATS.md) include the block, allow, and warn-class breakdown used to assess containment and false-positive behavior.

Most cases are self-contained JSON files with the attack payload, expected verdict (`block` or `allow`), severity, capability tags, and a machine-readable reason for the expected outcome. MCP drift cases under `cases/mcp-drift/` are multi-file before/after fixtures with `case.yaml` metadata.

## Quick start

**Prerequisites:** [Go 1.25+](https://go.dev/dl/) for the validator and portable runner. The runner uses its own Go module dependencies for fixtures and multi-file case parsing.

**Build the validator:**

```bash
cd validate && go build -o aeb-validate .
```

**Validate the corpus:**

```bash
./aeb-validate ../cases
```

**Validate a runner's results or tool profile:**

```bash
./aeb-validate results path/to/results.jsonl ../cases
./aeb-validate profile path/to/tool-profile.json
```

**Run against a tool.** Each tool ships its own runner. The Go program in [`runner/`](runner/) is the reference implementation; it brings up HTTP, TLS, WebSocket, DNS, and MCP HTTP fixtures, executes declared transports through the selected adapter, and emits the Gauntlet summary and an optional receipt-scoring profile.

For the pinned Pipelock release, use the portable entry point from a clean Linux clone on `origin/main` or a tag:

```bash
./scripts/run-pipelock-gauntlet.sh
```

The command downloads the reviewed Pipelock release, verifies its pinned asset digest, published checksum, and reported version, then confines target writes with Landlock and denies Unix-domain sockets with seccomp. It starts the required local fixtures and managed Pipelock processes, runs the single-file and multi-file cases, and leaves one timestamped directory under `continuous-gauntlet-runs/`. That directory contains the exact internal command, stdout results, stderr, summary, case index, corpus stats, release identity, file digests, and a machine-readable execution decision.

It requires Linux, Go 1.25 or newer, Python 3, Git, curl, jq, tar, GNU timeout, SHA-256 utilities, and one of `socat`, `ncat`, or `nc`. Use `--output-dir` to place the self-contained run directory somewhere else. The [Pipelock reference-runner guide](examples/pipelock/README.md) documents the evidence files, explicit development mode, the underlying long-form command, and a neutral scheduling example.

The raw directory intentionally has no made-up public URL. GitHub Actions or another retaining platform adds its real artifact ID and HTTPS location later, without modifying the evidence bytes. Creating a schedule and publishing a result are separate operator decisions.

The repository's scheduled Pipelock lane is read-only and produces review candidates, not automatic public claims. Approved candidates are retained as digest-addressed, hash-linked evidence directories, and a reviewed pull request advances the `latest-verified` pointer. The included reference renderer verifies and displays score, scope, N/A reasons, false-positive rate, and the canonical run URL together. It renders this repository's first-party Pipelock history and ranks nothing. See [Continuous Gauntlet Results](docs/CONTINUOUS-RESULTS.md) for the repository review and publication contract.

For other tools, the runner writes per-case JSONL results to stdout (one object per case, see [docs/RUNNER.md](docs/RUNNER.md)) and a Gauntlet summary JSON to the path passed via `--output` (containment, false-positive rate, non-scoring output-field diagnostics, and per-category results, see [docs/gauntlet.md](docs/gauntlet.md)). `--emit-receipt-profile` additionally writes a byte-reproducible receipt-scoring profile (see [docs/RECEIPT-SCORING.md](docs/RECEIPT-SCORING.md)).

> A minimal legacy shell example for fetch-only cases lives at [`examples/pipelock/harness.sh`](examples/pipelock/harness.sh). It covers a single transport (`/fetch?url=...` GET) and is kept for illustration only — it is not the Gauntlet and will misreport every body, header, WebSocket, MCP, and response-content case. Use the Go runner for any real benchmark.

## Gauntlet scoring

The Gauntlet reports containment and false-positive rate separately, plus non-scoring field-presence diagnostics. [docs/gauntlet.md](docs/gauntlet.md) owns metric definitions, result states, denominators, and measurement status. [Results Use and Attribution](docs/RESULTS-USE.md) owns the claims and disclosures that travel with a public result.

The maintainer's disclosed first-party Pipelock history is published at [pipelab.org/gauntlet](https://pipelab.org/gauntlet/). Every other publisher owns its results.

## What this does NOT test

This corpus has a specific scope. It does not cover:

- **Model alignment.** Whether the LLM refuses harmful instructions. Use AgentDojo, AgentHarm, or ASB for that.
- **Application-layer guardrails.** Whether a guardrail API flags a prompt as malicious. Use AgentShield-benchmark for that.
- **Code generation safety.** Whether the model writes insecure code. Use CyberSecEval for that.
- **Authentication or authorization.** Whether the agent has valid credentials for the APIs it calls.
- **Inbound traffic.** What enters the agent's environment. This corpus focuses on outbound (egress) traffic.

If you need to test the model, use a model benchmark. If you need to test the network security layer, use this.

## How it works

Cases encode wire inputs and expected verdicts. A runner sends each input through the tool and records the observed result. [`docs/SPEC.md`](docs/SPEC.md) owns case shape, [`docs/RUNNER.md`](docs/RUNNER.md) owns runner I/O, and [`docs/gauntlet.md`](docs/gauntlet.md) owns result states and scoring.

## Writing a runner for your tool

Start from the [runner template](examples/runner-template/) or the complete [Pipelock reference runner](examples/pipelock/). [RUNNER.md](docs/RUNNER.md) defines the contract, and [ADOPTION.md](docs/ADOPTION.md) covers the contribution workflow.

## OWASP Agentic Top 10 mapping

Every case category maps to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/). `make check-readme-categories` fails when this table and the corpus disagree, so the mapping stays complete as categories are added:

| Case category | OWASP item | What the cases cover |
|---------------|------------|---------------------|
| `url` | ASI02 Tool Misuse | Secret exfiltration via URL query strings and paths |
| `request_body` | ASI02 Tool Misuse | Secret exfiltration via POST bodies |
| `headers` | ASI02 Tool Misuse | Secret exfiltration via HTTP headers |
| `hostname_exfiltration` | ASI02 Tool Misuse | Encoded data in DNS hostname labels |
| `response_fetch` | ASI01 Goal Hijack + ASI06 Memory Poisoning | Prompt injection in fetched content |
| `response_mitm` | ASI01 Goal Hijack + ASI04 Supply Chain | Injection via tampered responses |
| `mcp_input` | ASI02 Tool Misuse | DLP and injection in tool arguments |
| `mcp_tool` | ASI04 Supply Chain | Poisoned tool descriptions, rug-pull changes |
| `mcp_chain` | ASI02 Tool Misuse + ASI08 Cascading Failures | Multi-step exfiltration sequences |
| `mcp_drift` | ASI04 Supply Chain | Tool inventory changes after approval |
| `a2a_message` | ASI07 Inter-Agent Communication | Secrets and injection in A2A messages |
| `a2a_agent_card` | ASI04 Supply Chain + ASI07 Inter-Agent | Poisoned Agent Card skill descriptions |
| `websocket_dlp` | ASI02 Tool Misuse | Secrets in WebSocket frames, fragment evasion |
| `ssrf_bypass` | ASI02 Tool Misuse | SSRF via IP encoding, cloud metadata |
| `encoding_evasion` | ASI02 Tool Misuse | Multi-layer encoding to bypass scanning |
| `shell_obfuscation` | ASI02 Tool Misuse + ASI05 Code Execution | Obfuscated shell commands in tool args |
| `crypto_financial` | ASI02 Tool Misuse | Wallet addresses, seed phrases, credit cards |
| `false_positive` | N/A | Benign traffic that must not be blocked |

Full mapping with MITRE ATT&CK techniques: [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md)

## Scope

This corpus evaluates the **security tool** that sits between an AI agent and the network (a proxy, firewall, or MCP wrapper): given an attack, did the tool catch it. It does not evaluate the agent or model's own behavior. Cases test observable outcomes at the wire level, such as whether an exfiltrated secret in a query string was blocked or whether prompt injection in a tool response was detected.

Each publisher publishes and owns its own results. This repository publishes no ranking, leaderboard, or cross-tool comparison table. <!-- claim-ok: states the non-claim -->

## Docs

Core contracts:

- [SPEC.md](docs/SPEC.md): case schema, field definitions, enums, payload formats
- [RUNNER.md](docs/RUNNER.md): runner input, output, adapter, and verdict-mapping contract
- [gauntlet.md](docs/gauntlet.md): result states, scoring, scope, and publication methodology
- [GOVERNANCE.md](docs/GOVERNANCE.md): neutrality, case immutability, versioning, and compatibility
- [RELEASES.md](docs/RELEASES.md): pinned runner, corpus, and schema release verification
- [OCI-RUNNER.md](docs/OCI-RUNNER.md): pinned runner image, reusable Action, devcontainer, and offline operation
- [contracts/artifacts.json](contracts/artifacts.json): machine-readable artifact compatibility inventory

Evidence and publication:

- [RECEIPT-SCORING.md](docs/RECEIPT-SCORING.md): receipt evidence scoring axis for independently verifiable artifacts
- [CONTROL-EVIDENCE.md](docs/CONTROL-EVIDENCE.md): v0 run-level control-evidence package and verifier contract
- [CONTROL-EVIDENCE-V1.md](docs/CONTROL-EVIDENCE-V1.md): active v4 registry-bound control-evidence contract
- [CAPABILITY-VOCABULARY.md](docs/CAPABILITY-VOCABULARY.md): immutable reporting-label registry and profile evolution policy
- [ARTIFACT-PROVENANCE.md](docs/ARTIFACT-PROVENANCE.md): opt-in external `schema-valid`, `authenticated-at(T)`, and `buyer-reproduced` provenance assessments
- [RESULTS-USE.md](docs/RESULTS-USE.md): assurance labels, public-result disclosures, and correction rules

Integration and reference:

- [GATEWAY-ADAPTER.md](docs/GATEWAY-ADAPTER.md): the narrow generic MCP gateway plugin contract and its current limits
- [ADOPTION.md](docs/ADOPTION.md): guide for vendors adopting the benchmark
- [GLOSSARY.md](docs/GLOSSARY.md): definitions of key terms (agent firewall, egress security, etc.)
- [OWASP-MAPPING.md](docs/OWASP-MAPPING.md): case categories mapped to OWASP Agentic Top 10
- [schemas/](schemas/): JSON Schema files for cases, tool profiles, and results

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Cases, runners, and documentation improvements are all welcome.

**Case IDs are immutable.** Once merged, a case ID never changes. Semantic changes to existing cases require a new case with a new ID.

## Governance

This corpus was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author. Contributions from any vendor or individual are welcome. This repository publishes no ranking, leaderboard, or cross-tool comparison table, and the maintainer awards no verification mark to anyone else's result. <!-- claim-ok: states the non-claim --> Each publisher publishes and owns its own results, under the labels defined in [docs/RESULTS-USE.md](docs/RESULTS-USE.md). Publishing a result that reflects badly on Pipelock needs no notice or approval.

**Conflict of interest disclosure:** The author builds an agent egress security tool. This corpus was designed to be tool-neutral: cases test observable behavior (did the request get blocked?), not implementation details. The [Pipelock runner](examples/pipelock/) is a reference implementation, not a privileged position.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md).

## Learn more

- [What is an Agent Firewall?](https://pipelab.org/agent-firewall/) — the security architecture this corpus tests
- [AI Agent Security: Three Layers](https://pipelab.org/learn/ai-agent-security/) — hooks, guardrails, and egress inspection explained
- [MCP Vulnerabilities](https://pipelab.org/learn/mcp-vulnerabilities/) — the MCP attack surface mapped
- [Pipelock Gauntlet history](https://pipelab.org/gauntlet/) — the maintainer's disclosed first-party run history

## License

Apache 2.0. See [LICENSE](LICENSE).

---

If this corpus is useful to you, give it a star. It helps others find it.
