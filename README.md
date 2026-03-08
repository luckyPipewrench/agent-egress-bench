# agent-egress-bench

[![Validate Cases](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/validate.yaml/badge.svg)](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/validate.yaml)
[![Security](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/security.yaml/badge.svg)](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/security.yaml)
[![Pipelock Scan](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml/badge.svg)](https://github.com/luckyPipewrench/agent-egress-bench/actions/workflows/pipelock.yaml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/luckyPipewrench/agent-egress-bench/badge)](https://scorecard.dev/viewer/?uri=github.com/luckyPipewrench/agent-egress-bench)
[![Go Report Card](https://goreportcard.com/badge/github.com/luckyPipewrench/agent-egress-bench)](https://goreportcard.com/report/github.com/luckyPipewrench/agent-egress-bench)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Pipelab](https://img.shields.io/badge/Pipelab-pipelab.org-blue)](https://pipelab.org)

A standardized test corpus for evaluating AI agent egress security tools. 73 cases across 8 categories, covering secret exfiltration, prompt injection, SSRF, MCP tool poisoning, and chain detection.

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

| Category | Directory | Cases | What it tests |
|----------|-----------|-------|---------------|
| URL DLP | `cases/url/` | 15 | Secrets leaked via query strings, encoded paths, high-entropy subdomains, SSRF, domain blocklist |
| Request body DLP | `cases/request-body/` | 10 | Secrets in POST bodies (JSON, YAML, CSV, multipart, base64, hex, env dumps) |
| Header DLP | `cases/headers/` | 9 | API keys and tokens in HTTP headers (Bearer, JWT, AWS, multi-header) |
| Response injection (fetch) | `cases/response-fetch/` | 8 | Prompt injection in fetched web content |
| Response injection (MITM) | `cases/response-mitm/` | 7 | Injection via tampered TLS-intercepted responses |
| MCP input scanning | `cases/mcp-input/` | 9 | DLP and injection in MCP tool arguments (base64, hex, scattered, SSH keys) |
| MCP tool poisoning | `cases/mcp-tool/` | 7 | Poisoned tool descriptions, schema injection, rug-pull changes |
| MCP chain detection | `cases/mcp-chain/` | 8 | Multi-step exfiltration sequences (read-then-send, env-to-network) |

57 malicious cases (expected: block) and 16 benign cases (expected: allow) to test false positive rates.

Each case is a self-contained JSON file with the attack payload, expected verdict (`block` or `allow`), severity, capability tags, and a machine-readable reason for the expected outcome.

## Quick start

**Prerequisites:** [Go 1.24+](https://go.dev/dl/) (stdlib only, no external dependencies).

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
./aeb-validate results path/to/results.jsonl
./aeb-validate profile path/to/tool-profile.json
```

**Run against a tool** (using the Pipelock reference runner as an example):

```bash
cd examples/pipelock
bash harness.sh /path/to/pipelock
```

Output is JSONL (one result per case). See [docs/RUNNER.md](docs/RUNNER.md) for the runner contract.

## What this does NOT test

This corpus has a specific scope. It does not cover:

- **Model alignment.** Whether the LLM refuses harmful instructions. Use AgentDojo, AgentHarm, or ASB for that.
- **Application-layer guardrails.** Whether a guardrail API flags a prompt as malicious. Use AgentShield-benchmark for that.
- **Code generation safety.** Whether the model writes insecure code. Use CyberSecEval for that.
- **Authentication or authorization.** Whether the agent has valid credentials for the APIs it calls.
- **Inbound traffic.** What enters the agent's environment. This corpus focuses on outbound (egress) traffic.

If you need to test the model, use a model benchmark. If you need to test the network security layer, use this.

## How it works

Each case file contains:
- A **payload** matching how the attack would appear in real agent traffic
- An **expected verdict** (`block` or `allow`)
- **Capability tags** describing what the case exercises (DLP, injection detection, SSRF, etc.)
- **Requirements** the tool must support to evaluate the case (TLS interception, body scanning, etc.)

A runner feeds each case to the security tool and observes whether it blocked or allowed the traffic. Cases the tool can't handle (missing capabilities) are scored `not_applicable`, not `fail`. See [docs/SCORING.md](docs/SCORING.md).

## Writing a runner for your tool

A runner connects your security tool to this corpus. You need:

1. A `tool-profile.json` declaring your tool's capabilities
2. A script that feeds each case to your tool and observes the verdict
3. JSONL output following the format in [docs/RUNNER.md](docs/RUNNER.md)

Start from the [runner template](examples/runner-template/) for a working skeleton, or look at the [Pipelock runner](examples/pipelock/) for a complete example. Put your runner in `examples/{your-tool}/` and open a PR. See [docs/ADOPTION.md](docs/ADOPTION.md) for the full guide.

## OWASP Agentic Top 10 mapping

The 8 case categories map to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):

| Case category | OWASP item | What the cases cover |
|---------------|------------|---------------------|
| `url` | ASI02 Tool Misuse | Secret exfiltration via URL query strings and paths |
| `request_body` | ASI02 Tool Misuse | Secret exfiltration via POST bodies |
| `headers` | ASI02 Tool Misuse | Secret exfiltration via HTTP headers |
| `response_fetch` | ASI01 Goal Hijack + ASI06 Memory Poisoning | Prompt injection in fetched content |
| `response_mitm` | ASI01 Goal Hijack + ASI04 Supply Chain | Injection via tampered responses |
| `mcp_input` | ASI02 Tool Misuse | DLP and injection in tool arguments |
| `mcp_tool` | ASI04 Supply Chain | Poisoned tool descriptions, rug-pull changes |
| `mcp_chain` | ASI02 Tool Misuse + ASI08 Cascading Failures | Multi-step exfiltration sequences |

Full mapping with MITRE ATT&CK techniques: [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md)

## How this differs from other benchmarks

Most AI agent security benchmarks test whether the **model** behaves safely. This one tests whether the **security tool** catches the attack.

| Benchmark | Tests what? | Focus |
|-----------|------------|-------|
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) (ETH Zurich) | The LLM agent | Robustness to prompt injection (629 cases) |
| [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) (UIUC) | The LLM agent | Indirect prompt injection success rate (1,054 cases) |
| [AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm) (UK AISI) | The LLM | Refusal of harmful multi-step tasks (440 cases) |
| [CyberSecEval](https://github.com/meta-llama/PurpleLlama) (Meta) | The LLM | Insecure code generation, cyberattack assistance |
| [ASB](https://github.com/agiresearch/ASB) (ICLR 2025) | The LLM agent | Defense prompts reducing attack success (90K cases) |
| [AgentShield-bench](https://github.com/doronp/agentshield-benchmark) (Agent Guard) | Security middleware | Prompt injection and jailbreak detection at API layer (537 cases) |
| **agent-egress-bench** | **Security tools** | **Secret exfiltration, SSRF, MCP poisoning at the network layer (73 cases)** |

The model-testing benchmarks assume the LLM is the last line of defense. This corpus assumes models will sometimes fail, and tests the defense-in-depth layer that sits between the agent and the network.

AgentShield-benchmark is the closest comparable, but operates at the application/API layer (is this prompt an injection?). agent-egress-bench operates at the wire level (did this HTTP request contain an exfiltrated secret in the query string? did this MCP tool response contain prompt injection?).

## Docs

- [SPEC.md](docs/SPEC.md): case schema, field definitions, enums, payload formats
- [SCORING.md](docs/SCORING.md): pass/fail/not_applicable/error scoring model
- [RUNNER.md](docs/RUNNER.md): runner output contract and verdict mapping
- [ADOPTION.md](docs/ADOPTION.md): guide for vendors adopting the benchmark
- [GLOSSARY.md](docs/GLOSSARY.md): definitions of key terms (agent firewall, egress security, etc.)
- [GOVERNANCE.md](docs/GOVERNANCE.md): neutrality policy, case immutability, contribution rules
- [OWASP-MAPPING.md](docs/OWASP-MAPPING.md): case categories mapped to OWASP Agentic Top 10
- [schemas/](schemas/): JSON Schema files for cases, tool profiles, and results

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Cases, runners, and documentation improvements are all welcome.

**Case IDs are immutable.** Once merged, a case ID never changes. Semantic changes to existing cases require a new case with a new ID.

## Governance

This corpus was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparison tables. Each tool publishes its own results independently.

**Conflict of interest disclosure:** The author builds an agent egress security tool. This corpus was designed to be tool-neutral: cases test observable behavior (did the request get blocked?), not implementation details. The [Pipelock runner](examples/pipelock/) is a reference implementation, not a privileged position.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
