# agent-egress-bench

A standardized test corpus for evaluating AI agent egress security tools. 35 attack cases across 8 categories, covering secret exfiltration, prompt injection, SSRF, MCP tool poisoning, and more.

**This tests the security tool, not the agent.** Every other benchmark in this space (AgentDojo, InjecAgent, CyberSecEval, AgentHarm, etc.) tests whether the LLM behaves correctly. This one tests whether the firewall, proxy, or scanner sitting between the agent and the network catches the attack.

## What's in the corpus

| Category | Directory | Cases | What it tests |
|----------|-----------|-------|---------------|
| URL DLP | `cases/url/` | 11 | Secrets leaked via query strings, encoded paths, high-entropy subdomains |
| Request body DLP | `cases/request-body/` | 6 | Secrets in POST bodies (JSON, multipart, base64, env dumps) |
| Header DLP | `cases/headers/` | 5 | API keys and tokens in HTTP headers |
| Response injection (fetch) | `cases/response-fetch/` | 5 | Prompt injection in fetched web content |
| Response injection (MITM) | `cases/response-mitm/` | 2 | Injection via tampered responses |
| MCP input scanning | `cases/mcp-input/` | 3 | DLP and injection in MCP tool arguments |
| MCP tool poisoning | `cases/mcp-tool/` | 2 | Poisoned tool descriptions, rug-pull definition changes |
| MCP chain detection | `cases/mcp-chain/` | 1 | Read-then-exfiltrate tool call sequences |

Each case is a self-contained JSON file with the attack payload, expected verdict (`block` or `allow`), severity, capability tags, and a machine-readable reason for the expected outcome. Benign cases are included to test false positive rates.

## Quick start

**Validate the corpus:**

```bash
cd validate && go build -o /tmp/aeb-validate . && /tmp/aeb-validate ../cases
```

**Run against a tool** (using the Pipelock reference runner as an example):

```bash
cd examples/pipelock
bash harness.sh /path/to/pipelock
```

Output is JSONL (one result per case). See [docs/RUNNER.md](docs/RUNNER.md) for the runner contract.

## Writing a runner for your tool

A runner connects your security tool to this corpus. You need:

1. A `tool-profile.json` declaring your tool's capabilities
2. A script that feeds each case to your tool and observes the verdict
3. JSONL output following the format in [docs/RUNNER.md](docs/RUNNER.md)

Cases your tool can't handle are scored `not_applicable`, not `fail`. If your tool doesn't do MCP scanning, those cases are skipped automatically based on your tool profile. See [docs/SCORING.md](docs/SCORING.md) for details.

Put your runner in `examples/{your-tool}/` and open a PR.

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

Full mapping with detailed rationale: [docs/OWASP-MAPPING.md](docs/OWASP-MAPPING.md)

## Docs

- [SPEC.md](docs/SPEC.md): case schema, field definitions, enums, payload formats
- [SCORING.md](docs/SCORING.md): pass/fail/not_applicable/error scoring model
- [RUNNER.md](docs/RUNNER.md): runner output contract and verdict mapping
- [OWASP-MAPPING.md](docs/OWASP-MAPPING.md): case categories mapped to OWASP Agentic Top 10

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Cases, runners, and documentation improvements are all welcome.

**Case IDs are immutable.** Once merged, a case ID never changes. Semantic changes to existing cases require a new case with a new ID.

## Governance

This corpus was created by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparison tables. Each tool publishes its own results independently.

**Conflict of interest disclosure:** The author builds an agent egress security tool. This corpus was designed to be tool-neutral: cases test observable behavior (did the request get blocked?), not implementation details. The [Pipelock runner](examples/pipelock/) is a reference implementation, not a privileged position.

## License

Apache 2.0. See [LICENSE](LICENSE).
