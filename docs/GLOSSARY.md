# Glossary

Terms used throughout agent-egress-bench. These define the category.

## Primary Terms

### Agent firewall

A network-layer security tool that sits between an AI agent and the internet. It intercepts, scans, and can block HTTP requests, WebSocket frames, and MCP messages before they leave the agent's environment. Unlike application-layer defenses (system prompts, guardrail APIs), an agent firewall operates on wire-level traffic: URLs, headers, request bodies, and tool call payloads.

### Agent egress security

The practice of controlling and scanning outbound traffic from AI agents. Covers secret exfiltration prevention (DLP), SSRF blocking, prompt injection detection in fetched content, MCP tool poisoning detection, and multi-step attack chain recognition. The "egress" distinction matters: it focuses on what leaves the agent's environment, not what enters it.

### Agent egress benchmark

A standardized corpus of test cases for evaluating agent egress security tools. Each case represents an attack pattern (or benign traffic) as it would appear on the wire. The benchmark tests the security tool's detection capability, not the AI model's behavior.

### Runner

A script or program that connects a specific security tool to the benchmark corpus. It feeds each case to the tool, observes the verdict (block or allow), and outputs structured results. See [RUNNER.md](RUNNER.md) for the full contract.

### Tool profile

A JSON declaration of a security tool's capabilities (what it claims to detect) and supported transports (how it intercepts traffic). Used to determine which benchmark cases apply to a given tool.

### Case

A single test scenario in the corpus. Contains an attack payload (or benign traffic), the expected verdict, severity, capability requirements, and metadata. Each case is a JSON file that encodes the payload and expected verdict. Some cases require runner-side setup (see [RUNNER.md](RUNNER.md) for details). See [SPEC.md](SPEC.md) for the schema.

### Verdict

The outcome of a security tool evaluating a case: `block` (traffic denied) or `allow` (traffic permitted). The benchmark compares the tool's actual verdict against the expected verdict to produce a score. See [SCORING.md](SCORING.md).

### Applicability

Whether a case is relevant to a given tool. Determined mechanically from the tool profile's `claims` and `supports` fields against the case's `capability_tags` and `requires` fields. Non-applicable cases are skipped, not scored as failures. There are no judgment calls. The check is deterministic.

## Secondary Terms

### Capability tag

A label describing what a case exercises. Examples: `url_dlp`, `mcp_input_scan`, `ssrf`, `response_injection`. Tools declare which tags they claim to handle. A case is only applicable to tools that claim all of its tags.

### Transport

How traffic reaches the security tool. One of: `fetch_proxy` (HTTP fetch endpoint), `http_proxy` (CONNECT tunnel), `mcp_stdio` (MCP subprocess wrapping), `mcp_http` (MCP HTTP proxy), `websocket`. Each case declares its expected transport. Tools declare which transports they support.

### DLP (Data Loss Prevention)

Detection of secrets, credentials, and sensitive data in outbound traffic. Covers API keys, tokens, environment variables, and high-entropy strings. In this corpus, DLP cases appear across URL, request body, header, and MCP input categories.

### Rug-pull

A type of MCP tool poisoning where a tool's description changes after the agent has already been granted access. The initial description is benign; the modified version contains malicious instructions. Detection requires comparing tool definitions over time (a tool baseline).
