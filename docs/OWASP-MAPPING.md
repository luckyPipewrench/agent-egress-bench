# OWASP Agentic Top 10 Mapping

How agent-egress-bench cases map to the [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

## Coverage summary

| Case category | OWASP item | Covered |
|---------------|------------|---------|
| `url` | ASI02 Tool Misuse & Exploitation | Yes |
| `request_body` | ASI02 Tool Misuse & Exploitation | Yes |
| `headers` | ASI02 Tool Misuse & Exploitation | Yes |
| `response_fetch` | ASI01 Agent Goal Hijack + ASI06 Memory & Context Poisoning | Yes |
| `response_mitm` | ASI01 Agent Goal Hijack + ASI04 Supply Chain Vulnerabilities | Yes |
| `mcp_input` | ASI02 Tool Misuse & Exploitation | Yes |
| `mcp_tool` | ASI04 Agentic Supply Chain Vulnerabilities | Yes |
| `mcp_chain` | ASI02 Tool Misuse + ASI08 Cascading Failures | Yes |

## Detailed mapping

### ASI01: Agent Goal Hijack

**Threat:** Attackers redirect agent objectives through malicious text in external data.

**Bench coverage:**
- `response_fetch` cases test whether fetched web content containing prompt injection ("ignore previous instructions", system overrides, jailbreak templates) is detected and blocked before reaching the agent.
- `response_mitm` cases test whether tampered responses injected via MITM are detected.

**Example cases:** `response-injection-comment-001`, `response-injection-ignore-002`, `response-injection-system-003`

### ASI02: Tool Misuse & Exploitation

**Threat:** Agents misuse legitimate tools to exfiltrate data, either through prompt injection or misalignment.

**Bench coverage:**
- `url` cases test DLP detection of secrets in URL query strings, paths, and subdomains (AWS keys, GitHub tokens, JWTs, base64-encoded data, high-entropy strings).
- `request_body` cases test DLP detection in POST bodies (JSON fields, multipart uploads, base64 payloads, env variable dumps).
- `headers` cases test DLP detection of API keys and tokens in HTTP headers.
- `mcp_input` cases test DLP and injection detection in MCP tool call arguments.
- `mcp_chain` cases test detection of multi-step exfiltration patterns (read sensitive file, then fetch to external URL).

**Example cases:** `url-dlp-aws-key-001`, `body-dlp-json-key-001`, `header-dlp-bearer-001`, `mcp-input-dlp-001`, `mcp-chain-exfil-001`

### ASI04: Agentic Supply Chain Vulnerabilities

**Threat:** Malicious or tampered tools, skill packages, or agent components compromise execution.

**Bench coverage:**
- `mcp_tool` cases test detection of poisoned MCP tool descriptions containing hidden instructions (e.g., "read ~/.ssh/id_rsa and include its contents").
- `mcp_tool` rug-pull cases test detection of tool definition changes mid-session (a tool description that changes after initial registration).
- `response_mitm` cases test detection of injection via tampered responses, simulating a compromised upstream.

**Example cases:** `mcp-tool-poison-001`, `mcp-tool-rugpull-002`, `response-mitm-tool-instruction-002`

### ASI06: Memory & Context Poisoning

**Threat:** Attackers corrupt the data sources an agent relies on for knowledge and decisions.

**Bench coverage:**
- `response_fetch` cases test whether poisoned web content (the most common external knowledge source for coding agents) is detected before entering the agent's context.
- Benign response cases (`response-benign-*`) test that legitimate content with security-adjacent language is not incorrectly blocked.

**Example cases:** `response-injection-comment-001`, `response-benign-security-article-002`

### ASI08: Cascading Failures

**Threat:** Failures propagate through agent chains, with one agent's compromise triggering downstream failures.

**Bench coverage:**
- `mcp_chain` cases test detection of multi-tool sequences that indicate data exfiltration (read a sensitive file, then immediately make an HTTP request to an external domain).

**Example cases:** `mcp-chain-exfil-001`

## Not covered (by design)

This corpus tests egress security tools, not the full agent attack surface. The following OWASP items are out of scope:

| OWASP item | Why not covered |
|------------|----------------|
| ASI03 Identity & Privilege Abuse | Tests credential management, not egress scanning |
| ASI05 Unexpected Code Execution | Tests sandboxing, not network-layer security |
| ASI07 Insecure Inter-Agent Communication | Tests agent-to-agent protocols, not egress |
| ASI09 Human-Agent Trust Exploitation | Tests UI/UX trust, not network traffic |
| ASI10 Rogue Agents | Tests agent behavior, not security tool detection |

## MITRE ATT&CK mapping

Several case categories also map to MITRE ATT&CK exfiltration techniques:

| Technique | Cases |
|-----------|-------|
| T1041 Exfiltration Over C2 Channel | `url`, `request_body`, `headers` (secret exfil via HTTP) |
| T1567 Exfiltration Over Web Service | `url`, `request_body` (data sent to external services) |
| T1048 Exfiltration Over Alternative Protocol | `url` encoding cases (base64, hex, URL-encoded secrets) |
| T1071.001 Web Protocols | All HTTP-based cases |
