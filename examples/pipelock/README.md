# Pipelock Reference Runner

> **For benchmark development use the Go runner in [`../../runner/`](../../runner/).** It executes fetch, forward-proxy URL, WebSocket, fetch-response, and MCP stdio paths without substituting another transport. MCP HTTP, A2A, forward-proxy TLS response interception, and fetch POST/body/header execution still need exact fixtures. Because Pipelock's profile claims those capabilities, the runner reports those cases as adapter errors and the run is invalid until the fixtures exist. Do not publish a score from an invalid run. The shell `harness.sh` remains a fetch-only illustration, not a scoring runner.

This directory contains the Pipelock-specific artifacts the Go runner needs to score Pipelock:

- [`tool-profile.json`](tool-profile.json): Pipelock's capability claims (what it supports, what it does not).
- [`pipelock-benchmark.yaml`](pipelock-benchmark.yaml): bench-only config (every scanner enabled, action=block, test blocklist domain included).
- [`receipt-verifier.json`](receipt-verifier.json): Pipelock's verifier metadata for the optional receipt-scoring profile.
- [`harness.sh`](harness.sh): legacy fetch-only example, kept for illustration.

## Development run

This command exposes the remaining adapter errors rather than manufacturing transport evidence:

```bash
# 1. Start a benchmark-configured Pipelock instance.
pipelock run --config examples/pipelock/pipelock-benchmark.yaml \
  --listen 127.0.0.1:18899 &

# 2. Build and run the gauntlet.
cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
/tmp/aeb-gauntlet \
  --adapter proxy \
  --proxy-addr 127.0.0.1:18899 \
  --scan-addr 127.0.0.1:9990 \
  --scan-token bench-test-token \
  --mcp-cmd "pipelock mcp proxy --config $PWD/examples/pipelock/pipelock-benchmark.yaml -- cat" \
  --cases ./cases \
  --multifile-cases ./cases/mcp-drift \
  --profile examples/pipelock/tool-profile.json \
  --fixtures \
  --output /tmp/gauntlet.json \
  --emit-receipt-profile /tmp/pipelock.json \
  --receipt-verifier-file examples/pipelock/receipt-verifier.json
```

The `pipelock-benchmark.yaml` config listens on 127.0.0.1:18899 (proxy), 127.0.0.1:9990 (scan API, bearer `bench-test-token`), and enables every scanner with `action: block`.

## Legacy fetch-only harness

`harness.sh` runs URL cases through Pipelock's `/fetch?url=...` GET endpoint. It is preserved as a minimal worked example of the runner contract for tools that only implement a fetch-style proxy. **It is not the Gauntlet** — body, header (POST), WebSocket, MCP, and response-content cases are not exercised, and any tool whose containment is reported off this harness alone will be undersold. Use the Go runner for any published score.

```bash
# Minimal fetch-only run (illustration, not a benchmark)
bash harness.sh /path/to/pipelock
```

Output is JSONL on stdout, summary on stderr.
