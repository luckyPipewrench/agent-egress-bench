# Pipelock Reference Runner

> **For real benchmark scoring use the Go runner in [`../../runner/`](../../runner/).** The Go runner is what produces [`profiles/pipelock.json`](../../profiles/pipelock.json) and the [pipelab.org gauntlet leaderboard](https://pipelab.org/gauntlet/). It covers every transport in the corpus (fetch, forward proxy, WebSocket, MCP stdio, MCP HTTP, A2A) and brings up its own TLS, WebSocket, and DNS fixtures. The shell `harness.sh` in this directory is a minimal fetch-only illustration; it skips body, header (POST), WebSocket, MCP, and response-content cases and will misreport them.

This directory contains the Pipelock-specific artifacts the Go runner needs to score Pipelock:

- [`tool-profile.json`](tool-profile.json): Pipelock's capability claims (what it supports, what it does not).
- [`pipelock-benchmark.yaml`](pipelock-benchmark.yaml): bench-only config (every scanner enabled, action=block, test blocklist domain included).
- [`receipt-verifier.json`](receipt-verifier.json): Pipelock's verifier metadata for the optional receipt-scoring profile.
- [`harness.sh`](harness.sh): legacy fetch-only example, kept for illustration.

## Canonical run

The full reproducible command lives in [`../../docs/RUNNER.md`](../../docs/RUNNER.md#reproducing-a-receipt-profile). Short form:

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
