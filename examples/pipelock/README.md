# Pipelock Reference Runner

> **For benchmark development use the Go runner in [`../../runner/`](../../runner/).** It executes the declared fetch, forward-proxy, WebSocket, MCP stdio, MCP HTTP, A2A, and TLS-intercepted request/response transports without substituting scan APIs or other surfaces. The shell `harness.sh` remains a fetch-only illustration, not a scoring runner.

This directory contains the Pipelock-specific artifacts the Go runner needs to score Pipelock:

- [`tool-profile.json`](tool-profile.json): Pipelock's capability claims (what it supports, what it does not).
- [`pipelock-benchmark.yaml`](pipelock-benchmark.yaml): bench-only config (every scanner enabled, action=block, test blocklist domain included).
- [`receipt-verifier.json`](receipt-verifier.json): Pipelock's verifier metadata for the optional receipt-scoring profile.
- [`harness.sh`](harness.sh): legacy fetch-only example, kept for illustration.

## Development run

The runner can either target already-running endpoints (`--proxy-addr`,
`--scan-addr`, `--mcp-http-url`) or start operator-provided commands with the
tool-neutral managed command hooks. Managed commands receive endpoint and
fixture values through environment variables; the runner does not parse or
mutate Pipelock configuration.

The canonical tool-neutral managed-command contract is documented in
[`../../docs/RUNNER.md`](../../docs/RUNNER.md#managed-command-hooks). This
example uses the same variables.

Available managed-command environment variables:

| Variable | Meaning |
| --- | --- |
| `AEB_PROXY_ADDR` | Host:port the managed forward/fetch proxy command should listen on |
| `AEB_SCAN_ADDR` | Host:port the managed scan API command should listen on |
| `AEB_MCP_HTTP_ADDR` | Host:port the managed MCP HTTP command should listen on |
| `AEB_MCP_HTTP_URL` | URL corresponding to `AEB_MCP_HTTP_ADDR` |
| `AEB_HTTP_FIXTURE_ADDR` | HTTP fixture address |
| `AEB_TLS_FIXTURE_ADDR` | HTTPS fixture address for intercepted request/response cases |
| `AEB_TLS_CA_FILE` | Fixture CA certificate path |
| `AEB_TLS_CA_KEY_FILE` | Fixture CA private-key path |
| `AEB_WS_FIXTURE_ADDR` | WebSocket fixture address |
| `AEB_DNS_FIXTURE_ADDR` | DNS fixture address |
| `AEB_MCP_HTTP_FIXTURE_URL` | MCP HTTP upstream fixture URL |

Example shape:

```bash
cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
export PIPELOCK_BIN=/path/to/pipelock
export PIPELOCK_BENCH_CONFIG="$PWD/examples/pipelock/pipelock-benchmark.yaml"
/tmp/aeb-gauntlet \
  --adapter proxy \
  --scan-token bench-test-token \
  --mcp-cmd "\"$PIPELOCK_BIN\" mcp proxy --config \"$PIPELOCK_BENCH_CONFIG\" -- cat" \
  --managed-proxy-cmd './examples/pipelock/start-proxy-for-benchmark.sh "$PIPELOCK_BIN"' \
  --managed-mcp-http-cmd './examples/pipelock/start-mcp-http-for-benchmark.sh "$PIPELOCK_BIN"' \
  --cases ./cases \
  --multifile-cases ./cases/mcp-drift \
  --profile examples/pipelock/tool-profile.json \
  --fixtures \
  --output /tmp/gauntlet.json \
  --emit-receipt-profile /tmp/pipelock.json \
  --receipt-verifier-file examples/pipelock/receipt-verifier.json
```

The example profile may be set to a release-candidate version while validating a
candidate binary. Published score reports should name the exact released binary
or candidate commit they executed.

## Legacy fetch-only harness

`harness.sh` runs URL cases through Pipelock's `/fetch?url=...` GET endpoint. It is preserved as a minimal worked example of the runner contract for tools that only implement a fetch-style proxy. **It is not the Gauntlet**: body, header (POST), WebSocket, MCP, and response-content cases are not exercised, and any tool whose containment is reported off this harness alone will be undersold. Use the Go runner for any published score.

```bash
# Minimal fetch-only run (illustration, not a benchmark)
bash harness.sh /path/to/pipelock
```

Output is JSONL on stdout, summary on stderr.
