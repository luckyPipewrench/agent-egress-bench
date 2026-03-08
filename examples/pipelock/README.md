# Pipelock Reference Runner

Runs the agent-egress-bench corpus against [Pipelock](https://github.com/luckyPipewrench/pipelock).

## Prerequisites

- `pipelock` binary (v0.3.6+)
- `jq`
- `python3` (for URL encoding)
- `curl`

## Usage

```bash
# Using pipelock from PATH
bash harness.sh

# Using a specific binary
bash harness.sh /path/to/pipelock

# Using a specific cases directory
bash harness.sh pipelock /path/to/cases
```

## What it runs

The harness starts Pipelock with `pipelock-benchmark.yaml` (all scanners enabled, actions set to block) and runs HTTP/fetch cases through the fetch proxy endpoint.

MCP and response-content cases are marked as `not_applicable` in v1 (the runner does not yet support those transports). The cases themselves are valid; the v1 harness only supports `fetch_proxy` transport.

## Output

JSONL to stdout (one result per case). Summary to stderr.

## Files

- `harness.sh`: runner script
- `tool-profile.json`: Pipelock's capability claims
- `pipelock-benchmark.yaml`: benchmark-specific config (all scanners on, block mode)
