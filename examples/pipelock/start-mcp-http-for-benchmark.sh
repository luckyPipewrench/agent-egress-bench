#!/usr/bin/env bash
set -euo pipefail

pipelock_bin="${1:-${PIPELOCK_BIN:-pipelock}}"
config="${PIPELOCK_BENCH_CONFIG:-examples/pipelock/pipelock-benchmark.yaml}"

required_vars=(
  AEB_MCP_HTTP_ADDR
  AEB_MCP_HTTP_FIXTURE_URL
)
for name in "${required_vars[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: ${name}" >&2
    exit 2
  fi
done

exec "$pipelock_bin" mcp proxy \
  --config "$config" \
  --listen "$AEB_MCP_HTTP_ADDR" \
  --upstream "$AEB_MCP_HTTP_FIXTURE_URL"
