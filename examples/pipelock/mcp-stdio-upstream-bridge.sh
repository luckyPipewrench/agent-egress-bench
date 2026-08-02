#!/bin/sh
# Connect a stdio MCP child to the runner-owned TCP JSON-RPC observer.
# The stream is deliberately passed through unchanged: one JSON-RPC message per
# line in each direction.
set -eu

addr=${AEB_MCP_STDIO_UPSTREAM_ADDR:-}
case "$addr" in
  *:*) ;;
  *)
    echo "AEB_MCP_STDIO_UPSTREAM_ADDR must be host:port" >&2
    exit 64
    ;;
esac

host=${addr%:*}
port=${addr##*:}
if [ -z "$host" ] || [ -z "$port" ]; then
  echo "AEB_MCP_STDIO_UPSTREAM_ADDR must be host:port" >&2
  exit 64
fi

if command -v socat >/dev/null 2>&1; then
  exec socat - "TCP:${host}:${port}"
fi
if command -v ncat >/dev/null 2>&1; then
  exec ncat "$host" "$port"
fi
if command -v nc >/dev/null 2>&1; then
  exec nc "$host" "$port"
fi

echo "MCP stdio upstream bridge requires socat, ncat, or nc" >&2
exit 69
