#!/bin/sh
# Connect a stdio MCP child to the runner-owned TCP JSON-RPC observer.
# The stream is deliberately passed through unchanged: one JSON-RPC message per
# line in each direction.
set -eu

config_error() {
  echo "AEB_MCP_STDIO_UPSTREAM_ADDR must be host:port with a port from 1 to 65535" >&2
  exit 64
}

addr=${AEB_MCP_STDIO_UPSTREAM_ADDR:-}
case "$addr" in
  *:*) ;;
  *) config_error ;;
esac

host=${addr%:*}
port=${addr##*:}
if [ -z "$host" ] || [ -z "$port" ]; then
  config_error
fi
case "$host" in
  *:*) config_error ;;
esac
case "$port" in
  *[!0-9]*) config_error ;;
esac

# Normalize leading zeroes before the range check so every accepted value is
# passed to the connector in an unambiguous decimal form.
while [ "${port#0}" != "$port" ]; do
  port=${port#0}
done
[ -n "$port" ] || port=0
if [ "${#port}" -gt 5 ] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  config_error
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
