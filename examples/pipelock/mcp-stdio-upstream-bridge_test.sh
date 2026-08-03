#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
bridge="$script_dir/mcp-stdio-upstream-bridge.sh"

expect_config_error() {
  addr=$1
  set +e
  PATH=/nonexistent AEB_MCP_STDIO_UPSTREAM_ADDR="$addr" /bin/sh "$bridge" >/dev/null 2>&1
  status=$?
  set -e
  if [ "$status" -ne 64 ]; then
    echo "expected configuration error for address '$addr', got status $status" >&2
    exit 1
  fi
}

expect_connector_selection() {
  addr=$1
  set +e
  PATH=/nonexistent AEB_MCP_STDIO_UPSTREAM_ADDR="$addr" /bin/sh "$bridge" >/dev/null 2>&1
  status=$?
  set -e
  if [ "$status" -ne 69 ]; then
    echo "expected connector selection for address '$addr', got status $status" >&2
    exit 1
  fi
}

for addr in \
  "" \
  "127.0.0.1" \
  ":1234" \
  "127.0.0.1:" \
  "127.0.0.1:abc" \
  "127.0.0.1:0" \
  "127.0.0.1:65536" \
  "127.0.0.1:99999999999999999999" \
  "127.0.0.1:1:2"
do
  expect_config_error "$addr"
done

expect_connector_selection "127.0.0.1:1"
expect_connector_selection "runner.example:065535"

echo "mcp stdio upstream bridge tests: OK"
