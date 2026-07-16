#!/usr/bin/env bash
set -euo pipefail

pipelock_bin="${1:-${PIPELOCK_BIN:-pipelock}}"
config="${PIPELOCK_BENCH_CONFIG:-examples/pipelock/pipelock-benchmark.yaml}"

required_vars=(
  AEB_PROXY_ADDR
  AEB_SCAN_ADDR
  AEB_TLS_CA_FILE
  AEB_TLS_CA_KEY_FILE
)
for name in "${required_vars[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "missing required environment variable: ${name}" >&2
    exit 2
  fi
done

tmp_config="$(mktemp "${TMPDIR:-/tmp}/aeb-pipelock-XXXXXX.yaml")"
trap 'rm -f "$tmp_config"' EXIT

awk -v scan_addr="$AEB_SCAN_ADDR" '
  /^scan_api:/ { in_scan_api = 1 }
  in_scan_api && /^[[:space:]]+listen:/ {
    print "  listen: \"" scan_addr "\""
    in_scan_api = 0
    next
  }
  { print }
  END {
    print ""
    print "tls_interception:"
    print "  enabled: true"
    print "  ca_cert: \"" ENVIRON["AEB_TLS_CA_FILE"] "\""
    print "  ca_key: \"" ENVIRON["AEB_TLS_CA_KEY_FILE"] "\""
  }
' "$config" > "$tmp_config"

exec "$pipelock_bin" run --config "$tmp_config" --listen "$AEB_PROXY_ADDR"
