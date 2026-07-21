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

# The benchmark's TLS interception fixture serves a leaf signed by the
# benchmark CA. Pipelock intercepts the connection and then verifies the origin
# itself, so without this the upstream handshake fails and the proxy answers 502.
# A 502 is indistinguishable from a policy block by status alone, so an untrusted
# fixture silently scores every response-interception case as "blocked" while the
# response is never actually scanned.
export SSL_CERT_FILE="$AEB_TLS_CA_FILE"

exec "$pipelock_bin" run --config "$tmp_config" --listen "$AEB_PROXY_ADDR"
