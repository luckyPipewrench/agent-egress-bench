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

# Receipt-axis runs are OPT-IN. Emitting durable signed receipts costs measurable
# time per request, so enabling it by default would change what a published
# containment score measures. Set AEB_RECEIPT_EVIDENCE_DIR to turn it on; the
# runner's receipt_evidence declaration in tool-profile.json points at the same
# directory. Left unset, this script and the resulting score are unchanged.
receipt_yaml=""
if [[ -n "${AEB_RECEIPT_EVIDENCE_DIR:-}" ]]; then
  mkdir -p "$AEB_RECEIPT_EVIDENCE_DIR"
  chmod 750 "$AEB_RECEIPT_EVIDENCE_DIR"
  receipt_key="${AEB_RECEIPT_SIGNING_KEY:-${AEB_RECEIPT_EVIDENCE_DIR}/signing.key}"
  if [[ ! -s "$receipt_key" ]]; then
    "$pipelock_bin" signing key generate --purpose receipt-signing --out "$receipt_key" >/dev/null
    "$pipelock_bin" signing pubkey --key-file "$receipt_key" --out "${receipt_key}.pub" >/dev/null
    # Set the modes here rather than relying on whatever the signing tool chose.
    # The evidence directory is group-readable, so an unrestricted private key
    # would be readable by any member of that group.
    chmod 600 "$receipt_key"
    chmod 644 "${receipt_key}.pub"
  fi
  # The tool profile's verify_command references $AEB_RECEIPT_PUBKEY. The runner
  # expands an unset variable to an empty string, so leaving this unexported
  # hands the verifier an empty --key and scores every row
  # receipt_independently_verifiable=no without reporting a configuration error.
  export AEB_RECEIPT_PUBKEY="${AEB_RECEIPT_PUBKEY:-${receipt_key}.pub}"
  # The same profile references $PIPELOCK_BIN for the verifier argv.
  export PIPELOCK_BIN="${PIPELOCK_BIN:-$pipelock_bin}"
  receipt_yaml=$(
    printf 'flight_recorder:\n'
    printf '  enabled: true\n'
    printf '  dir: "%s"\n' "$AEB_RECEIPT_EVIDENCE_DIR"
    printf '  signing_key_path: "%s"\n' "$receipt_key"
    printf '  redact: true\n'
    printf '  sign_checkpoints: true\n'
  )
fi
# awk reads this through ENVIRON, matching how the TLS paths are passed, so it
# must be exported rather than assigned as an awk variable.
export AEB_RECEIPT_YAML="$receipt_yaml"

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
    if (ENVIRON["AEB_RECEIPT_YAML"] != "") {
      print ""
      printf "%s", ENVIRON["AEB_RECEIPT_YAML"]
    }
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
