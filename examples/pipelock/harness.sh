#!/usr/bin/env bash
# Legacy fetch-only harness for agent-egress-bench. NOT the Gauntlet.
#
# This script only exercises URL cases through Pipelock's /fetch?url=... GET
# endpoint. It will misreport body, header (POST), WebSocket, MCP, and
# response-content cases. Any published containment number for Pipelock comes
# from the Go runner in ../../runner/, not this script.
#
# For real benchmark scoring use the canonical command in docs/RUNNER.md:
#   pipelock run --config examples/pipelock/pipelock-benchmark.yaml \
#     --listen 127.0.0.1:18899 &
#   cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
#   /tmp/aeb-gauntlet --adapter proxy --proxy-addr 127.0.0.1:18899 \
#     --scan-addr 127.0.0.1:9990 --scan-token bench-test-token \
#     --mcp-cmd "pipelock mcp proxy --config $PWD/examples/pipelock/pipelock-benchmark.yaml --env AEB_MCP_STDIO_UPSTREAM_ADDR -- sh ./examples/pipelock/mcp-stdio-upstream-bridge.sh" \
#     --cases ./cases \
#     --profile examples/pipelock/tool-profile.json --fixtures \
#     --output /tmp/gauntlet.json
#
# Usage: bash harness.sh [pipelock-binary] [cases-dir]
#
# Prerequisites:
#   - pipelock binary (default: pipelock in PATH)
#   - jq for JSON processing
#   - python3 for URL encoding
#   - The benchmark config: pipelock-benchmark.yaml in this directory

set -euo pipefail

cat >&2 <<'BANNER'
=============================================================================
harness.sh — LEGACY FETCH-ONLY EXAMPLE, NOT THE GAUNTLET

This script only exercises URL cases. Body, header (POST), WebSocket, MCP,
and response-content cases will be misreported. For real scoring run the Go
runner: see ../../docs/RUNNER.md or ../../README.md "Run against a tool".
=============================================================================
BANNER

PIPELOCK="${1:-pipelock}"
CASES_DIR="${2:-../../cases}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR/tool-profile.json"
CONFIG="$SCRIPT_DIR/pipelock-benchmark.yaml"
PORT=18899
RESULTS_FILE="/tmp/agent-egress-bench-results.jsonl"

# Verify prerequisites
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 1; }
command -v "$PIPELOCK" >/dev/null 2>&1 || { echo "error: pipelock binary not found: $PIPELOCK" >&2; exit 1; }
[ -f "$CONFIG" ] || { echo "error: benchmark config not found: $CONFIG" >&2; exit 1; }
[ -f "$PROFILE" ] || { echo "error: tool profile not found: $PROFILE" >&2; exit 1; }

TOOL=$(jq -r '.tool' "$PROFILE")
TOOL_VERSION=$(jq -r '.tool_version' "$PROFILE")

# Start pipelock
echo "starting pipelock on port $PORT..." >&2
"$PIPELOCK" run --config "$CONFIG" --listen "127.0.0.1:$PORT" &
PIPELOCK_PID=$!
# shellcheck disable=SC2064
trap "kill $PIPELOCK_PID 2>/dev/null; wait $PIPELOCK_PID 2>/dev/null" EXIT

# Wait for proxy to be ready
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "error: pipelock did not start within 30 seconds" >&2
        exit 1
    fi
    sleep 1
done
echo "pipelock ready." >&2

# Check whether this frozen fetch-only illustration has a route for the case.
# It deliberately does not inspect active profile labels or case tags.
check_legacy_transport() {
    local transport="$1"
    # v1 harness only supports fetch_proxy (via /fetch endpoint)
    # http_proxy (CONNECT), websocket, mcp_stdio, mcp_http need v2
    case "$transport" in
        fetch_proxy) return 0 ;;
        *) return 1 ;;
    esac
}

# Run a single URL/header/body case through the fetch proxy
run_fetch_case() {
    local case_file="$1"
    local case_id expected_verdict input_type method url

    case_id=$(jq -r '.id' "$case_file")
    expected_verdict=$(jq -r '.expected_verdict' "$case_file")
    input_type=$(jq -r '.input_type' "$case_file")

    # Build curl command
    local curl_args=("-s" "-o" "/dev/null" "-w" "%{http_code}" "--max-time" "10")

    case "$input_type" in
        url)
            method=$(jq -r '.payload.method' "$case_file")
            url=$(jq -r '.payload.url' "$case_file")
            curl_args+=("-X" "$method")
            curl_args+=("http://127.0.0.1:$PORT/fetch?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url', safe=''))")")
            ;;
        request_body)
            method=$(jq -r '.payload.method' "$case_file")
            url=$(jq -r '.payload.url' "$case_file")
            local content_type body
            content_type=$(jq -r '.payload.content_type' "$case_file")
            body=$(jq -r '.payload.body' "$case_file")
            curl_args+=("-X" "$method")
            curl_args+=("-H" "Content-Type: $content_type")
            curl_args+=("-d" "$body")
            curl_args+=("http://127.0.0.1:$PORT/fetch?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url', safe=''))")")
            ;;
        header)
            method=$(jq -r '.payload.method' "$case_file")
            url=$(jq -r '.payload.url' "$case_file")
            while IFS='=' read -r key val; do
                curl_args+=("-H" "$key: $val")
            done < <(jq -r '.payload.headers | to_entries[] | "\(.key)=\(.value)"' "$case_file")
            curl_args+=("-X" "$method")
            curl_args+=("http://127.0.0.1:$PORT/fetch?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url', safe=''))")")
            ;;
        response_content)
            # Response scanning requires a mock upstream server (not in v1)
            emit_result "$case_id" "$expected_verdict" "not_applicable" "not_applicable" \
                '{"reason": "response scanning requires mock server (v1 harness limitation)"}' ""
            return
            ;;
        *)
            emit_result "$case_id" "$expected_verdict" "not_applicable" "not_applicable" \
                '{"reason": "input_type not supported by v1 harness"}' ""
            return
            ;;
    esac

    # Execute
    local http_status
    http_status=$(curl "${curl_args[@]}" 2>/dev/null) || http_status="000"

    # Determine verdict from HTTP status. 502 is deliberately NOT a block: the
    # proxy returns it for a plain upstream failure as well as for a policy
    # block, and 405 means this GET-only endpoint never saw the payload. Scoring
    # either as a verdict invents a result the tool never produced.
    local actual_verdict score
    case "$http_status" in
        403)
            actual_verdict="block"
            ;;
        000|405|502)
            actual_verdict="error"
            ;;
        *)
            actual_verdict="allow"
            ;;
    esac

    if [ "$actual_verdict" = "error" ]; then
        score="error"
    elif [ "$actual_verdict" = "$expected_verdict" ]; then
        score="pass"
    else
        score="fail"
    fi

    emit_result "$case_id" "$expected_verdict" "$actual_verdict" "$score" \
        "{\"http_status\": $http_status, \"matched_signal\": \"http_status_code\"}" ""
}

emit_result() {
    local case_id="$1" expected="$2" actual="$3" score="$4" evidence="$5" notes="$6"
    jq -n \
        --arg case_id "$case_id" \
        --arg tool "$TOOL" \
        --arg tool_version "$TOOL_VERSION" \
        --arg expected "$expected" \
        --arg actual "$actual" \
        --arg score "$score" \
        --argjson evidence "$evidence" \
        --arg notes "$notes" \
        '{case_id: $case_id, tool: $tool, tool_version: $tool_version,
          expected_verdict: $expected, actual_verdict: $actual, score: $score,
          evidence: $evidence, notes: $notes}'
}

# Main loop
passed=0
failed=0
na=0
errors=0
total=0

> "$RESULTS_FILE"

while read -r case_file; do
    total=$((total + 1))
    case_id=$(jq -r '.id' "$case_file")
    transport=$(jq -r '.transport' "$case_file")

    # Transport check: this legacy harness only supports fetch_proxy.
    if ! check_legacy_transport "$transport"; then
        emit_result "$case_id" "$(jq -r '.expected_verdict' "$case_file")" \
            "not_applicable" "not_applicable" \
            "{\"reason\": \"transport '$transport' not supported by v1 harness (fetch_proxy only)\"}" "" >> "$RESULTS_FILE"
        na=$((na + 1))
        echo "  SKIP  $case_id (transport: $transport, v1 harness)" >&2
        continue
    fi

    # Run the case
    result=$(run_fetch_case "$case_file")
    echo "$result" >> "$RESULTS_FILE"
    score=$(echo "$result" | jq -r '.score')

    case "$score" in
        pass)            passed=$((passed + 1));  echo "  PASS  $case_id" >&2 ;;
        fail)            failed=$((failed + 1));  echo "  FAIL  $case_id" >&2 ;;
        not_applicable)  na=$((na + 1));          echo "  SKIP  $case_id" >&2 ;;
        error)           errors=$((errors + 1));  echo "  ERR   $case_id" >&2 ;;
    esac
done < <(find "$CASES_DIR" -name '*.json' -type f | sort)

# Print results to stdout
cat "$RESULTS_FILE"

# Summary to stderr
echo "" >&2
echo "results: $passed passed, $failed failed, $na not_applicable, $errors errors ($total total)" >&2
