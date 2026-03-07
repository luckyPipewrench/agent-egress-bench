#!/usr/bin/env bash
# Reference runner for Pipelock against agent-egress-bench corpus.
# Runs HTTP/fetch cases through Pipelock's fetch proxy and reports results.
#
# Usage: bash harness.sh [pipelock-binary] [cases-dir]
#
# Prerequisites:
#   - pipelock binary (default: pipelock in PATH)
#   - jq for JSON processing
#   - The benchmark config: pipelock-benchmark.yaml in this directory

set -euo pipefail

PIPELOCK="${1:-pipelock}"
CASES_DIR="${2:-../../cases}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR/tool-profile.json"
CONFIG="$SCRIPT_DIR/pipelock-benchmark.yaml"
PORT=18899
RESULTS_FILE="/tmp/agent-egress-bench-results.jsonl"

# Verify prerequisites
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
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

# Read tool profile claims and supports
CLAIMS=$(jq -r '.claims[]' "$PROFILE")
SUPPORTS=$(jq -r '.supports | to_entries[] | select(.value == true) | .key' "$PROFILE")

# Check if case is applicable
check_applicable() {
    local case_file="$1"

    # Check capability_tags against claims
    local tags
    tags=$(jq -r '.capability_tags[]' "$case_file")
    for tag in $tags; do
        if ! echo "$CLAIMS" | grep -qx "$tag"; then
            return 1
        fi
    done

    # Check requires against supports
    local reqs
    reqs=$(jq -r '.requires[]' "$case_file" 2>/dev/null)
    for req in $reqs; do
        if [ -z "$req" ]; then continue; fi
        if ! echo "$SUPPORTS" | grep -qx "$req"; then
            return 1
        fi
    done

    return 0
}

# Run a single URL/header/body case through the fetch proxy
run_http_case() {
    local case_file="$1"
    local case_id expected_verdict input_type method url

    case_id=$(jq -r '.id' "$case_file")
    expected_verdict=$(jq -r '.expected_verdict' "$case_file")
    input_type=$(jq -r '.input_type' "$case_file")

    # Build curl command based on input_type
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
            # Response cases are tested differently: we need a mock server
            # For now, skip these and mark as error with a note
            emit_result "$case_id" "$expected_verdict" "error" "error" \
                '{"reason": "response cases require mock server (not implemented in v1 harness)"}' \
                "response case runner not yet implemented"
            return
            ;;
        *)
            emit_result "$case_id" "$expected_verdict" "error" "error" \
                '{"reason": "unsupported input_type"}' ""
            return
            ;;
    esac

    # Execute
    local http_status
    http_status=$(curl "${curl_args[@]}" 2>/dev/null) || http_status="000"

    # Determine verdict
    local actual_verdict score
    case "$http_status" in
        403|502)
            actual_verdict="block"
            ;;
        000)
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
    input_type=$(jq -r '.input_type' "$case_file")

    # Applicability check
    if ! check_applicable "$case_file"; then
        emit_result "$case_id" "$(jq -r '.expected_verdict' "$case_file")" \
            "not_applicable" "not_applicable" '{}' "" >> "$RESULTS_FILE"
        na=$((na + 1))
        echo "  SKIP  $case_id (not applicable)" >&2
        continue
    fi

    # Route by input type
    case "$input_type" in
        url|request_body|header|response_content)
            result=$(run_http_case "$case_file")
            echo "$result" >> "$RESULTS_FILE"
            score=$(echo "$result" | jq -r '.score')
            ;;
        mcp_tool_call|mcp_tool_result|mcp_tool_definition|mcp_tool_sequence)
            # MCP cases need a different runner (mock MCP server)
            emit_result "$case_id" "$(jq -r '.expected_verdict' "$case_file")" \
                "error" "error" '{"reason": "MCP runner not implemented in v1 harness"}' "" >> "$RESULTS_FILE"
            score="error"
            ;;
        *)
            emit_result "$case_id" "$(jq -r '.expected_verdict' "$case_file")" \
                "error" "error" '{"reason": "unknown input_type"}' "" >> "$RESULTS_FILE"
            score="error"
            ;;
    esac

    case "$score" in
        pass)    passed=$((passed + 1)); echo "  PASS  $case_id" >&2 ;;
        fail)    failed=$((failed + 1)); echo "  FAIL  $case_id" >&2 ;;
        error)   errors=$((errors + 1)); echo "  ERR   $case_id" >&2 ;;
    esac
done < <(find "$CASES_DIR" -name '*.json' -type f | sort)

# Print results to stdout
cat "$RESULTS_FILE"

# Summary to stderr
echo "" >&2
echo "results: $passed passed, $failed failed, $na not_applicable, $errors errors ($total total)" >&2
