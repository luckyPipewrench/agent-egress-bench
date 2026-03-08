#!/usr/bin/env bash
# Skeleton runner for agent-egress-bench
#
# Copy this file and tool-profile-template.json to examples/your-tool/
# and fill in the TODOs.
#
# Usage: bash skeleton.sh [tool-binary] [cases-dir]
#
# Output: JSONL to stdout (one result per case), summary to stderr.
# See docs/RUNNER.md for the full output contract.

set -euo pipefail

# --- Configuration ---
TOOL_BINARY="${1:-your-tool}"
CASES_DIR="${2:-../../cases}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROFILE="$SCRIPT_DIR/tool-profile.json"

# --- Prerequisites ---
command -v jq >/dev/null 2>&1 || { echo "error: jq required" >&2; exit 1; }
[ -f "$PROFILE" ] || { echo "error: tool profile not found: $PROFILE" >&2; exit 1; }

# Read tool identity from profile
TOOL=$(jq -r '.tool' "$PROFILE")
TOOL_VERSION=$(jq -r '.tool_version' "$PROFILE")
CLAIMS=$(jq -r '.claims[]' "$PROFILE")
SUPPORTS=$(jq -r '.supports | to_entries[] | select(.value == true) | .key' "$PROFILE")

# --- Applicability check ---
# This function is complete. Copy it as-is.
# Returns 0 if the case applies to this tool, 1 if not.
check_applicable() {
    local case_file="$1"

    # Every capability_tag must be in the tool's claims
    local tags
    tags=$(jq -r '.capability_tags[]' "$case_file")
    for tag in $tags; do
        if ! echo "$CLAIMS" | grep -qx "$tag"; then
            return 1
        fi
    done

    # Every requires entry must be in the tool's supports
    local reqs
    reqs=$(jq -r '.requires[]' "$case_file" 2>/dev/null)
    for req in $reqs; do
        [ -z "$req" ] && continue
        if ! echo "$SUPPORTS" | grep -qx "$req"; then
            return 1
        fi
    done

    return 0
}

# --- Emit a single JSONL result line to stdout ---
# This function is complete. Copy it as-is.
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

# ============================================================
# TODO 1: Start your tool
# ============================================================
# Launch your tool and wait for it to be ready.
# Example for an HTTP proxy tool:
#
#   PORT=18899
#   "$TOOL_BINARY" start --listen "127.0.0.1:$PORT" &
#   TOOL_PID=$!
#   trap "kill $TOOL_PID 2>/dev/null; wait $TOOL_PID 2>/dev/null" EXIT
#
#   # Wait for readiness (adjust the health check URL for your tool)
#   for i in $(seq 1 30); do
#       if curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
#           break
#       fi
#       if [ "$i" -eq 30 ]; then
#           echo "error: tool did not start within 30 seconds" >&2
#           exit 1
#       fi
#       sleep 1
#   done
#   echo "tool ready on port $PORT" >&2
#
# For MCP proxy tools, you may not need a background process.
# Instead, you might pipe messages through your tool per-case.
# ============================================================

echo "error: TODO 1 not implemented: start your tool" >&2
exit 1

# --- Main loop ---
passed=0
failed=0
na=0
errors=0
total=0

while read -r case_file; do
    total=$((total + 1))
    case_id=$(jq -r '.id' "$case_file")
    expected=$(jq -r '.expected_verdict' "$case_file")
    input_type=$(jq -r '.input_type' "$case_file")
    transport=$(jq -r '.transport' "$case_file")

    # --- Applicability check (profile-based) ---
    if ! check_applicable "$case_file"; then
        emit_result "$case_id" "$expected" "not_applicable" "not_applicable" \
            '{"reason": "case requires capabilities not claimed by tool profile"}' ""
        na=$((na + 1))
        echo "  SKIP  $case_id (not applicable)" >&2
        continue
    fi

    # ============================================================
    # TODO 2: Check transport support
    # ============================================================
    # Skip cases with transports your runner does not handle yet.
    # Even if your tool supports a transport, your runner might not
    # have the plumbing for it. Be honest about what works.
    #
    # Example (fetch_proxy only):
    #
    #   case "$transport" in
    #       fetch_proxy) ;;  # supported by this runner
    #       *)
    #           emit_result "$case_id" "$expected" "not_applicable" "not_applicable" \
    #               "{\"reason\": \"transport '$transport' not supported by runner\"}" ""
    #           na=$((na + 1))
    #           echo "  SKIP  $case_id (transport: $transport)" >&2
    #           continue
    #           ;;
    #   esac
    # ============================================================

    # ============================================================
    # TODO 3: Feed the case to your tool and observe the verdict
    # ============================================================
    # This is where your tool-specific logic goes. Read the payload,
    # build a request, send it through your tool, observe the result.
    #
    # For HTTP proxy tools:
    #   1. Extract method, url, headers, body from the payload
    #   2. Build a curl command targeting your proxy
    #   3. Check the HTTP status code
    #   4. Map status to verdict:
    #      - 403 or 502 with block marker => "block"
    #      - 200, 301, 404, etc.          => "allow"
    #      - 000 (connection failed)      => "error"
    #
    # For MCP proxy tools:
    #   1. Extract jsonrpc_messages from the payload
    #   2. Pipe each message through your MCP proxy
    #   3. Check if the message was forwarded or blocked
    #   4. Map the observation to verdict:
    #      - Message withheld or error response => "block"
    #      - Message forwarded                  => "allow"
    #      - Transport failure                  => "error"
    #
    # For response scanning:
    #   1. Start a local HTTP server returning the response_body
    #   2. Fetch through your proxy
    #   3. Check if the response was flagged
    #
    # Replace the placeholder below with your implementation.
    # ============================================================

    actual_verdict="error"
    evidence='{"reason": "TODO: implement tool-specific verdict observation"}'

    # --- Score the result ---
    if [ "$actual_verdict" = "error" ]; then
        score="error"
    elif [ "$actual_verdict" = "$expected" ]; then
        score="pass"
    else
        score="fail"
    fi

    emit_result "$case_id" "$expected" "$actual_verdict" "$score" "$evidence" ""

    case "$score" in
        pass)           passed=$((passed + 1));  echo "  PASS  $case_id" >&2 ;;
        fail)           failed=$((failed + 1));  echo "  FAIL  $case_id" >&2 ;;
        not_applicable) na=$((na + 1));          echo "  SKIP  $case_id" >&2 ;;
        error)          errors=$((errors + 1));  echo "  ERR   $case_id" >&2 ;;
    esac
done < <(find "$CASES_DIR" -name '*.json' -type f | sort)

# --- Summary ---
echo "" >&2
echo "results: $passed passed, $failed failed, $na not_applicable, $errors errors ($total total)" >&2
