#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

github_api_token="${GH_TOKEN:-}"
unset GH_TOKEN GITHUB_TOKEN

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
provenance_script="$repo_root/scripts/build_gauntlet_provenance.py"
release_pin="$repo_root/examples/pipelock/release.env"
corpus_repository="luckyPipewrench/agent-egress-bench"

output_dir=""
development_mode=false
development_binary=""
benchmark_timeout_seconds=$((24 * 60))
deadline_epoch=""
reserve_seconds=$((6 * 60))
original_args=("$@")

usage() {
  cat <<'EOF'
Usage: ./scripts/run-pipelock-gauntlet.sh [options]

Run the canonical Pipelock Gauntlet and leave one hash-bound evidence directory.

Options:
  --output-dir DIR                 Write evidence to a new DIR.
  --deadline-epoch SECONDS         Stop early enough to preserve finalization time.
  --reserve-seconds SECONDS        Keep this many seconds before the deadline (default: 360).
  --benchmark-timeout-seconds N    Maximum runner time without a deadline (default: 1440).
  --development                    Allow a dirty or unreviewed corpus and mark the run noncanonical.
  --development-binary PATH        Use PATH instead of a released binary and mark the run noncanonical.
  -h, --help                       Show this help.
EOF
}

die() {
  failure_reason="$*"
  printf 'run-pipelock-gauntlet: %s\n' "$failure_reason" >&2
  exit 1
}

require_uint() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$label must be a non-negative integer"
}

while (($#)); do
  case "$1" in
    --output-dir)
      (($# >= 2)) || die "--output-dir requires a value"
      output_dir="$2"
      shift 2
      ;;
    --deadline-epoch)
      (($# >= 2)) || die "--deadline-epoch requires a value"
      deadline_epoch="$2"
      shift 2
      ;;
    --reserve-seconds)
      (($# >= 2)) || die "--reserve-seconds requires a value"
      reserve_seconds="$2"
      shift 2
      ;;
    --benchmark-timeout-seconds)
      (($# >= 2)) || die "--benchmark-timeout-seconds requires a value"
      benchmark_timeout_seconds="$2"
      shift 2
      ;;
    --development)
      development_mode=true
      shift
      ;;
    --development-binary)
      (($# >= 2)) || die "--development-binary requires a value"
      development_binary="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

require_uint "--benchmark-timeout-seconds" "$benchmark_timeout_seconds"
require_uint "--reserve-seconds" "$reserve_seconds"
if [[ -n "$deadline_epoch" ]]; then
  require_uint "--deadline-epoch" "$deadline_epoch"
fi
((benchmark_timeout_seconds > 0)) || die "--benchmark-timeout-seconds must be greater than zero"

[[ "$(pwd -P)" == "$repo_root" ]] || die "run this command from the repository root: $repo_root"
[[ -f "$release_pin" ]] || die "missing reviewed release pin: $release_pin"
unset PIPELOCK_REPO PIPELOCK_TAG PIPELOCK_VERSION
# shellcheck disable=SC1090
source "$release_pin"
: "${PIPELOCK_REPO:?release pin must define PIPELOCK_REPO}"
: "${PIPELOCK_TAG:?release pin must define PIPELOCK_TAG}"
: "${PIPELOCK_VERSION:?release pin must define PIPELOCK_VERSION}"
[[ "$PIPELOCK_REPO" == "luckyPipewrench/pipelock" ]] || die "release pin names an unexpected repository"
[[ "$PIPELOCK_TAG" == "v$PIPELOCK_VERSION" ]] || die "release tag and version do not match"

started_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
run_stamp="$(date -u +'%Y%m%dT%H%M%SZ')"
local_run_id="local:${run_stamp}:$$"
if [[ -z "$output_dir" ]]; then
  output_dir="$repo_root/continuous-gauntlet-runs/${run_stamp}-$$"
elif [[ "$output_dir" != /* ]]; then
  output_dir="$repo_root/$output_dir"
fi

[[ ! -L "$output_dir" ]] || die "output directory cannot be a symbolic link: $output_dir"
output_dir="$(realpath -m "$output_dir")"
[[ "$output_dir" != "$repo_root/.git" && "$output_dir" != "$repo_root/.git/"* ]] || \
  die "output directory cannot be inside the repository's Git metadata"
[[ ! -e "$output_dir" ]] || \
  die "output directory must not already exist: $output_dir"
mkdir -p "$(dirname "$output_dir")"
mkdir "$output_dir"
chmod 0750 "$output_dir"

failure_reason="setup did not complete"
bundle_complete=false
work_dir=""

on_exit() {
  local status=$?
  trap - EXIT
  if [[ "$bundle_complete" != true ]]; then
    if ! PYTHONDONTWRITEBYTECODE=1 python3 "$provenance_script" bundle \
      --repo-root "$repo_root" \
      --run-dir "$output_dir" \
      --failure "$failure_reason"; then
      jq -n --arg failure "$failure_reason" '{
        schema_version: 1,
        local_run_id: null,
        blocked: true,
        execution_status: "blocked",
        publication_eligible: false,
        failures: [$failure],
        evidence_sha256: {}
      }' > "$output_dir/execution-decision.json.tmp" 2>/dev/null || true
      if [[ -f "$output_dir/execution-decision.json.tmp" ]]; then
        mv "$output_dir/execution-decision.json.tmp" "$output_dir/execution-decision.json"
      fi
    fi
  fi
  if [[ -n "$work_dir" && -d "$work_dir" ]]; then
    rm -rf -- "$work_dir"
  fi
  exit "$status"
}
trap on_exit EXIT

printf '%q ' "$0" "${original_args[@]}" > "$output_dir/entrypoint-command.txt"
printf '\n' >> "$output_dir/entrypoint-command.txt"

for command_name in git python3 go curl jq sha256sum tar timeout realpath make; do
  command -v "$command_name" >/dev/null || die "required command is unavailable: $command_name"
done
command -v socat >/dev/null || command -v ncat >/dev/null || command -v nc >/dev/null || \
  die "MCP stdio bridge requires socat, ncat, or nc"

failure_reason="corpus identity check failed"
[[ "$(git rev-parse --show-toplevel)" == "$repo_root" ]] || die "repository root identity mismatch"
remote_url="$(git remote get-url origin 2>/dev/null || true)"
case "$remote_url" in
  git@github.com:luckyPipewrench/agent-egress-bench.git|ssh://git@github.com/luckyPipewrench/agent-egress-bench.git|https://github.com/luckyPipewrench/agent-egress-bench|https://github.com/luckyPipewrench/agent-egress-bench.git)
    remote_matches=true
    ;;
  *)
    remote_matches=false
    ;;
esac

noncanonical_reasons=()
if [[ "$development_mode" == true ]]; then
  noncanonical_reasons+=("development corpus mode was requested")
else
  [[ "$remote_matches" == true ]] || die "origin is not the canonical $corpus_repository repository"
  git fetch --force --prune --prune-tags --tags \
    https://github.com/luckyPipewrench/agent-egress-bench.git \
    '+refs/heads/main:refs/remotes/origin/main'
fi

if [[ "$output_dir" == "$repo_root/"* && "$development_mode" != true ]]; then
  output_relative="${output_dir#"$repo_root/"}"
  git check-ignore -q -- "$output_relative" || \
    die "an output directory inside the repository must be covered by .gitignore"
fi
dirty_output="$(git status --porcelain=v1 --untracked-files=all)"
if [[ -n "$dirty_output" ]]; then
  corpus_dirty=true
  if [[ "$development_mode" != true ]]; then
    printf '%s\n' "$dirty_output" >&2
    die "corpus checkout is dirty; use a clean origin/main or tag checkout"
  fi
  noncanonical_reasons+=("corpus checkout was dirty")
else
  corpus_dirty=false
fi

corpus_git_sha="$(git rev-parse HEAD)"
origin_main_sha="$(git rev-parse --verify origin/main 2>/dev/null || true)"
if [[ "$development_mode" == true ]]; then
  pointed_tags="$(git tag --points-at HEAD)"
else
  pointed_tags="$(git ls-remote --tags https://github.com/luckyPipewrench/agent-egress-bench.git | \
    awk -v sha="$corpus_git_sha" '$1 == sha { print $2 }')"
fi
if [[ "$corpus_git_sha" == "$origin_main_sha" ]]; then
  corpus_ref_kind="origin/main"
elif [[ -n "$pointed_tags" ]]; then
  corpus_ref_kind="tag"
elif [[ "$development_mode" == true ]]; then
  corpus_ref_kind="development"
  noncanonical_reasons+=("corpus commit was neither fetched origin/main nor a tag")
else
  die "corpus checkout is neither fetched origin/main nor a tag"
fi
if [[ "$remote_matches" != true ]]; then
  noncanonical_reasons+=("origin did not match $corpus_repository")
fi

canonical_execution=true
if [[ "$development_mode" == true || -n "$development_binary" || "$corpus_dirty" == true || "$remote_matches" != true ]]; then
  canonical_execution=false
fi
if [[ -n "$development_binary" ]]; then
  noncanonical_reasons+=("development Pipelock binary was requested")
fi

start_args=(
  start
  --output "$output_dir/run-metadata.json"
  --local-run-id "$local_run_id"
  --generated-at "$started_at"
  --corpus-repository "$corpus_repository"
  --corpus-ref-kind "$corpus_ref_kind"
  --corpus-git-sha "$corpus_git_sha"
  --dirty "$corpus_dirty"
  --canonical-execution "$canonical_execution"
)
for reason in "${noncanonical_reasons[@]}"; do
  start_args+=(--noncanonical-reason "$reason")
done
PYTHONDONTWRITEBYTECODE=1 python3 "$provenance_script" "${start_args[@]}"
cp "$repo_root/cases/MANIFEST.txt" "$output_dir/corpus-manifest.txt"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/aeb-pipelock-gauntlet.XXXXXX")"
pipelock_bin=""
asset=""
asset_sha256=""
released_binary=true

failure_reason="Pipelock release verification failed"
if [[ -n "$development_binary" ]]; then
  [[ -x "$development_binary" ]] || die "development binary is not executable: $development_binary"
  pipelock_bin="$(realpath "$development_binary")"
  asset="development-binary"
  released_binary=false
  : > "$output_dir/checksums.txt"
else
  case "$(uname -m)" in
    x86_64) release_arch=amd64 ;;
    aarch64|arm64) release_arch=arm64 ;;
    *) die "unsupported Linux architecture: $(uname -m)" ;;
  esac
  [[ "$(uname -s)" == "Linux" ]] || die "the portable Pipelock runner currently supports Linux only"
  asset="pipelock_${PIPELOCK_VERSION}_linux_${release_arch}.tar.gz"
  release_json="$work_dir/release.json"
  api_headers=( -H 'Accept: application/vnd.github+json' )
  auth_header_file=""
  if [[ -n "$github_api_token" ]]; then
    auth_header_file="$work_dir/github-api.headers"
    printf 'Authorization: Bearer %s\n' "$github_api_token" > "$auth_header_file"
    chmod 0600 "$auth_header_file"
    api_headers+=( -H "@$auth_header_file" )
  fi
  curl -fsSL "${api_headers[@]}" \
    "https://api.github.com/repos/${PIPELOCK_REPO}/releases/tags/${PIPELOCK_TAG}" \
    -o "$release_json"
  if [[ -n "$auth_header_file" ]]; then
    rm -f -- "$auth_header_file"
  fi
  github_api_token=""
  actual_tag="$(jq -r '.tag_name // empty' "$release_json")"
  is_draft="$(jq -r 'if has("draft") then (.draft | tostring) else empty end' "$release_json")"
  is_prerelease="$(jq -r 'if has("prerelease") then (.prerelease | tostring) else empty end' "$release_json")"
  if [[ "$actual_tag" != "$PIPELOCK_TAG" || "$is_draft" != "false" || "$is_prerelease" != "false" ]]; then
    die "expected stable released tag $PIPELOCK_TAG, got tag=${actual_tag:-<none>} draft=${is_draft:-<none>} prerelease=${is_prerelease:-<none>}"
  fi
  asset_url="$(jq -r --arg name "$asset" '.assets[] | select(.name == $name) | .browser_download_url' "$release_json")"
  checksums_url="$(jq -r '.assets[] | select(.name == "checksums.txt") | .browser_download_url' "$release_json")"
  [[ -n "$asset_url" && "$asset_url" != "null" ]] || die "release asset is missing: $asset"
  [[ -n "$checksums_url" && "$checksums_url" != "null" ]] || die "release checksums.txt is missing"
  [[ "$(printf '%s\n' "$asset_url" | wc -l)" == "1" ]] || die "release has duplicate assets named $asset"
  [[ "$(printf '%s\n' "$checksums_url" | wc -l)" == "1" ]] || die "release has duplicate checksums.txt assets"
  curl -fsSL "$asset_url" -o "$work_dir/$asset"
  curl -fsSL "$checksums_url" -o "$output_dir/checksums.txt"
  checksum_line="$(awk -v asset="$asset" '{ name = $2; sub(/^\*/, "", name); if (name == asset) print }' "$output_dir/checksums.txt")"
  [[ "$(printf '%s\n' "$checksum_line" | sed '/^$/d' | wc -l)" == "1" ]] || \
    die "checksums.txt must contain exactly one entry for $asset"
  (
    cd "$work_dir"
    printf '%s\n' "$checksum_line" | sha256sum --check -
  )
  asset_sha256="$(sha256sum "$work_dir/$asset" | awk '{print $1}')"
  tar -xzf "$work_dir/$asset" -C "$work_dir"
  pipelock_bin="$work_dir/pipelock"
  chmod 0755 "$pipelock_bin"
fi

version_output="$($pipelock_bin --version)"
printf '%s\n' "$version_output" > "$output_dir/pipelock-version.txt"
reported_version="$(awk '/^pipelock version / { print $3 }' <<<"$version_output")"
[[ "$reported_version" == "$PIPELOCK_VERSION" ]] || \
  die "Pipelock version mismatch: expected $PIPELOCK_VERSION, got ${reported_version:-<none>}"
binary_sha256="$(sha256sum "$pipelock_bin" | awk '{print $1}')"

release_args=(
  release
  --output "$output_dir/pipelock-release.json"
  --repository "$PIPELOCK_REPO"
  --tag "$PIPELOCK_TAG"
  --version "$PIPELOCK_VERSION"
  --asset "$asset"
  --binary-sha256 "$binary_sha256"
  --version-output "$version_output"
  --released-binary "$released_binary"
)
if [[ -n "$asset_sha256" ]]; then
  release_args+=(--asset-sha256 "$asset_sha256")
fi
PYTHONDONTWRITEBYTECODE=1 python3 "$provenance_script" "${release_args[@]}"

failure_reason="Gauntlet runner build failed"
gauntlet_bin="$work_dir/aeb-gauntlet"
(
  cd "$repo_root/runner"
  go build -o "$gauntlet_bin" .
)

export PIPELOCK_BIN="$pipelock_bin"
export PIPELOCK_BENCH_CONFIG="$repo_root/examples/pipelock/pipelock-benchmark.yaml"
summary_path="$output_dir/raw-summary.json"
results_path="$output_dir/results.jsonl"
stderr_path="$output_dir/runner.stderr"
command_path="$output_dir/command.txt"
stats_path="$output_dir/make-stats.txt"
case_index_path="$output_dir/case-index.json"

mcp_cmd="\"$PIPELOCK_BIN\" mcp proxy --config \"$PIPELOCK_BENCH_CONFIG\" --env AEB_MCP_STDIO_UPSTREAM_ADDR -- sh ./examples/pipelock/mcp-stdio-upstream-bridge.sh"
managed_proxy_cmd='./examples/pipelock/start-proxy-for-benchmark.sh "$PIPELOCK_BIN"'
managed_mcp_http_cmd='./examples/pipelock/start-mcp-http-for-benchmark.sh "$PIPELOCK_BIN"'
cmd=(
  "$gauntlet_bin"
  --adapter proxy
  --scan-token bench-test-token
  --mcp-cmd "$mcp_cmd"
  --managed-proxy-cmd "$managed_proxy_cmd"
  --managed-mcp-http-cmd "$managed_mcp_http_cmd"
  --cases ./cases
  --multifile-cases ./cases/mcp-drift
  --profile examples/pipelock/tool-profile.json
  --fixtures
  --output "$summary_path"
)

benchmark_cap_seconds="$benchmark_timeout_seconds"
if [[ -n "$deadline_epoch" ]]; then
  now_epoch="$(date +%s)"
  available_seconds=$((deadline_epoch - now_epoch - reserve_seconds))
  ((available_seconds > 0)) || die "insufficient total-job budget remains to run the benchmark safely"
  if ((available_seconds < benchmark_cap_seconds)); then
    benchmark_cap_seconds="$available_seconds"
  fi
fi
run_cmd=(timeout --signal=TERM --kill-after=30s "${benchmark_cap_seconds}s" "${cmd[@]}")
printf '%q ' "${run_cmd[@]}" > "$command_path"
printf '\n' >> "$command_path"

failure_reason="canonical runner command contract failed"
grep -Eq '(^|[[:space:]])--fixtures($|[[:space:]])' "$command_path" || \
  die "recorded command does not include --fixtures"
grep -Eq '(^|[[:space:]])--multifile-cases($|[[:space:]])' "$command_path" || \
  die "recorded command does not include --multifile-cases"

failure_reason="corpus statistics or case index generation failed"
make stats > "$stats_path"
"$gauntlet_bin" --cases ./cases --case-index > "$case_index_path"

failure_reason="Gauntlet runner failed"
set +e
"${run_cmd[@]}" > "$results_path" 2> "$stderr_path"
run_status=$?
set -e
if [[ "$run_status" -ne 0 ]]; then
  failure_reason="Gauntlet runner failed with exit code $run_status"
  cat "$stderr_path" >&2
  exit "$run_status"
fi
grep -Eq '^Fixtures: HTTP=.* TLS=.* WS=.* DNS=.* MCP_HTTP=' "$stderr_path" || \
  die "runner did not report fixture startup"

failure_reason="Gauntlet result validation failed"
results_abs="$(realpath "$results_path")"
(
  cd "$repo_root/validate"
  go run . results "$results_abs"
)
jq -e '.case_count.errors == 0' "$summary_path" >/dev/null || \
  die "runner summary contains errors"

failure_reason="portable evidence bundle validation failed"
PYTHONDONTWRITEBYTECODE=1 python3 "$provenance_script" bundle \
  --repo-root "$repo_root" \
  --run-dir "$output_dir"
bundle_complete=true

printf 'Portable Gauntlet run complete: %s\n' "$output_dir"
if [[ "$canonical_execution" == true ]]; then
  printf 'Publication eligibility: canonical execution bundle (platform finalization still required)\n'
else
  printf 'Publication eligibility: noncanonical development bundle\n'
fi
