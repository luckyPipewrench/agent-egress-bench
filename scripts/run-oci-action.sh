#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "agent-egress-bench Action: $*" >&2
  exit 2
}

[[ -n "${GITHUB_WORKSPACE:-}" ]] || fail "GITHUB_WORKSPACE is required"
[[ -n "${INPUT_PROFILE:-}" ]] || fail "profile is required"
[[ -n "${INPUT_ADAPTER:-}" ]] || fail "adapter is required"

workspace_real="$(realpath "$GITHUB_WORKSPACE")"
profile_real="$(realpath "$GITHUB_WORKSPACE/$INPUT_PROFILE")"
[[ "$profile_real" == "$workspace_real/"* ]] || fail "profile must be inside GITHUB_WORKSPACE"
profile_rel="${profile_real#"$workspace_real/"}"

output_dir="${INPUT_OUTPUT_DIR:-aeb-results}"
[[ "$output_dir" != /* && "$output_dir" != *".."* ]] || fail "output-dir must be a relative path without '..'"
mkdir -p "$GITHUB_WORKSPACE/$output_dir"
output_real="$(realpath "$GITHUB_WORKSPACE/$output_dir")"
[[ "$output_real" == "$workspace_real/"* ]] || fail "output-dir must stay inside GITHUB_WORKSPACE"
output_rel="${output_real#"$workspace_real/"}"

parse_string_array() {
  python3 -c 'import json, re, sys
value = json.loads(sys.argv[1])
if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
    raise SystemExit("expected a JSON array of strings")
if any("\n" in item or "\x00" in item for item in value):
    raise SystemExit("array values cannot contain newlines or NUL bytes")
for item in value:
    print(item)' "$1"
}

runner_args_text="$(parse_string_array "${INPUT_RUNNER_ARGS:-[]}")" || fail "runner-args must be a JSON array of strings"
runner_args=()
if [[ -n "$runner_args_text" ]]; then
  mapfile -t runner_args <<< "$runner_args_text"
fi
for arg in "${runner_args[@]}"; do
  case "$arg" in
    --cases|--cases=*|--profile|--profile=*|--adapter|--adapter=*|--output|--output=*|--require-complete|--require-complete=*)
      fail "runner-args cannot override $arg"
      ;;
  esac
done

env_names_text="$(parse_string_array "${INPUT_ENVIRONMENT:-[]}")" || fail "environment must be a JSON array of variable names"
env_names=()
if [[ -n "$env_names_text" ]]; then
  mapfile -t env_names <<< "$env_names_text"
fi
env_args=()
for name in "${env_names[@]}"; do
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "invalid environment variable name: $name"
  [[ -v "$name" ]] || fail "requested environment variable is unset: $name"
  env_args+=(--env "$name")
done

image="${INPUT_IMAGE:-}"
offline="${INPUT_OFFLINE:-false}"
case "$offline" in
  true|false) ;;
  *) fail "offline must be true or false" ;;
esac

if [[ -n "$image" ]]; then
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || fail "image must use an immutable @sha256 digest"
  if [[ "$offline" == true ]]; then
    docker image inspect "$image" >/dev/null 2>&1 || fail "offline image isn't loaded: $image"
  else
    docker pull "$image"
  fi
else
  [[ "$offline" == false ]] || fail "offline mode requires a preloaded digest-pinned image"
  action_ref="${AEB_ACTION_REF:-local}"
  safe_ref="${action_ref//[^A-Za-z0-9_.-]/-}"
  image="aeb-gauntlet-action:$safe_ref"
  docker build \
    --build-arg "AEB_VERSION=action-$action_ref" \
    --build-arg "AEB_COMMIT=$action_ref" \
    --tag "$image" \
    "$GITHUB_ACTION_PATH"
fi

network_args=()
network_mode="container-default"
if [[ "$offline" == true ]]; then
  network_args=(--network none --env AEB_OFFLINE=1)
  network_mode="none"
fi

results_path="$output_real/results.jsonl"
summary_path="$output_real/summary.json"
metadata_path="$output_real/run-metadata.json"
image_id="$(docker image inspect --format '{{.Id}}' "$image")"

set +e
docker run --rm --init --security-opt label=disable --user "$(id -u):$(id -g)" \
  "${network_args[@]}" \
  "${env_args[@]}" \
  --volume "$workspace_real:/work" \
  --workdir /work \
  "$image" \
  --cases /opt/aeb/cases \
  --profile "/work/$profile_rel" \
  --adapter "$INPUT_ADAPTER" \
  --output "/work/$output_rel/summary.json" \
  --require-complete \
  "${runner_args[@]}" >"$results_path"
run_exit=$?
set -e

export AEB_ACTION_METADATA_PATH="$metadata_path"
export AEB_ACTION_IMAGE="$image"
export AEB_ACTION_IMAGE_ID="$image_id"
export AEB_ACTION_NETWORK_MODE="$network_mode"
export AEB_ACTION_RUN_EXIT="$run_exit"
export AEB_ACTION_REF_VALUE="${AEB_ACTION_REF:-local}"
python3 - <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["AEB_ACTION_METADATA_PATH"])
path.write_text(json.dumps({
    "action_ref": os.environ["AEB_ACTION_REF_VALUE"],
    "image": os.environ["AEB_ACTION_IMAGE"],
    "image_id": os.environ["AEB_ACTION_IMAGE_ID"],
    "network_mode": os.environ["AEB_ACTION_NETWORK_MODE"],
    "require_complete": True,
    "runner_exit_code": int(os.environ["AEB_ACTION_RUN_EXIT"]),
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

measurement_status="absent"
if [[ -s "$summary_path" ]]; then
  measurement_status="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["measurement_status"])' "$summary_path")"
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "results=$results_path" >> "$GITHUB_OUTPUT"
  echo "summary=$summary_path" >> "$GITHUB_OUTPUT"
  echo "metadata=$metadata_path" >> "$GITHUB_OUTPUT"
  echo "measurement-status=$measurement_status" >> "$GITHUB_OUTPUT"
fi

exit "$run_exit"
