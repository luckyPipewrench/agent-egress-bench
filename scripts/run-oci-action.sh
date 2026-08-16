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
output_real="$(python3 "$GITHUB_ACTION_PATH/scripts/action_artifacts.py" prepare --workspace "$workspace_real" --output-dir "$output_dir")" || fail "cannot prepare output-dir without following symlinks"
output_rel="${output_real#"$workspace_real/"}"
results_path="$output_real/results.jsonl"
summary_path="$output_real/summary.json"
metadata_path="$output_real/run-metadata.json"

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
    -cases|-cases=*|--cases|--cases=*|-profile|-profile=*|--profile|--profile=*|-adapter|-adapter=*|--adapter|--adapter=*|-output|-output=*|--output|--output=*|-require-complete|-require-complete=*|--require-complete|--require-complete=*|-version|-version=*|--version|--version=*|-release-identity-metadata|-release-identity-metadata=*|--release-identity-metadata|--release-identity-metadata=*|-stats|-stats=*|--stats|--stats=*|-case-index|-case-index=*|--case-index|--case-index=*|-report|-report=*|--report|--report=*)
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

stage_parent="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
trusted_stage="$(mktemp -d "$stage_parent/aeb-action-trusted.XXXXXX")"
container_stage="$(mktemp -d "$stage_parent/aeb-action-container.XXXXXX")"
cleanup() {
  rm -rf -- "$trusted_stage" "$container_stage"
}
trap cleanup EXIT
results_stage="$trusted_stage/results.jsonl"
metadata_stage="$trusted_stage/run-metadata.json"
summary_stage="$container_stage/summary.json"

image="${INPUT_IMAGE:-}"
offline="${INPUT_OFFLINE:-false}"
case "$offline" in
  true|false) ;;
  *) fail "offline must be true or false" ;;
esac
allow_unverified_image="${INPUT_ALLOW_UNVERIFIED_IMAGE:-false}"
case "$allow_unverified_image" in
  true|false) ;;
  *) fail "allow-unverified-image must be true or false" ;;
esac

workspace_file() {
  local input_name=$1
  local input_value=$2
  [[ -n "$input_value" ]] || fail "$input_name is required"
  [[ "$input_value" != /* && "$input_value" != *".."* ]] || fail "$input_name must be a relative path without '..'"
  local staged="$trusted_stage/$input_name"
  python3 "$GITHUB_ACTION_PATH/scripts/action_artifacts.py" stage-input \
    --workspace "$workspace_real" \
    --path "$input_value" \
    --destination "$staged" || fail "$input_name must be a no-follow regular file inside GITHUB_WORKSPACE"
}

verify_image_identity() {
  local official_repository="ghcr.io/luckypipewrench/agent-egress-bench-runner"
  [[ "$image" == "$official_repository"@sha256:* ]] || fail "image must use the approved release repository; set allow-unverified-image to true only for a reviewed mirror or custom image"
  command -v gh >/dev/null 2>&1 || fail "GitHub CLI is required to verify runner image publisher identity"

  local metadata_path
  metadata_path="$(workspace_file image-metadata "${INPUT_IMAGE_METADATA:-}")"
  local verify_args=(
    attestation verify "$metadata_path"
    --repo luckyPipewrench/agent-egress-bench
    --signer-workflow github.com/luckyPipewrench/agent-egress-bench/.github/workflows/release.yaml
  )
  if [[ "$offline" == true ]]; then
    local bundle_path trusted_root_path
    bundle_path="$(workspace_file image-attestation "${INPUT_IMAGE_ATTESTATION:-}")"
    trusted_root_path="$(workspace_file attestation-trusted-root "${INPUT_ATTESTATION_TRUSTED_ROOT:-}")"
    verify_args+=(--bundle "$bundle_path" --custom-trusted-root "$trusted_root_path")
  elif [[ -n "${INPUT_IMAGE_ATTESTATION:-}" || -n "${INPUT_ATTESTATION_TRUSTED_ROOT:-}" ]]; then
    fail "image-attestation and attestation-trusted-root are used together only in offline mode"
  fi
  gh "${verify_args[@]}" >/dev/null || fail "runner image metadata provenance verification failed"

  python3 - "$metadata_path" "$image" <<'PY' || fail "runner image does not match signed release metadata"
import json
import re
import sys

metadata = json.load(open(sys.argv[1], encoding="utf-8"))
expected_keys = {"schema_version", "image", "digest", "source_repository", "source_commit", "release_tag"}
if not isinstance(metadata, dict) or set(metadata) != expected_keys:
    raise SystemExit("runner image metadata has an invalid shape")
if metadata["schema_version"] != 1:
    raise SystemExit("runner image metadata has an unsupported schema version")
if metadata["image"] != sys.argv[2]:
    raise SystemExit("runner image reference differs from signed metadata")
digest = sys.argv[2].rsplit("@", 1)[1]
if metadata["digest"] != digest:
    raise SystemExit("runner image digest differs from signed metadata")
if metadata["source_repository"] != "https://github.com/luckyPipewrench/agent-egress-bench":
    raise SystemExit("runner image metadata names an unexpected source repository")
if not isinstance(metadata["source_commit"], str) or re.fullmatch(r"[0-9a-f]{40}", metadata["source_commit"]) is None:
    raise SystemExit("runner image metadata has an invalid source commit")
if not isinstance(metadata["release_tag"], str) or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", metadata["release_tag"]) is None:
    raise SystemExit("runner image metadata has an invalid release tag")
PY
}

if [[ -n "$image" ]]; then
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || fail "image must use an immutable @sha256 digest"
  if [[ "$allow_unverified_image" == false ]]; then
    verify_image_identity
  fi
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

image_id="$(docker image inspect --format '{{.Id}}' "$image")"
docker_security_options="$(docker info --format '{{json .SecurityOptions}}')" || fail "cannot inspect Docker security options"
volume_label_suffix=""
selinux_labeling="unavailable"
if [[ "$docker_security_options" == *'name=selinux'* ]]; then
  volume_label_suffix=",z"
  selinux_labeling="enabled"
else
  echo "agent-egress-bench Action: Docker SELinux labeling is unavailable; read-only mounts and process restrictions remain active" >&2
fi

set +e
docker run --rm --init \
  --security-opt no-new-privileges=true \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --user "$(id -u):$(id -g)" \
  --env HOME=/tmp \
  --env TMPDIR=/tmp \
  "${network_args[@]}" \
  "${env_args[@]}" \
  --volume "$workspace_real:/work:ro$volume_label_suffix" \
  --volume "$container_stage:/aeb-output:rw$volume_label_suffix" \
  --workdir /work \
  "$image" \
  --cases /opt/aeb/cases \
  --profile "/work/$profile_rel" \
  --adapter "$INPUT_ADAPTER" \
  --output "/aeb-output/summary.json" \
  --require-complete \
  "${runner_args[@]}" >"$results_stage"
container_exit=$?
set -e
run_exit=$container_exit

measurement_status="absent"
summary_publish_args=()
if [[ -e "$summary_stage" || -L "$summary_stage" ]]; then
  if [[ -f "$summary_stage" && ! -L "$summary_stage" ]]; then
    summary_publish_args=(--summary "$summary_stage")
    set +e
    measurement_status="$(python3 "$GITHUB_ACTION_PATH/scripts/action_artifacts.py" inspect-summary --path "$summary_stage")"
    summary_status_exit=$?
    set -e
    if [[ "$summary_status_exit" -ne 0 ]]; then
      measurement_status="invalid"
      echo "agent-egress-bench Action: summary is malformed or has no valid measurement_status; retaining raw artifacts" >&2
      [[ "$run_exit" -ne 0 ]] || run_exit=1
    fi
  else
    echo "agent-egress-bench Action: summary artifact isn't a regular file; refusing to follow it" >&2
    measurement_status="invalid"
    [[ "$run_exit" -ne 0 ]] || run_exit=1
  fi
fi
if [[ "$measurement_status" != measured && "$run_exit" -eq 0 ]]; then
  echo "agent-egress-bench Action: measurement status is $measurement_status; retained artifacts describe a partial run" >&2
  run_exit=1
fi

export AEB_ACTION_METADATA_PATH="$metadata_stage"
export AEB_ACTION_IMAGE="$image"
export AEB_ACTION_IMAGE_ID="$image_id"
export AEB_ACTION_NETWORK_MODE="$network_mode"
export AEB_ACTION_SELINUX_LABELING="$selinux_labeling"
export AEB_ACTION_RUNNER_EXIT="$container_exit"
export AEB_ACTION_EXIT="$run_exit"
export AEB_ACTION_REF_VALUE="${AEB_ACTION_REF:-local}"
export AEB_ACTION_MEASUREMENT_STATUS="$measurement_status"
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
    "selinux_labeling": os.environ["AEB_ACTION_SELINUX_LABELING"],
    "measurement_status": os.environ["AEB_ACTION_MEASUREMENT_STATUS"],
    "require_complete": True,
    "runner_exit_code": int(os.environ["AEB_ACTION_RUNNER_EXIT"]),
    "action_exit_code": int(os.environ["AEB_ACTION_EXIT"]),
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

python3 "$GITHUB_ACTION_PATH/scripts/action_artifacts.py" publish \
  --workspace "$workspace_real" \
  --output-dir "$output_rel" \
  --results "$results_stage" \
  "${summary_publish_args[@]}" \
  --metadata "$metadata_stage" || fail "cannot publish Action artifacts without following symlinks"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "results=$results_path" >> "$GITHUB_OUTPUT"
  echo "summary=$summary_path" >> "$GITHUB_OUTPUT"
  echo "metadata=$metadata_path" >> "$GITHUB_OUTPUT"
  echo "measurement-status=$measurement_status" >> "$GITHUB_OUTPUT"
fi

exit "$run_exit"
