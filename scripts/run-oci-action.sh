#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "agent-egress-bench Action: $*" >&2
  exit 2
}

if (($#)); then
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
  doctor_mode=""
  export GITHUB_WORKSPACE="$(pwd -P)"
  export GITHUB_ACTION_PATH="$repo_root"
  export INPUT_OFFLINE=true
  export INPUT_RUNNER_ARGS='[]'
  export INPUT_ENVIRONMENT='[]'
  export INPUT_OUTPUT_DIR=aeb-results
  export INPUT_ALLOW_UNVERIFIED_IMAGE=false
  export INPUT_PROFILE=""
  export INPUT_ADAPTER=""
  export INPUT_IMAGE=""
  export INPUT_IMAGE_METADATA=""
  export INPUT_IMAGE_ATTESTATION=""
  export INPUT_ATTESTATION_TRUSTED_ROOT=""
  export AEB_ACTION_REF=local-offline
  while (($#)); do
    case "$1" in
      --profile) (($# >= 2)) || fail "--profile requires a value"; export INPUT_PROFILE="$2"; shift 2 ;;
      --adapter) (($# >= 2)) || fail "--adapter requires a value"; export INPUT_ADAPTER="$2"; shift 2 ;;
      --image) (($# >= 2)) || fail "--image requires a value"; export INPUT_IMAGE="$2"; shift 2 ;;
      --image-metadata) (($# >= 2)) || fail "--image-metadata requires a value"; export INPUT_IMAGE_METADATA="$2"; shift 2 ;;
      --image-attestation) (($# >= 2)) || fail "--image-attestation requires a value"; export INPUT_IMAGE_ATTESTATION="$2"; shift 2 ;;
      --attestation-trusted-root) (($# >= 2)) || fail "--attestation-trusted-root requires a value"; export INPUT_ATTESTATION_TRUSTED_ROOT="$2"; shift 2 ;;
      --runner-args) (($# >= 2)) || fail "--runner-args requires a value"; export INPUT_RUNNER_ARGS="$2"; shift 2 ;;
      --environment) (($# >= 2)) || fail "--environment requires a value"; export INPUT_ENVIRONMENT="$2"; shift 2 ;;
      --output-dir) (($# >= 2)) || fail "--output-dir requires a value"; export INPUT_OUTPUT_DIR="$2"; shift 2 ;;
      --allow-unverified-image) export INPUT_ALLOW_UNVERIFIED_IMAGE=true; shift ;;
      --doctor) doctor_mode=text; shift ;;
      --doctor-json) doctor_mode=json; shift ;;
      -h|--help)
        cat <<'EOF'
Usage: ./scripts/run-oci-action.sh --profile FILE --adapter NAME --image REF [options]

Run the pre-staged OCI benchmark locally with network access disabled.

Required:
  --profile FILE                    Workspace-relative tool profile.
  --adapter NAME                    Runner adapter name.
  --image REF                       Preloaded digest-pinned image.

Required for publisher verification:
  --image-metadata FILE             Signed runner-image.ref asset.
  --image-attestation FILE          Offline attestation bundle.
  --attestation-trusted-root FILE   Offline GitHub attestation trusted root.

Options:
  --runner-args JSON                Additional runner arguments as a JSON string array.
  --environment JSON                Environment variable names as a JSON string array.
  --output-dir DIR                  Workspace-relative output directory (default: aeb-results).
  --allow-unverified-image          Permit a reviewed mirror or custom digest-pinned image
                                    without publisher-verification inputs.
  --doctor                          Check offline-run prerequisites without starting a run.
  --doctor-json                     Emit the prerequisite report as JSON.
EOF
        exit 0
        ;;
      *) fail "unknown local option: $1" ;;
    esac
  done
fi

run_doctor() {
  local failed=0 code status remediation index value material_valid=true publisher_verified=false
  local metadata_check="" attestation_check="" trusted_root_check=""
  local workspace_check
  local -a codes=() statuses=() remediations=()

  add_check() {
    codes+=("$1")
    statuses+=("$2")
    remediations+=("$3")
    [[ "$2" == ok || "$2" == waived ]] || failed=$((failed + 1))
  }

  workspace_check="$(realpath "$GITHUB_WORKSPACE" 2>/dev/null || true)"
  inside_workspace() {
    [[ "$workspace_check" == / && "$1" == /* ]] || [[ "$1" == "$workspace_check/"* ]]
  }

  if [[ "$(uname -s 2>/dev/null || true)" == Linux ]]; then
    add_check platform_linux ok ""
  else
    add_check platform_linux unsupported "run the offline OCI path on Linux"
  fi
  for code in python3 realpath docker; do
    if command -v "$code" >/dev/null 2>&1; then
      add_check "command_$code" ok ""
    else
      add_check "command_$code" missing "install $code and retry"
    fi
  done
  if [[ -z "${INPUT_PROFILE:-}" ]]; then
    add_check profile missing "pass --profile with a workspace-relative file"
  elif profile_check="$(realpath "$GITHUB_WORKSPACE/$INPUT_PROFILE" 2>/dev/null)" &&
    inside_workspace "$profile_check" && [[ -f "$profile_check" && ! -L "$GITHUB_WORKSPACE/$INPUT_PROFILE" ]]; then
    add_check profile ok ""
  else
    add_check profile invalid "use a regular, non-symlink file inside the workspace"
  fi
  if [[ -z "${INPUT_ADAPTER:-}" ]]; then
    add_check adapter missing "pass --adapter with the target adapter name"
  else
    add_check adapter ok ""
  fi
  if [[ ! "${INPUT_IMAGE:-}" =~ @sha256:[0-9a-f]{64}$ ]]; then
    add_check image_digest invalid "pass --image with an immutable sha256 digest"
  elif command -v docker >/dev/null 2>&1 && docker image inspect "$INPUT_IMAGE" >/dev/null 2>&1; then
    add_check image_loaded ok ""
  else
    add_check image_loaded missing "load the exact digest-pinned image and retry"
  fi
  if [[ "${INPUT_ALLOW_UNVERIFIED_IMAGE:-false}" == true ]]; then
    add_check publisher_material waived "publisher identity was not verified; retain this waiver in the run packet"
  else
    if [[ "${INPUT_IMAGE:-}" == ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:* ]]; then
      add_check image_repository ok ""
    else
      add_check image_repository invalid "use the approved release repository or pass --allow-unverified-image for a reviewed mirror"
    fi
    if command -v gh >/dev/null 2>&1; then
      add_check command_gh ok ""
    else
      add_check command_gh missing "install GitHub CLI and retry"
    fi
    for code in image-metadata image-attestation attestation-trusted-root; do
      case "$code" in
        image-metadata) value="${INPUT_IMAGE_METADATA:-}" ;;
        image-attestation) value="${INPUT_IMAGE_ATTESTATION:-}" ;;
        attestation-trusted-root) value="${INPUT_ATTESTATION_TRUSTED_ROOT:-}" ;;
      esac
      if [[ -n "$value" ]] && material_check="$(realpath "$GITHUB_WORKSPACE/$value" 2>/dev/null)" &&
        inside_workspace "$material_check" && [[ -f "$material_check" && ! -L "$GITHUB_WORKSPACE/$value" ]]; then
        add_check "${code//-/_}" ok ""
        case "$code" in
          image-metadata) metadata_check="$material_check" ;;
          image-attestation) attestation_check="$material_check" ;;
          attestation-trusted-root) trusted_root_check="$material_check" ;;
        esac
      else
        add_check "${code//-/_}" missing "stage a regular, non-symlink $code file inside the workspace"
        material_valid=false
      fi
    done
    if command -v gh >/dev/null 2>&1 && [[ "$material_valid" == true ]] &&
      [[ "${INPUT_IMAGE:-}" == ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:* ]] &&
      gh attestation verify "$metadata_check" \
        --repo luckyPipewrench/agent-egress-bench \
        --signer-workflow github.com/luckyPipewrench/agent-egress-bench/.github/workflows/release.yaml \
        --bundle "$attestation_check" \
        --custom-trusted-root "$trusted_root_check" >/dev/null 2>&1 &&
      [[ "$(<"$metadata_check")" == "${INPUT_IMAGE:-}" ]]; then
      add_check publisher_identity ok ""
      publisher_verified=true
    else
      add_check publisher_identity invalid "stage publisher evidence that verifies and names the requested image"
    fi
  fi

  if [[ "$doctor_mode" == json ]]; then
    printf '{"schema_version":1,"ready":%s,"publisher_verified":%s,"checks":[' \
      "$([[ "$failed" == 0 ]] && printf true || printf false)" "$publisher_verified"
    for ((index = 0; index < ${#codes[@]}; index++)); do
      ((index == 0)) || printf ','
      printf '{"code":"%s","status":"%s","remediation":"%s"}' "${codes[$index]}" "${statuses[$index]}" "${remediations[$index]}"
    done
    printf ']}\n'
  else
    for ((index = 0; index < ${#codes[@]}; index++)); do
      printf '%-28s %s' "${codes[$index]}" "${statuses[$index]}"
      [[ -z "${remediations[$index]}" ]] || printf ' - %s' "${remediations[$index]}"
      printf '\n'
    done
  fi
  ((failed == 0))
}

if [[ -n "${doctor_mode:-}" ]]; then
  run_doctor
  exit $?
fi

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
publisher_verified=false

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

  python3 - "$metadata_path" "$image" <<'PY' || fail "runner image does not match the signed release reference"
from pathlib import Path
import sys

if Path(sys.argv[1]).read_bytes() != (sys.argv[2] + "\n").encode("utf-8"):
    raise SystemExit("signed runner image reference differs from the requested image")
PY
}

if [[ -n "$image" ]]; then
  [[ "$image" =~ @sha256:[0-9a-f]{64}$ ]] || fail "image must use an immutable @sha256 digest"
  if [[ "$allow_unverified_image" == false ]]; then
    verify_image_identity
    publisher_verified=true
  fi
  if [[ "$offline" == true ]]; then
    command -v docker >/dev/null 2>&1 || fail "Docker is required for an offline run"
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
export AEB_ACTION_PUBLISHER_VERIFIED="$publisher_verified"
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
    "publisher_verified": os.environ["AEB_ACTION_PUBLISHER_VERIFIED"] == "true",
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
