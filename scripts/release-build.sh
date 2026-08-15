#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/release-build.sh --tag vX.Y.Z --commit <40-char-sha> [--snapshot]" >&2
  exit 2
}

require_option_value() {
  local option=$1
  local value=${2-}
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "release-build: $option requires a value" >&2
    usage
  fi
}

tag=""
commit=""
dist="dist"
snapshot=false
while (($#)); do
  case "$1" in
    --tag) require_option_value "$1" "${2-}"; tag=$2; shift 2 ;;
    --commit) require_option_value "$1" "${2-}"; commit=$2; shift 2 ;;
    --dist) require_option_value "$1" "${2-}"; dist=$2; shift 2 ;;
    --snapshot) snapshot=true; shift ;;
    *) usage ;;
  esac
done
[[ -n "$tag" && -n "$commit" ]] || usage
if [[ "$dist" != dist ]]; then
  echo "release-build: only the configured dist directory is supported; omit --dist" >&2
  exit 2
fi

if [[ "$snapshot" == true ]]; then
  [[ "$tag" == snapshot ]] || usage
  # Pin the tag GoReleaser resolves from instead of predicting which one it
  # would pick. Both sides then derive the version from one explicit input, so
  # the two cannot disagree; previously each selected a tag independently and a
  # divergence was only caught later by the final verify.
  goreleaser_tag="$(python3 scripts/release_build.py snapshot-tag --repo-root . --commit "$commit")"
  export GORELEASER_CURRENT_TAG="$goreleaser_tag"
  version="$(python3 scripts/release_build.py snapshot-version --repo-root . --commit "$commit")"
  snapshot_args=(--snapshot)
else
  [[ "$tag" == v* ]] || usage
  tag_commit="$(git rev-parse "${tag}^{commit}")"
  supplied_commit="$(git rev-parse "${commit}^{commit}")"
  if [[ "$supplied_commit" != "$tag_commit" ]]; then
    echo "release-build: --commit does not resolve to tag $tag" >&2
    exit 1
  fi
  commit=$tag_commit
  version=${tag#v}
  export GORELEASER_CURRENT_TAG="$tag"
  snapshot_args=()
fi

identity=.release/release-identity.json
rm -rf "$dist" .release
mkdir -p .release
export TMPDIR="$HOME/.cache/pipelock-tmp"
export GOCACHE="$HOME/.cache/go-build"
mkdir -p "$TMPDIR" "$GOCACHE"
python3 scripts/release_build.py prepare \
  --tag "$tag" \
  --version "$version" \
  --commit "$commit" \
  "${snapshot_args[@]}" \
  --output "$identity"

goreleaser release --clean "${snapshot_args[@]}"
release_dir="$dist/release"
mkdir -p "$release_dir"
find "$dist" -maxdepth 1 -type f \( -name 'agent-egress-bench_*.tar.gz' -o -name 'agent-egress-bench_*.zip' \) -exec mv {} "$release_dir" \;
python3 scripts/release_build.py data-bundle --identity "$identity" --dist "$release_dir"
schema_catalog="$release_dir/agent-egress-bench_${version}_schema-catalog.json"
python3 scripts/write_schema_catalog.py --release "$tag" --output "$schema_catalog"
python3 scripts/release_build.py schema-bundle --identity "$identity" --catalog "$schema_catalog" --dist "$release_dir"
python3 scripts/release_build.py checksums --identity "$identity" --dist "$release_dir"
# Run the binary this host can actually execute. Hardcoding linux/amd64 works on
# CI and silently breaks a macOS or arm64 developer running a snapshot. When no
# archive matches the host, verify without the executable check and SAY so, so a
# skipped check is never mistaken for a passed one.
host_os="$(go env GOOS)"
host_arch="$(go env GOARCH)"
host_archive="$release_dir/agent-egress-bench_${version}_${host_os}_${host_arch}.tar.gz"
if [[ -f "$host_archive" ]]; then
  native_dir="$(mktemp -d "$TMPDIR/aeb-${host_os}-${host_arch}.XXXXXX")"
  trap 'rm -rf "$native_dir"' EXIT
  tar -xzf "$host_archive" -C "$native_dir"
  python3 scripts/release_build.py verify --release-dir "$release_dir" --executable "$native_dir/aeb-gauntlet"
else
  echo "release-build: no archive for ${host_os}/${host_arch}; verifying without the executable check" >&2
  python3 scripts/release_build.py verify --release-dir "$release_dir"
fi
