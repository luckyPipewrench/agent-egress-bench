#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/release-build.sh --tag vX.Y.Z --commit <40-char-sha> [--snapshot]" >&2
  exit 2
}

tag=""
commit=""
dist="dist"
snapshot=false
while (($#)); do
  case "$1" in
    --tag) tag=${2:-}; shift 2 ;;
    --commit) commit=${2:-}; shift 2 ;;
    --dist) dist=${2:-}; shift 2 ;;
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
  version="1.0.0-SNAPSHOT-${commit:0:7}"
  snapshot_args=(--snapshot)
else
  [[ "$tag" == v* ]] || usage
  version=${tag#v}
  snapshot_args=()
fi

identity=.release/release-identity.json
rm -rf "$dist" .release
mkdir -p .release
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
python3 scripts/release_build.py checksums --identity "$identity" --dist "$release_dir"
python3 scripts/release_build.py verify --release-dir "$release_dir"
