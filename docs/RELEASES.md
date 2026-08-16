# Release artifacts

A tagged release fixes the corpus, schemas, contracts, runner source revision, and runner archives in one package. A release tag identifies the source revision. The `release-identity.json` asset records the exact revision and the SHA-256 digest of every bundled corpus and schema file.

Each release contains:

- One corpus data bundle.
- One commit-pinned schema catalog and schema bundle. The bundle contains the
  catalog and every schema it names, so a vendor can validate schema bytes
  after download without a network connection.
- `aeb-gauntlet` archives for Linux, macOS, and Windows on amd64 and arm64.
- `checksums.txt` covering every release asset.
- `release-identity.json` with the corpus version, active schema versions, source commit, and supported archive matrix.
- `runner-image.ref` with the full digest-pinned OCI image reference.
- GitHub Artifact Attestations for every release asset.

## Verify a downloaded release

Pick the immutable release tag that a result cites and use that same tag in every command below. This example uses `v0.1.0` only as a command shape. It does not refer to a published release.

```bash
mkdir aeb-release
gh release download v0.1.0 --repo luckyPipewrench/agent-egress-bench --dir aeb-release
mkdir aeb-release/extracted
tar -xzf aeb-release/agent-egress-bench_0.1.0_data.tar.gz -C aeb-release/extracted
(cd aeb-release/extracted && python3 scripts/release_build.py verify --release-dir ..)
```

The verifier rejects a missing asset, a checksum mismatch, an archive whose embedded identity differs from the release identity, a changed corpus or schema file, a schema catalog or bundle that disagrees with the release commit, or a data bundle whose file list differs from the recorded tree.

To bind that package back to the cited source, clone the same tag and supply it to the verifier:

```bash
git clone --depth 1 --branch v0.1.0 https://github.com/luckyPipewrench/agent-egress-bench.git aeb-source
(cd aeb-source && python3 scripts/release_build.py verify --release-dir ../aeb-release --repo-root .)
```

That command refuses when the release identity does not match the checked-out source tree.

An operator can also check the GitHub provenance attached to any release asset:

```bash
gh attestation verify aeb-release/agent-egress-bench_0.1.0_linux_amd64.tar.gz --repo luckyPipewrench/agent-egress-bench
```

After extracting the platform archive, run `aeb-gauntlet --version`. A tagged binary prints its release version and exact source commit. The release verifier accepts that output with `--executable` when the archive matches the current host.

## Build without publishing

`make release-snapshot` builds the archive matrix, corpus data bundle, schema catalog and bundle, checksums, and identity verification under `dist/release`. It creates no tag and no GitHub release. The command requires a pinned GoReleaser installation. The release workflow installs GoReleaser v2.17.1 and runs this snapshot path for manual workflow dispatches.

Tag pushes matching `v*` run the same gates against the tag, attach provenance to every release asset, upload the generated artifacts for inspection, and publish a draft only after those checks pass. If the publish job fails after creating a draft, rerunning that workflow resumes the existing draft and refuses to overwrite a published release. The workflow stops before publication when the release identity, corpus data, schema contract, archive layout, or checksum verification disagrees.
