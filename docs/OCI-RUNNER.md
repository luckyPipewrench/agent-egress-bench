# OCI runner, reusable Action, devcontainer, and offline runs

The runner image packages `aeb-gauntlet`, the corpus, schemas, contracts, capability registry, and examples in one Linux environment that is built for `linux/amd64` and `linux/arm64`.

The image is based on Alpine 3.24.1 and built with Go 1.25.12. Both base images are pinned by OCI index digest in the `Dockerfile`, both indexes contain amd64 and arm64 manifests, and the release workflow checks the installed Buildx and runner versions instead of trusting a tag. The runtime image uses the unprivileged `aeb` user; the Action maps that process to the caller's UID and GID for bind-mounted files.

## Build and inspect the image

Run these commands from the repository root on a connected machine. The build downloads Go modules and verifies them against `runner/go.sum`:

```bash
docker build --build-arg AEB_VERSION=local --build-arg AEB_COMMIT=f8078cb -t aeb-gauntlet:local .
docker run --rm aeb-gauntlet:local --version
docker run --rm --entrypoint /bin/cat aeb-gauntlet:local /etc/alpine-release
```

The expected version lines for that exact build are `aeb-gauntlet local f8078cb` and `3.24.1`.

Build both release architectures with the same Dockerfile:

```bash
docker buildx build --platform linux/amd64,linux/arm64 --build-arg AEB_VERSION=local --build-arg AEB_COMMIT=f8078cb --output type=oci,dest=/tmp/aeb-gauntlet-local.oci.tar .
```

The tagged release workflow publishes the multi-architecture index to `ghcr.io/luckypipewrench/agent-egress-bench-runner`, verifies that the index contains both required platforms, runs the amd64 image, and records the full digest-pinned reference in the signed `runner-image.json` release asset.

The workflow logs out of GHCR and pulls the digest again before the GitHub Release can be created. GitHub documents that a newly published container package can start private, so the first publication must be made public in the package settings and rerun if that anonymous pull fails; a public package can then be pulled by an outside lab without credentials. See [Configuring a package's access control and visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility).

No published runner-image digest exists for this unreleased change, so this document doesn't invent one. After the first tagged publication, use the exact `ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:...` value in `runner-image.json` and never replace it with a tag in a reproducibility record. The release checksums and GitHub attestation cover that identity file.

## Reusable GitHub Action

The Action runs the benchmark in the OCI image, replaces its own `results.jsonl`, `summary.json`, and `run-metadata.json` files on each invocation, and fails the job unless the new summary reports `measurement_status: measured`. A malformed summary or one without that field is retained as raw evidence, while `run-metadata.json` records `measurement_status: invalid`, the original runner exit code, and the Action's failing exit code.

This smoke-test workflow uses the exact Action commit and intentionally produces an incomplete measurement with the synthetic `dryrun` adapter, so a correct run ends red while preserving all case rows:

```yaml
name: Check incomplete-result handling
on: workflow_dispatch
jobs:
  benchmark:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0
      - id: aeb
        uses: luckyPipewrench/agent-egress-bench@f8078cb2a8812f2ac3200a9ad429d21780c673fd
        with:
          profile: examples/pipelock/tool-profile.json
          adapter: dryrun
      - if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0
        with:
          name: aeb-results
          path: aeb-results/
```

A real tool workflow selects `proxy` or `mcp-gateway` and supplies its endpoints, managed start commands, fixture switch, and other adapter settings as a JSON string array in `runner-args`; the adapter contract and complete command are documented in [RUNNER.md](RUNNER.md).

When `image` is omitted, the Action builds the image from its own pinned Action checkout and needs network access for uncached base images and Go modules. When `image` is set, the Action requires the official `ghcr.io/luckypipewrench/agent-egress-bench-runner` repository, an immutable digest, and the matching signed `runner-image.json` release asset. Digest pinning fixes the bytes while the signed metadata proves which release workflow published them.

A lab using a reviewed mirror or custom image must set `allow-unverified-image: 'true'`. That opt-in keeps mirrors available without letting an arbitrary input silently inherit the official publisher claim.

The Action works on GitHub's amd64 runners and on arm64 self-hosted runners because Docker selects the matching manifest and the Dockerfile cross-builds the runner for the selected target architecture. The container gets a read-only workspace and root filesystem, a writable temporary filesystem and isolated output mount, no Linux capabilities, and no privilege escalation. On a Docker daemon with SELinux support, the wrapper uses shared relabeling for both bind mounts; on a host without SELinux support it reports that labeling is unavailable while keeping the other restrictions active.

## Devcontainer

Open the repository in a devcontainer-aware editor and choose **Reopen in Container**. `.devcontainer/devcontainer.json` builds the same pinned Dockerfile, opens the checkout under `/workspaces` using its actual directory name, updates the unprivileged `aeb` user to the caller's UID, and overrides the image entrypoint so an interactive shell can stay open.

From the devcontainer terminal, confirm the installed artifacts with real commands:

```bash
aeb-gauntlet --version
cat /etc/alpine-release
aeb-gauntlet --cases /opt/aeb/cases --stats
```

On an Apple Silicon laptop, Docker builds the native `linux/arm64` target. The runner itself also cross-compiles for `darwin/arm64`, but this container remains Linux because OCI containers share the Linux container runtime rather than the macOS kernel.

## Prepare an air-gapped run

The connected staging machine must download `runner-image.json`, its GitHub attestation bundle, and the current trusted root before the lab loses network access. This example uses `v0.1.0` only as a command shape:

```bash
mkdir -p benchmark/release
gh release download v0.1.0 --repo luckyPipewrench/agent-egress-bench --pattern runner-image.json --dir benchmark/release
(cd benchmark/release && gh attestation download runner-image.json --repo luckyPipewrench/agent-egress-bench --limit 1)
mv benchmark/release/sha256:*.jsonl benchmark/release/runner-image.attestation.jsonl
gh attestation trusted-root > benchmark/release/runner-image.trusted-root.jsonl
```

Read the exact multi-architecture digest from `runner-image.json`, copy that full `ghcr.io/luckypipewrench/agent-egress-bench-runner@sha256:...` reference into `aeb-gauntlet-image.ref`, and record the transferred bytes without replacing the digest with a tag:

```bash
docker pull "$(cat aeb-gauntlet-image.ref)"
docker image inspect "$(cat aeb-gauntlet-image.ref)"
docker image save --output aeb-gauntlet-image.tar "$(cat aeb-gauntlet-image.ref)"
sha256sum aeb-gauntlet-image.tar > aeb-gauntlet-image.tar.sha256
```

This transfer path doesn't need the source checkout, a Go compiler, or a vendor tree. Transfer the three image identity files with `aeb-gauntlet-image.ref` and the tarball checksum.

Inside the air-gapped lab, verify and load the exact transfer:

```bash
sha256sum --check aeb-gauntlet-image.tar.sha256
docker image load --input aeb-gauntlet-image.tar
docker image inspect "$(cat aeb-gauntlet-image.ref)"
```

Set the Action inputs `image` to that full digest reference and `offline` to `true`. Offline mode first requires that exact reference to exist locally, then starts the benchmark container with Docker network mode `none` and the same strict completion check used online.

```yaml
      - id: image
        shell: bash
        run: echo "ref=$(cat aeb-gauntlet-image.ref)" >> "$GITHUB_OUTPUT"
      - id: aeb
        uses: luckyPipewrench/agent-egress-bench@f8078cb2a8812f2ac3200a9ad429d21780c673fd
        with:
          profile: benchmark/tool-profile.json
          adapter: proxy
          image: ${{ steps.image.outputs.ref }}
          image-metadata: benchmark/release/runner-image.json
          image-attestation: benchmark/release/runner-image.attestation.jsonl
          attestation-trusted-root: benchmark/release/runner-image.trusted-root.jsonl
          offline: 'true'
          runner-args: '["--fixtures","--managed-proxy-cmd","/work/benchmark/start-proxy.sh","--proxy-addr","127.0.0.1:18899"]'
```

The target binary, configuration, profile, start script, license material, and any receipt-verification key needed by that command must already be in the checked-out workspace or image. A dynamically linked target must be compatible with Alpine Linux and the image architecture; a static target avoids that host-library dependency.

Offline mode cannot test a remote SaaS endpoint, download a target, contact a license server, use a host or sibling-container proxy, or resolve an Action checkout on its own. Fetch the repository, Action commit, image, target, and verification material before isolation, and run the target inside the same network-disabled container with a managed command.

The runner still emits one visible row for every corpus case. Unreachable, unsupported, adapter-error, or unknown outcomes make `measurement_status` incomplete, do not count as passes, and cause `--require-complete` and the Action to exit nonzero after retaining the artifacts.
