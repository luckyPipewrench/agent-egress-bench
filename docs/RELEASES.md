# Release artifacts

A tagged release fixes the corpus, schemas, contracts, runner source revision, and runner archives in one package. A release tag identifies the source revision. The `release-identity.json` asset records the exact revision and the SHA-256 digest of every bundled corpus and schema file.

Each release contains:

- One corpus data bundle. It carries the cases, the schemas, the contracts, the
  core capability registry, and the operator kit under `examples/`: the tool
  profile template the runner requires, the MCP gateway plugin template, the
  runner skeleton, the operator-kit README, the evidence-custody checklist, the
  report template, and the reference harness. Bundle members preserve their tracked executable bit;
  other files extract with mode `0644`.
- One commit-pinned schema catalog and schema bundle. The bundle contains the
  catalog and every schema it names, so a vendor can validate schema bytes
  after download without a network connection.
- `release-notes.md`, used as the GitHub Release body. It lists every schema
  identity and version carried by that release and links to the offline
  validation walkthrough and adapter quickstarts.
- Archives for Linux, macOS, and Windows on amd64 and arm64. Each one carries
  both `aeb-gauntlet`, which runs the corpus, and `aeb-validate`, which checks a
  result against the contracts. The release verifier refuses an archive missing
  either binary, carrying one built for another platform, or carrying the same
  program under both names. That last check exists because a name, an executable
  bit, and a machine type are all satisfied by one program copied under two
  names, which is what a build configured to produce the same binary twice
  produces. It does not establish which program either binary is; see the note
  under Verify a downloaded release.
- `checksums.txt` covering every release asset.
- `release-identity.json` with the corpus version, active schema versions, source commit, and supported archive matrix.
- `runner-image.ref` with the full digest-pinned OCI image reference.
- GitHub Artifact Attestations for every release asset.

The platform archives are the bench tools (`aeb-gauntlet` and `aeb-validate`). The official Pipelock Gauntlet entrypoint is `scripts/run-pipelock-gauntlet.sh`, and that script is Linux-only: it downloads Linux Pipelock assets, uses Landlock and seccomp, and refuses any other kernel with `the portable Pipelock runner currently supports Linux only`. A macOS archive lets you inspect cases and validate saved artifacts on that host. It does not mean the full Pipelock Gauntlet runs on a Mac.

Opening an N-1 artifact with a reader from tagged release N is family-specific. Pin package verification to the tag that produced the archives. [GOVERNANCE.md](GOVERNANCE.md#mixed-release-readers) records which saved run artifacts still verify and which fail with a named machine-readable error.

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

After extracting the platform archive, run `aeb-gauntlet --version` and `aeb-validate --version`. A tagged binary prints its release version and exact source commit. When the archive matches the current host, hand both back to the verifier so it reads the identity out of the running programs rather than off their filenames:

```bash
python3 scripts/release_build.py verify --release-dir .. \
  --executable ./aeb-gauntlet --validator-executable ./aeb-validate
```

The Windows archives carry `aeb-gauntlet.exe` and `aeb-validate.exe`, so name those instead:

```powershell
python3 scripts/release_build.py verify --release-dir .. `
  --executable .\aeb-gauntlet.exe --validator-executable .\aeb-validate.exe
```

Be precise about what that establishes. Without those two options the verifier checks each binary's name, executable bit, machine type, and that the two archive members are different programs. Supplying them adds two things: the file you point at must be the same bytes as that binary inside a release archive, and running it must print the identity this release records. Pointing the option at some other program is refused before it runs, so the option reports on the release rather than on whatever happens to be on your path.

What none of it establishes is what a program does. A binary carrying the release's own bytes and reporting its version could still behave differently from the source it claims, and the release identity naming the validator is a label rather than a proof of role. These checks catch the mistake and the swap: a build configured to produce one program twice, a member replaced with another, an archive assembled for the wrong platform.

What binds the bytes is `checksums.txt` over every asset, and the GitHub attestation over those assets. Altering a binary inside an archive fails checksum verification immediately, so defeating it means regenerating the checksums, which means controlling the build. At that point a second manifest of binary digests written by the same build would be regenerated too, which is why there isn't one. Verify the attestation when the question is whether the release came from this repository's workflow.

## Run the corpus from a downloaded release

The platform archive and the data bundle together are enough to inspect and run the corpus. Neither step needs a Go toolchain, a clone, or a network connection.

```bash
tar -xzf aeb-release/agent-egress-bench_0.1.0_linux_amd64.tar.gz -C aeb-release/extracted
cd aeb-release/extracted
mkdir artifacts
./aeb-gauntlet --stats --cases cases
./aeb-gauntlet --cases cases --profile examples/runner-template/tool-profile-template.json \
  --output artifacts/raw-summary.json > artifacts/results.jsonl
./aeb-gauntlet --report artifacts --report-output artifacts/report.md
```

The runner writes one JSON result per case to standard output and its human summary to standard error, so redirecting standard output produces `results.jsonl` without mixing the two. `--report` reads a directory rather than a single file, and it reads the summary under the name `raw-summary.json`, so write `--output` to that name when the run is meant to be reported. A summary saved under any other name leaves the report's method, target, and score sections reading as absent even though the file is sitting in the directory.

Every artifact the report reads is individually optional, so a run that produced only some of them still renders, and each missing fact is reported as absent rather than guessed.

Check the corpus and the result with the validator from the same archive. It reads the case directory alongside the results so it can bind each row back to the case it claims to answer:

```bash
./aeb-validate cases cases
./aeb-validate results artifacts/results.jsonl cases
```

Read a validator refusal as a statement about the rows in front of it, and never suppress one to make a run look clean. Two denial-of-wallet cases, for instance, require a target to carry timing evidence for any block it claims, so a target that claims the block without producing the evidence is refused. A real target either supplies the evidence or does not claim the block.

The template profile names no real product, so that run exercises the corpus and the artifact path rather than measuring anything. Copy it, set `tool` and `tool_version` to the target under test, and select the adapter that reaches it. `--adapter mcp-gateway --gateway-plugin` drives an MCP gateway from `examples/gateway-plugin-template.json`; `docs/GATEWAY-ADAPTER.md` states that plugin contract.

A run that reaches no target reports `measurement_status: incomplete`, and the score covers only the cases the adapter actually routed. Pass `--require-complete` to exit nonzero on an incomplete measurement instead of reading a partial run as a result.

## Build without publishing

`make release-snapshot` builds the archive matrix, corpus data bundle, schema catalog and bundle, checksums, and identity verification under `dist/release`. It creates no tag and no GitHub release. The command requires a pinned GoReleaser installation. The release workflow installs GoReleaser v2.17.1 and runs this snapshot path for manual workflow dispatches.

Tag pushes matching `v*` run the same gates against the tag, attach provenance to every release asset, upload the generated artifacts for inspection, and publish a draft only after those checks pass. If the publish job fails after creating a draft, rerunning that workflow resumes the existing draft and refuses to overwrite a published release. The workflow stops before publication when the release identity, corpus data, schema contract, archive layout, or checksum verification disagrees.
