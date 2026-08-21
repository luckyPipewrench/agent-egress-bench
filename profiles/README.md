# Receipt Profiles

This directory holds maintainer-published receipt-scoring profiles described in
[`docs/RECEIPT-SCORING.md`](../docs/RECEIPT-SCORING.md). A receipt profile
records, for every applicable corpus case, whether a tool blocked the action,
explained the verdict, produced a signed receipt, produced one that is
independently verifiable, and (for benign baselines) whether it blocked a
case it should have allowed. Profiles are evidence artifacts published by
the tool's maintainer. The corpus does not certify or audit them. <!-- claim-ok: states the non-claim -->

## Historical records

[`pipelock.json`](pipelock.json) preserves a historical run of Pipelock `3.1.0`
against corpus `v2.0.0`:
196 per-case rows, including 148 blocked malicious cases. The
[`retained-artifacts.json`](retained-artifacts.json) manifest pins that exact
file's digest and identity. The runner test rejects any edit that changes the
record without updating this explicit historical declaration.

Current Pipelock measurements belong in the active Gauntlet result flow. Do
not update this artifact to make an old run look current.

## Where profiles come from

A profile is the output of one recorded run of the reference runner
against a tool. The runner is in [`../runner/`](../runner/) and accepts
`--emit-receipt-profile <path>` to write the artifact alongside the
standard Gauntlet summary. Per-case rows are sorted by `case_id` and no
timestamps appear in the file. Byte-identical output additionally requires
the same `benchmark_manifest_sha256`, a `clean` `corpus_git_status` with the
recorded `corpus_git_sha`, and the same tool-version command output. Other Git
statuses do not identify checkout bytes that can be reproduced by cloning a
revision. `observed_tool_version.status` records whether the runner observed the
output, couldn't obtain it, or wasn't asked to run a version command. A
reproduction must match the recorded status and, when the status is `observed`,
the recorded bounded value. The exact JSON-argv command is retained in the
runner command as `--tool-version-command`.

The reference command for Pipelock is documented in
[`../docs/RUNNER.md`](../docs/RUNNER.md). Other tools provide their own
runner or adapter; the schema is tool-neutral.

## What a profile proves

- **The tool's per-case behavior at a specific corpus input.**
  `benchmark_manifest_sha256` pins the exact loaded paths, boundaries, and
  bytes. `corpus_sha256` remains a legacy content digest. `corpus_git_sha`
  identifies the source revision only when `corpus_git_status` is `clean`.
- **The tool label and its self-report.** `tool_version` is a declared
  compatibility label. `observed_tool_version` records the tool command's
  stdout or an explicit reason the runner could not obtain it.
- **Whether the tool emits independently verifiable evidence.** The
  `verifier` block plus the per-case `receipt_produced` and
  `receipt_independently_verifiable` dimensions answer the procurement
  question: can a third party validate what the tool did, offline, without
  trusting the vendor.
- **Whether the tool blocked benign baselines.** The `false_positive`
  dimension counts cases marked `expected_verdict: allow` in the corpus
  that the tool blocked.

## What a profile does not prove

- **It is not a ranking.** Per [`docs/RECEIPT-SCORING.md`](../docs/RECEIPT-SCORING.md):
  "Each tool can publish its own results. Cross-tool comparison tables
  are not part of this repo." Aggregate scores across profiles are out
  of scope for this directory.
- **It is not a certification.** <!-- claim-ok: states the non-claim --> Profile submissions are reviewed for
  shape and referenced case IDs. The corpus maintainers do not validate
  the values; relying parties reproduce the profile before trusting it.
- **It is not a weight on which dimensions matter.** A buyer evaluating
  a tool for a regulated workload weights
  `receipt_independently_verifiable` differently than a buyer evaluating
  a tool for developer-workstation hardening.

## How to add a profile

1. Implement a runner or adapter that exercises the corpus against your
   tool. The reference runner in [`../runner/`](../runner/) handles
   Pipelock; tools that speak the same HTTP-proxy + scan-API surface can
   reuse it. Other tools provide their own runner.
2. Run your tool against the corpus and emit a profile that conforms to
   [`../schemas/receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json).
3. Add `profiles/<tool>.json` and (optionally) a sibling `notes.md`
   describing how to reproduce the profile from scratch.
4. Open a pull request.

The PR is reviewed for:

- Profile JSON validates against
  [`receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json).
- Per-case results reference real case IDs in [`../cases/`](../cases/).
- The `verifier` block, license, and exit-code contract are accurate.
- The `corpus_version` and `benchmark_manifest_sha256` identify the corpus the
  profile actually read. A `clean` `corpus_git_status` requires the recorded
  `corpus_git_sha`; every other status requires an empty SHA.
- `observed_tool_version` has a recorded status. An `observed` status requires
  a bounded non-empty value; every other status requires a null value.

The PR is not reviewed for whether the tool "passes" anything. There is
nothing to pass. The profile is the published evidence.

## Coverage scope

The reference runner discovers the 234 single-file cases under
[`../cases/`](../cases/) plus the 6 multi-file cases in
[`../cases/mcp-drift/`](../cases/mcp-drift/) (18 JSON fixture files total:
`before.json`, `after.json`, and `expected.json` per case). The optional
`--multifile-cases` flag only relocates that complete family. The runner
refuses an override whose IDs differ from the loader-backed corpus. It loads
each case directory, converts the before/after snapshot pair into a
four-message JSON-RPC sequence (two `tools/list` requests interleaved with
the two snapshots), and replays the sequence through a single MCP session
against the running tool. The verdict on the second response is what the
per-case row records.

## Files in this directory

- [`pipelock.json`](pipelock.json): historical Pipelock receipt-scoring
  evidence for version `3.1.0` on corpus `v2.0.0`. The file makes no current
  product claim. The pinned manifest records its 196 rows and 148 blocked
  malicious cases.
- [`retained-artifacts.json`](retained-artifacts.json): machine-readable
  identity and digest pins for historical profile evidence.
- [`EXAMPLE.json`](EXAMPLE.json): minimal template showing the four
  per-case combinations (blocked malicious, missed malicious, allowed
  benign, false-positive benign) plus a placeholder verifier block. Uses
  `tool: "example-tool"` and SHA fields filled with zeros so it cannot
  be mistaken for a real profile.
- [`../schemas/receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json):
  the JSON Schema for newly emitted profile files. Historical profiles retain
  their declared schema version.

## Reproducing a published profile

A relying party reproduces a profile by cloning the tool source, building or
installing the recorded tool version, running the matching corpus version with
the recorded tool-version command, and comparing the output with the committed
profile via `sha256sum`. A byte
mismatch is informative: the corpus, tool, or artifact changed. Publish a new
active measurement through the current Gauntlet result flow.

How far that goes depends on the provenance a given artifact actually carries,
and a version label is not a revision. `pipelock.json` is the retained
historical case: `retained-artifacts.json` pins its SHA-256, tool version, and
corpus version, but no corpus or runner source revision and no tool binary
digest. It is therefore **digest-verifiable but not byte-for-byte reproducible
from repository contents**, and its recorded digest is the check to run against
it. See the provenance limitation in
[`../docs/RUNNER.md`](../docs/RUNNER.md). Recording immutable corpus and runner
revisions plus a binary digest is what would make a retained profile
reproducible rather than only verifiable.
