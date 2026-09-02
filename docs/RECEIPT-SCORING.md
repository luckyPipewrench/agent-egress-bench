# Receipt-Scoring Axis (v1)

> **Status:** v1 design. Complementary to [`docs/gauntlet.md`](gauntlet.md). Where the Gauntlet method
> tracks whether a tool produced the expected verdict on a benchmark case, this
> file tracks whether the tool produced **signed, independently-verifiable
> evidence** of that verdict. Both axes are per-tool profiles. Neither
> axis is a ranking.

## Why a receipt axis

A tool that blocks an attack but produces no durable evidence is hard to
distinguish later from a tool that only logged the attack. For a procurement
reviewer or auditor, the question that matters is:

> Did the tool both stop the attack and emit a signed artifact a third
> party can verify offline without trusting the vendor?

The verdict axis in [`gauntlet.md`](gauntlet.md) answers half. This axis answers the other.

## The five dimensions

Each case in the corpus, when run against a tool, produces five values
on the receipt axis:

| Dimension | Values | What it means |
|-----------|--------|---------------|
| `blocked` | `yes` / `no` / `n/a` | Did the tool prevent the action? `n/a` when the case is allow-expected (benign baseline) or the runner could not measure a verdict. |
| `explained` | `yes` / `no` | Did the tool produce a human-readable reason (layer, pattern, severity, or natural language) tied to this specific action? Boolean only; quality of explanation is not graded. |
| `receipt_produced` | `yes` / `no` | Did the tool emit a structured record of this action that includes verdict, target, principal, and a verifiable signature? |
| `receipt_independently_verifiable` | `yes` / `partial` / `no` | Can a third party verify the receipt offline against a pinned public key with an open-source verifier? `partial` covers internal-consistency-only (hash chain valid but no signer attestation). `no` covers anything that requires trusting the vendor's dashboard or proprietary verifier. |
| `false_positive` | `yes` / `no` / `n/a` | Did the tool block a benign baseline case? `n/a` on malicious cases or when the runner could not measure a verdict. |

The five dimensions are independent. A tool can score `blocked=yes` and
`receipt_produced=no`. A tool can score `receipt_produced=yes` and
`receipt_independently_verifiable=no` if the receipt format only verifies
inside the vendor's own stack.

A runner-layer error is not a tool outcome. Its per-case row remains visible,
but records both `blocked` and `false_positive` as `n/a` and contributes to no
outcome summary count. The raw Gauntlet result carries the error state.

## Receipt-profile format

A tool can publish a receipt profile as a JSON file in the `profiles/`
directory. The shape is defined by
[`schemas/receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json)
(`$id`:
`https://github.com/luckyPipewrench/agent-egress-bench/schemas/receipt-scoring-profile-v5.schema.json`).
This is separate from the runner capability profile described in
[`docs/RUNNER.md`](RUNNER.md) and
[`schemas/tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json).

```json
{
  "schema_version": 5,
  "tool": "example-tool",
  "tool_version": "1.2.3",
  "observed_tool_version": {
    "status": "observed",
    "value": "example-tool 1.2.4"
  },
  "corpus_version": "v2.1.0",
  "corpus_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "benchmark_manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "corpus_git_sha": "0000000000000000000000000000000000000000",
  "corpus_git_status": "clean",
  "tool_profile_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "capability_registry": {
    "id": "aeb.core-capabilities",
    "format": 1,
    "revision": 3,
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "verifier": {
    "shipped": true,
    "open_source": true,
    "verifier_url": "https://github.com/example/example-verifier",
    "license": "Apache-2.0",
    "exit_code_contract": "0 valid, 1 invalid, 2 error, 64 usage"
  },
  "summary": {
    "blocked_yes_count": 18,
    "blocked_no_count": 4,
    "explained_yes_count": 22,
    "receipt_produced_yes_count": 1,
    "receipt_independently_verifiable_yes_count": 0,
    "false_positive_yes_count": 1
  },
  "per_case": [
    {
      "case_id": "mcp-drift-rugpull-desc-002",
      "blocked": "yes",
      "explained": "yes",
      "receipt_produced": "no",
      "receipt_independently_verifiable": "no",
      "receipt_observation_reason": "no matching receipt found",
      "false_positive": "n/a"
    },
    {
      "case_id": "url-dlp-token-001",
      "blocked": "yes",
      "explained": "yes",
      "receipt_produced": "yes",
      "receipt_independently_verifiable": "partial",
      "receipt_observation_reason": "verifier reported internal consistency only",
      "false_positive": "n/a"
    }
  ]
}
```

The two tool-version fields intentionally have different sources. `tool_version`
is the declared label from `tool-profile.json`; it remains for compatibility.
`observed_tool_version` is stdout from the tool-version argv the runner ran. An
unavailable observation records a status such as `not_requested`,
`command_failed`, or `timed_out` and a null value. The runner never fills it
from the declared label.

`corpus_sha256` remains the legacy content digest. It does not bind file
boundaries or membership. `benchmark_manifest_sha256` is the exact corpus
identity for a run because it binds the loaded paths, boundaries, and bytes.
`corpus_git_sha` is an additional source-checkout reference only when
`corpus_git_status=clean`. A dirty checkout, a non-Git source, several source
directories, an unavailable Git query, or a change during snapshot capture
uses an empty SHA and names the state rather than guessing a revision.

`receipt_independently_verifiable` takes `yes`, `partial`, or `no`. Only `yes`
increments `receipt_independently_verifiable_yes_count`; a `partial` row is
counted in `receipt_produced_yes_count` but not in the verifiable count, so a
profile with partial rows shows a verifiable count lower than its produced
count. The schema also requires `receipt_produced=yes` on any row claiming
`partial` or `yes`, because a receipt that does not exist cannot be verified.

A receipt profile is published by the tool's maintainer, not by this
corpus. The corpus does not certify or audit profiles. <!-- claim-ok: states the non-claim --> A relying party
reads profiles directly and reproduces them before trusting them.

## Runner observation contract

The runner only marks `receipt_produced=yes` or
`receipt_independently_verifiable=yes` from observed evidence. Tool profiles can
declare an optional `receipt_evidence` block in
[`schemas/tool-profile-v4.schema.json`](../schemas/tool-profile-v4.schema.json):

```json
{
  "receipt_evidence": {
    "evidence_dir": "/var/tmp/tool-receipts",
    "file_glob": "evidence-*.jsonl",
    "jsonl_record_type": "action_receipt",
    "detail_json_pointer": "/detail",
    "detail_encoding": "object_or_json_string",
    "record_case_id_json_pointer": "",
    "record_identifier_json_pointer": "/action_record/target",
    "case_identifier_json_pointer": "/payload/url",
    "verify_command": ["tool-verify-receipt", "{evidence_file}", "--key", "/var/tmp/tool.pub"],
    "verify_timeout_seconds": 10,
    "valid_exit_codes": [0],
    "partial_exit_codes": []
  }
}
```

If the block is omitted, the runner preserves the v1 behavior:
`receipt_produced=no` and `receipt_independently_verifiable=no` for every row.
Relative `evidence_dir` values are resolved relative to the tool-profile file.
`verify_command` is argv, not a shell string; the runner expands environment
variables and replaces `{evidence_file}` with the evidence file being checked.

A profile that references environment variables in `verify_command` is declaring
a setup contract, and the runner cannot enforce it: an unset variable expands to
an empty string, so the verifier is invoked with an empty argument and every row
scores `receipt_independently_verifiable=no` without any configuration error
being reported. A profile that uses environment variables should name them, and
whatever launches the tool should export them. The committed Pipelock profile
uses two, both exported by
[`examples/pipelock/start-proxy-for-benchmark.sh`](../examples/pipelock/start-proxy-for-benchmark.sh):

| Variable | Meaning |
|---|---|
| `PIPELOCK_BIN` | path to the `pipelock` binary that runs `verify-receipt` |
| `AEB_RECEIPT_PUBKEY` | path to the receipt-signing public key the verifier pins against |

Prefer absolute paths in a profile where the launcher is not guaranteed.

The runner treats the declared verifier as authoritative. It does not
reimplement signature, chain, timestamp, or key verification. A valid exit code
from the declared command yields `receipt_independently_verifiable=yes`; a
declared partial exit code yields `partial`; any other exit code, missing
binary, timeout, or unreadable evidence yields `no` with
`receipt_observation_reason` on the affected row.

## Receipt correlation

Correlation is deliberately conservative because exact URL matching fails when a
tool redacts credential values in receipts. The runner uses this order:

1. If `record_case_id_json_pointer` is declared and exactly one record carries
   the case ID, that record is the match.
2. Otherwise the runner extracts the case identifier from
   `case_identifier_json_pointer` and the receipt identifier from
   `record_identifier_json_pointer`.
3. Non-URL identifiers must match exactly.
4. URL identifiers match when scheme, host, path, and query keys agree. Query
   values may differ only when either side is visibly redacted, such as
   `[redacted-value]`.

If no record matches, the row is `receipt_produced=no`. If multiple records
match, the row is also `receipt_produced=no` with an ambiguous-correlation
reason. The runner does not fall back to sequence or ordering guesses; tools
that need stronger correlation should emit the benchmark case ID or another
stable per-action identifier in the receipt and declare the corresponding JSON
Pointer.

## What this corpus provides

- The case set (`cases/`) the profiles score against.
- The receipt conformance corpus (`receipts/v0/conformance/`) for tools
  that emit the bench's v0 receipt format.
- This rubric document.
- A `profiles/` directory where tool maintainers contribute their own
  profile artifacts.

## What this corpus does not provide

- A cross-tool ranking, percentage, or letter grade. Per [`docs/gauntlet.md`](gauntlet.md):
  "Each tool can publish its own results. Cross-tool comparison tables
  are not part of this repo."
- A certification mark. A profile is published evidence, not a seal. <!-- claim-ok: states the non-claim -->
- A judgment of how much weight a buyer should give each dimension. A
  buyer evaluating a tool against a regulated workload weights
  `receipt_independently_verifiable` differently than a buyer doing
  developer-workstation hardening.

## How a tool earns each value

### `blocked`

The tool prevented the action from completing. For network egress tools,
that means a 4xx/5xx response to the client request, an MCP-protocol
error to the agent, or a sandbox-level refusal. The case definition's
`expected_verdict` determines whether `blocked=yes` is the expected
score.

### `explained`

The tool produced a machine-readable or human-readable explanation tied
to this action. Examples of `yes`: a `block_reason` field in the response,
a structured log entry with layer / pattern / severity, a Slack alert
naming the case. Examples of `no`: silent block, generic "request denied"
with no detail.

The dimension is boolean. A one-word `block_reason: "dlp"` earns `yes`
the same way a paragraph of natural-language explanation does. Quality
of explanation is out of scope.

### `receipt_produced`

The tool emitted a structured record of this action with at minimum:

- Action type, target, and verdict.
- Principal or actor identifier.
- A cryptographic signature (Ed25519 or equivalent).
- Either a chain reference or a timestamp that lets a verifier replay
  the record's position in a sequence.

A traditional access log entry does not earn `yes`. A Splunk-ingested
JSON event without a signature does not earn `yes`.

### `receipt_independently_verifiable`

The strongest dimension. A `yes` requires:

1. The verifier code is open source under a recognized OSI license.
2. The verifier runs offline. No network call to the vendor's API is
   required to produce accept/reject.
3. The verifier accepts a pinned public key as a CLI flag or config
   parameter.
4. The verifier's receipts conform to a published schema with a
   public conformance corpus.
5. Reproduction steps are public enough that a relying party can run the
   verifier over the published receipts and reach the same accept/reject
   decision.

`partial` is allowed for receipts that pass internal consistency checks
(hash chain valid, schema valid) but where no signer key is pinned
because the tool does not publish one.

`no` is the default for any receipt that cannot be verified without
trusting the vendor's dashboard.

Tools that emit the bench's v0 receipt format should also pass the
fixtures in `receipts/v0/conformance/` before claiming
`receipt_independently_verifiable=yes` for those receipts. Tools that
emit a different format need their own public schema and conformance
corpus; the claim is still allowed, but the evidence must be reproducible
without vendor-side services.

### `false_positive`

The tool blocked a case the case definition marks as
`expected_verdict: allow`. False positives on benign baselines are
operationally expensive even when the malicious-case detection rate is
high.

## How a relying party reads a profile

1. Open the tool's `profiles/<tool>.json`.
2. Decide which dimensions matter for the workload. A regulated workload
   prioritizes `receipt_independently_verifiable`. A developer-workstation
   workload may prioritize `blocked` + `false_positive`.
3. Run the corpus locally against the tool to reproduce the profile.
   Do not trust the profile without reproducing.
4. Compare profiles across tools. The corpus deliberately does not
   produce an aggregate score; the buyer is the one who weights the
   dimensions.

## Publishing a profile

A tool maintainer publishes their receipt profile by submitting a pull request
to this repo adding `profiles/<tool>.json` and (optionally) a `notes.md`
sibling describing reproduction steps. The PR is reviewed for:

- Profile JSON validates against the published receipt-profile schema
  once that schema exists under `schemas/`.
- Per-case results reference real case IDs in `cases/`.
- The verifier URL, license, and exit-code contract are accurate.

The PR is not reviewed for whether the tool "passes" anything. There
is nothing to pass. The profile is the published evidence.

## Reference and examples

This repo may include example receipt profiles so maintainers can copy
the shape, but examples are not privileged. A reference runner in
`examples/` does not give that tool a special scoring position.

If a tool publishes a profile with `receipt_independently_verifiable=yes`
that does not match the criteria above, the relying party should reject
that specific claim. The corpus does not enforce this; relying parties do.

## What this rubric is for

It is for a buyer or auditor who wants to ask a tool vendor a sharper
question than "does it work." The sharper question is:

> Can you prove what your tool did, with evidence I can verify offline?

The rubric exists so that question has a structured answer instead of a
marketing claim.

## Reference artifacts in this repo

- [`schemas/receipt-scoring-profile-v5.schema.json`](../schemas/receipt-scoring-profile-v5.schema.json):
  JSON Schema for receipt-scoring profile validation.
- [`profiles/EXAMPLE.json`](../profiles/EXAMPLE.json): minimal template
  profile showing the four per-case combinations plus a placeholder
  verifier block. Uses `tool: "example-tool"` and zeros for the SHA
  fields so it cannot be mistaken for a real profile.
- [`profiles/pipelock.json`](../profiles/pipelock.json): a retained
  historical profile from a reproducible runner pass against Pipelock
  3.1.0 on corpus v2.0.0. It is evidence of that run, not a current
  result, and `profiles/retained-artifacts.json` pins its identity.
- Runner integration: `runner/main.go` accepts
  `--emit-receipt-profile <path>`, `--receipt-verifier-file <path>`, and
  `--tool-version-command <json-argv>`
  to emit a profile alongside the standard Gauntlet summary. Output is
  reproducible against the retained inputs and observations. Byte-for-byte
  equality also requires the corpus Git state and tool-version command output
  to match. See [`docs/RUNNER.md`](RUNNER.md).

## Version

This is v1 of the receipt-scoring rubric. Profile schemas version their
provenance fields independently; v5 adds attribution without changing a
receipt-scoring dimension or value. A breaking change to dimensions or values
will land in `RECEIPT-SCORING.md` v2 alongside a migration note in this file.
