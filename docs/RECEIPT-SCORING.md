# Receipt-Scoring Axis (v1)

> **Status:** v1 design. Complementary to `docs/SCORING.md`. Where SCORING.md
> tracks whether a tool produced the expected verdict on a network case, this
> file tracks whether the tool produced **signed, independently-verifiable
> evidence** of that verdict. Both axes are per-tool profiles. Neither
> axis is a ranking.

## Why a receipt axis

A tool that blocks an attack but produces no evidence is operationally
indistinguishable from a tool that logged the attack without blocking. For
a procurement reviewer or auditor, the question that matters is:

> Did the tool both stop the attack and emit a signed artifact a third
> party can verify offline without trusting the vendor?

The verdict axis in SCORING.md answers half. This axis answers the other.

## The five dimensions

Each case in the corpus, when run against a tool, produces five values
on the receipt axis:

| Dimension | Values | What it means |
|-----------|--------|---------------|
| `blocked` | `yes` / `no` / `n/a` | Did the tool prevent the action? `n/a` when the case is allow-expected (benign baseline). |
| `explained` | `yes` / `no` | Did the tool produce a human-readable reason (layer, pattern, severity, or natural language) tied to this specific action? Boolean only; quality of explanation is not graded. |
| `receipt_produced` | `yes` / `no` | Did the tool emit a structured record of this action that includes verdict, target, principal, and a verifiable signature? |
| `receipt_independently_verifiable` | `yes` / `partial` / `no` | Can a third party verify the receipt offline against a pinned public key with an open-source verifier? `partial` covers internal-consistency-only (hash chain valid but no signer attestation). `no` covers anything that requires trusting the vendor's dashboard or proprietary verifier. |
| `false_positive` | `yes` / `no` / `n/a` | Did the tool block a benign baseline case? `n/a` on malicious cases. |

The five dimensions are independent. A tool can score `blocked=yes` and
`receipt_produced=no`. A tool can score `receipt_produced=yes` and
`receipt_independently_verifiable=no` if the receipt format only verifies
inside the vendor's own stack.

## Profile format

A tool publishes its profile as a JSON file in the
`profiles/` directory:

```json
{
  "tool": "example-tool",
  "version": "1.2.3",
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
    "receipt_produced_yes_count": 0,
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
      "false_positive": "n/a"
    }
  ]
}
```

A profile is published by the tool's maintainer, not by this corpus.
The corpus does not certify or audit profiles. A relying party reads
profiles directly.

## What this corpus provides

- The case set (`cases/`) the profiles score against.
- The receipt conformance corpus (`receipts/v0/conformance/`) any
  receipt the tool emits must pass before `receipt_independently_verifiable=yes`
  can honestly be claimed.
- This rubric document.
- A `profiles/` directory where tool maintainers contribute their own
  profile artifacts.

## What this corpus does not provide

- A cross-tool ranking, percentage, or letter grade. Per `docs/SCORING.md`:
  "Each tool can publish its own results. Cross-tool comparison tables
  are not part of this repo."
- A certification mark. A profile is published evidence, not a seal.
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
5. At least one independently-authored verifier (different organization,
   different repo) reaches the same accept/reject decision on the same
   inputs.

`partial` is allowed for receipts that pass internal consistency checks
(hash chain valid, schema valid) but where no signer key is pinned
because the tool does not publish one. This is the
`self_consistent_only` posture in Pipelock's verifier verdict enum.

`no` is the default for any receipt that cannot be verified without
trusting the vendor's dashboard.

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

A tool maintainer publishes their profile by submitting a pull request
to this repo adding `profiles/<tool>.json` and (optionally) a `notes.md`
sibling describing reproduction steps. The PR is reviewed for:

- Profile JSON validates against the published schema (forthcoming
  `profiles/profile.schema.json`).
- Per-case results reference real case IDs in `cases/`.
- The verifier URL, license, and exit-code contract are accurate.

The PR is not reviewed for whether the tool "passes" anything. There
is nothing to pass. The profile is the published evidence.

## Reference profile: Pipelock

A Pipelock profile lives at `profiles/pipelock.json` and serves as the
reference shape. Pipelock claims `yes` on all five dimensions for the
receipt-bearing cases and references the public Audit Packet v0 schema
plus the four reference verifiers in Go, TypeScript, Rust, and Python.
The profile is reproducible: a third party clones this repo, runs the
Pipelock runner over `cases/`, and computes the same per-case values.

If any other tool publishes a profile with `receipt_independently_verifiable=yes`
that does not match all five criteria above, the profile is wrong and
the relying party should reject it. The corpus does not enforce this;
relying parties do.

## What this rubric is for

It is for a buyer or auditor who wants to ask a tool vendor a sharper
question than "does it work." The sharper question is:

> Can you prove what your tool did, with evidence I can verify offline?

The rubric exists so that question has a structured answer instead of a
marketing claim.

## Next steps

- `profiles/profile.schema.json`: JSON Schema for profile validation.
- `profiles/pipelock.json`: reference profile generated from a Pipelock
  runner pass over `cases/`.
- `profiles/EXAMPLE.json`: a template profile showing the shape with
  fake values.
- Integration with `runner/main.go` so it can emit a draft profile
  artifact alongside the standard SCORING summary.

## Version

This is v1 of the receipt-scoring rubric. Breaking changes to dimensions,
values, or the profile format will land in `RECEIPT-SCORING.md` v2
alongside a migration note in this file.
