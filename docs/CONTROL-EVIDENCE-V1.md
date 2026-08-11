# Control Evidence Envelope v1

Control Evidence Envelope v1 carries active schema v4 Gauntlet evidence. It is a separate verifier at `control-evidence/v1/verifier`. The v0 verifier and its fixtures remain frozen historical readers.

Each v1 package binds the same capability-registry reference in its signed requirement, run envelope, outcomes ledger, runner summary, tool profile, and receipt-scoring profile. The manifest retains the raw registry snapshot as a `capability-registry` member. The verifier hashes those raw bytes, resolves the exact ID, format, revision, and SHA-256 reference, then validates every reported claim and exercised tag against that snapshot.

Any missing snapshot, unknown label, duplicate label, unsupported format, digest mismatch, or reference disagreement makes the package uninterpretable. The verifier does not substitute a newer registry or recalculate a result.

Registry snapshots are append-only. A new or deprecated reporting label creates a new registry revision, not a new profile schema. Historical v0 packages contain no registry snapshot bytes and cannot be normalized into v1 provenance.

See [Capability Vocabulary and Profile Evolution](CAPABILITY-VOCABULARY.md) for the active policy and [Control Evidence Envelope v0](CONTROL-EVIDENCE.md) for the frozen v0 contract.

## Canonical package schemas

The v1 directory-package contract is defined by these retained schemas:

| Artifact | Canonical schema |
|---|---|
| DSSE wrapper | `schemas/control-evidence-dsse-v1.schema.json` |
| Buyer requirement | `schemas/control-evidence-requirement-v1.schema.json` |
| Run envelope | `schemas/control-evidence-run-envelope-v1.schema.json` |
| Package manifest | `schemas/control-evidence-manifest-v1.schema.json` |
| Outcomes ledger | `schemas/control-evidence-outcomes-v1.schema.json` |
| Completion clock evidence | `schemas/control-evidence-clock-evidence-v1.schema.json` |
| Observer evidence | `schemas/control-evidence-observer-evidence-v1.schema.json` |
| Decrypted token material | `schemas/control-evidence-token-material-v1.schema.json` |
| Decrypted health-control material | `schemas/control-evidence-health-control-material-v1.schema.json` |
| Independent verification context | `schemas/control-evidence-context-v1.schema.json` |
| Buyer reproduction DSSE wrapper | `schemas/control-evidence-buyer-reproduction-statement-v1.schema.json` |
| Buyer reproduction payload | `schemas/control-evidence-buyer-reproduction-v1.schema.json` |
| Normalized reproduction transcript | `schemas/control-evidence-buyer-reproduction-transcript-v1.schema.json` |

`scripts/check_schema_copies.py` requires the v1 verifier's complete embedded
schema inventory to match the canonical files byte for byte.

## Executable conformance corpus

Payload-bearing directory packages live under `control-evidence/v1/conformance`.
The independent context and expected result files live outside each package so
the production package loader can reject every undeclared member. The corpus
test drives the public verifier API and checks all six verifier outcomes plus
fresh and repeated-envelope replay states. The deterministic generator verifies
every committed package, context, and expectation byte during preflight.

The current corpus establishes outcome coverage, not exhaustive branch
coverage. Authentication failures, cross-envelope replay, clock attestation,
encrypted material, liveness evidence, and non-applicable/error-row families
remain explicit expansion targets.
