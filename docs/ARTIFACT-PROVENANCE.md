# Artifact provenance predicates

This opt-in G2 assessor evaluates one predicate only: `authenticated-at(T)`.
It reads a Control Evidence v0 directory package, an externally supplied signed
trust policy, an independent context, and a durable verifier-owned policy
checkpoint. The CLI emits its result on standard output; callers must retain
that assessment outside the submitted package.

`PASS` means every required DSSE wrapper is signed by a key authorized for its
exact role and payload purpose at assessment time `T`. Authority is assigned
by the external trust-policy entry; where a v0 payload also declares signer
authority, the two must agree. V0 observer evidence does not declare an
authority, so this predicate does not infer observer independence or ownership.
It does not claim
schema validity, freshness, completeness, independent observation, anchoring,
reproduction, counterparty confirmation, or any tier or score.

The package's `trust-policy-copy` role is never a trust source. Missing, stale,
or unavailable policy/checkpoint state is `UNVERIFIABLE`; cryptographic,
authorization, revocation, rollback, and same-epoch equivocation failures are
`FAIL`. Policy epochs are serialized per policy ID. If another assessor holds
the checkpoint lock, the result is `UNVERIFIABLE`; a stale lock must be
inspected and removed by the checkpoint owner rather than guessed around.

Non-pass assessments include only bindings established before the failure.
For example, an unreadable context cannot honestly contain an assessment time
or evidence digest. A `PASS` assessment always includes the time, exact
envelope-payload digest, policy ID/epoch/digest, checkpoint digest, and verifier
identity. It also binds the exact independent authentication-context digest and
the pinned bootstrap key ID.
