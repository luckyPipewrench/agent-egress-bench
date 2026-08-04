# Artifact provenance predicates

This opt-in G2 assessor evaluates one predicate only: `authenticated-at(T)`.
It reads a Control Evidence v0 directory package, an externally supplied signed
trust policy, an independently managed verifier trust context, and a durable
verifier-owned policy checkpoint. The trust context is the root of trust: the
buyer or verifier operator must deliver and protect it outside the producer's
control. A producer-supplied context can select its own bootstrap key and must
never be accepted as independent input. The CLI emits its result on standard
output; callers must retain that assessment outside the submitted package.

`PASS` means the requirement and run-envelope wrappers, plus every observer and
clock wrapper declared by the supplied manifest, are signed by keys authorized
for their exact roles and payload purposes at assessment time `T`. Authority is
assigned by the external trust-policy entry; where a v0 payload also declares
signer authority, the two must agree. V0 observer evidence does not declare an
authority, so this predicate does not infer observer independence or ownership.
This assessor intentionally does not validate the complete v0 package contract:
a separate `schema-valid` predicate must establish manifest fields, lengths,
media types, required roles, and closed membership. Do not present
`authenticated-at(T)` alone as proof of package validity or completeness. It
also does not claim freshness, anchoring, reproduction, counterparty
confirmation, or any tier or score.

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
