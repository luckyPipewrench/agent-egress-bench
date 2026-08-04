# Artifact provenance predicates

The opt-in G2 assessors currently evaluate two separately callable predicates:
`schema-valid` and `authenticated-at(T)`. They do not combine those results
into a tier, score, or producer-awarded badge. Each assessment artifact carries
one predicate and the identity of the verifier binary that evaluated it;
consumers compose the separate results by their shared evidence binding.

`schema-valid` is a package-format claim. `PASS` means the bounded directory
shape is safe, the manifest is closed and matches every committed member's
path, role, media type, length, and digest, the envelope binds that exact
manifest, schema-governed v0 documents satisfy their closed schemas, other
JSON members are strict JSON without duplicate keys or trailing data, and
every signed payload is RFC 8785 JCS. It does not verify any signature or
trusted signer and makes no claim about correctness, freshness, or complete
benchmark scope. Opaque policy, adapter, provenance, and attachment documents
have no v0 content schema; their bytes are manifest-bound and JSON-typed ones
must parse strictly, but `schema-valid` does not invent semantics for them.
Whether every artifact demanded by the buyer requirement is present belongs to
the separate `closed-scope-complete` predicate; format validity does not absorb
that completeness claim.

The schema assessor accepts directory packages only. It rejects fixture
`context.json` and `expect.json` sidecars as undeclared members unless the
explicit conformance-only option is selected. An unavailable package or
verifier-schema failure is `UNVERIFIABLE`; a presented malformed package is
`FAIL`.

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
the separate `schema-valid` predicate establishes package shape and governed
schemas. Do not present
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
