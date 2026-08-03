# Control Evidence Envelope v0

Control Evidence Envelope v0 is a portable, offline-verifiable package that binds a buyer's
pre-run requirement to one benchmark run. It is a run-level commitment, not a product certificate,
an action-receipt replacement, or a claim that every route was mediated.

The initial profile is deliberately narrow: `mcp-stdio-gateway` with the `mcp_stdio` transport.
That names a deployment shape, not a product. A conforming runner may use any tool-neutral adapter
that implements the pinned observer protocol and content identities.

## Package

A directory or archive contains these fixed files:

| Role | Required path | Purpose |
| --- | --- | --- |
| `requirement` | `requirement.dsse.json` | Buyer-signed pre-run requirement |
| `summary` | `summary.json` | Preserved runner summary bytes |
| `outcomes` | `outcomes.json` | Strict per-case, per-trial ledger |
| `envelope` | `envelope.dsse.json` | Authorized run commitment; signs the manifest digest |
| `manifest` | `manifest.json` | Digest, media type, and byte-length mapping for every other artifact |

Optional closed roles include clock evidence, observer evidence, buyer-readable token material, a
trust-policy copy, and content-addressed attachments. The package must not include production traffic,
credentials, environment values, or secrets.

`manifest.json` does not list itself or `envelope.dsse.json`. The envelope binds the manifest digest;
including the envelope in the manifest would create a circular hash. Fixed filenames and strict package
membership identify those two framing files, while the signed manifest covers every other artifact.

`requirement.dsse.json`, `envelope.dsse.json`, and any clock or observer evidence artifact use the
DSSE wrapper schema. Their payload is standard RFC 4648 base64-decoded JSON signed with the
corresponding payload type; it is not the outer wrapper bytes. Clock-evidence and observer-evidence
wrappers decode to their corresponding schemas below. The manifest covers every observer-evidence
wrapper, while an outcomes row references that wrapper by SHA-256; observer payloads do not include
the outcomes digest, avoiding a circular hash.

The verifier maps each fixed DSSE artifact path to one exact payload type and rejects a valid
signature under the wrong type: `requirement.dsse.json` uses
`application/vnd.agent-egress-bench.control-evidence-requirement.v0+json`, `envelope.dsse.json` uses
`application/vnd.agent-egress-bench.control-evidence-envelope.v0+json`, a `clock-evidence` manifest
member uses `application/vnd.agent-egress-bench.control-evidence-clock-evidence.v0+json`, and an
`observer-evidence` member uses
`application/vnd.agent-egress-bench.control-evidence-observer-evidence.v0+json`.

## Schemas

All v0 schemas are JSON Schema draft 2020-12 and reject unknown fields.

Signed payload bytes are RFC 8785 JCS bytes. V0 schemas use closed ASCII property names and bounded
safe integers, so non-BMP property-name ordering and unsafe JSON numbers are outside valid instances.
String escaping remains RFC 8785 behavior, including literal `<`, `>`, and `&` where RFC 8785 permits
them; a producer or verifier must not use Go HTML escaping when forming or checking signed bytes.

| File | Decoded content |
| --- | --- |
| `schemas/control-evidence-dsse.schema.json` | DSSE wrapper shape |
| `schemas/control-evidence-requirement.schema.json` | Buyer requirement payload |
| `schemas/control-evidence-run-envelope.schema.json` | Run commitment payload |
| `schemas/control-evidence-manifest.schema.json` | Closed package manifest |
| `schemas/control-evidence-outcomes.schema.json` | Per-case/trial/canary ledger |
| `schemas/control-evidence-clock-evidence.schema.json` | Non-vendor completion-clock record |
| `schemas/control-evidence-observer-evidence.schema.json` | Observer-signed health or liveness record |
| `schemas/control-evidence-token-material.schema.json` | Decrypted closed canary-ID/input mapping |
| `schemas/control-evidence-health-control-material.schema.json` | Decrypted closed control-ID/input mapping |
| `schemas/control-evidence-context.schema.json` | Independent conformance trust, material, clock, and replay input |

The requirement pins its challenge nonce, required cases and canaries, observer identity/key,
allowed signer roles, runner/adapter/tool identities, error limit, freshness policy, and independent
trust-policy digest. It separately pins the exact approved run-policy bytes by SHA-256; that enforcement
policy is not the verifier's independent trust policy. In v0 it requires one exact transport (`mcp_stdio`) and one exact deployment
archetype (`mcp-stdio-gateway`). It also pins the approved live tool profile by exact SHA-256.

Required positive and negative canary ID sets must be disjoint; a canary ID cannot be selected under both polarities.

The run envelope binds that requirement digest and nonce to the runner, corpus, tool, policy,
adapter, scope, manifest, outcome ledger, times, and signer. A `result_claim` is diagnostic only;
the verifier derives the authoritative result.

## Observation semantics

Each outcome row represents one `(case_id, trial_index)`. It contains strict scoring facts and
one or more canary observations. A positive canary is proven only by its `observation_ref`: an
observer-signed `target-observation` DSSE wrapper joining the exact case, trial, canary ID, token, target,
and observed time. A negative canary is useful only when the target did not observe the expected block
action *and* the observer was continuously demonstrated healthy across its observation window.

For a negative canary that did not report observer unavailability, the ledger carries either
bracketing signed health controls or a signed, ordered liveness record. Each reference is the SHA-256
of the complete DSSE wrapper artifact, not merely its decoded JSON; that artifact is an
`observer-evidence` manifest member. The verifier checks the observer signature/key pin, decoded
payload type, requirement/run/target/transport binding, and either temporal bracketing or ordered
liveness coverage with no gap above the pinned limit. Liveness coverage is derived from the first and
last entries after the verifier confirms strictly increasing sequences and timestamps; no separate
claimed coverage window is trusted. An unavailable observer is explicit,
may omit those unavailable evidence references structurally, and cannot be silently treated as a
successful block: it remains insufficient evidence.

The token commitment is `SHA-256` over a concatenation of length-prefixed UTF-8 fields. For each
field, append its byte length as an unsigned four-byte big-endian integer, then its UTF-8 bytes. The
fields, in order, are: `aeb-cee-v0/canary`, lowercase hexadecimal requirement digest, run ID, case ID,
decimal trial index without leading zeroes, canary ID, transport, target identity, polarity, and the independent
buyer token input. The buyer token input must be valid UTF-8 and is retained or deterministically
derived under the signed requirement; a redacted display string is not the input. This formula binds a
canary ID to its requirement, run, case, trial, transport, target, and polarity. Schema validation alone
does not recompute or verify the commitment.

For `packaged-encrypted` token material, the signed requirement pins the token-material manifest
entry's SHA-256 of its stored encrypted member bytes as `artifact_sha256`; the verifier requires that
entry and digest to match, then the buyer independently decrypts and recomputes the commitment. For
`buyer-derived` material, no package artifact digest is allowed: the buyer uses the pinned profile and
input identifier to derive the input.

### Token material resolution

In `buyer-derived` mode, the signed token-material profile defines a versioned deterministic
derivation from verifier-held independent secret/input and exactly `(profile, key_or_input_id,
canary_id)`. Requirement, run, case, and trial enter the later token commitment formula, not this base
input derivation. In `packaged-encrypted` mode, `artifact_sha256` pins the stored encrypted bytes of
exactly one `token-material` manifest member; after profile-defined decryption with independently
supplied verifier material, its UTF-8 JSON bytes must validate against
`schemas/control-evidence-token-material.schema.json`. The decoded mapping must match the signed
profile/ID and contain exactly the required canary IDs once each. Context must match the signed
mode/profile/ID and provides only the buyer's independent handle or decryption material, never a token
mapping. The verifier rejects duplicate JSON object keys, then requires the decrypted plaintext bytes
to equal the RFC 8785 JCS encoding of the parsed value before schema validation. Missing, duplicate,
or extra canary IDs fail closed.

A health control retains the negative canary subject tuple but uses its own `control_id` and
`health_control_commitment_sha256`; it must not reuse the blocked canary token as an allow observation. Its
commitment is recomputed with the same length-prefix encoding over `aeb-cee-v0/health-control`, the
requirement digest, run ID, subject case ID, decimal subject trial, subject canary ID, lowercase subject
token commitment, control ID, transport, target identity, and an independently buyer-pinned control-token
input. Including the subject token commitment binds the control proof to that exact negative token.
Control IDs resolve their inputs only under the signed `health_control_material` profile and
`key_or_input_id`; fixture context cannot invent a producer-chosen trust source. In packaged-encrypted
mode the signed material also pins a `health-control-material` manifest artifact digest of its stored
encrypted bytes.

### Health-control material resolution

Every control ID referenced by a health-control record must resolve before verification. In
`buyer-derived` mode, the signed profile defines a versioned deterministic derivation from verifier-held
independent secret/input and the exact tuple `(profile, key_or_input_id, control_id)`; context supplies
only a handle to that independently managed input, and its mode/profile/ID must equal the signed values.
In `packaged-encrypted` mode, the signed `artifact_sha256` identifies exactly one
`health-control-material` manifest member. After decryption with material independently supplied to the
verifier, its UTF-8 JSON bytes must validate against
`schemas/control-evidence-health-control-material.schema.json` and match the signed profile and ID.
The closed `controls[]` mapping provides `control_id -> input` bytes; context cannot supply or override
that mapping. The verifier rejects duplicate JSON object keys, then requires the decrypted plaintext
bytes to equal the RFC 8785 JCS encoding of the parsed value before schema validation. It rejects
missing, duplicate, or extra control IDs rather than selecting a subset.

The buyer controls the independent input lifecycle: create it before issuing a requirement, rotate by
issuing a new signed profile/ID and requirement, revoke an ID in its verifier trust/input store, recover
only through the buyer's approved key recovery process, and inspect the resolved ID/profile before
accepting a run. None of those lifecycle actions are inferred from producer-provided package content.

## Canonical outcomes projection

`summary.json` is retained as exact runner output and may use legacy JSON formatting. It is not
treated as canonical JSON. The verifier derives the normative projection from `outcomes.json` and
compares only the mapped summary facts below.

| Projection field | Ledger source | Rule |
| --- | --- | --- |
| selected case set | `rows[].case_id` | Exact set equals the signed requirement |
| trials per case | `rows[].trial_index` | Exactly one for live-summary comparison in v0 |
| pass/fail/N/A/error totals | `rows[].outcome` | Count after validating each row |
| expected/actual verdict totals | `rows[].expected_verdict`, `rows[].actual_verdict` | Count after validating each row |
| score numerator/denominator | validated rows and `scoring_facts` | Integer arithmetic only |
| canary totals | `rows[].canaries[]` | Count by required ID, polarity, and state |

`summary.json` is the exact live runner GauntletSummary, not a control-evidence score object. Its mapped
identity fields are `gauntlet_version`, `scoring_version`, `runner_version`, `tool`, `tool_version`,
and corpus identity. Its mapped integer facts are `case_count`, not-applicable reasons, errors,
applicable counts by category, and the inputs to `sufficient`. `tool_support` must match the signed
scope and support profile. The floating values under `scores.full` and `scores.applicable` are retained
as diagnostic runner output but are not authoritative verifier inputs.

Exactly one manifest member has role `tool-profile`. Its exact bytes must hash to the signed
`approved_tool_profile.sha256`, must validate against `schemas/tool-profile.schema.json`, and must also
equal the live summary's `tool_profile_sha256`. Applicability, `tool_support`, and sufficiency inputs are
derived from that buyer-approved artifact, never from the summary alone. A missing member is
`insufficient-evidence`; a digest or decoded tool/runner identity mismatch is `scope-mismatch`.

The authoritative projection derives integer numerators and denominators from outcomes using scoring
v2.2: containment is `actual=block` among expected-block rows; false-positive rate is `actual=block`
among expected-allow rows; detection is classification-present among blocked malicious rows; evidence
is structured-evidence-present among blocked malicious rows. `full` denominators include every corpus
case in the corresponding dimension; `applicable` denominators include only rows applicable under the
pinned support profile. V0 permits exactly one trial per case when comparing to a live summary: repeated
trials are valuable evidence but cannot be faithfully represented by the runner's one-result-per-case
summary, so they require a later versioned aggregate contract.

V0 also permits only `runner.execution_mode: approved-binary`, bound to the buyer-approved runner
digest. Compatibility or provenance-based runner modes require a later versioned contract that defines
and requires the exact manifest-bound proof; a producer declaration alone is never sufficient.

A `not_applicable` row is valid only when the signed requirement's `allowed_not_applicable` contains
the exact case ID and exact reason. It contributes to `case_count.not_applicable` and the matching
`not_applicable_reasons` bucket, never to `case_count.applicable`. An unauthorized case or mismatched
reason is `scope-mismatch`; inconsistent N/A row fields or summary counts are `invalid`.

Error rows remain runner-applicable, but the truthful derived error count must be less than or equal to the signed requirement's `maximum_errors`; exceeding that cap is invalid with reason `maximum_errors_exceeded`, independently of diagnostic summary `sufficient`.

Runner JSON floating-point score fields are diagnostic and non-authoritative. Normalized control-evidence
`scoring_facts` do not reconstruct the runner's raw `CaseResult.Evidence` helper predicates, and the
verifier never compares the summary floats to those facts. The verifier compares
only mapped identity facts and derived integer counts; it does not use host floating-point equality.
Any mismatch in a mapped count or identity fact fails validation. Opaque summary metadata and free-form
evidence are ignored for projection.

## What schema validation does not prove

Schemas validate bounded field shape. The offline verifier must additionally fail closed on:

- DSSE PAE/Ed25519 verification, key-ID policy, duplicate JSON keys, and JCS byte equality.
- Independent buyer requirement and trust-policy inputs; package copies cannot establish their own trust.
- Artifact digests and lengths; safe archive extraction, role/path uniqueness, and total resource caps.
- Ordered timestamps, expiry, future skew, freshness basis, and nonce replay using durable verifier state.
- Signer and clock-attestor authorization/separation, including distinct witness and runner identities.
- Exact membership of cases, trials, canaries, transports, observer target, token commitments, and
  negative-canary health/liveness windows.
- Approved runner binary, adapter, corpus, policy, and tool identity.
- Derivation of all normative totals and scores from the ledger rather than signer-declared aggregates.

The top-level verifier results are mutually exclusive: `valid`, `invalid`, `stale`,
`scope-mismatch`, `insufficient-evidence`, and `unverifiable`. It must not convert a missing
required control to not-applicable.

Each test fixture's `context.json` is an independent verifier input, not package content and not a
manifest role. A durable verifier may annotate a valid re-verification of the same retained package as
`previously-accepted`; that nonce status is an annotation, while the top-level outcome remains `valid`.
The verifier rejects duplicate object keys and validates the complete context against
`schemas/control-evidence-context.schema.json` before using any value. Context pins the exact decoded
buyer-requirement payload digest, trust-policy ID and digest, and corpus version, corpus digest,
manifest digest, and scoring version. A trusted key alone is insufficient: a vendor cannot select a
different permissive requirement previously signed by the same buyer or self-declare a substitute
corpus under an otherwise authorized run signature. The fixture-local context files use public
synthetic keys for conformance only. In a real verification flow, the buyer or operator must deliver
and manage context through an independent trusted channel; accepting producer-supplied context would
let the producer choose the keys and every approved digest and would collapse the trust boundary.

## Replay ledger

A durable verifier namespaces its replay ledger by the exact tuple `(requirement signer key ID,
requirement_id, challenge_nonce)`. Its value is the SHA-256 of the exact decoded canonical run-envelope
payload bytes, never the outer DSSE wrapper bytes. On first verification of a tuple the verifier records
that digest. The same tuple with the same digest is a valid re-verification annotated
`nonce_status: reverified_same_envelope`; the top-level result remains `valid`. The same tuple with a
different digest is `invalid` and annotated `nonce_status: different_envelope_replay`. Different tuples
are isolated and are evaluated as first verification, subject to all other checks.
Replay-ledger namespace tuple keys must be unique; duplicate entries, including conflicting duplicate digests, are invalid and must not be resolved by first- or last-entry selection.

## Conformance-only material profiles

The following profiles make corpus fixtures interoperable and are not production guidance.
`aeb-cee-conformance-token-derived/v1` and `aeb-cee-conformance-health-derived/v1` return lowercase
hex SHA-256 over four-byte-big-endian-length-prefixed UTF-8 fields. The fields are, in order, the
domain label (`aeb-cee-conformance-token-input/v1` or
`aeb-cee-conformance-health-input/v1`), profile, signed material ID, element ID, and independent
context input. AES profiles are `aeb-cee-conformance-token-aesgcm/v1` and
`aeb-cee-conformance-health-aesgcm/v1`. They use standard Go AES-256-GCM with a 32-byte context key
decoded from standard base64, plaintext equal to RFC8785 JCS bytes of the corresponding closed mapping,
and stored bytes `nonce(12) || ciphertext_and_tag`. Nonce is the first 12 bytes of SHA-256 over the
length-prefixed UTF-8 fields `aeb-cee-conformance-nonce/v1`, signed requirement ID, signed material
profile, signed material ID, and manifest role. AAD is the length-prefixed UTF-8 profile plus signed
material ID. The conformance harness accepts only these four named profiles. An unsupported profile is
`unverifiable`; there is no fallback parser or derivation. Production verifiers must reject every
`aeb-cee-conformance-*` profile. These profiles and deterministic nonce derivation are test-only.
`artifact_sha256` hashes exact stored bytes.

## Non-claims

A valid package proves only that the verifier accepted the declared requirement, package bytes,
and evidence under its supplied trust policy. It does not prove complete mediation, no bypass,
policy correctness, product safety, operator honesty, key safety, continuous protection after the
run, or independent observation unless the buyer separately required and verified those properties.
Bracketing health controls must be distinct signed wrapper artifacts. The verifier requires the
preceding control time to be at or before `window_start`, the following control time at or after
`window_end`, and each control within the buyer-pinned maximum control interval of its adjacent window
boundary. Identical preceding/following wrappers are invalid.
