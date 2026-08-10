# Control-Evidence Envelope Conformance Corpus (v0)

This is a small, vendor-neutral fixture corpus for offline implementations of
the Control-Evidence Envelope v0 verifier. It is intentionally a corpus, not a
reference verifier: each package says which outcome a correct verifier must
emit under the fixture's pinned requirement and trust policy.

Every fixture is a portable package directory containing a signed buyer
requirement, a byte-preserved live Gauntlet summary, a closed outcomes ledger, a
content manifest, and a signed run envelope. `expect.json` supplies the
expected outcome and reason. The deterministic generator signs with distinct
public, test-only Ed25519 identities committed under `_generator/`.

Each fixture also has `context.json`. It is independently supplied verifier
input, not package content and not manifest-bound: it pins the buyer, runner,
observer, and clock keys; the exact buyer-approved requirement, trust policy,
and corpus identities; the reference time; exact synthetic buyer token and
health-control inputs; and any durable nonce-ledger state needed to exercise
replay behavior.

## Layout

```text
golden/     complete packages a verifier must accept
edge/       valid boundaries and replay/live-summary projection behavior
malicious/  intact-looking or tampered packages a verifier must not accept
```

The frozen policy clock is `2026-08-02T12:00:00Z`; future-skew is 60 seconds.
These fixtures use only synthetic tokens and example identities.

## Material profiles

The corpus uses exact, test-only material profiles documented in
`docs/CONTROL-EVIDENCE.md`: `aeb-cee-conformance-token-derived/v1` and
`aeb-cee-conformance-health-derived/v1` for independently derived inputs, and
`aeb-cee-conformance-token-aesgcm/v1` and
`aeb-cee-conformance-health-aesgcm/v1` for packaged material. Context supplies
the signed descriptor plus an independent root input or AES key, never a
producer-selected ID-to-input mapping. The deterministic AES nonce construction
is fixture-only and prohibited in production.
Every context rejects duplicate JSON keys and validates against
`schemas/control-evidence-context-v0.schema.json`. The harness accepts only those
four exact material profiles; unsupported profiles are `unverifiable`, with no
fallback. After AES authentication, decrypted bytes must already be exact RFC
8785 JCS and must validate against the corresponding closed material schema.

## Expected outcomes

`valid`, `invalid`, `stale`, `scope-mismatch`, `insufficient-evidence`, and
`unverifiable` use the v0 envelope outcome vocabulary. Re-verifying the same
retained envelope is still `valid`; its `expect.json` records
`nonce_status: reverified_same_envelope`.

Canary commitments are SHA-256 of length-delimited UTF-8 fields in this order:
`aeb-cee-v0/canary`, requirement digest, run ID, case ID, trial index, canary
ID, transport, target identity, polarity, and the independently supplied
synthetic buyer token input. Health controls use the separately documented
`aeb-cee-v0/health-control` domain and independent pre/post control inputs;
they do not reuse the blocked token as an allow observation. All observer
references are SHA-256 digests of the exact signed DSSE wrapper bytes.

## Reproduce

```bash
cd control-evidence/v0/conformance/_generator
go run . --verify
```

`--verify` regenerates every expected byte in memory, re-derives every DSSE
signature and manifest digest, and reports missing, changed, or unexpected
fixture files. `--write` updates the committed corpus. The generator is not a
verifier and deliberately does not decide conformance outcomes from fixture
contents.

Do not use this test key or any fixture token outside conformance testing.
