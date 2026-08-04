# Control-evidence verifier v0

This module is the independent, offline verifier for
`control-evidence-envelope/v0` directory packages. It verifies DSSE signatures
against separately supplied trusted keys, checks every manifest-bound byte, and
derives the result from the signed requirement, outcomes, observer evidence,
material commitments, freshness evidence, tool profile, and replay ledger.
The independent context pins the exact buyer requirement, trust policy, corpus,
and trusted role keys; a valid signature alone cannot select the accepted scope.
For conformance convenience, each fixture stores that context beside the package.
That layout is not a production trust model: an operator must obtain the context
through a buyer-controlled channel and must never accept a context supplied by
the package producer.

The verifier does not import the conformance generator and does not read
`expect.json`. The conformance test uses that file only as a test assertion.

## Run

```sh
cd control-evidence/v0/verifier
install -d -m 700 "$HOME/.cache/aeb-cee-replay-demo"
go run ./cmd/aeb-cee-verify \
  --package ../conformance/golden/g01-vendor-time \
  --context ../conformance/golden/g01-vendor-time/context.json \
  --replay-ledger "$HOME/.cache/aeb-cee-replay-demo"
```

The command above is a conformance example using public synthetic keys. Real
verification must point `--context` at the operator's independently managed
context, even if the evidence package also contains a file named `context.json`.
It must also point `--replay-ledger` at an existing buyer-controlled directory
with mode `0700`, outside the package. The verifier atomically records the
single-use challenge there. Omitting durable replay state returns
`unverifiable`, never `valid`.

The separately callable G2 format assessor needs no trust policy and does not
verify signatures:

```sh
go run ./cmd/aeb-ce-schema-valid \
  --package ../conformance/golden/g01-vendor-time \
  --allow-conformance-sidecars
```

The sidecar flag exists only for the public corpus layout. Omit it for submitted
packages so undeclared `context.json` or `expect.json` files fail closed. A
`schema-valid` PASS proves bounded package structure, closed manifest binding,
strict/schema-governed JSON, and JCS signed payload bytes. It does not prove
signature authentication, trusted ownership, freshness, result correctness,
or scope completeness; compose it with the corresponding independent G2
predicates instead of over-reading it.

The buyer-reproduction assessor compares a later buyer-signed statement with an
immutable source package and digest-binds a closed, normalized reproduction
transcript:

```sh
go run ./cmd/aeb-ce-buyer-reproduced \
  --package /srv/evidence/source-package \
  --statement /srv/evidence/reproduction/buyer-reproduction.dsse.json \
  --transcript /srv/evidence/reproduction/normalized-transcript.json
```

The statement and transcript must be regular files outside the source package.
A `buyer-reproduced` PASS means the same requirement-signing key attested a
distinct run with the exact source/input bindings and matching logical outcome
projection re-derived from that normalized transcript. It does not authorize
that key, prove the named binary/corpus ran, or prove the transcript was derived
from raw protocol I/O; compose it with separately bound authentication and
execution predicates.

Replay records are append-only in v0. Back up and restore the complete private
directory as one unit. If it is lost or damaged, issue a new buyer requirement
and nonce; do not replace it with an empty directory and continue trusting old
requirements. v0 deliberately has no pruning or force-accept operation.

The full `aeb-cee-verify` command emits one
`control-evidence-verification-result/v0` JSON object. The G2 assessors emit
versioned `control-evidence-assessment/*` objects documented by their public
schemas; `buyer-reproduced` uses v2 so the strict, published v1 contract remains
unchanged.
Exit status `0` means valid, `1` means a semantic non-valid result, and `2`
means invalid CLI usage or an internal encoding failure.

The v0 CLI accepts directory packages only. Archive ingestion is deliberately
outside this slice so archive extraction cannot add a second, less-reviewed
path and file-type trust boundary.

Directory verification is bounded to 258 files (256 manifest entries plus the
manifest and envelope), 512 total tree entries, eight path levels, 64 MiB per
file, 256 MiB of manifest-committed bytes, and one 64 MiB cap for each of the
manifest and envelope wrappers. Strict JSON parsing rejects
nesting deeper than 128 levels before schema validation.

This reference implementation accepts only the four `aeb-cee-conformance-*`
material profiles used by the public corpus. Those deterministic profiles are
test-only; production verifiers must reject them and define their own
buyer-controlled material profiles and lifecycle.

## Test

```sh
go test -race -count=1 ./...
```

The corpus test covers all 85 v0 packages and asserts the complete outcome,
reason, and nonce-status distribution. A schema-drift test pins the embedded
verifier schemas to the canonical repository copies.
