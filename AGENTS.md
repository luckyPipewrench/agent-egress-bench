# AGENTS.md: agent-egress-bench repository guide

agent-egress-bench is a public, tool-neutral corpus for testing AI agent egress security tools. Treat case IDs and merged case semantics as immutable. Never add real secrets or cross-tool rankings.

## Repository map

| Path | Purpose |
| --- | --- |
| `cases/` | Single-file cases and multi-file MCP drift fixtures |
| `validate/` | Stdlib-only Go validator |
| `runner/` | Gauntlet runner, adapters, loaders, scoring, and reports |
| `schemas/` | Public JSON Schema documents |
| `contracts/artifacts.json` | Machine-readable artifact compatibility inventory |
| `examples/` | Tool integration templates and reference runners |
| `control-evidence/` | Control Evidence protocols, fixtures, and verifiers |
| `gauntlet-site/` | Retained first-party result records and site data |
| `docs/` | Public contracts, governance, and adoption guidance |
| `scripts/` | CI, publication, and integrity checks |

## Contract owners

| Contract | Owner |
| --- | --- |
| Case and multi-file fixture format | [`docs/SPEC.md`](docs/SPEC.md) |
| Runner inputs and outputs | [`docs/RUNNER.md`](docs/RUNNER.md) |
| Result states, scoring, and methodology | [`docs/gauntlet.md`](docs/gauntlet.md) |
| Versioning, compatibility, neutrality, and immutability | [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) |
| Receipt-scoring profiles | [`docs/RECEIPT-SCORING.md`](docs/RECEIPT-SCORING.md) |
| Capability labels | [`docs/CAPABILITY-VOCABULARY.md`](docs/CAPABILITY-VOCABULARY.md) |
| Public result claims | [`docs/RESULTS-USE.md`](docs/RESULTS-USE.md) |

Do not copy field lists, enum values, version numbers, profile fields, or scoring rules into this file. Update the owner document and its executable gate.

## Exact commands

The repository root has no Go module. Set the shared caches before every Go command because `/tmp` is quota-constrained.

```bash
export TMPDIR="$HOME/.cache/pipelock-tmp"
export GOCACHE="$HOME/.cache/go-build"
mkdir -p "$TMPDIR" "$GOCACHE"

make check-contracts
make stats
make preflight
```

For a narrow validator change:

```bash
(cd validate && go test -race -count=1 ./...)
(cd validate && go build -o "$TMPDIR/aeb-validate" .)
"$TMPDIR/aeb-validate" cases cases
```

For a narrow runner change:

```bash
(cd runner && go test -race -count=1 ./...)
(cd runner && go build -o "$TMPDIR/aeb-gauntlet" .)
"$TMPDIR/aeb-gauntlet" --cases cases --profile examples/pipelock/tool-profile.json --output "$TMPDIR/summary.json"
```

After adding or removing a logical case:

```bash
make cases-manifest
make stats-update
make preflight
```

Use [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution steps. Run `make stats` before citing corpus counts. Run `make preflight` before proposing a public commit or pull request.
