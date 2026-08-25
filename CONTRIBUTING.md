# Contributing

Contributions welcome: new test cases, runners for your security tool, documentation, and spec improvements.

## Adding a case

1. Pick the right category directory under `cases/` (see [docs/SPEC.md](docs/SPEC.md) for the full list)
2. Follow the naming, field, and payload rules in [docs/SPEC.md](docs/SPEC.md)
3. Check immutability, provenance, and synthetic-fixture requirements in [docs/GOVERNANCE.md](docs/GOVERNANCE.md)
4. Run the required checks:

```bash
export TMPDIR="$HOME/.cache/pipelock-tmp"
export GOCACHE="$HOME/.cache/go-build"
mkdir -p "$TMPDIR" "$GOCACHE"
(cd validate && go build -o "$TMPDIR/aeb-validate" .)
"$TMPDIR/aeb-validate" cases cases
make cases-manifest
make stats-update
make preflight
```

### Do NOT change existing cases

Follow the immutability and supersession process in [docs/GOVERNANCE.md](docs/GOVERNANCE.md). If you disagree with an expected verdict, open an issue before changing corpus content.

### Fake secrets, and getting your push blocked

Cases carry intentionally fake credentials, so GitHub Push Protection will reject a push that looks like a real leak. It flags shapes such as `AKIA`, `ghp_`, `xoxb-`, and `sk-live_`.

- Use obviously synthetic values. The AWS documentation example key is written here as `"AKIA" + "IOSFODNN7EXAMPLE"` because this file is scanned too, and writing that key whole would fail the repository's own secret scan.
- Split a value at the pattern boundary when a push or a scan blocks it, exactly as the line above does.
- `SG.FAKE_TEST_KEY` works for SendGrid-shaped tokens.
- Never commit a real secret, including an expired one.

A blocked push means the scanner matched a shape, not that you leaked anything. Reshape the fixture rather than bypassing the check.

## Adding a runner

Start from the [runner template](examples/runner-template/) and follow [docs/ADOPTION.md](docs/ADOPTION.md). [docs/RUNNER.md](docs/RUNNER.md) owns the profile and output contracts.

## Validation

All case files must pass validation before merge:

```bash
export TMPDIR="$HOME/.cache/pipelock-tmp"
export GOCACHE="$HOME/.cache/go-build"
mkdir -p "$TMPDIR" "$GOCACHE"
(cd validate && go build -o "$TMPDIR/aeb-validate" .)
"$TMPDIR/aeb-validate" cases cases
```

CI runs this automatically on every pull request along with CodeQL security analysis and dependency review.

## Governance

This repo is maintained by the Pipelock author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparisons. Each publisher hosts its own evidence; a mechanically admitted pointer may be listed under `result-pointers/`. Listing is not approval.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md). Vendor adoption guide: [docs/ADOPTION.md](docs/ADOPTION.md).
