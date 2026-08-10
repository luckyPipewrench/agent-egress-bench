# Contributing

Contributions welcome: new test cases, runners for your security tool, documentation, and spec improvements.

## Adding a case

1. Pick the right category directory under `cases/` (see [docs/SPEC.md](docs/SPEC.md) for the full list)
2. Follow the naming, field, and payload rules in [docs/SPEC.md](docs/SPEC.md)
3. Check immutability, provenance, and synthetic-fixture requirements in [docs/GOVERNANCE.md](docs/GOVERNANCE.md)
4. Run the validator:

```bash
cd validate && go build -o aeb-validate . && ./aeb-validate ../cases
```

### Do NOT change existing cases

Follow the immutability and supersession process in [docs/GOVERNANCE.md](docs/GOVERNANCE.md). If you disagree with an expected verdict, open an issue before changing corpus content.

## Adding a runner

Start from the [runner template](examples/runner-template/) and follow [docs/ADOPTION.md](docs/ADOPTION.md). [docs/RUNNER.md](docs/RUNNER.md) owns the profile and output contracts.

## Validation

All case files must pass validation before merge:

```bash
cd validate && go build -o aeb-validate . && ./aeb-validate ../cases
```

CI runs this automatically on every pull request along with CodeQL security analysis and dependency review.

## Governance

This repo is maintained by the Pipelock author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparisons. Each tool can publish its own results independently.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md). Vendor adoption guide: [docs/ADOPTION.md](docs/ADOPTION.md).
