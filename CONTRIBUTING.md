# Contributing

Contributions welcome: new test cases, runners for your security tool, documentation, and spec improvements.

## Adding a case

1. Pick the right category directory under `cases/` (see [docs/SPEC.md](docs/SPEC.md) for the full list)
2. Name your file `{category}-{subcategory}-{NNN}.json` where the filename (minus `.json`) matches the `id` field
3. Include all required fields from the [spec](docs/SPEC.md)
4. Run the validator:

```bash
cd validate && go build -o aeb-validate . && ./aeb-validate ../cases
```

### Requirements for new cases

- **Rationale:** Why this case matters (in `description`)
- **Expected verdict:** `block` or `allow` with reasoning (in `why_expected`)
- **Source:** Where the attack pattern or credential format comes from (in `source`)
- **False-positive assessment:** How likely this is to trigger on clean traffic (in `false_positive_risk`)
- **Benign cases:** If `expected_verdict` is `allow`, you MUST set `"safe_example": true`

### Case ID rules

- IDs are **immutable** once merged. Never rename.
- Format: `{category}-{subcategory}-{NNN}`
- Numbers are zero-padded to three digits

### Fake secrets only

All credentials in test cases must be obviously synthetic. Use patterns like:
- AWS: `AKIA` + `EXAMPLE000000000000`
- GitHub: `ghp_` + `ExampleToken0000000000000000000000`
- Generic: `sk-test-example-not-real-key`

Never use real secrets, even expired ones. GitHub Push Protection will flag some patterns; adjust the fake value if blocked.

### Do NOT change existing cases

Existing case semantics are stable. If you disagree with an expected verdict, open an issue. If the attack surface has changed, propose a new case instead.

## Adding a runner

Start from the [runner template](examples/runner-template/) for a working skeleton. Create a directory under `examples/{tool-name}/` with:

- A runner script or program
- A `tool-profile.json` declaring capabilities (see [tool profile schema](schemas/tool-profile.schema.json))
- A README explaining how to run it

Runner output must follow [docs/RUNNER.md](docs/RUNNER.md). You can validate your output with `validate results <file.jsonl>` and your profile with `validate profile <file.json>`.

## Validation

All case files must pass validation before merge:

```bash
cd validate && go build -o aeb-validate . && ./aeb-validate ../cases
```

CI runs this automatically on every pull request along with CodeQL security analysis and dependency review.

## Governance

This repo is maintained by the Pipelock author. Contributions from any vendor or individual are welcome. This repo does not produce rankings or cross-tool comparisons. Each tool can publish its own results independently.

Full governance policy: [docs/GOVERNANCE.md](docs/GOVERNANCE.md). Vendor adoption guide: [docs/ADOPTION.md](docs/ADOPTION.md).
