# Adopting agent-egress-bench

This guide is for vendors and developers who want to run the benchmark against their security tool, publish results, or contribute new cases.

## Build a runner

A runner connects your tool to the corpus. It feeds each case to your tool, observes the verdict, and emits structured JSONL.

**Start here:**

1. Copy the skeleton from [examples/runner-template/](../examples/runner-template/) into `examples/your-tool/`
2. Read the [Runner Template README](../examples/runner-template/README.md) for a step-by-step walkthrough
3. Read [docs/RUNNER.md](RUNNER.md) for the formal output contract

The skeleton gives you JSONL emission and the main loop. You fill in three
things: starting your tool, proving an exact delivery route, and feeding cases
to your tool while observing a verdict.

The [Pipelock reference runner](../examples/pipelock/) is a complete example. The fetch-only `harness.sh` beside it is a legacy illustration and is not a Gauntlet runner.

### What to claim

[`RUNNER.md`](RUNNER.md) owns the active tool-profile and delivery contracts.
[`SPEC.md`](SPEC.md) owns case shapes, with the exact combinations published in
[`contracts/case-shapes-v4.json`](../contracts/case-shapes-v4.json).
[`gauntlet.md`](gauntlet.md) owns result states and scoreability, with every
active combination published in
[`contracts/result-states-v5.json`](../contracts/result-states-v5.json).
[`CAPABILITY-VOCABULARY.md`](CAPABILITY-VOCABULARY.md) owns reporting-label
semantics.

## Publish results

Run your runner and save the JSONL output. How you share results is up to you. Some options:

- A page on your docs site with summary stats and the raw JSONL
- A separate GitHub repo with versioned results (tagged per tool version)
- A blog post walking through your results

**Do not submit Gauntlet results to this repo.** This repo contains attack cases, scoring methodology, and optional receipt profiles under `profiles/`. There is no in-repo results table and no maintainer-awarded mark. Each vendor publishes and owns its own results.

Label the run and publish every identifying fact required by [RESULTS-USE.md](RESULTS-USE.md).

### Suggested format

```
results/
  v0.3.6/
    results.jsonl       # Raw JSONL output
    summary.txt         # Summary line from stderr
    tool-profile.json   # Copy of your tool profile
    capability-registry.json # Exact raw registry snapshot named by the profile
    README.md           # Verdict mapping, notes, how to reproduce
```

Tag or date your results directories by tool version so readers can track progress over time.

## Contribute cases

If your tool catches attack patterns not in the corpus, add them. More cases make the benchmark more useful for everyone, including your competitors. That is the point.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full guide. The short version:

1. Create a JSON file in the right `cases/` subdirectory
2. Follow the [case schema](SPEC.md) (all required fields, fake secrets only)
3. Run `make validate` from the repository root
4. Open a PR

### What makes a good case

- A real attack pattern seen in the wild or described in security research
- A benign traffic pattern that naive scanners would flag (false-positive testing)
- A new encoding or evasion technique not covered by existing cases
- An MCP-specific attack (tool poisoning, chain exfiltration, rug-pull)

### What does not belong

- Cases that test implementation details (specific regex, internal data structures)
- Cases that only one tool can pass by design
- Cases with real secrets (even expired ones)
- Duplicate patterns with cosmetic differences

## Report issues

If you find a problem with an existing case, open an issue. Valid concerns:

- **Wrong expected verdict.** The case says `block` but the traffic is actually benign (or vice versa). Explain why.
- **Implementation-coupled.** The case tests a specific implementation detail rather than observable behavior. For example: testing whether the tool uses a specific regex, rather than whether it detects the secret.
- **Ambiguous payload.** The case could reasonably be blocked or allowed depending on interpretation.
- **Missing context.** The `description` or `why_expected` does not explain why this verdict is correct.

Do not open issues asking to change a case ID. IDs are immutable. Semantic changes go in new cases with new IDs.

## Questions

Open a GitHub issue or discussion. The project is maintained by the [Pipelock](https://github.com/luckyPipewrench/pipelock) author, but contributions from any vendor or individual are welcome.
