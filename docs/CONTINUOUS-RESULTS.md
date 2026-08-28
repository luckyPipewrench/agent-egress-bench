# Continuous results

This repository owns the corpus, runner, scoring contracts, and portable command. A completed run is evidence, not a public claim by itself. Each operator decides which results to publish and hosts its own evidence.

PipeLab publishes its first-party Pipelock history at [pipelab.org/gauntlet/results](https://pipelab.org/gauntlet/results/). Pipelock's scheduled candidate runs in [luckyPipewrench/pipelock](https://github.com/luckyPipewrench/pipelock). This repository doesn't schedule or publish those results.

The read-only `Continuous Gauntlet` workflow remains available as a manually dispatched example. It runs the portable Pipelock adapter and retains a candidate evidence bundle for 14 days. It has no permission to change repository contents or open a pull request.

## Archived Pipelock records

Before result ownership moved to the product and site repositories, this repository stored three reviewed Pipelock records under:

```text
gauntlet-site/results/pipelock/<candidate-sha256>/
```

Those records are a read-only restore copy. The repository doesn't accept new Pipelock records or advance `gauntlet-site/latest-verified.json`. The migration inventory binds every retained file to its byte count, SHA-256 digest, original commit, and PipeLab destination.

Each record manifest hash-links its predecessor, and the selected pointer binds the archived head. `make check-gauntlet-site` verifies the chain, reconstructs the recorded decisions from raw evidence, and compares the retained bytes with the migration inventory. The readers remain because old public evidence must stay verifiable. They don't create a current score or a publication path.

The reference renderer under `gauntlet-site/` reads the archived records and fails closed when required evidence is missing, malformed, or digest-mismatched. It isn't the published page on pipelab.org.

## Independent operators

The portable command isn't tied to GitHub Actions:

```bash
./scripts/run-pipelock-gauntlet.sh
```

An independent lab can repeat that reference run with its own scheduler and retain the same portable bundle. Matching the Pipelock release, corpus commit and digest, runner version, fixtures, and applicable scope lets readers reconcile two runs without pretending they share an operator.

An operator calling its program continuous declares the publication selection rule before execution, keeps each completed scored result in scope, and shows the run date beside every displayed score. Superseding records link to retained predecessors. An error, incomplete measurement, or unknown state stays visibly unsuccessful instead of leaving an older result looking current. The publication lockup described in [RESULTS-USE.md](RESULTS-USE.md) keeps the reproduction facts beside the score without transferring ownership of the method or the operator's brand.
