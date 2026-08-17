# Evidence custody checklist

Complete this file while operating the run. Keep it beside the raw artifacts.

## Run identity

- Run ID:
- Operator or lab:
- Execution host custodian:
- Artifact custodian:
- Start time, timezone, and clock source:
- End time, timezone, and clock source:
- Benchmark repository:
- Benchmark commit:
- Corpus version and manifest SHA-256:
- Target product and version:
- Target artifact or image digest:
- Runner release, binary digest, or OCI image reference and image ID:
- Target configuration path and SHA-256:
- Adapter identity, owner, and SHA-256:
- Tool profile path and SHA-256:
- Capability-registry path, revision, and SHA-256:
- Exact command:
- Publisher verification status (`verified` or `waived`) and retained doctor report:
- Transparency start commitment, publication time, third-party log operator, and entry URL (`not claimed` if unused):
- Challenge holdout selection and retirement rule (`not claimed` if unused):

## Before execution

- [ ] The benchmark source matches the recorded commit.
- [ ] The target version came from the running target or its exact pinned artifact, not from a hand-entered label alone.
- [ ] The target configuration, adapter, profile, registry snapshot, and command are saved before execution.
- [ ] The operator recorded any setup help supplied by the target vendor or benchmark maintainer.
- [ ] The run directory is new or empty, so stale output can't stand in for this run.
- [ ] The operator recorded who can write to the execution host and artifact directory during the run.

## During execution

- [ ] The operator recorded the start and end clocks.
- [ ] Standard output, standard error, the raw summary, result rows, execution decision, and run bundle were captured without manual rewriting.
- [ ] Any retry, interruption, configuration change, or manual intervention is listed below with its time and reason.
- [ ] The operator stopped publication if the runner or validator reported an error, unreachable row, incomplete measurement, digest mismatch, or failed contract check.

Interventions and deviations:

```text
None, or list each event here.
```

## Retained files

Record each file's relative path and SHA-256. Every run packet keeps the result rows, runner summary, exact command, tool profile, capability-registry snapshot, target configuration evidence, generated report, and all run-status metadata produced by the selected path. The OCI path keeps `results.jsonl`, `summary.json`, `raw-summary.json`, `run-metadata.json`, and `doctor.json`; `run-metadata.json` records `measurement_status`, exit codes, publisher verification, and the runner image. The Pipelock path also keeps `runner.stderr` and `command.txt`. Keep `case-index.json`, `receipt-profile.json`, `execution-decision.json`, and `run-bundle.json` when the selected run path produces them.

```text
SHA256  RELATIVE_PATH
```

- [ ] Digests were computed from the retained bytes before report editing.
- [ ] The raw directory is read-only or stored in a location where later changes are visible.
- [ ] Analysis and redaction use copies, leaving the retained raw bytes unchanged.
- [ ] Every omitted or access-controlled file is listed below with its digest, custodian, reason, and request path.

Omitted or access-controlled evidence:

```text
None, or list each item here.
```

## Transfer and publication

- [ ] The report links to the raw packet or states how a reviewer can request restricted evidence.
- [ ] The published digest list matches the retained files.
- [ ] The reproduction command names the exact benchmark commit, target version, adapter, profile, and configuration.
- [ ] Outcome scores and exercised-control coverage appear as separate sections.
- [ ] The report names unreachable, historical not-applicable, and error counts instead of hiding them in one denominator.
- [ ] The report carries the non-claims required by `docs/RESULTS-USE.md`.
- [ ] Each declared assurance label names the retained evidence that satisfies every part of its definition in `docs/RESULTS-USE.md`.

Transferred by:

Received by:

Transfer time and method:

Recipient verification result:
