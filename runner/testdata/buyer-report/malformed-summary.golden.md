# Agent Egress Bench Run Report

This report renders facts retained by one Gauntlet run. It does not combine the four metrics or assign a grade, rank, or pass mark.

## Artifact input status

- raw-summary.json: Malformed JSON: unexpected EOF
- results.jsonl: Readable
- run-metadata.json: Readable
- run-bundle.json: Readable
- execution-decision.json: Readable

## Method identity

- Repository: example/agent-egress-bench
- Exact commit: cccccccccccccccccccccccccccccccccccccccc
- Corpus version: Absent from run artifacts
- Gauntlet version: Absent from run artifacts
- Scoring version: Absent from run artifacts
- Runner version: Absent from run artifacts
- Run date: Absent from run artifacts
- corpus_sha256: Absent from run artifacts

## Target identity

- Product: Absent from run artifacts
- Version: Absent from run artifacts
- Declared configuration: Absent from run artifacts
- Declared configuration digest: Absent from run artifacts

## Capability profile and adapter

- tool_profile_sha256: Absent from run artifacts
- Registry ID: Absent from run artifacts
- Registry format: Absent from run artifacts
- Registry revision: Absent from run artifacts
- Registry SHA-256: Absent from run artifacts
- Reporting labels:
  - Absent from run artifacts
- Exercised transports (this run):
  - Absent from run artifacts
- Exercised categories (this run):
  - Absent from run artifacts
- Exercised capability tags (this run):
  - Absent from run artifacts
- Adapter identity: Absent from run artifacts
- Adapter owner: Absent from run artifacts

## Scope

- Total cases: Absent from run artifacts
- Applicable cases: Absent from run artifacts
- Not-applicable cases: Absent from run artifacts
- Error cases: Absent from run artifacts
- Not-applicable case IDs and reasons:
  - Invalid: the summary does not carry a usable not-applicable count

## Metric vector

Each metric stands on its own. Full-corpus scores retain historical N/A rows as misses; unreachable rows are excluded and make the run insufficient. Applicable-only scores cover only cases this adapter delivered and observed.

### Full corpus

- Containment: Absent from run artifacts
- Detection: Absent from run artifacts
- Evidence: Absent from run artifacts
- False-positive rate: Absent from run artifacts

### Applicable cases

- Containment: Absent from run artifacts
- Detection: Absent from run artifacts
- Evidence: Absent from run artifacts
- False-positive rate: Absent from run artifacts

## Execution and bundle status

- Execution status: complete
- Execution blocked: false
- Execution publication eligibility: true
- Execution failures:
  - None declared
- Execution review notes:
  - None declared
- Run-bundle declared validation status: complete
- Run-bundle publication eligibility: true
- Run-bundle noncanonical reasons:
  - None declared
- Publication eligibility recorded by the run: Not established because retained validation checks are not valid
- Run-bundle digest and binding recheck: Invalid: capability\_registry has no report filename mapping; raw-summary.json is not readable JSON; receipt\_profile has no report filename mapping; summary case counts are absent or malformed; tool\_profile has no report filename mapping
- Execution-decision consistency: Self-consistent: run identifier and evidence digests match the bundle

These three lines are an internal consistency check. Every input to them, including the digests they compare against, comes from the supplied artifact directory, so they show the retained files agree with each other. They do not authenticate the bundle against anything outside it, and a directory edited as a whole would still reconcile. Independent assurance needs a signature over the bundle from a key the reader already trusts, which this corpus does not yet produce.

## Non-claims

This result does not establish:

- a formal conformance status, accreditation, or pass mark;
- legal or regulatory compliance;
- insurance eligibility or pricing;
- security outside the exercised capability profile;
- absence of evasions, including variants of classes exercised here.

## Reproduce the run

Run the retained entrypoint command from a checkout of the repository and exact commit listed above. The entrypoint records the runner command and material files used by this result.

Credential-shaped values in the commands below are replaced with REDACTED. Read them before publishing anyway: local paths and hostnames are preserved so the run can be reproduced, and no denylist recognizes every secret.

### Entrypoint command

    ./run-gauntlet.sh --output-dir ./artifacts

### Recorded runner command

    ./runner --adapter example --scan-token REDACTED --cases ./cases --profile ./profile.json

### Retained material

- capability\_registry (sha256 9c5461fc6eff394ea11c70dedfee328263ea7a811f270b6983d9301d3bf3c5d9)
- case-index.json (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- checksums.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- command.txt (sha256 d2068c6f30093a7d4621fde48d8e38054f881b7db06dbd45a4217de8981003fa)
- corpus-manifest.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- entrypoint-command.txt (sha256 6ed6633e53c72b755d52398b49031be5bf998feab21f904e02ebf9432ef05b9a)
- make-stats.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- pipelock-release.json (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- pipelock-version.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- raw-summary.json (sha256 a6fb08fda1acb957b6116bd37811a1fe41a01611c0631edbf786d6889a27a55c)
- receipt\_profile (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- results.jsonl (sha256 d1413b853523d00171fb500f4c0bb02973cd4aa2276c1eed650295f9eace651f)
- run-metadata.json (sha256 2ec73028d323d3cf0d2bd7b3e8eb598f515aa3e0f0053e46ef03a53916ac1bc4)
- runner.stderr (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- tool\_profile (sha256 5ff9c3781a107a41fb75d76e48e980fe265ffa2d0dec4cf55aa3c6c3b4509296)
