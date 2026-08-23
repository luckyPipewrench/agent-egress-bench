# Agent Egress Bench Run Report

This report renders facts retained by one Gauntlet run. It does not combine the four metrics or assign a grade, rank, or pass mark.

## Artifact input status

- raw-summary.json: Readable
- results.jsonl: Readable
- run-metadata.json: Readable
- run-bundle.json: Readable
- execution-decision.json: Readable

## Method identity

- Repository: example/agent-egress-bench
- Exact commit: cccccccccccccccccccccccccccccccccccccccc
- Corpus version: v2.3.0
- Gauntlet version: 1.0
- Scoring version: 2.4
- Runner version: 0.4.2
- Run date: Absent from run artifacts
- corpus_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

## Target identity

- Product: example-tool
- Version: 1.2.3
- Declared configuration: /etc/example/target.yaml
- Declared configuration digest: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

## Capability profile and adapter

- tool_profile_sha256: 5ff9c3781a107a41fb75d76e48e980fe265ffa2d0dec4cf55aa3c6c3b4509296
- Registry ID: aeb.core-capabilities
- Registry format: 1
- Registry revision: 1
- Registry SHA-256: 9c5461fc6eff394ea11c70dedfee328263ea7a811f270b6983d9301d3bf3c5d9
- Reporting labels:
  - ssrf
  - url\_dlp
- Exercised transports (this run):
  - Absent from run artifacts
- Exercised categories (this run):
  - Absent from run artifacts
- Exercised capability tags (this run):
  - None declared
- Adapter identity: example
- Adapter owner: Example Lab

## Scope

- Total cases: 2
- Routed cases: 2
- Not-applicable cases: 0
- Error cases: 0
- Not-applicable case IDs and reasons:
  - None recorded

## Metric vector

Each metric stands on its own. Full-corpus scores retain historical N/A rows as misses; error and unreachable rows are excluded and make the measurement incomplete. Applicable-only scores cover only the routed cases this adapter delivered AND observed, so error rows are counted as routed but are excluded from every score denominator.

### Full corpus

- Containment: 75.00%
- Detection: 50.00%
- Evidence: 25.00%
- False-positive rate: 10.00%

### Applicable-only observed cases

- Containment: 80.00%
- Detection: 60.00%
- Evidence: 40.00%
- False-positive rate: 0.00%

### Applicable-only malicious category profile

This profile is evidence of category coverage and concentration, not a score or ranking. It uses observed malicious rows only. Containment gives every observed malicious case equal influence, and the share column shows how corpus composition sets the category weighting. Do not compare this profile with full-corpus containment when their scopes differ.

Unavailable: requires a v5 summary and bound active evidence.

### Applicable-only benign category profile

This profile is evidence of category coverage and concentration, not a score or ranking. It uses observed benign rows only. False-positive rate gives every observed benign case equal influence, and the share column shows how corpus composition sets the category weighting. Do not compare this profile with full-corpus false-positive rate when their scopes differ.

Unavailable: requires a v5 summary and bound active evidence.

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
- Publication eligibility recorded by the run: Recorded eligible by both retained decisions
- Run-bundle digest and binding recheck: Self-consistent: 15 retained evidence digests match the bundle
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

- capability-registry.json (sha256 9c5461fc6eff394ea11c70dedfee328263ea7a811f270b6983d9301d3bf3c5d9)
- case-index.json (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- checksums.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- command.txt (sha256 d2068c6f30093a7d4621fde48d8e38054f881b7db06dbd45a4217de8981003fa)
- corpus-manifest.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- entrypoint-command.txt (sha256 6ed6633e53c72b755d52398b49031be5bf998feab21f904e02ebf9432ef05b9a)
- make-stats.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- pipelock-release.json (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- pipelock-version.txt (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- raw-summary.json (sha256 781e0a631463e382b52048729130018277e49e6119ba1329be14f19f68bf8d83)
- receipt-profile.json (sha256 e6dd449c31e34ec84ded60b75b507e5acb1fe2a1c7493afad341362ddfe75cb9)
- results.jsonl (sha256 2c3de64ce408ca1cba1345ed5634e2261967bc92fa8b04256a977b0b3816ab57)
- run-metadata.json (sha256 2ec73028d323d3cf0d2bd7b3e8eb598f515aa3e0f0053e46ef03a53916ac1bc4)
- runner.stderr (sha256 9bdaff9d24e8e222099c05ad4495d5828e9f455b31759ebb0e6dcd96d881b460)
- tool-profile.json (sha256 5ff9c3781a107a41fb75d76e48e980fe265ffa2d0dec4cf55aa3c6c3b4509296)
