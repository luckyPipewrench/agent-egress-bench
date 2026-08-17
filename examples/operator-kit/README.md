# Operator kit

This directory is the run packet for a lab, vendor, or customer operating Agent Egress Bench. It doesn't replace the runner contract. It keeps the setup record, saved evidence, report, and correction path together so another person can tell what ran and repeat it.

## Start a run packet

Create a directory for the run and copy these files into it:

```bash
set -e
packet_dir="aeb-run-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir "$packet_dir"
cp examples/operator-kit/evidence-custody-checklist.md "$packet_dir/"
cp examples/operator-kit/report-template.md "$packet_dir/report.md"
cp examples/runner-template/tool-profile-template.json "$packet_dir/tool-profile.json"
cp examples/runner-template/skeleton.sh "$packet_dir/adapter.sh"
```

The copied adapter and profile are starting points. Replace every placeholder before treating the run as a measurement. The [runner template](../runner-template/README.md) explains the adapter and profile fields. The formal behavior contract lives in [`docs/RUNNER.md`](../../docs/RUNNER.md).

## Before execution

Fill in the first section of `evidence-custody-checklist.md`. Record the exact benchmark commit, target version, target configuration digest, adapter owner, profile digest, command, host clock source, and who controls the run directory. The commands below use `aeb-run`; substitute the timestamped packet directory you just created.

Run the bundled doctor before execution when using the OCI path:

```bash
./scripts/run-oci-action.sh \
  --profile aeb-run/tool-profile.json \
  --adapter dryrun \
  --image registry.vendor.example/aeb-runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --allow-unverified-image \
  --doctor-json > aeb-run/doctor.json
```

Replace `dryrun` with the adapter that reaches the target and replace the example image with the reviewed digest-pinned image you loaded. This example explicitly waives official publisher verification; `doctor.json` records that check as `waived`, not `ok`. For an official image, omit `--allow-unverified-image` and supply the release's image metadata, attestation, and trusted root as described in [OCI runner](../../docs/OCI-RUNNER.md). A doctor success means every prerequisite passed or was explicitly waived. It doesn't prove that the later run reached the target or produced a complete measurement.

## After execution

Keep the raw artifacts before editing a report. Record a SHA-256 digest for each retained file, make the raw directory read-only, and perform analysis on a copy. The checklist names the minimum files and explains how to record an intentional omission.

Render the buyer report from the retained artifact directory:

```bash
./aeb-gauntlet --report aeb-run/artifacts --report-output aeb-run/generated-report.md
```

Use `report-template.md` for the publication page around that generated output. It keeps measured outcomes separate from exercised-control coverage, which prevents a reporting label from reading like proof that a control operated.

## Publish or transfer

Publish the raw artifacts, their digests, the completed checklist, the report, and the reproduction command together. If access controls prevent publishing a raw file, name the omitted file, its digest, its custodian, and how a reviewer can request it. Don't replace a missing artifact with a summary written after the run.

Follow [`docs/RESULTS-USE.md`](../../docs/RESULTS-USE.md) for assurance labels and non-claims. A saved packet may be artifact-validated without being independently executed. Independent execution requires a separate operator to control the execution host and retain the artifacts.

The completed checklist records what the operator declares happened. It doesn't prove the declaration or create an assurance label by itself. The retained bytes, digests, validator result, and execution arrangement determine which statements the publisher can support.

## Corrections and appeals

Use the public route that matches the disagreement:

- Open an Issue for a case's expected verdict, payload meaning, or other case semantics. Case IDs stay immutable, so a semantic change becomes a new case.
- Open a Discussion for scoring, method application, adapter behavior, or a published result that appears to misstate the method.

Include the exact benchmark commit, case IDs when applicable, the report URL, and the relevant artifacts or digests. The original result stays available. A correction adds a visible record; it doesn't silently replace the run.
