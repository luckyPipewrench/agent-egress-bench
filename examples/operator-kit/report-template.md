# Agent Egress Bench result

Replace every bracketed field. Delete instructional comments only after the report contains the underlying fact.

Choose assurance labels from [`docs/RESULTS-USE.md`](../../docs/RESULTS-USE.md) only when the saved evidence and execution arrangement satisfy their definitions. A completed checklist doesn't create a label by itself.

## Run identity

| Field | Value |
|---|---|
| Assurance label or labels | `[self-run / artifact-validated / independently executed / transparency-registered / challenge-verified]` |
| Operator or lab | `[name]` |
| Target product and version | `[product and version read from the target or pinned artifact]` |
| Target configuration | `[public path or retained-artifact path plus SHA-256]` |
| Benchmark repository and commit | `[repository URL and full commit]` |
| Corpus and scoring version | `[versions]` |
| Benchmark manifest SHA-256 | `[digest]` |
| Runner release, binary digest, or OCI image reference and image ID | `[identity and digest]` |
| Publisher verification | `[verified / waived, with doctor report path]` |
| Adapter identity, owner, and SHA-256 | `[adapter, author or organization, and digest]` |
| Tool profile and SHA-256 | `[path or URL plus digest]` |
| Capability registry | `[ID, format, revision, path or URL, and raw-byte digest]` |
| Execution window | `[start and end with timezone]` |
| Artifact packet | `[URL or request path]` |

## Measured outcomes

Report containment and false-positive rate separately. Don't publish a composite score.

| Outcome | Count or rate |
|---|---:|
| Malicious cases blocked with scoreable evidence | `[count]` |
| Malicious cases allowed with scoreable evidence | `[count]` |
| Benign cases allowed | `[count]` |
| Benign cases blocked | `[count]` |
| Full-corpus containment | `[rate and full malicious corpus denominator]` |
| Applicable-only containment diagnostic | `[rate and applicable malicious denominator]` |
| False-positive rate | `[rate and denominator]` |

## Result-state accounting

| State | Count | Explanation |
|---|---:|---|
| Applicable and measured | `[count]` | `[scope]` |
| Unreachable | `[count]` | `[adapter coverage gaps]` |
| Historical not-applicable | `[count]` | `[frozen-record reason]` |
| Error | `[count]` | `[errors]` |

State whether `measurement_status` is `measured` or `incomplete`. An incomplete run isn't a publishable full-corpus result. Keep it as diagnostic evidence and say why it's incomplete.

## Exercised-control coverage

List only transports, categories, and capability tags mapped from rows with `evidence.result_state=observed`. Publication checks this mapping against the pinned case index. A tool-profile declaration or framework mapping isn't evidence that the run exercised a control.

| Surface | Observed coverage |
|---|---|
| Transports | `[observed transports]` |
| Categories | `[observed categories]` |
| Capability tags | `[observed tags / not recorded]` |

## Method and reproduction

Exact command:

```text
[command]
```

Setup notes needed to repeat the run:

```text
[notes, including any vendor or maintainer guidance]
```

Validator command and result:

```text
[command and exit status]
```

## Evidence and custody

Link the completed `evidence-custody-checklist.md` and the digest inventory. Name any file that isn't public, why access is restricted, who holds it, and how a reviewer can request it.

## Limits and non-claims

This result covers the named target version, configuration, adapter, exercised profile, corpus, and scoring version. It doesn't establish certification, legal or regulatory compliance, insurance eligibility, security outside the exercised profile, or the absence of bypasses. <!-- claim-ok: required non-claims for a result report -->

Record any additional limitation discovered during the run:

```text
[limitations]
```

## Corrections and disputes

Case semantics and expected-verdict appeals: `[Issue URL or "none"]`

Scoring, method, adapter, or result dispute: `[Discussion URL or "none"]`

Correction history:

```text
None, or append dated corrections without replacing the original result.
```
