# Published schema audit

This audit covers every versioned JSON Schema in the public catalog. The catalog currently contains 53 canonical contracts and 36 verifier copies. `make check-schema-copies` requires each verifier copy to remain byte-identical to its canonical schema, so the canonical row also covers every copied path.

`make check-contracts` scans all published copies. Known object shapes must set `additionalProperties: false`. Typed maps remain open only over constrained values. Every other open object needs an exact schema ID and JSON Pointer entry in `scripts/check_schema_closure.py`, with a reason and a non-stale gate.

The weakest-instance column describes the least informative structurally valid record, not a sample producers should emit. Cross-field arithmetic, digest-to-file equality, chronology, signature checks, and archive containment are enforced by the named semantic verifier because standard JSON Schema can't compare two instance values or inspect a file.

| Canonical schema | Closed or guarded openness | Weakest accepted meaning and remaining verifier | Version decision |
| --- | --- | --- | --- |
| `case-index-v1.schema.json` | Closed root; array items closed | Empty and duplicate-bearing indexes are structurally valid | Frozen v1 unchanged; v2 replaces it |
| `case-index-v2.schema.json` | Closed root; typed case-ID map | At least one uniquely keyed case with category and expected verdict | New v2 because tightening v1 would reject saved artifacts |
| `case-index-v3.schema.json` | Closed root and case rows | V2 fields plus the canonical transport and capability tags needed to reconstruct exercised-control coverage | New v3 because adding required evidence labels to v2 would reject saved artifacts |
| `case-v4.schema.json` | Closed except `payload` | A complete identified case with bounded ID syntax and unique capability and requirement sets; payload varies by `input_type` and the Go validator checks the selected shape | In-place amendment; every published case retains the same meaning |
| `multi-file-case-v4.schema.json` | Closed, including the file inventory | A complete temporal case with three normalized relative JSON filenames; absolute and parent paths fail | Unchanged |
| `result-v4.schema.json` | Closed except frozen adapter evidence | A complete historical scored row; evidence is a frozen extension point | Frozen v4 unchanged |
| `result-v5.schema.json` | Closed except adapter evidence with required `result_state` | A complete identified scored or explicit unmeasured row; the validator binds state, verdict, and score | In-place amendment; retained v5 rows keep the same result |
| `summary-v4.schema.json` | Open frozen root | The historical required summary fields can carry unknown siblings | Frozen v4 unchanged |
| `summary-v5.schema.json` | Closed; category and reason names are typed maps; publication provenance is optional for local runs | A non-empty counted run with bounded rates, diagnostics, registry binding, and explicit measurement status | Active v5 unchanged; the publication candidate owns the stricter promotion rule |
| `provenance-candidate-v1.schema.json` | Closed root; three nested historical objects are open | Empty count, score, and metric objects are structurally valid | Frozen v1 unchanged; v5 replaces it |
| `provenance-candidate-v2.schema.json` | Closed root; historical measurement objects are open | Empty count, score, and metric objects are structurally valid | Frozen v2 unchanged; v5 replaces it |
| `provenance-candidate-v4.schema.json` | Closed root; legacy measurement, registry, and exercised objects are open | The schema alone permits weak nested records; the promotion evaluator performs the legacy semantic checks | Supported reader version unchanged; active writers use v6 |
| `provenance-candidate-v5.schema.json` | Closed at every known object; reason names are a typed map | At least one case, complete counts, complete scores and diagnostics, registry binding, exercised surfaces, and all governed evidence digests | Frozen v5 unchanged; v6 replaces it |
| `provenance-candidate-v6.schema.json` | Closed at every known object | A complete v5 measurement plus the repository and commit, adapter identity and owner, and target configuration reference and digest | New v6 because those publication facts are now required |
| `promoted-record-v1.schema.json` | Closed root; digest map accepts any non-empty filename | Absolute, traversal, and unrelated inventory keys are structurally valid | Frozen v1 unchanged; v2 replaces it |
| `promoted-record-v2.schema.json` | Closed root and allowlisted file inventory | A candidate file digest plus record identity; the reader binds the top-level digest to the inventory and actual file | New v2 because tightening v1 would reject retained records |
| `promotion-baseline-v1.schema.json` | Closed; reason names are a typed map | A reviewed identity, observed counts, bounded score floors, and bounded ceilings | Active v1 unchanged because candidate v6 still uses summary generation 5 |
| `tool-profile-v1.schema.json` | Closed | A named historical tool and its declared capabilities; optional receipt paths are runtime-contained | Frozen v1 unchanged |
| `tool-profile-v3.schema.json` | Closed | A named historical tool and its claims; receipt evidence may use absolute directories, while glob results and symlinks are contained by the runner | Frozen v3 unchanged |
| `tool-profile-v4.schema.json` | Closed | A named tool, runner version, registry reference, and claim set; optional receipt evidence is contained and resolved by the runner | Active v4 unchanged |
| `receipt-scoring-profile-v1.schema.json` | Closed | Identified corpus and tool evidence with complete summary and per-case rows | Frozen v1 unchanged |
| `receipt-scoring-profile-v3.schema.json` | Closed | Identified corpus and tool evidence with bounded enumerated observations | Frozen v3 unchanged |
| `receipt-scoring-profile-v4.schema.json` | Closed | Active registry-bound receipt observations with explicit unmeasured states | Active v4 unchanged |
| `control-evidence-assessment-v1.schema.json` | Closed | Identified verifier predicates and assessment profile | Unchanged |
| `control-evidence-assessment-v2.schema.json` | Closed | Identified verifier predicates and assessment profile | Unchanged |
| `control-evidence-authentication-context-v1.schema.json` | Closed | Trust policy, trusted keys, and bounded authentication context | Unchanged |
| `control-evidence-buyer-reproduction-statement-v0.schema.json` | Closed | Signed source bindings and a buyer reproduction statement | Published v0 unchanged |
| `control-evidence-buyer-reproduction-statement-v1.schema.json` | Closed | Registry-bound signed source bindings and a buyer reproduction statement | Published v1 unchanged |
| `control-evidence-buyer-reproduction-transcript-v0.schema.json` | Closed | Source envelope digest, reproduction run ID, and outcomes | Published v0 unchanged |
| `control-evidence-buyer-reproduction-transcript-v1.schema.json` | Closed | Source envelope digest, reproduction run ID, and outcomes | Published v1 unchanged |
| `control-evidence-buyer-reproduction-v0.schema.json` | Closed | Buyer, signer, source digest set, and reproduction result | Published v0 unchanged |
| `control-evidence-buyer-reproduction-v1.schema.json` | Closed | Registry-bound buyer, signer, source digest set, and reproduction result | Published v1 unchanged |
| `control-evidence-clock-evidence-v0.schema.json` | Closed | Run-bound timestamps and an identified clock attestor | Published v0 unchanged |
| `control-evidence-clock-evidence-v1.schema.json` | Closed | Run-bound timestamps and an identified clock attestor | Published v1 unchanged |
| `control-evidence-context-v0.schema.json` | Closed | Reference time, requirement digest, trust inputs, material, and nonce ledger | Published v0 unchanged |
| `control-evidence-context-v1.schema.json` | Closed | Registry-bound reference time, requirement digest, trust inputs, material, and nonce ledger | Published v1 unchanged |
| `control-evidence-dsse-v0.schema.json` | Closed | Non-empty payload type, encoded payload, and at least one signature | Published v0 unchanged |
| `control-evidence-dsse-v1.schema.json` | Closed | Non-empty payload type, encoded payload, and at least one signature | Published v1 unchanged |
| `control-evidence-health-control-material-v0.schema.json` | Closed | Identified material profile with a control mapping; verifier checks exact required IDs | Published v0 unchanged |
| `control-evidence-health-control-material-v1.schema.json` | Closed | Identified material profile with a control mapping; verifier checks exact required IDs | Published v1 unchanged |
| `control-evidence-manifest-v0.schema.json` | Closed entries; three `contains` nodes are partial predicates over them | At least the required roles with normalized relative paths, bounded sizes, and digests; verifier checks uniqueness and archive containment | Published v0 unchanged |
| `control-evidence-manifest-v1.schema.json` | Closed entries; three `contains` nodes are partial predicates over them | At least the required roles with normalized relative paths, bounded sizes, and digests; verifier checks uniqueness and archive containment | Published v1 unchanged |
| `control-evidence-observer-evidence-v0.schema.json` | Closed | Requirement-bound observer identity, transport, target, and observation kind | Published v0 unchanged |
| `control-evidence-observer-evidence-v1.schema.json` | Closed | Requirement-bound observer identity, transport, target, and observation kind | Published v1 unchanged |
| `control-evidence-outcomes-v0.schema.json` | Closed | Requirement digest, run ID, and outcome rows with enumerated states | Published v0 unchanged |
| `control-evidence-outcomes-v1.schema.json` | Closed | Registry-bound requirement digest, run ID, and outcome rows with enumerated states | Published v1 unchanged |
| `control-evidence-requirement-v0.schema.json` | Closed | Time-bounded challenge, approved identities, required artifacts, canaries, limits, and signer policy | Published v0 unchanged |
| `control-evidence-requirement-v1.schema.json` | Closed | Registry-bound time-bounded challenge, approved identities, required artifacts, canaries, limits, and signer policy | Published v1 unchanged |
| `control-evidence-run-envelope-v0.schema.json` | Closed | Requirement-bound run identity, time window, corpus, tool, policy, adapter, artifacts, observations, and signer | Published v0 unchanged |
| `control-evidence-run-envelope-v1.schema.json` | Closed | Registry-bound run identity, time window, corpus, tool, policy, adapter, artifacts, observations, and signer | Published v1 unchanged |
| `control-evidence-token-material-v0.schema.json` | Closed | Identified material profile with a token mapping; verifier checks exact required IDs | Published v0 unchanged |
| `control-evidence-token-material-v1.schema.json` | Closed | Identified material profile with a token mapping; verifier checks exact required IDs | Published v1 unchanged |
| `control-evidence-trust-policy-dsse-v1.schema.json` | Closed | Signed trust-policy payload with bounded signatures | Published v1 unchanged |
| `control-evidence-trust-policy-v1.schema.json` | Closed | Policy identity, trusted signers, roles, algorithms, and validity rules | Published v1 unchanged |

## File-bearing fields

`multi-file-case-v4` and both Control Evidence manifest schemas constrain archive or fixture paths to normalized relative names and reject parent traversal. `promoted-record-v2` uses an exact filename allowlist. `promoted-record-v1` remains weak because it's frozen.

Tool-profile receipt evidence is deliberately different. `evidence_dir` may be an operator-selected absolute directory, and `file_glob` is an operator pattern. The runner restricts matches to entries physically listed inside that directory, rejects non-regular files, and resolves symlinks before accepting a match. Absolute and traversal glob patterns therefore produce no outside match instead of importing another file.

Counts and rates use non-negative bounds and zero-to-one bounds where those values are portable. Tool-profile verifier exit codes are the exception: process exit status is platform-defined, so the schema constrains the array shape while the runner compares the declared integers to the process result.

## Long-term source shape

Hand-written JSON Schema remains useful for portable structural validation, but it can't be the only authority for cross-field contracts. The result-state vocabulary now generates its Go and Python bindings from `contracts/result-states-v5.json`. Count arithmetic, rate equality, digest-to-file binding, archive containment, and signature policy stay in semantic verifiers with negative tests because JSON Schema can't express or observe them.

The next contract with a vocabulary consumed in more than one language should follow the same pattern: govern the vocabulary once, generate static bindings, and make the public-contract gate reject stale output. A larger schema generator isn't justified yet because most schemas don't share enough shape to offset the migration and review cost.
