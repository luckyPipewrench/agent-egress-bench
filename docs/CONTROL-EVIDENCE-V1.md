# Control Evidence Envelope v1

Control Evidence Envelope v1 carries active schema v4 Gauntlet evidence. It is a separate verifier at `control-evidence/v1/verifier`. The v0 verifier and its fixtures remain frozen historical readers.

Each v1 package binds the same capability-registry reference in its signed requirement, run envelope, outcomes ledger, runner summary, tool profile, and receipt-scoring profile. The manifest retains the raw registry snapshot as a `capability-registry` member. The verifier hashes those raw bytes, resolves the exact ID, format, revision, and SHA-256 reference, then validates every reported claim and exercised tag against that snapshot.

Any missing snapshot, unknown label, duplicate label, unsupported format, digest mismatch, or reference disagreement makes the package uninterpretable. The verifier does not substitute a newer registry or recalculate a result.

Registry snapshots are append-only. A new or deprecated reporting label creates a new registry revision, not a new profile schema. Historical v0 packages contain no registry snapshot bytes and cannot be normalized into v1 provenance.

See [Capability Vocabulary and Profile Evolution](CAPABILITY-VOCABULARY.md) for the active policy and [Control Evidence Envelope v0](CONTROL-EVIDENCE.md) for the frozen v0 contract.
