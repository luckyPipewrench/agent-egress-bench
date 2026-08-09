# Capability Vocabulary and Profile Evolution

Active profiles use schema v4. Capability claims and case capability tags are reporting labels only. They never determine delivery, applicability, score, sufficiency, publication eligibility, or coverage denominators.

Every active profile and result binds an immutable capability-registry snapshot by registry ID, format, revision, and SHA-256. Producers validate IDs against that exact snapshot before execution. Consumers reject missing, unknown, mismatched, or unsupported registry references before rendering or publishing a measurement.

Capability registry snapshots are append-only. IDs are never removed, reassigned, or redefined. Deprecation records a replacement in a later snapshot and does not alter historical snapshots or evidence.

A profile schema bump occurs only for structural, scoring, delivery-protocol, provenance, or security-validation changes. Adding or deprecating a reporting capability ID does not require a profile schema bump.

Adapter-proven delivery and verdict observation determine applicability. Profile claims cannot influence scope. Historical artifacts remain under their frozen schemas and are never normalized into active scoring semantics.
