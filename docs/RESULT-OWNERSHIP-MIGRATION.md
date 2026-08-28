# Pipelock result ownership migration

Agent Egress Bench owns the method, corpus, runner contracts, and portable verification tools.
Pipelock owns its scheduled runs and release gates. PipeLab owns Pipelock's published result page and
new immutable result bundles.

The old Pipelock result bytes remain in this repository as a read-only restore copy. The migration
inventory records commit-pinned and live GitHub URLs, the exact byte count and SHA-256 digest, the
planned PipeLab destination, and the repository responsible for retention. `make check-gauntlet-site`
rejects changed, missing, reordered, or symlinked snapshot evidence. It also reruns the existing
record verifier against the live result chain.

The migration is complete. This repository keeps the listed bytes and the readers needed to verify
them, but it doesn't accept or publish new Pipelock result records. New Pipelock runs belong in the
product repository, and PipeLab owns their public pages and retained bundles.
