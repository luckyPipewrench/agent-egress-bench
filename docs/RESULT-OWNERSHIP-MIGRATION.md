# Pipelock result ownership migration

Agent Egress Bench owns the method, corpus, runner contracts, and portable verification tools.
Pipelock owns its scheduled runs and release gates. PipeLab owns Pipelock's published result page and
new immutable result bundles.

The old Pipelock result bytes remain in this repository as a read-only restore copy. The migration
inventory records commit-pinned and live GitHub URLs, the exact byte count and SHA-256 digest, the
planned PipeLab destination, and the repository responsible for retention. `make check-gauntlet-site`
rejects changed, missing, reordered, or symlinked snapshot evidence. It also reruns the existing
record verifier against the live result chain.

The inventory stays pinned to its recorded source commit if the old lane promotes another result
before cutover. After migration, this repository keeps the listed bytes and the generic readers, but
it no longer schedules Pipelock or publishes new Pipelock results.

To cut a later snapshot, commit the reviewed record first, then regenerate the inventory from that
commit:

```bash
python3 scripts/validate_pipelock_result_inventory.py --write
```
