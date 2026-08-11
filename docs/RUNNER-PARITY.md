# Runner parity protocol

Two independent runners can accidentally agree in public after one side has
seen the other's output. This protocol makes each side bind its result vector
first, then reveal and compare it.

## Protocol

1. Both sides agree on a unique comparison ID and pin the same corpus,
   benchmark manifest, tool binary version, and tool profile digest. The
   prepare step reads the manifest itself, commits its digest, and requires
   exactly one result row for every selected case ID with no extras. Never
   reuse the comparison ID for a later round.
2. Each side runs privately and creates a reveal object with
   `scripts/runner_parity.py prepare`. The command prints a SHA-256 commitment.
3. Both sides publish only that digest. Neither side reveals its result rows
   until both digests are durable.
4. Each side reveals the JSON object it kept private. Anyone can run `verify`
   against the earlier digest, then `compare` the two reveals.
5. Equal normalized vectors are parity. A difference is a runner bug, tool
   nondeterminism, or a bad case until reproduced and explained; it is never
   silently averaged away.

The comparison ID prevents an old reveal from being replayed as a new run. Each
side's distinct 128-bit random nonce prevents practical guessing of a
low-entropy result vector from its digest before reveal and proves the two
commitments were independently prepared. Canonical JSON is UTF-8 with sorted
keys, no insignificant whitespace, and no ASCII escaping.

## Normalized result vector

Rows are uniquely sorted by `case_id` and retain exactly:

- `case_id`
- `expected_verdict`
- `actual_verdict`
- `score`
- `evidence.result_state`

That last field keeps delivery, observation, adapter, and reachability failures
from collapsing into one generic `error`. Tool-specific evidence and notes are
excluded because they are not cross-runner decision semantics.

## Environment block

The commitment binds runner implementation and version, runtime, operating
system, architecture, concurrency, timeout, fixture mode, and network mode.
The tool version remains a separate identity field. Environment metadata is
excluded from the normalized vector, so two honest runs on different machines
can match while their distinct execution conditions remain tamper-evident.

## Commands

Create a private reveal and capture the digest printed to stdout:

```bash
python3 scripts/runner_parity.py prepare \
  --results /tmp/run-a/results.jsonl \
  --output /tmp/run-a/reveal.json \
  --comparison-id vendor-a-vendor-b-2026-08-10-round-1 \
  --corpus-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --benchmark-manifest cases/MANIFEST.txt \
  --tool pipelock --tool-version 4.0.0 \
  --tool-profile-sha256 23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01 \
  --runner aeb-gauntlet --runner-version 4 \
  --runtime go1.25.12 --os linux --arch amd64 \
  --concurrency 1 --timeout-seconds 15 \
  --fixture-mode local --network-mode contained
```

After both commitments are public:

```bash
python3 scripts/runner_parity.py verify \
  --reveal /tmp/run-a/reveal.json \
  --benchmark-manifest cases/MANIFEST.txt \
  --commitment-sha256 3456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef012
python3 scripts/runner_parity.py compare \
  --benchmark-manifest cases/MANIFEST.txt \
  /tmp/run-a/reveal.json /tmp/run-b/reveal.json
```

The reveal file is sensitive before both commitments exist. Keep it private;
publishing it early defeats the anti-following property of the protocol.
