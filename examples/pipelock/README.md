# Pipelock Reference Runner

> **For benchmark development use the Go runner in [`../../runner/`](../../runner/).** It executes the declared fetch, forward-proxy, WebSocket, MCP stdio, MCP HTTP, A2A, and TLS-intercepted request/response transports without substituting scan APIs or other surfaces. The shell `harness.sh` remains a fetch-only illustration, not a scoring runner.

This directory contains the Pipelock-specific artifacts the Go runner needs to score Pipelock:

- [`tool-profile.json`](tool-profile.json): Pipelock's registry-bound reporting labels.
- [`pipelock-benchmark.yaml`](pipelock-benchmark.yaml): bench-only config (every scanner enabled, action=block, test blocklist domain included).
- [`receipt-verifier.json`](receipt-verifier.json): Pipelock's verifier metadata for the optional receipt-scoring profile.
- [`release.env`](release.env): the single reviewed Pipelock release tag and version used by the portable runner and GitHub workflow.
- [`harness.sh`](harness.sh): legacy fetch-only example, kept for illustration.

## Portable release run

From a clean Linux clone on `origin/main` or a repository tag:

```bash
./scripts/run-pipelock-gauntlet.sh
```

The default output is a unique directory under `continuous-gauntlet-runs/`. To choose the location explicitly:

```bash
./scripts/run-pipelock-gauntlet.sh --output-dir /var/lib/agent-egress-bench/runs/manual-20260805
```

The destination must not already exist. The command verifies the corpus Git identity and cleanliness, downloads the release named by `release.env`, rejects draft or prerelease assets, verifies the archive against the release's `checksums.txt`, and verifies the extracted binary's version before running it. It then builds the repository runner and executes every canonical fixture and multi-file MCP drift case.

Important files in the completed directory:

| File | Meaning |
| --- | --- |
| `execution-decision.json` | Whether execution completed, whether platform finalization is eligible, and any blocking failure |
| `run-bundle.json` | Hash-bound portable bundle used by a later platform finalizer |
| `raw-summary.json` | Four-axis Gauntlet summary and case counts |
| `results.jsonl` | One result row per logical case |
| `tool-profile.json` and `capability-registry.json` | Raw profile and exact registry snapshot that define the reporting labels |
| `runner.stderr` | Fixture startup proof and runner diagnostics |
| `command.txt` | Exact internal runner command, including timeout and all canonical flags |
| `case-index.json` | Loader-normalized case IDs and expected verdicts |
| `corpus-manifest.txt` | Exact logical-case manifest bytes behind the recorded manifest digest |
| `make-stats.txt` | Loader-backed corpus counts used for full denominators |
| `pipelock-release.json` | Release tag, version, archive digest, binary digest, and reported version |
| `checksums.txt` | Published checksum bytes that bind the downloaded release archive |
| `pipelock-version.txt` | Version output from the executed Pipelock binary |
| `run-metadata.json` | Corpus identity, ref kind, dirty state, and canonicality decision |
| `entrypoint-command.txt` | Exact operator command that started the run |

A runner error or timeout still leaves a blocked decision plus whatever evidence was produced. A successful portable run still is not a published result. A platform must retain the directory, assign a real artifact ID and HTTPS URL, finalize the candidate, and apply its reviewed publication policy.

### Explicit development mode

To test uncommitted runner changes with an already-built Pipelock binary:

```bash
./scripts/run-pipelock-gauntlet.sh \
  --development \
  --development-binary /usr/local/bin/pipelock
```

The output records why the run is noncanonical. The provenance finalizer refuses to turn that bundle into a publication candidate. A binary found on `PATH` is never selected silently.

### Repeating the command on Linux

Scheduling is an ordinary operator task, separate from evidence validation or publication. For example, if the repository is installed at `/opt/agent-egress-bench`, this crontab entry starts the same command every day at 06:17 UTC:

```cron
CRON_TZ=UTC
17 6 * * * cd /opt/agent-egress-bench && ./scripts/run-pipelock-gauntlet.sh
```

That timer does not update the repository, delete old runs, upload evidence, or publish a result. The machine operator must choose update, retention, and publication policies separately. Run the command manually once and inspect `execution-decision.json` and `run-bundle.json` before connecting it to any timer.

### Publication is separate from this example

This directory is only a reference execution adapter. It does not grant Pipelock a benchmark endorsement, vendor submission path, ranking, or certification. <!-- claim-ok: states the non-claim --> Other tools use the same runner contract and control their own result publication.

The repository maintainer's separately governed, first-party regression record is documented in [`../../docs/CONTINUOUS-RESULTS.md`](../../docs/CONTINUOUS-RESULTS.md). It is disclosed operational evidence for this reference adapter, not a status available through `examples/` and not the published pipelab.org page that renders the same history.

## Advanced runner invocation

The runner can either target already-running endpoints (`--proxy-addr`,
`--scan-addr`, `--mcp-http-url`) or start operator-provided commands with the
tool-neutral managed command hooks. Managed commands receive endpoint and
fixture values through environment variables; the runner does not parse or
mutate Pipelock configuration.

The canonical tool-neutral managed-command contract is documented in
[`../../docs/RUNNER.md`](../../docs/RUNNER.md#managed-command-hooks). This
example uses the same variables.

Available managed-command environment variables:

| Variable | Meaning |
| --- | --- |
| `AEB_PROXY_ADDR` | Host:port the managed forward/fetch proxy command should listen on |
| `AEB_SCAN_ADDR` | Host:port the managed scan API command should listen on |
| `AEB_MCP_HTTP_ADDR` | Host:port the managed MCP HTTP command should listen on |
| `AEB_MCP_HTTP_URL` | URL corresponding to `AEB_MCP_HTTP_ADDR` |
| `AEB_HTTP_FIXTURE_ADDR` | HTTP fixture address |
| `AEB_TLS_FIXTURE_ADDR` | HTTPS fixture address for intercepted request/response cases |
| `AEB_TLS_CA_FILE` | Fixture CA certificate path |
| `AEB_TLS_CA_KEY_FILE` | Fixture CA private-key path |
| `AEB_WS_FIXTURE_ADDR` | WebSocket fixture address |
| `AEB_DNS_FIXTURE_ADDR` | DNS fixture address |
| `AEB_MCP_HTTP_FIXTURE_URL` | MCP HTTP upstream fixture URL |
| `AEB_MCP_STDIO_UPSTREAM_ADDR` | Runner-owned line-delimited JSON-RPC TCP upstream for MCP stdio cases |

For MCP stdio, Pipelock passes the observer address to its backend explicitly
with `--env AEB_MCP_STDIO_UPSTREAM_ADDR`: Pipelock otherwise sanitizes the
child environment. The checked-in bridge connects its stdin/stdout to that
address without parsing the JSON-RPC stream. It prefers `socat`, then falls
back to `ncat` or `nc`; a machine running this example needs one of those
programs. The continuous Gauntlet verifies that one is available before it
runs.

### Budget capability scope

Profiles do not select budget cases. The runner executes them whenever the
adapter can deliver the MCP sequence and observe each result.

The current cases require per-subject accounting, while the canonical MCP
stdio invocation is one authenticated session. Their `subject_id` values are
test data, not a trusted identity boundary. Pipelock's session-wide tool-call
limit measures a different boundary, so the benchmark config leaves it
unlimited. This keeps an unrelated early session block from earning credit for
per-subject enforcement. Pipelock either enforces the case boundary or records
a measured failure; the adapter must not convert that outcome to N/A.

The portable entry point above is the normal Pipelock operator surface. The long form below is retained for runner development and to make the managed-command contract inspectable:

```bash
cd runner && go build -o /tmp/aeb-gauntlet . && cd ..
export PIPELOCK_BIN=/path/to/pipelock
export PIPELOCK_BENCH_CONFIG="$PWD/examples/pipelock/pipelock-benchmark.yaml"
/tmp/aeb-gauntlet \
  --adapter proxy \
  --scan-token bench-test-token \
  --mcp-cmd "\"$PIPELOCK_BIN\" mcp proxy --config \"$PIPELOCK_BENCH_CONFIG\" --env AEB_MCP_STDIO_UPSTREAM_ADDR -- sh ./examples/pipelock/mcp-stdio-upstream-bridge.sh" \
  --managed-proxy-cmd './examples/pipelock/start-proxy-for-benchmark.sh "$PIPELOCK_BIN"' \
  --managed-mcp-http-cmd './examples/pipelock/start-mcp-http-for-benchmark.sh "$PIPELOCK_BIN"' \
  --cases ./cases \
  --profile examples/pipelock/tool-profile.json \
  --fixtures \
  --output /tmp/gauntlet.json \
  --emit-receipt-profile /tmp/pipelock.json \
  --receipt-verifier-file examples/pipelock/receipt-verifier.json
```

The example profile may be set to a release-candidate version while validating a
candidate binary. Published score reports should name the exact released binary
or candidate commit they executed.

## Legacy fetch-only harness

`harness.sh` runs URL cases through Pipelock's `/fetch?url=...` GET endpoint. It is preserved as a minimal worked example of the runner contract for tools that only implement a fetch-style proxy. **It is not the Gauntlet**: body, header (POST), WebSocket, MCP, and response-content cases are not exercised, and any tool whose containment is reported off this harness alone will be undersold. Use the Go runner for any published score.

```bash
# Minimal fetch-only run (illustration, not a benchmark)
bash harness.sh /path/to/pipelock
```

Output is JSONL on stdout, summary on stderr.
