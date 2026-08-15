# Schema identifiers and discovery

Each versioned schema declares an identifier in this form:

```
https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/main/schemas/<name>-vN.schema.json
```

The versioned filename is part of the identifier. There are no unversioned
aliases. Consumers that need an exact byte revision can use the SHA-256 from
the generated discovery document:

```
https://raw.githubusercontent.com/luckyPipewrench/agent-egress-bench/main/schemas/index.json
```

`schemas/index.json` lists every versioned schema with its repository path,
declared identifier, and SHA-256. It is generated from `schemas/`; the catalog
does not define schema content. `make check-schema-catalog` fails if the
checked-in document no longer matches the canonical schema files.

The repository owns the schema bytes and identifiers. GitHub serves the raw
document endpoint. GitHub currently labels raw JSON responses as
`text/plain; charset=utf-8`; this repository cannot set that header. Consumers
should parse the response body as JSON. A future serving surface controlled by
the repository must return `application/json` without changing these
identifiers.

## Stability

An active schema may change only under the compatibility rules in
[GOVERNANCE.md](GOVERNANCE.md). A change that alters accepted meaning requires
a new versioned filename and identifier. Frozen schemas have both their
identifier and their bytes pinned in `contracts/artifacts.json`; the contract
gate rejects a byte change unless a maintainer deliberately changes that
compatibility record.

## Adapter quickstarts

The reference runner supports four adapter classes. Copy the profile template
before using any command, replace its identity fields, and retain that profile
with the result.

```bash
export TMPDIR="$HOME/.cache/pipelock-tmp"
export GOCACHE="$HOME/.cache/go-build"
mkdir -p "$TMPDIR" "$GOCACHE"
cp examples/runner-template/tool-profile-template.json tool-profile.json
(cd runner && go build -o "$TMPDIR/aeb-gauntlet" .)
```

### Fetch-style forward proxy

Start the target's fetch endpoint on `127.0.0.1:18899`, then run:

```bash
"$TMPDIR/aeb-gauntlet" --cases cases --profile tool-profile.json --adapter proxy --proxy-addr 127.0.0.1:18899 --fixtures --output fetch-summary.json
```

### CONNECT-capable forward proxy

Start the target as an HTTPS forward proxy on `127.0.0.1:18899`, then run:

```bash
"$TMPDIR/aeb-gauntlet" --cases cases --profile tool-profile.json --adapter proxy --proxy-addr 127.0.0.1:18899 --fixtures --output connect-summary.json
```

### MCP Streamable HTTP listener

Start the target's MCP HTTP listener at `http://127.0.0.1:18899/mcp`, then
run:

```bash
"$TMPDIR/aeb-gauntlet" --cases cases --profile tool-profile.json --adapter proxy --mcp-http-url http://127.0.0.1:18899/mcp --fixtures --output mcp-http-summary.json
```

### MCP gateway

Create the tool-neutral gateway plugin described in
[GATEWAY-ADAPTER.md](GATEWAY-ADAPTER.md), save it as `gateway-plugin.json`,
start the gateway, then run:

```bash
"$TMPDIR/aeb-gauntlet" --cases cases --profile tool-profile.json --adapter mcp-gateway --gateway-plugin gateway-plugin.json --fixtures --output mcp-gateway-summary.json
```

The runner records unsupported delivery tuples as `unreachable`. Do not relabel
another transport as one of these four classes to produce a broader result.
