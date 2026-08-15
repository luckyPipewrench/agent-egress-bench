# Schema identifiers and discovery

## An identifier is a name, not an address

Every versioned schema declares an `$id`. That identifier names the contract.
It is not a download location and fetching it is not expected to work:

```text
https://github.com/luckyPipewrench/agent-egress-bench/schemas/<name>-vN.schema.json
```

JSON Schema treats `$id` as an identifier rather than a network locator, and
tools are expected to load schemas locally rather than resolve them over the
network. These identifiers are therefore permanent. They will not be rewritten
to make them fetchable, because a consumer that registered one, or referenced
it from another schema, would silently be naming a different resource
afterwards.

Retrieval and integrity are answered by the catalog instead, which is a
separate document that can change location freely without disturbing identity.

## The catalog

`schemas/index.json` lists every published versioned schema with its
repository path, its declared identifier, and the SHA-256 of its exact bytes.
It covers the canonical `schemas/` directory and the governed Control Evidence
verifier copies.

The catalog is generated from the schema files. It records identity; it never
assigns it. `make check-schema-catalog` regenerates it and fails when the
checked-in document no longer matches the schemas on disk, so a schema edit
that skips the catalog cannot merge.

The in-repo copy is deterministic and carries no commit or release field. A
commit cannot name the commit that contains it, so embedding one would make
the committed catalog permanently disagree with its own regeneration check.

## Pinning a version, and reproducing an old run

Pin the released catalog artifact, not the copy on the default branch. The
released copy adds `source_commit` and `release`, so it states which
repository state produced the bytes it lists:

```bash
python3 scripts/write_schema_catalog.py --release v1.2.3 --output catalog.json
```

For a result you intend to reproduce later, retain the catalog artifact, its
digest, and the schema bytes themselves alongside the result. A digest says
which bytes; the commit and release say which repository state produced them.
Reproducing a two-year-old run needs both.

To validate:

1. Fetch or vendor the schema files and verify each SHA-256 against the
   catalog.
2. Register each schema in your validator under the `$id` it declares.
3. Validate against the registered identifier.

Step 2 is what makes offline and air-gapped validation work, and it is the
step that would break if identifiers were rewritten. No network access is
required at any point.

## Stability

An active schema may change only under the compatibility rules in
[GOVERNANCE.md](GOVERNANCE.md). A change that alters accepted meaning requires
a new versioned filename and identifier.

Frozen schemas are byte-pinned. `make check-frozen-schema-immutability`
compares every frozen and retained schema against the base revision and
rejects any byte difference, including a reformat or a key reorder that leaves
the parsed document identical, because a consumer pinning a digest sees those
as a different document. There is no permitted-migration exception. Changing a
frozen contract means publishing a new version.

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
