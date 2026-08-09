# MCP gateway adapter plugin contract

The `mcp-gateway` runner adapter drives a gateway through a generic MCP client
endpoint. A plugin describes the gateway's protocol surface and deny signals;
it must not identify or depend on a particular gateway product.

The adapter supports five narrow paths, all sent to a plugin with
`"transport": "streamable_http"`:

- A corpus `mcp_http` case containing one `mcp_tool_call` message.
- A corpus `mcp_http` case containing a dependent `mcp_tool_sequence`. The
  adapter sends each `tools/call` in order over one session, proves every
  dependency at the runner-owned upstream, and records a separate execution
  proof for the final sink.
- A corpus `mcp_stdio` or `mcp_http` case containing exactly one
  `mcp_tool_definition`: the case models the upstream inventory while the
  adapter drives the gateway over Streamable HTTP. It installs the inventory
  under one request identity in the runner-managed fixture, then sends `initialize`,
  `notifications/initialized`, and `tools/list`.
- A corpus `mcp_http` case containing exactly one `mcp_tool_result`: the adapter
  installs that result under one request identity, then drives a correlated call
  through the gateway.
- A single-server `mcp_http` case containing one
  `mcp_tool_sequence_temporal`: the adapter establishes the original inventory,
  proves the agent received it, then delivers the changed inventory through the
  same negotiated `Mcp-Session-Id`. A stateless initialize response is
  unscoreable for this path. The adapter compares the full canonical tool
  definitions. Name-only matches do not prove delivery.

Other corpus transport and input-type tuples are not selected for this adapter;
the runner records a named error when no declared delivery tuple exists. If a
declared route cannot establish its delivery proof, the adapter returns `skip`
and the runner promotes that out-of-contract verdict to an error rather than
inventing a product verdict. Native `mcp_http` temporal drift is modelled only
for one upstream server. The adapter does not relabel stdio drift as HTTP and
does not flatten a multi-server case into one session.

For every request the adapter needs to prove, it mints one request identity and
adds it in `params._meta.aeb_request_identity`. It also uses that identity as
the JSON-RPC request ID. The runner-managed fixture records the identity,
method, and canonical JSON fingerprint it received. The adapter accepts exactly
one matching observation, so an unrelated request, a copied identity on changed
content, or a replay cannot prove delivery for this case. A sequence in which
the gateway answers a call without forwarding it is therefore `skip`, with
`upstream_reached: false`. A `tools/call` deny is a `block` only when an adapter
supplies authoritative atomic non-delivery proof for that exact request; the
generic shell plugin does not. A proven result names its
`blocked_message_index`. A dependent sequence also proves every successful
prefix call before crediting a deny. An allow requires one exact execution at
the runner-owned final sink.

For a `tools/list` path, an allow is credited only when the fixture records the
case's matching observation and every declared tool name is present in the
gateway response.
Names are lowercased for this presence comparison, so a gateway that only
changes case is not credited as filtering a tool. A declared tool absent from
the returned list is a `block`; a JSON-RPC error in the configured deny range
is a `block` only with the same delivery proof. A successful local
`tools/list` response without the matching observation is always `skip`, never
`allow`.

For a tool-result path, both allow and block require the fixture to record that
case's matching observation while the case owns the identity-scoped response
lease. A deny before the call reaches the fixture is `skip`, because it does not
prove that the gateway inspected the declared result. The lease is released and
cleared after each case, and an ordinary concurrent `tools/call` has no matching
identity so it receives the fixture's default response.

Every JSON-RPC response is structurally validated and correlated by the exact
request ID before deny classification. This is identical for ordinary JSON and
SSE responses; a valid SSE response with another ID is a named correlation
failure, not malformed SSE. An HTTP response from the adapter's `http.Client`
is already correlated to that request, so configured HTTP status and body-marker
denies may score `block` without a JSON-RPC body, but only when the fixture
observation satisfies that surface's delivery direction. A stale JSON-RPC deny,
malformed response, or unproven fixture observation never scores `block`.
For an outbound `tools/call` deny, silence for a fixed time is not proof. A
generic shell-managed gateway has no authoritative ownership boundary: a
daemonized worker can outlive its launcher and forward later. The runner therefore
does not manufacture non-delivery proof from process-group teardown or a closed
listener. Unless an adapter supplies a stronger atomic proof, an apparent deny on
this delivery direction is `skip` rather than a false containment result.

## Plugin fields

`name` names the integration for local output. `transport` is the plugin
protocol transport; PR1 accepts only `streamable_http`.

`gateway` describes how the runner starts and waits for the gateway:

- `start_command`: command that starts the gateway. When set, the runner
  executes it, waits for `ready_addr`, and stops its launch process group when
  the run ends. That lifecycle is not treated as atomic non-delivery proof.
  When empty, the runner does not manage a lifecycle: start the gateway
  externally and point `client` at its Streamable HTTP endpoint.
- `ready_addr`: host:port readiness target the runner polls before driving any
  case. Required when `start_command` is set.
- `env_passthrough`: environment names or values required by the gateway.

`fixture_registration` describes how the runner points the managed gateway at
the benchmark's runner-owned MCP upstream:

- `method`: registration mechanism name.
- `register_command`: run to completion after the gateway is ready; a nonzero
  exit fails the run so an unregistered upstream is never mistaken for a wired
  one. This is the executed mechanism today: wrap any file write or API call
  needed to point the gateway at `$AEB_MCP_HTTP_FIXTURE_URL` in this command.
- `deregister_command`: run on a best-effort basis at teardown.
- `config_template_path` and `api_endpoint`: reserved fields for file-based and
  API-based registration methods; they are not executed yet. Use
  `register_command` for those flows for now.

When `start_command` is set, the runner executes gateway lifecycle and
registration commands; a run with an operator-started gateway leaves both empty.
This managed path is proven end-to-end against an in-repo synthetic gateway.

The adapter binds a session: when the gateway returns an `Mcp-Session-Id` header
on initialize, the adapter replays it on the case's later requests, so a
session-enforcing gateway is driven correctly. An `mcp_http` case may carry an
ordered sequence of `tools/call` messages; the adapter drives them over the one
session, stops at the first denied call and reports its index, and allows only
when every call reaches upstream. A deny scores `block` only with the atomic
proof contract described above; generic plugins return `skip`. Resources, prompts, and
multi-server topologies remain out of scope, and a maintainer-opt-in run against
an unrelated third-party gateway is still pending.

`client.endpoint` is the absolute HTTP(S) MCP endpoint and `client.headers`
are literal HTTP headers sent with every MCP request. Static
`Mcp-Session-Id` headers are rejected. Session identity comes only from the
validated `initialize` response.

`deny_signals` normalizes a gateway's documented deny behavior:

- `jsonrpc_error_code_range`: inclusive `[minimum, maximum]` JSON-RPC deny
  range; `[0, 0]` disables this signal.
- `http_status_codes`: HTTP statuses that mean deny.
- `custom_body_markers`: literal response-body strings that mean deny.
- `tool_filtered_from_list`: descriptive metadata only. It documents that an
  integration blocks tool definitions by omitting them from `tools/list`, but it
  does not gate detection. `runToolDefinition` detects an omitted declared tool
  directly and never reads `DenySignals.ToolFilteredFromList`.
- `connection_closed_no_output` and `non_zero_exit`: declared signals reserved
  for relevant follow-on paths. The adapter records a configured connection
  close on a measured case request as `skip`, not `block`, because no response
  exists to bind the failure to this request rather than a transport fault. A
  close during `initialize` is an adapter error because no measurable session
  was established.

## Managed variables and interpolation

`LoadGatewayPlugin` replaces only variables whose names start with `$AEB_`.
It leaves `$HOME`, `${HOME}`, command substitutions, and all other shell-like
text untouched. Values are plain string data: interpolation neither invokes a
shell nor parses a substituted semicolon, quote, or command substitution.
An unset `$AEB_*` variable is an error.

The runner's fixture environment names are:

- `AEB_HTTP_FIXTURE_ADDR`
- `AEB_TLS_FIXTURE_ADDR`, `AEB_TLS_CA_FILE`, `AEB_TLS_CA_KEY_FILE`
- `AEB_WS_FIXTURE_ADDR`
- `AEB_DNS_FIXTURE_ADDR`
- `AEB_MCP_HTTP_FIXTURE_ADDR`, `AEB_MCP_HTTP_FIXTURE_URL`

Only when the plugin declares a `start_command` does the runner manage the
gateway lifecycle, allocate the gateway listen address at run time, and supply:

- `AEB_GATEWAY_ADDR`: the allocated host:port the gateway must bind.
- `AEB_GATEWAY_URL`: `http://AEB_GATEWAY_ADDR/`.

The fixture values are interpolated into every plugin at load time. The two
gateway values are added only for a managed plugin and are exported to its
gateway, registration, and deregistration commands. Because the loader fails on
any unresolved `$AEB_*` variable, a managed plugin references `$AEB_GATEWAY_ADDR`
for its listen address and `$AEB_MCP_HTTP_FIXTURE_URL` for its upstream rather
than hardcoding a runtime address.

An operator-started gateway with no `start_command` gets no runner-allocated
gateway address. Point its `client.endpoint` at the address the operator
started, either literally or through an `$AEB_*` value the operator sets in the
runner process environment. Do not reference `$AEB_GATEWAY_ADDR` or
`$AEB_GATEWAY_URL` from an operator-started plugin; the runner does not set them
in that case.

Start from [gateway-plugin-template.json](../examples/gateway-plugin-template.json).
