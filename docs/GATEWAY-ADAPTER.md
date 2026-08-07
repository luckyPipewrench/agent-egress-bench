# MCP gateway adapter plugin contract

The `mcp-gateway` runner adapter drives a gateway through a generic MCP client
endpoint. A plugin describes the gateway's protocol surface and deny signals;
it must not identify or depend on a particular gateway product.

The adapter supports two narrow paths, both sent to a plugin with
`"transport": "streamable_http"`:

- A corpus `mcp_http` case containing exactly one `mcp_tool_call`: the adapter
  sends `initialize`, `notifications/initialized`, and the case's `tools/call`.
- A corpus `mcp_stdio` case containing exactly one `mcp_tool_definition`: the
  corpus definition models the upstream inventory, while the adapter drives the
  gateway over HTTP. It configures the runner-managed fixture with the declared
  definitions, then sends `initialize`, `notifications/initialized`, and
  `tools/list`.

Other corpus transports and input types return `skip` with a reason rather than
inventing a verdict. This does not model multi-call sequences or temporal tool
drift.

An allow is credited only when the runner-managed MCP fixture's `tools/call`
counter advances after the gateway response. A successful response generated
by a gateway without forwarding is therefore `skip`, with
`upstream_reached: false`.

For a `tools/list` path, an allow is credited only when the fixture's dedicated
`tools/list` counter advances and every declared tool name is present in the
gateway response. Names are lowercased for this presence comparison, so a
gateway that only changes case is not credited as filtering a tool. A declared
tool absent from the returned list is a `block`; a JSON-RPC error in the
configured deny range is also a `block`. A successful local `tools/list`
response without a fixture counter advance is always `skip`, never `allow`.

## Plugin fields

`name` names the integration for local output. `transport` is the plugin
protocol transport; PR1 accepts only `streamable_http`.

`gateway` describes how the runner starts and waits for the gateway:

- `start_command`: command that starts the gateway. When set, the runner
  executes it, waits for `ready_addr`, and stops it when the run ends. When
  empty, the runner does not manage a lifecycle: start the gateway externally
  and point `client` at its Streamable HTTP endpoint.
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
Sessions, multi-call sequences, resources, prompts, and multi-server topologies
remain out of scope, and a maintainer-opt-in run against an unrelated third-party
gateway is still pending.

`client.endpoint` is the absolute HTTP(S) MCP endpoint and `client.headers`
are literal HTTP headers sent with every MCP request.

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
  for relevant follow-on paths; the adapter applies
  `connection_closed_no_output` when an MCP request fails before a response is
  received.

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

When the runner manages the gateway lifecycle it also allocates the gateway
listen address at run time and supplies:

- `AEB_GATEWAY_ADDR`: the allocated host:port the gateway must bind.
- `AEB_GATEWAY_URL`: `http://AEB_GATEWAY_ADDR/`.

All of these values are interpolated into the plugin at load time and exported
to the gateway, registration, and deregistration commands. Because the loader
fails on any unresolved `$AEB_*` variable, a managed plugin references
`$AEB_GATEWAY_ADDR` for its listen address and `$AEB_MCP_HTTP_FIXTURE_URL` for
its upstream rather than hardcoding a runtime address. For an operator-started
gateway with no `start_command`, supply any additional `$AEB_*` values in the
runner process environment.

Start from [gateway-plugin-template.json](../examples/gateway-plugin-template.json).
