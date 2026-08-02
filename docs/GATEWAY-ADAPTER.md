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

`gateway` is lifecycle metadata for later slices:

- `start_command`: command that starts the gateway.
- `ready_addr`: host:port readiness target.
- `env_passthrough`: environment names or values required by the gateway.

`fixture_registration` describes how a future slice registers the
runner-managed MCP upstream:

- `method`: registration mechanism name.
- `register_command` and `deregister_command`: lifecycle commands.
- `config_template_path`: configuration template used by a file-based method.
- `api_endpoint`: endpoint used by an API-based method.

PR1 records these fields but does not execute gateway lifecycle or registration
commands. Start the generic target gateway externally and point `client` at
its Streamable HTTP endpoint.

`client.endpoint` is the absolute HTTP(S) MCP endpoint and `client.headers`
are literal HTTP headers sent with every MCP request.

`deny_signals` normalizes a gateway's documented deny behavior:

- `jsonrpc_error_code_range`: inclusive `[minimum, maximum]` JSON-RPC deny
  range; `[0, 0]` disables this signal.
- `http_status_codes`: HTTP statuses that mean deny.
- `custom_body_markers`: literal response-body strings that mean deny.
- `tool_filtered_from_list`: documents that an integration blocks tool
  definitions by omitting them from `tools/list`. The adapter detects omission
  directly for its supported tools/list path.
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

These values are available to runner-managed process commands today. The
plugin lifecycle commands are deliberately declarative, so supply any values
needed during plugin loading in the runner process environment.

Start from [gateway-plugin-template.json](../examples/gateway-plugin-template.json).
