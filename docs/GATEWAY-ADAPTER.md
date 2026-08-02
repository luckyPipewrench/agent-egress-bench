# MCP gateway adapter plugin contract

The `mcp-gateway` runner adapter drives a gateway through a generic MCP client
endpoint. A plugin describes the gateway's protocol surface and deny signals;
it must not identify or depend on a particular gateway product.

PR1 supports one narrow path: a corpus `mcp_http` case containing exactly one
`mcp_tool_call`, sent to a plugin with `"transport": "streamable_http"`. The
adapter sends `initialize`, `notifications/initialized`, and the case's
`tools/call`. Other corpus transports and input types return `skip` with a
reason rather than inventing a verdict.

An allow is credited only when the runner-managed MCP fixture's `tools/call`
counter advances after the gateway response. A successful response generated
by a gateway without forwarding is therefore `skip`, with
`upstream_reached: false`.

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
- `tool_filtered_from_list`, `connection_closed_no_output`, and
  `non_zero_exit`: declared signals reserved for the relevant follow-on paths;
  PR1 applies `connection_closed_no_output` when an MCP request fails before a
  response is received.

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

These values are available to runner-managed process commands today. PR1's
plugin lifecycle commands are deliberately declarative, so supply any values
needed during plugin loading in the runner process environment.

Start from [gateway-plugin-template.json](../examples/gateway-plugin-template.json).
