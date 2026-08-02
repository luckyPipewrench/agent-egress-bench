package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// MCPGatewayAdapter drives a plugin-configured MCP gateway. It supports the
// Streamable HTTP tools/call path and the MCP tool-definition tools/list path;
// lifecycle and fixture registration commands remain plugin contract fields.
type MCPGatewayAdapter struct {
	plugin   GatewayPlugin
	fixtures *fixture.Manager
}

// NewMCPGatewayAdapter creates an adapter for a loaded gateway plugin.
func NewMCPGatewayAdapter(plugin GatewayPlugin, fixtures *fixture.Manager) (*MCPGatewayAdapter, error) {
	if plugin.Name == "" {
		return nil, fmt.Errorf("gateway plugin name is required")
	}
	if plugin.Transport != "streamable_http" {
		return nil, fmt.Errorf("gateway plugin transport %q is unsupported; PR1 supports streamable_http", plugin.Transport)
	}
	endpoint, err := url.Parse(plugin.Client.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return nil, fmt.Errorf("gateway plugin client.endpoint must be an absolute URL: %q", plugin.Client.Endpoint)
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return nil, fmt.Errorf("gateway plugin client.endpoint has unsupported scheme %q", endpoint.Scheme)
	}
	codeRange := plugin.DenySignals.JSONRPCErrorCodeRange
	if codeRange != [2]int{} && codeRange[0] > codeRange[1] {
		return nil, fmt.Errorf("gateway plugin JSON-RPC deny range start exceeds end")
	}
	return &MCPGatewayAdapter{plugin: plugin, fixtures: fixtures}, nil
}

// Run drives a supported corpus case through the gateway's Streamable HTTP
// endpoint. Corpus mcp_stdio tool definitions represent the upstream MCP tool
// inventory even though the gateway-facing client transport is HTTP.
func (a *MCPGatewayAdapter) Run(c Case, timeout time.Duration) Result {
	switch c.InputType {
	case "mcp_tool_call":
		if c.Transport != "mcp_http" {
			return gatewaySkip(c, "gateway tools/call supports corpus transport mcp_http only")
		}
		return a.runToolsCall(c, timeout)
	case "mcp_tool_definition":
		if c.Transport != "mcp_stdio" {
			return gatewaySkip(c, "gateway tools/list supports corpus transport mcp_stdio only")
		}
		return a.runToolDefinition(c, timeout)
	default:
		return gatewaySkip(c, "gateway adapter does not support input type "+c.InputType)
	}
}

func (a *MCPGatewayAdapter) runToolsCall(c Case, timeout time.Duration) Result {
	toolsCall, err := oneToolsCall(c)
	if err != nil {
		return Result{Err: err}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{}
	initialize := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-initialize",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]string{"name": "agent-egress-bench", "version": "1"},
		},
	}
	if result := a.send(ctx, client, c.ID, initialize, false); result != nil {
		return *result
	}
	initialized := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}
	if result := a.send(ctx, client, c.ID, initialized, false); result != nil {
		return *result
	}

	upstreamBefore, proofAvailable := a.upstreamCalls()
	result := a.send(ctx, client, c.ID, toolsCall, true)
	if result != nil {
		return *result
	}
	upstreamAfter, proofAvailableAfter := a.upstreamCalls()
	evidence := map[string]interface{}{
		"product_surface": "mcp_gateway_streamable_http",
	}
	if proofAvailable && proofAvailableAfter {
		evidence["upstream_calls_before"] = upstreamBefore
		evidence["upstream_calls_after"] = upstreamAfter
	}
	if !proofAvailable || !proofAvailableAfter || upstreamAfter <= upstreamBefore {
		evidence["upstream_reached"] = false
		if !proofAvailable || !proofAvailableAfter {
			evidence["upstream_proof"] = "unavailable"
		}
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["upstream_reached"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

func (a *MCPGatewayAdapter) runToolDefinition(c Case, timeout time.Duration) Result {
	tools, declaredNames, err := declaredTools(c)
	if err != nil {
		return gatewaySkip(c, "gateway tools/list requires one tools/list-style tool definition: "+err.Error())
	}
	if upstream := a.mcpHTTPFixture(); upstream != nil {
		release := upstream.AcquireToolDefinitionLease(tools)
		defer release()
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{}
	if result := a.initialize(ctx, client, c.ID); result != nil {
		return *result
	}

	upstreamBefore, proofAvailable := a.upstreamListCalls()
	toolsList := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-tools-list",
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}
	responseBody, result := a.sendResponse(ctx, client, c.ID, toolsList, true, "empty_tools_list_response")
	if result != nil {
		return *result
	}
	upstreamAfter, proofAvailableAfter := a.upstreamListCalls()
	evidence := map[string]interface{}{
		"product_surface": "mcp_gateway_streamable_http",
	}
	if proofAvailable && proofAvailableAfter {
		evidence["upstream_tools_list_calls_before"] = upstreamBefore
		evidence["upstream_tools_list_calls_after"] = upstreamAfter
	}
	if !proofAvailable || !proofAvailableAfter || upstreamAfter <= upstreamBefore {
		evidence["upstream_reached"] = false
		if !proofAvailable || !proofAvailableAfter {
			evidence["upstream_proof"] = "unavailable"
		}
		return Result{Verdict: "skip", Evidence: evidence}
	}

	returnedNames, validInventory := toolsListNames(responseBody)
	if !validInventory {
		evidence["upstream_reached"] = true
		evidence["reason"] = "malformed_tools_list"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	for _, declaredName := range declaredNames {
		if !containsNormalizedToolName(returnedNames, declaredName) {
			evidence["upstream_reached"] = true
			evidence["filtered_tool_name"] = declaredName
			return Result{Verdict: "block", Evidence: evidence}
		}
	}
	evidence["upstream_reached"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

func (a *MCPGatewayAdapter) initialize(ctx context.Context, client *http.Client, caseID string) *Result {
	initialize := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-initialize",
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]string{"name": "agent-egress-bench", "version": "1"},
		},
	}
	if result := a.send(ctx, client, caseID, initialize, false); result != nil {
		return result
	}
	initialized := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}
	return a.send(ctx, client, caseID, initialized, false)
}

func gatewaySkip(c Case, reason string) Result {
	return Result{Verdict: "skip", Evidence: map[string]interface{}{
		"reason":              reason,
		"requested_transport": c.Transport,
		"upstream_reached":    false,
	}}
}

func oneToolsCall(c Case) (map[string]interface{}, error) {
	rawMessages, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMessages) != 1 {
		return nil, fmt.Errorf("case %s: PR1 requires exactly one jsonrpc_messages tools/call", c.ID)
	}
	message, ok := rawMessages[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("case %s: tools/call message must be an object", c.ID)
	}
	if method, _ := message["method"].(string); method != "tools/call" {
		return nil, fmt.Errorf("case %s: PR1 requires tools/call, got %q", c.ID, method)
	}
	return message, nil
}

func declaredTools(c Case) ([]json.RawMessage, []string, error) {
	rawMessages, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMessages) != 1 {
		return nil, nil, fmt.Errorf("requires exactly one jsonrpc_messages entry")
	}
	message, ok := rawMessages[0].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("tool definition message must be an object")
	}
	result, ok := message["result"].(map[string]interface{})
	if !ok {
		return nil, nil, fmt.Errorf("tool definition message must have a result object")
	}
	rawTools, ok := result["tools"].([]interface{})
	if !ok || len(rawTools) == 0 {
		return nil, nil, fmt.Errorf("tool definition result must contain at least one tool")
	}
	tools := make([]json.RawMessage, 0, len(rawTools))
	names := make([]string, 0, len(rawTools))
	for _, rawTool := range rawTools {
		tool, ok := rawTool.(map[string]interface{})
		if !ok {
			return nil, nil, fmt.Errorf("declared tool must be an object")
		}
		name, ok := tool["name"].(string)
		if !ok || name == "" {
			return nil, nil, fmt.Errorf("declared tool must have a non-empty name")
		}
		encoded, err := json.Marshal(tool)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal declared tool %q: %w", name, err)
		}
		tools = append(tools, encoded)
		names = append(names, name)
	}
	return tools, names, nil
}

func toolsListNames(body []byte) ([]string, bool) {
	var response struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &response); err != nil || len(response.Result) == 0 || bytes.Equal(bytes.TrimSpace(response.Result), []byte("null")) {
		return nil, false
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(response.Result, &result); err != nil {
		return nil, false
	}
	rawTools, ok := result["tools"]
	if !ok || bytes.Equal(bytes.TrimSpace(rawTools), []byte("null")) {
		return nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil || tools == nil {
		return nil, false
	}
	names := make([]string, 0, len(tools))
	for _, rawTool := range tools {
		var tool struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(rawTool, &tool); err != nil || tool.Name == "" {
			return nil, false
		}
		names = append(names, tool.Name)
	}
	return names, true
}

func containsNormalizedToolName(names []string, wanted string) bool {
	normalizedWanted := strings.ToLower(wanted)
	for _, name := range names {
		if strings.ToLower(name) == normalizedWanted {
			return true
		}
	}
	return false
}

func (a *MCPGatewayAdapter) send(ctx context.Context, client *http.Client, caseID string, message map[string]interface{}, requireResponse bool) *Result {
	_, result := a.sendResponse(ctx, client, caseID, message, requireResponse, "empty_tools_call_response")
	return result
}

func (a *MCPGatewayAdapter) sendResponse(ctx context.Context, client *http.Client, caseID string, message map[string]interface{}, requireResponse bool, emptyResponseReason string) ([]byte, *Result) {
	body, err := json.Marshal(message)
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: marshal MCP message: %w", caseID, err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.plugin.Client.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: build MCP gateway request: %w", caseID, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for key, value := range a.plugin.Client.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		if a.plugin.DenySignals.ConnectionClosedNoOut {
			return nil, &Result{Verdict: "block", Evidence: map[string]interface{}{
				"product_surface": "mcp_gateway_streamable_http",
				"reason":          "connection_closed_without_output",
			}}
		}
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway request: %w", caseID, err)}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: read MCP gateway response: %w", caseID, err)}
	}
	if slices.Contains(a.plugin.DenySignals.HTTPStatusCodes, resp.StatusCode) {
		return nil, &Result{Verdict: "block", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"http_status":     resp.StatusCode,
		}}
	}
	if marker := matchingBodyMarker(string(responseBody), a.plugin.DenySignals.CustomBodyMarkers); marker != "" {
		return nil, &Result{Verdict: "block", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"body_marker":     marker,
		}}
	}
	if requireResponse {
		responseBody, err = decodeGatewayResponse(resp.Header.Get("Content-Type"), responseBody, message["id"])
		if err != nil {
			return nil, &Result{Err: fmt.Errorf("case %s: decode MCP gateway response: %w", caseID, err)}
		}
	}
	if result := classifyGatewayJSONRPCError(responseBody, a.plugin.DenySignals.JSONRPCErrorCodeRange); result != nil {
		return nil, result
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"reason":          "unclassified_http_status",
			"http_status":     resp.StatusCode,
		}}
	}
	if requireResponse && len(bytes.TrimSpace(responseBody)) == 0 {
		return nil, &Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface":  "mcp_gateway_streamable_http",
			"reason":           emptyResponseReason,
			"upstream_reached": false,
		}}
	}
	return responseBody, nil
}

func classifyGatewayJSONRPCError(body []byte, denyRange [2]int) *Result {
	var response struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(body), &response); err != nil || response.Error == nil {
		return nil
	}
	evidence := map[string]interface{}{
		"product_surface": "mcp_gateway_streamable_http",
		"error_code":      response.Error.Code,
		"error_message":   response.Error.Message,
	}
	if denyRange != [2]int{} && response.Error.Code >= denyRange[0] && response.Error.Code <= denyRange[1] {
		return &Result{Verdict: "block", Evidence: evidence}
	}
	evidence["reason"] = "unclassified_jsonrpc_error"
	return &Result{Verdict: "skip", Evidence: evidence}
}

func decodeGatewayResponse(contentType string, body []byte, requestID interface{}) ([]byte, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "text/event-stream" {
		return body, nil
	}
	wantedID, err := json.Marshal(requestID)
	if err != nil {
		return nil, fmt.Errorf("marshal request id: %w", err)
	}
	return jsonRPCMessageFromSSE(body, wantedID)
}

func jsonRPCMessageFromSSE(body, wantedID []byte) ([]byte, error) {
	var dataLines [][]byte
	for _, rawLine := range bytes.Split(body, []byte("\n")) {
		line := bytes.TrimSuffix(rawLine, []byte("\r"))
		if len(line) != 0 {
			if bytes.HasPrefix(line, []byte("data:")) {
				data := line[len("data:"):]
				if len(data) > 0 && data[0] == ' ' {
					data = data[1:]
				}
				dataLines = append(dataLines, data)
			}
			continue
		}
		if message := matchingSSEJSONRPCMessage(dataLines, wantedID); message != nil {
			return message, nil
		}
		dataLines = nil
	}
	if message := matchingSSEJSONRPCMessage(dataLines, wantedID); message != nil {
		return message, nil
	}
	return nil, fmt.Errorf("SSE response has no JSON-RPC message for request id %s", wantedID)
}

func matchingSSEJSONRPCMessage(dataLines [][]byte, wantedID []byte) []byte {
	if len(dataLines) == 0 {
		return nil
	}
	message := bytes.Join(dataLines, []byte("\n"))
	var response struct {
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(message, &response); err != nil || len(response.ID) == 0 {
		return nil
	}
	var got, wanted interface{}
	if json.Unmarshal(response.ID, &got) != nil || json.Unmarshal(wantedID, &wanted) != nil || !jsonRPCIDsEqual(got, wanted) {
		return nil
	}
	return message
}

func jsonRPCIDsEqual(got, wanted interface{}) bool {
	return reflect.DeepEqual(got, wanted)
}

func matchingBodyMarker(body string, markers []string) string {
	for _, marker := range markers {
		if marker != "" && strings.Contains(body, marker) {
			return marker
		}
	}
	return ""
}

func (a *MCPGatewayAdapter) upstreamCalls() (int64, bool) {
	if a.mcpHTTPFixture() == nil {
		return 0, false
	}
	return a.mcpHTTPFixture().ToolCalls(), true
}

func (a *MCPGatewayAdapter) upstreamListCalls() (int64, bool) {
	if a.mcpHTTPFixture() == nil {
		return 0, false
	}
	return a.mcpHTTPFixture().ListCalls(), true
}

func (a *MCPGatewayAdapter) mcpHTTPFixture() *fixture.MCPHTTPFixture {
	if a.fixtures == nil {
		return nil
	}
	return a.fixtures.MCPHTTP()
}
