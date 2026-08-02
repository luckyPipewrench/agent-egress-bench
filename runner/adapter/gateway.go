package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// MCPGatewayAdapter drives a plugin-configured MCP gateway. PR1 deliberately
// supports one Streamable HTTP tools/call path only; lifecycle and fixture
// registration commands remain plugin contract fields for later slices.
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

// Run performs initialize, initialized, and exactly one corpus tools/call.
func (a *MCPGatewayAdapter) Run(c Case, timeout time.Duration) Result {
	if c.Transport != "mcp_http" {
		return gatewaySkip(c, "PR1 supports corpus transport mcp_http only")
	}
	if c.InputType != "mcp_tool_call" {
		return gatewaySkip(c, "PR1 supports mcp_tool_call input only")
	}
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

func (a *MCPGatewayAdapter) send(ctx context.Context, client *http.Client, caseID string, message map[string]interface{}, requireResponse bool) *Result {
	body, err := json.Marshal(message)
	if err != nil {
		return &Result{Err: fmt.Errorf("case %s: marshal MCP message: %w", caseID, err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.plugin.Client.Endpoint, bytes.NewReader(body))
	if err != nil {
		return &Result{Err: fmt.Errorf("case %s: build MCP gateway request: %w", caseID, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	for key, value := range a.plugin.Client.Headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		if a.plugin.DenySignals.ConnectionClosedNoOut {
			return &Result{Verdict: "block", Evidence: map[string]interface{}{
				"product_surface": "mcp_gateway_streamable_http",
				"reason":          "connection_closed_without_output",
			}}
		}
		return &Result{Err: fmt.Errorf("case %s: MCP gateway request: %w", caseID, err)}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return &Result{Err: fmt.Errorf("case %s: read MCP gateway response: %w", caseID, err)}
	}
	if slices.Contains(a.plugin.DenySignals.HTTPStatusCodes, resp.StatusCode) {
		return &Result{Verdict: "block", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"http_status":     resp.StatusCode,
		}}
	}
	if marker := matchingBodyMarker(string(responseBody), a.plugin.DenySignals.CustomBodyMarkers); marker != "" {
		return &Result{Verdict: "block", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"body_marker":     marker,
		}}
	}
	if result := classifyMCPHTTPBlockForRange(responseBody, a.plugin.DenySignals.JSONRPCErrorCodeRange, "mcp_gateway_streamable_http"); result != nil {
		return result
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"reason":          "unclassified_http_status",
			"http_status":     resp.StatusCode,
		}}
	}
	if requireResponse && len(bytes.TrimSpace(responseBody)) == 0 {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface":  "mcp_gateway_streamable_http",
			"reason":           "empty_tools_call_response",
			"upstream_reached": false,
		}}
	}
	return nil
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
	if a.fixtures == nil || a.fixtures.MCPHTTP() == nil {
		return 0, false
	}
	return a.fixtures.MCPHTTP().Calls(), true
}
