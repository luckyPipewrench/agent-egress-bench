package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// MCPGatewayAdapter drives a plugin-configured MCP gateway over Streamable
// HTTP. Tool definitions use that same client transport and do not substitute
// for corpus mcp_stdio cases.
type MCPGatewayAdapter struct {
	plugin   GatewayPlugin
	fixtures *fixture.Manager
}

var gatewayRequestSequence atomic.Uint64

// gatewayRequest is the single correlation primitive for a case request. The
// adapter mints it before configuring the fixture; the fixture then routes the
// leased response and records the same identity, method, and fingerprint.
type gatewayRequest struct {
	identity    string
	method      string
	fingerprint string
}

func nextGatewayRequestIdentity() string {
	return fmt.Sprintf("aeb-request-%d", gatewayRequestSequence.Add(1))
}

func withGatewayRequestIdentity(message map[string]interface{}, identity string) (map[string]interface{}, gatewayRequest, error) {
	copyMessage := make(map[string]interface{}, len(message))
	for key, value := range message {
		copyMessage[key] = value
	}
	params, _ := message["params"].(map[string]interface{})
	copyParams := make(map[string]interface{}, len(params)+1)
	for key, value := range params {
		copyParams[key] = value
	}
	meta, _ := params["_meta"].(map[string]interface{})
	copyMeta := make(map[string]interface{}, len(meta)+1)
	for key, value := range meta {
		copyMeta[key] = value
	}
	copyMeta["aeb_request_identity"] = identity
	copyParams["_meta"] = copyMeta
	copyMessage["params"] = copyParams
	// The case's literal request ID is not a safe correlation key: many cases
	// legitimately reuse it. The adapter owns this wire ID, so make it unique
	// per request and use the same value in JSON and SSE response validation.
	copyMessage["id"] = identity
	body, err := json.Marshal(copyMessage)
	if err != nil {
		return nil, gatewayRequest{}, fmt.Errorf("marshal request identity: %w", err)
	}
	fingerprint, err := fixture.MCPRequestFingerprint(body)
	if err != nil {
		return nil, gatewayRequest{}, err
	}
	method, _ := copyMessage["method"].(string)
	return copyMessage, gatewayRequest{identity: identity, method: method, fingerprint: fingerprint}, nil
}

// DeliveryTuples declares the exact wire paths this adapter can drive. The
// runner does not use this declaration for scoring until the result-state
// implementation supplies unreachable and evidence semantics.
func (a *MCPGatewayAdapter) DeliveryTuples() []DeliveryTuple {
	return []DeliveryTuple{
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_call", Lifecycle: "mcp_session"},
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_definition", Lifecycle: "mcp_session"},
		// The corpus historically models tool definitions as mcp_stdio input
		// while this adapter drives their semantic inventory over Streamable HTTP.
		{WireTransport: "mcp_stdio", SemanticSurface: "mcp_tool_definition", Lifecycle: "mcp_session"},
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_result", Lifecycle: "mcp_session"},
	}
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
// endpoint.
func (a *MCPGatewayAdapter) Run(c Case, timeout time.Duration) Result {
	switch c.InputType {
	case "mcp_tool_call":
		if c.Transport != "mcp_http" {
			return gatewaySkip(c, "gateway tools/call supports corpus transport mcp_http only")
		}
		return a.runToolsCall(c, timeout)
	case "mcp_tool_definition":
		if c.Transport != "mcp_http" && c.Transport != "mcp_stdio" {
			return gatewaySkip(c, "gateway tools/list supports corpus transport mcp_http or mcp_stdio")
		}
		return a.runToolDefinition(c, timeout)
	case "mcp_tool_result":
		if c.Transport != "mcp_http" {
			return gatewaySkip(c, "gateway tool-result response supports corpus transport mcp_http only")
		}
		return a.runToolResult(c, timeout)
	default:
		return gatewaySkip(c, "gateway adapter does not support input type "+c.InputType)
	}
}

func (a *MCPGatewayAdapter) runToolResult(c Case, timeout time.Duration) Result {
	resultPayload, err := declaredToolResult(c)
	if err != nil {
		return gatewaySkip(c, "gateway tool-result response requires one JSON-RPC result: "+err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	upstream := a.mcpHTTPFixture()
	if upstream == nil {
		return gatewaySkip(c, "gateway tool-result response requires the MCP HTTP fixture")
	}
	identity := nextGatewayRequestIdentity()
	call := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-tool-result",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "aeb_tool_result_fixture",
			"arguments": map[string]interface{}{},
		},
	}
	call, request, err := withGatewayRequestIdentity(call, identity)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare tool-result request: %w", c.ID, err)}
	}
	release, err := upstream.AcquireToolResultLease(ctx, request.identity, resultPayload)
	if err != nil {
		return gatewaySkip(c, "gateway tool-result lease timeout")
	}
	defer release()

	client := &http.Client{}
	sess := &gatewaySession{}
	if result := a.initialize(ctx, client, c.ID, sess); result != nil {
		return *result
	}

	_, observed := a.sendResponse(ctx, client, c.ID, call, true, "empty_tool_result_response", sess, &request, deliveryRequired)
	delivered, proofAvailable := a.requestDelivered(request)
	if observed != nil {
		return *observed
	}
	if !proofAvailable || !delivered {
		return Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface":  "mcp_gateway_streamable_http",
			"reason":           "tool_result_upstream_unproven",
			"upstream_reached": false,
			"request_identity": request.identity,
		}}
	}
	return Result{Verdict: "allow", Evidence: map[string]interface{}{
		"product_surface":  "mcp_gateway_streamable_http",
		"upstream_reached": true,
		"request_identity": request.identity,
	}}
}

func (a *MCPGatewayAdapter) runToolsCall(c Case, timeout time.Duration) Result {
	toolsCalls, err := toolsCallMessages(c)
	if err != nil {
		return Result{Err: err}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := &http.Client{}
	sess := &gatewaySession{}
	if result := a.initialize(ctx, client, c.ID, sess); result != nil {
		return *result
	}

	// Drive the tools/call sequence in order over the one session. A deny on any
	// call blocks the whole sequence and names which message the gateway stopped.
	requests := make([]gatewayRequest, 0, len(toolsCalls))
	for i, toolsCall := range toolsCalls {
		message, request, err := withGatewayRequestIdentity(toolsCall, nextGatewayRequestIdentity())
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/call request %d: %w", c.ID, i, err)}
		}
		requests = append(requests, request)
		result := a.send(ctx, client, c.ID, message, true, sess, &request, deliveryAbsent)
		if result != nil {
			if len(toolsCalls) > 1 && result.Verdict == "block" && result.Evidence != nil {
				result.Evidence["blocked_message_index"] = i
			}
			return *result
		}
	}
	evidence := map[string]interface{}{
		"product_surface": "mcp_gateway_streamable_http",
	}
	if len(toolsCalls) > 1 {
		evidence["tools_call_count"] = len(toolsCalls)
	}
	requestIdentities := make([]string, 0, len(requests))
	for _, request := range requests {
		requestIdentities = append(requestIdentities, request.identity)
		// The per-request observation avoids both counter-delta contamination and
		// copied-token proof. This ordinary tools/call path allows only after its
		// own request reached the fixture.
		if delivered, proofAvailable := a.requestDelivered(request); !proofAvailable || !delivered {
			evidence["upstream_reached"] = false
			if !proofAvailable {
				evidence["upstream_proof"] = "unavailable"
			}
			return Result{Verdict: "skip", Evidence: evidence}
		}
	}
	evidence["request_identities"] = requestIdentities
	evidence["upstream_reached"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

func (a *MCPGatewayAdapter) runToolDefinition(c Case, timeout time.Duration) Result {
	tools, declaredNames, err := declaredTools(c)
	if err != nil {
		return gatewaySkip(c, "gateway tools/list requires one tools/list-style tool definition: "+err.Error())
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	toolsList := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-tools-list",
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}
	toolsList, request, err := withGatewayRequestIdentity(toolsList, nextGatewayRequestIdentity())
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare tools/list request: %w", c.ID, err)}
	}
	if upstream := a.mcpHTTPFixture(); upstream != nil {
		release, err := upstream.AcquireToolDefinitionLease(ctx, request.identity, tools)
		if err != nil {
			return Result{Verdict: "skip", Evidence: map[string]interface{}{
				"product_surface":     "mcp_gateway_streamable_http",
				"reason":              "tool_definition_lease_timeout",
				"requested_transport": c.Transport,
				"upstream_reached":    false,
			}}
		}
		defer release()
	}

	client := &http.Client{}
	sess := &gatewaySession{}
	if result := a.initialize(ctx, client, c.ID, sess); result != nil {
		return *result
	}

	responseBody, result := a.sendResponse(ctx, client, c.ID, toolsList, true, "empty_tools_list_response", sess, &request, deliveryRequired)
	if result != nil {
		return *result
	}
	evidence := map[string]interface{}{
		"product_surface":  "mcp_gateway_streamable_http",
		"request_identity": request.identity,
	}
	delivered, proofAvailable := a.requestDelivered(request)
	if !proofAvailable || !delivered {
		evidence["upstream_reached"] = false
		if !proofAvailable {
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

func (a *MCPGatewayAdapter) requestDelivered(request gatewayRequest) (bool, bool) {
	upstream := a.mcpHTTPFixture()
	if upstream == nil {
		return false, false
	}
	observations := upstream.Observation(request.identity)
	if len(observations) != 1 {
		return false, true
	}
	observation := observations[0]
	return observation.Identity == request.identity && observation.Method == request.method && observation.Fingerprint == request.fingerprint, true
}

func (a *MCPGatewayAdapter) initialize(ctx context.Context, client *http.Client, caseID string, sess *gatewaySession) *Result {
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
	if result := a.send(ctx, client, caseID, initialize, false, sess, nil, deliveryAbsent); result != nil {
		return result
	}
	initialized := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}
	return a.send(ctx, client, caseID, initialized, false, sess, nil, deliveryAbsent)
}

func gatewaySkip(c Case, reason string) Result {
	return Result{Verdict: "skip", Evidence: map[string]interface{}{
		"reason":              reason,
		"requested_transport": c.Transport,
		"upstream_reached":    false,
	}}
}

func toolsCallMessages(c Case) ([]map[string]interface{}, error) {
	rawMessages, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMessages) == 0 {
		return nil, fmt.Errorf("case %s: requires at least one jsonrpc_messages tools/call", c.ID)
	}
	messages := make([]map[string]interface{}, 0, len(rawMessages))
	for i, raw := range rawMessages {
		message, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("case %s: tools/call message %d must be an object", c.ID, i)
		}
		if method, _ := message["method"].(string); method != "tools/call" {
			return nil, fmt.Errorf("case %s: message %d must be tools/call, got %q", c.ID, i, method)
		}
		messages = append(messages, message)
	}
	return messages, nil
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

func declaredToolResult(c Case) (json.RawMessage, error) {
	rawMessages, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMessages) != 1 {
		return nil, fmt.Errorf("requires exactly one jsonrpc_messages entry")
	}
	message, ok := rawMessages[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("tool result message must be an object")
	}
	result, ok := message["result"]
	if !ok || result == nil {
		return nil, fmt.Errorf("tool result message must have a non-null result")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshal tool result: %w", err)
	}
	return encoded, nil
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

func (a *MCPGatewayAdapter) send(ctx context.Context, client *http.Client, caseID string, message map[string]interface{}, requireResponse bool, sess *gatewaySession, request *gatewayRequest, expectation deliveryExpectation) *Result {
	_, result := a.sendResponse(ctx, client, caseID, message, requireResponse, "empty_tools_call_response", sess, request, expectation)
	return result
}

// gatewaySession carries the Mcp-Session-Id a Streamable HTTP gateway binds on
// initialize across the remaining requests of a single case. It is created per
// case so a session never leaks between cases or races across concurrent runs.
type gatewaySession struct {
	id string
}

func (a *MCPGatewayAdapter) sendResponse(ctx context.Context, client *http.Client, caseID string, message map[string]interface{}, requireResponse bool, emptyResponseReason string, sess *gatewaySession, request *gatewayRequest, expectation deliveryExpectation) ([]byte, *Result) {
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
	// Replay a bound session id on every request after initialize. Set it after
	// the operator headers so the live session id is authoritative.
	if sess != nil && sess.id != "" {
		req.Header.Set("Mcp-Session-Id", sess.id)
	}

	resp, err := client.Do(req)
	if err != nil {
		return a.classifyGatewayResponse(nil, nil, err, requireResponse, emptyResponseReason, request, expectation, caseID)
	}
	defer func() { _ = resp.Body.Close() }()
	// Capture the session id the gateway assigns on initialize so later requests
	// in this case carry it. The binding is initialize-only: an Mcp-Session-Id on
	// any later response is not adopted, so an unnegotiated id never reaches the
	// tools/call.
	if sess != nil && sess.id == "" && message["method"] == "initialize" {
		if assigned := resp.Header.Get("Mcp-Session-Id"); assigned != "" {
			sess.id = assigned
		}
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: read MCP gateway response: %w", caseID, err)}
	}
	return a.classifyGatewayResponse(resp, responseBody, nil, requireResponse, emptyResponseReason, request, expectation, caseID)
}

type deliveryExpectation bool

const (
	// deliveryAbsent applies where a gateway blocks an outbound tools/call. A
	// block requires proof that the exact request did not reach the fixture.
	deliveryAbsent deliveryExpectation = false
	// deliveryRequired applies where the gateway must first see runner-owned
	// upstream content: tool-result inspection and tools/list filtering.
	deliveryRequired deliveryExpectation = true
)

// classifyGatewayResponse is the only place that turns a gateway response and
// fixture observation into a disposition. The two directions are deliberate:
// no stale, uncorrelated, or unproven denial can score block; a configured HTTP
// status or documented body marker from http.Client.Do is already correlated to
// this request and must not lose credit merely because it has no JSON-RPC body.
func (a *MCPGatewayAdapter) classifyGatewayResponse(resp *http.Response, body []byte, transportErr error, requireResponse bool, emptyResponseReason string, request *gatewayRequest, expectation deliveryExpectation, caseID string) ([]byte, *Result) {
	if transportErr != nil {
		if a.plugin.DenySignals.ConnectionClosedNoOut {
			// A connection failure has no response bound to the request. Even with
			// fixture evidence it is indistinguishable from a network failure, so it
			// cannot meet the correlation requirement for block.
			return nil, a.gatewaySkipWithObservation("connection_closed_without_output", request, 0, "")
		}
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway request: %w", caseID, transportErr)}
	}
	if !requireResponse {
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return nil, a.gatewaySkipWithObservation("unclassified_initialization_status", request, resp.StatusCode, "")
		}
		return body, nil
	}
	if slices.Contains(a.plugin.DenySignals.HTTPStatusCodes, resp.StatusCode) {
		return nil, a.gatewayDeny("http_status", request, expectation, resp.StatusCode, "")
	}
	if marker := matchingBodyMarker(string(body), a.plugin.DenySignals.CustomBodyMarkers); marker != "" {
		return nil, a.gatewayDeny("body_marker", request, expectation, resp.StatusCode, marker)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, a.gatewaySkipWithObservation("unclassified_http_status", request, resp.StatusCode, "")
	}
	response, err := decodeGatewayResponse(resp.Header.Get("Content-Type"), body, messageID(request))
	if err != nil {
		return nil, a.gatewayDecodeFailure(err, request, resp.StatusCode)
	}
	if result := classifyGatewayJSONRPCError(response, a.plugin.DenySignals.JSONRPCErrorCodeRange); result != nil {
		if result.Verdict == "block" {
			return nil, a.gatewayDeny("jsonrpc_error", request, expectation, resp.StatusCode, "")
		}
		a.attachObservation(result, request)
		return nil, result
	}
	return response, nil
}

func messageID(request *gatewayRequest) interface{} {
	if request == nil {
		return nil
	}
	return request.identity
}

func (a *MCPGatewayAdapter) gatewayDeny(signal string, request *gatewayRequest, expectation deliveryExpectation, status int, marker string) *Result {
	delivered, proofAvailable := false, false
	if request != nil {
		delivered, proofAvailable = a.requestDelivered(*request)
	}
	evidence := map[string]interface{}{"product_surface": "mcp_gateway_streamable_http", "deny_signal": signal}
	if status != 0 {
		evidence["http_status"] = status
	}
	if marker != "" {
		evidence["body_marker"] = marker
	}
	a.attachObservationEvidence(evidence, request, delivered, proofAvailable)
	if !proofAvailable || delivered != bool(expectation) {
		evidence["reason"] = "deny_delivery_unproven"
		return &Result{Verdict: "skip", Evidence: evidence}
	}
	return &Result{Verdict: "block", Evidence: evidence}
}

func (a *MCPGatewayAdapter) gatewaySkipWithObservation(reason string, request *gatewayRequest, status int, marker string) *Result {
	delivered, proofAvailable := false, false
	if request != nil {
		delivered, proofAvailable = a.requestDelivered(*request)
	}
	evidence := map[string]interface{}{"product_surface": "mcp_gateway_streamable_http", "reason": reason}
	if status != 0 {
		evidence["http_status"] = status
	}
	if marker != "" {
		evidence["body_marker"] = marker
	}
	a.attachObservationEvidence(evidence, request, delivered, proofAvailable)
	return &Result{Verdict: "skip", Evidence: evidence}
}

func (a *MCPGatewayAdapter) gatewayDecodeFailure(err error, request *gatewayRequest, status int) *Result {
	reason := "malformed_jsonrpc_response"
	var mismatch *responseCorrelationError
	var malformedSSE *malformedSSEResponseError
	if errors.As(err, &mismatch) {
		reason = "response_id_mismatch"
	} else if errors.As(err, &malformedSSE) {
		reason = "malformed_sse_response"
	}
	return a.gatewaySkipWithObservation(reason, request, status, "")
}

func (a *MCPGatewayAdapter) attachObservation(result *Result, request *gatewayRequest) {
	if result == nil {
		return
	}
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	delivered, proofAvailable := false, false
	if request != nil {
		delivered, proofAvailable = a.requestDelivered(*request)
	}
	a.attachObservationEvidence(result.Evidence, request, delivered, proofAvailable)
}

func (a *MCPGatewayAdapter) attachObservationEvidence(evidence map[string]interface{}, request *gatewayRequest, delivered, proofAvailable bool) {
	if request != nil {
		evidence["request_identity"] = request.identity
	}
	evidence["upstream_reached"] = delivered
	if !proofAvailable {
		evidence["upstream_proof"] = "unavailable"
	}
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
	wantedID, err := json.Marshal(requestID)
	if err != nil {
		return nil, fmt.Errorf("marshal request id: %w", err)
	}
	if err != nil || mediaType != "text/event-stream" {
		response, err := jsonRPCMessageForRequest(body, wantedID)
		if err != nil {
			return nil, fmt.Errorf("JSON response: %w", err)
		}
		return response, nil
	}
	response, err := jsonRPCMessageFromSSE(body, wantedID)
	if err != nil {
		return nil, &malformedSSEResponseError{err: err}
	}
	return response, nil
}

type malformedSSEResponseError struct{ err error }

func (e *malformedSSEResponseError) Error() string { return e.err.Error() }

func (e *malformedSSEResponseError) Unwrap() error { return e.err }

type responseCorrelationError struct{ err error }

func (e *responseCorrelationError) Error() string { return e.err.Error() }

func (e *responseCorrelationError) Unwrap() error { return e.err }

func jsonRPCMessageFromSSE(body, wantedID []byte) ([]byte, error) {
	var dataLines [][]byte
	var mismatch error
	var malformed error
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
		if message, err := matchingSSEJSONRPCMessage(dataLines, wantedID); err == nil && message != nil {
			return message, nil
		} else if err != nil {
			var correlation *responseCorrelationError
			if errors.As(err, &correlation) {
				mismatch = err
			} else {
				malformed = err
			}
		}
		dataLines = nil
	}
	if message, err := matchingSSEJSONRPCMessage(dataLines, wantedID); err == nil && message != nil {
		return message, nil
	} else if err != nil {
		var correlation *responseCorrelationError
		if errors.As(err, &correlation) {
			mismatch = err
		} else {
			malformed = err
		}
	}
	if mismatch != nil {
		return nil, mismatch
	}
	if malformed != nil {
		return nil, &malformedSSEResponseError{err: malformed}
	}
	return nil, &malformedSSEResponseError{err: fmt.Errorf("SSE response has no JSON-RPC message for request id %s", wantedID)}
}

func matchingSSEJSONRPCMessage(dataLines [][]byte, wantedID []byte) ([]byte, error) {
	if len(dataLines) == 0 {
		return nil, nil
	}
	message := bytes.Join(dataLines, []byte("\n"))
	if _, err := jsonRPCMessageForRequest(message, wantedID); err != nil {
		return nil, err
	}
	return message, nil
}

func jsonRPCMessageForRequest(message, wantedID []byte) ([]byte, error) {
	var response map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(message), &response); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	version, ok := response["jsonrpc"]
	if !ok || !bytes.Equal(bytes.TrimSpace(version), []byte(`"2.0"`)) {
		return nil, errors.New("JSON-RPC response must contain jsonrpc 2.0")
	}
	id, ok := response["id"]
	if !ok || len(id) == 0 {
		return nil, errors.New("JSON-RPC response has no id")
	}
	_, hasResult := response["result"]
	_, hasError := response["error"]
	if hasResult == hasError {
		return nil, errors.New("JSON-RPC response must contain exactly one result or error")
	}
	if hasError {
		var rpcError struct {
			Code    *int    `json:"code"`
			Message *string `json:"message"`
		}
		if err := json.Unmarshal(response["error"], &rpcError); err != nil || rpcError.Code == nil || rpcError.Message == nil {
			return nil, errors.New("JSON-RPC response error must contain code and message")
		}
	}
	var got, wanted interface{}
	if err := json.Unmarshal(id, &got); err != nil {
		return nil, fmt.Errorf("decode response id: %w", err)
	}
	if err := json.Unmarshal(wantedID, &wanted); err != nil {
		return nil, fmt.Errorf("decode request id: %w", err)
	}
	if !jsonRPCIDsEqual(got, wanted) {
		return nil, &responseCorrelationError{err: fmt.Errorf("JSON-RPC response id %s does not match request id %s", id, wantedID)}
	}
	return message, nil
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

func (a *MCPGatewayAdapter) mcpHTTPFixture() *fixture.MCPHTTPFixture {
	if a.fixtures == nil {
		return nil
	}
	return a.fixtures.MCPHTTP()
}
