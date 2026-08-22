package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// MCPGatewayAdapter drives a plugin-configured MCP gateway over Streamable
// HTTP. Tool definitions use that same client transport and do not substitute
// for corpus mcp_stdio cases.
type MCPGatewayAdapter struct {
	plugin   GatewayPlugin
	fixtures *fixture.Manager
	// denyBarrier is an optional authoritative atomic non-delivery proof. The
	// generic shell lifecycle does not supply one: process groups and listener
	// closure cannot contain daemonized workers.
	denyBarrier func(observe func() bool) (absent bool, err error)
}

// gatewayRequest is the single correlation primitive for a case request. The
// adapter mints an opaque identity immediately before configuring the fixture;
// the fixture then routes the leased response and records the same identity,
// method, and fingerprint.
type gatewayRequest struct {
	identity    string
	method      string
	fingerprint string
}

func nextGatewayRequestIdentity() (string, error) {
	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generate request identity: %w", err)
	}
	// Fixed-width decimal preserves all 256 random bits while keeping these
	// correlation values below 4-bit query-entropy thresholds. Hex plus the
	// fixed prefix can block the benchmark's own delivery proof before it
	// reaches the trusted fixture.
	decimal := new(big.Int).SetBytes(nonce[:]).String()
	return "aeb-request-" + strings.Repeat("0", 78-len(decimal)) + decimal, nil
}

func prepareGatewayRequest(message map[string]interface{}) (map[string]interface{}, gatewayRequest, error) {
	identity, err := nextGatewayRequestIdentity()
	if err != nil {
		return nil, gatewayRequest{}, err
	}
	return withGatewayRequestIdentity(message, identity)
}

func withGatewayRequestIdentity(message map[string]interface{}, identity string) (map[string]interface{}, gatewayRequest, error) {
	copyMessage := make(map[string]interface{}, len(message))
	for key, value := range message {
		copyMessage[key] = value
	}
	rawParams, present := message["params"]
	params, ok := rawParams.(map[string]interface{})
	if present && rawParams != nil && !ok {
		return nil, gatewayRequest{}, fmt.Errorf("request params must be a JSON object")
	}
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

// DeliveryTuples declares the exact wire paths this adapter can attempt. The
// result-state machine still needs per-case delivery proof and a correlated
// verdict before it can score any declared tuple.
func (a *MCPGatewayAdapter) DeliveryTuples() []DeliveryTuple {
	return []DeliveryTuple{
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_call", Lifecycle: "mcp_session"},
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_sequence", Lifecycle: "mcp_session"},
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_sequence_temporal", Lifecycle: "mcp_session"},
		{WireTransport: "mcp_http", SemanticSurface: "mcp_tool_definition", Lifecycle: "mcp_session"},
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
	for key := range plugin.Client.Headers {
		if strings.EqualFold(key, "Mcp-Session-Id") {
			return nil, fmt.Errorf("gateway plugin client.headers must not set Mcp-Session-Id; the adapter binds only the live initialize response")
		}
	}
	return &MCPGatewayAdapter{plugin: plugin, fixtures: fixtures}, nil
}

// SetDenyBarrier supplies an authoritative proof that a denied request cannot
// be forwarded after the adapter scores it. Generic managed and operator-run
// gateways have no such proof, so their denies remain unscoreable instead of
// relying on a finite silence window or process-lifecycle inference.
func (a *MCPGatewayAdapter) SetDenyBarrier(barrier func(observe func() bool) (bool, error)) {
	a.denyBarrier = barrier
}

// Run drives a supported corpus case through the gateway's Streamable HTTP
// endpoint.
func (a *MCPGatewayAdapter) Run(c Case, timeout time.Duration) Result {
	var result Result
	switch c.InputType {
	case "mcp_tool_call":
		if c.Transport != "mcp_http" {
			result = gatewaySkip(c, "gateway tools/call supports corpus transport mcp_http only")
			break
		}
		result = a.runToolsCall(c, timeout, false)
	case "mcp_tool_sequence":
		if c.Transport != "mcp_http" {
			result = gatewaySkip(c, "gateway dependent tools/call sequence supports corpus transport mcp_http only")
			break
		}
		result = a.runToolsCall(c, timeout, true)
	case "mcp_tool_sequence_temporal":
		if c.Transport != "mcp_http" {
			result = gatewaySkip(c, "gateway temporal inventory supports native mcp_http cases only")
			break
		}
		result = a.runTemporalInventory(c, timeout)
	case "mcp_tool_definition":
		if c.Transport != "mcp_http" {
			result = gatewaySkip(c, "gateway tools/list supports corpus transport mcp_http only")
			break
		}
		result = a.runToolDefinition(c, timeout)
	case "mcp_tool_result":
		if c.Transport != "mcp_http" {
			result = gatewaySkip(c, "gateway tool-result response supports corpus transport mcp_http only")
			break
		}
		result = a.runToolResult(c, timeout)
	default:
		result = gatewaySkip(c, "gateway adapter does not support input type "+c.InputType)
	}
	// An allow can only come from a fixture-correlated forward path. A block may
	// come from that same path or from gatewayDeny, which records its own
	// direction-sensitive proof below. Do not turn a syntactically normal verdict
	// into proof here: malformed, stale, and lifecycle responses stay unobserved.
	if result.Err == nil && (result.Verdict == "allow" || result.Verdict == "block") && result.Evidence != nil {
		if delivered, _ := result.Evidence["upstream_reached"].(bool); delivered {
			result.DeliveryProven = true
			result.VerdictObserved = true
		}
	} else if result.Err == nil && result.Evidence != nil {
		result.DeliveryProven, _ = result.Evidence["upstream_reached"].(bool)
	}
	return result
}

type temporalInventoryStep struct {
	request   map[string]interface{}
	tools     []json.RawMessage
	canonical []byte
}

func (a *MCPGatewayAdapter) runTemporalInventory(c Case, timeout time.Duration) Result {
	steps, err := temporalInventorySteps(c)
	if err != nil {
		return gatewaySkip(c, "gateway temporal inventory requires one before/after tools/list pair: "+err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	upstream := a.mcpHTTPFixture()
	if upstream == nil {
		return gatewaySkip(c, "gateway temporal inventory requires the MCP HTTP fixture")
	}

	client := &http.Client{}
	sess := &gatewaySession{}
	if result := a.initialize(ctx, client, c.ID, sess); result != nil {
		return *result
	}
	if sess.id == "" {
		return Result{Verdict: "skip", Evidence: map[string]interface{}{
			"product_surface": "mcp_gateway_streamable_http",
			"reason":          "temporal_session_unbound",
			"session_bound":   false,
		}}
	}
	evidence := map[string]interface{}{
		"product_surface": "mcp_gateway_streamable_http",
		"session_bound":   true,
	}
	requests := make([]gatewayRequest, 0, len(steps))

	baselineMessage, baselineRequest, err := prepareGatewayRequest(steps[0].request)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare baseline tools/list request: %w", c.ID, err)}
	}
	baselineRelease, err := upstream.AcquireSessionToolDefinitionLease(ctx, baselineRequest.identity, sess.id, steps[0].tools)
	if err != nil {
		return gatewaySkip(c, "gateway baseline inventory lease failed: "+err.Error())
	}
	requests = append(requests, baselineRequest)

	baselineBody, baselineResult := a.sendResponse(ctx, client, c.ID, baselineMessage, true, "empty_baseline_tools_list_response", sess, &requests[0], deliveryRequired)
	baselineRelease()
	evidence["inventory_request_identities"] = []string{requests[0].identity}
	if baselineResult != nil {
		baselineResult.Verdict = "skip"
		if baselineResult.Evidence == nil {
			baselineResult.Evidence = evidence
		} else {
			for key, value := range evidence {
				baselineResult.Evidence[key] = value
			}
		}
		baselineResult.Evidence["reason"] = "baseline_inventory_not_established"
		baselineResult.Evidence["original_inventory_delivered_to_agent"] = false
		baselineResult.Evidence["changed_inventory_delivered_to_agent"] = false
		return *baselineResult
	}
	baselineDelivered, baselineProof := a.requestDelivered(requests[0])
	baselineCanonical, baselineValid := toolsListCanonical(baselineBody)
	if !baselineProof || !baselineDelivered || !baselineValid || !bytes.Equal(baselineCanonical, steps[0].canonical) {
		evidence["reason"] = "baseline_inventory_not_established"
		evidence["original_inventory_reached_upstream"] = baselineDelivered
		evidence["original_inventory_delivered_to_agent"] = false
		evidence["changed_inventory_delivered_to_agent"] = false
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["original_inventory_reached_upstream"] = true
	evidence["original_inventory_delivered_to_agent"] = true

	changedMessage, changedRequest, err := prepareGatewayRequest(steps[1].request)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare changed tools/list request: %w", c.ID, err)}
	}
	changedRelease, err := upstream.AcquireSessionToolDefinitionLease(ctx, changedRequest.identity, sess.id, steps[1].tools)
	if err != nil {
		return gatewaySkip(c, "gateway changed inventory lease failed: "+err.Error())
	}
	requests = append(requests, changedRequest)
	evidence["inventory_request_identities"] = []string{requests[0].identity, requests[1].identity}
	changedBody, changedResult := a.sendResponse(ctx, client, c.ID, changedMessage, true, "empty_changed_tools_list_response", sess, &requests[1], deliveryRequired)
	changedRelease()
	changedDelivered, changedProof := a.requestDelivered(requests[1])
	evidence["changed_inventory_reached_upstream"] = changedProof && changedDelivered
	if changedResult != nil {
		if changedResult.Evidence == nil {
			changedResult.Evidence = map[string]interface{}{}
		}
		for key, value := range evidence {
			changedResult.Evidence[key] = value
		}
		changedResult.Evidence["changed_inventory_delivered_to_agent"] = false
		return *changedResult
	}
	if !changedProof || !changedDelivered {
		evidence["reason"] = "changed_inventory_upstream_unproven"
		evidence["changed_inventory_delivered_to_agent"] = false
		return Result{Verdict: "skip", Evidence: evidence}
	}
	// Past this guard the changed inventory is proven to have reached the
	// runner-owned upstream, which is what delivery means for this path. Run
	// derives DeliveryProven and VerdictObserved from upstream_reached alone,
	// so recording delivery only under temporal-specific keys left every
	// temporal allow and block unproven, scored as an error, and made the
	// drift cases this path exists for unscoreable. It is set here rather than
	// on each return so a later branch cannot forget it, and only after the
	// proof is established so it can never assert delivery that did not happen.
	evidence["upstream_reached"] = true
	changedCanonical, changedValid := toolsListCanonical(changedBody)
	if !changedValid {
		evidence["reason"] = "malformed_changed_inventory"
		evidence["changed_inventory_delivered_to_agent"] = false
		return Result{Verdict: "skip", Evidence: evidence}
	}
	if !bytes.Equal(changedCanonical, steps[1].canonical) {
		evidence["reason"] = "changed_inventory_withheld_or_modified"
		evidence["changed_inventory_delivered_to_agent"] = false
		return Result{Verdict: "block", Evidence: evidence}
	}
	evidence["changed_inventory_delivered_to_agent"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

func temporalInventorySteps(c Case) ([]temporalInventoryStep, error) {
	rawMessages, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMessages) != 4 {
		return nil, fmt.Errorf("requires exactly four request/response messages; multi-server topology is unsupported")
	}
	steps := make([]temporalInventoryStep, 0, 2)
	for i := 0; i < len(rawMessages); i += 2 {
		request, ok := rawMessages[i].(map[string]interface{})
		if !ok || request["method"] != "tools/list" {
			return nil, fmt.Errorf("message %d must be a tools/list request", i)
		}
		requestID, hasRequestID := request["id"]
		response, ok := rawMessages[i+1].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("message %d must be a tools/list response", i+1)
		}
		responseID, hasResponseID := response["id"]
		if !hasRequestID || !hasResponseID || !reflect.DeepEqual(requestID, responseID) {
			return nil, fmt.Errorf("messages %d and %d must carry matching IDs", i, i+1)
		}
		result, ok := response["result"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("message %d must contain a result object", i+1)
		}
		rawTools, ok := result["tools"].([]interface{})
		if !ok || len(rawTools) == 0 {
			return nil, fmt.Errorf("message %d result must contain at least one tool", i+1)
		}
		tools := make([]json.RawMessage, 0, len(rawTools))
		for j, rawTool := range rawTools {
			encoded, marshalErr := json.Marshal(rawTool)
			if marshalErr != nil {
				return nil, fmt.Errorf("message %d tool %d: %w", i+1, j, marshalErr)
			}
			tools = append(tools, encoded)
		}
		canonical, canonicalErr := canonicalJSON(tools)
		if canonicalErr != nil {
			return nil, canonicalErr
		}
		steps = append(steps, temporalInventoryStep{request: request, tools: tools, canonical: canonical})
	}
	return steps, nil
}

func toolsListCanonical(body []byte) ([]byte, bool) {
	var response struct {
		Result struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Result.Tools) == 0 {
		return nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(response.Result.Tools, &tools); err != nil || len(tools) == 0 {
		return nil, false
	}
	canonical, err := canonicalJSON(tools)
	return canonical, err == nil
}

func canonicalJSON(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized interface{}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return nil, err
	}
	return json.Marshal(normalized)
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
	call := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-tool-result",
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      "aeb_tool_result_fixture",
			"arguments": map[string]interface{}{},
		},
	}
	call, request, err := prepareGatewayRequest(call)
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

func (a *MCPGatewayAdapter) runToolsCall(c Case, timeout time.Duration, requireFinalSink bool) Result {
	toolsCalls, err := toolsCallMessages(c)
	if err != nil {
		return Result{Err: err}
	}
	// The documented split is that mcp_tool_call is exactly one call and
	// mcp_tool_sequence carries dependent multi-call flows with prefix and
	// final-sink proof. Nothing enforced it, so a case labeled mcp_tool_call
	// carrying several calls took the weaker path: it could be credited as
	// allow without final-sink proof, or have a denial evaluated without
	// prefix-delivery checks. No corpus case does this today, which is why it
	// was invisible, but a documented contract that only holds by convention
	// is not a contract.
	if !requireFinalSink && len(toolsCalls) > 1 {
		return gatewaySkip(c, fmt.Sprintf(
			"gateway mcp_tool_call is exactly one call, got %d; a dependent sequence must be labeled mcp_tool_sequence so it is scored with final-sink proof",
			len(toolsCalls)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	requests := make([]gatewayRequest, 0, len(toolsCalls))
	if requireFinalSink {
		if a.mcpHTTPFixture() == nil {
			return gatewaySkip(c, "gateway dependent tools/call sequence requires the MCP HTTP fixture")
		}
	}

	client := &http.Client{}
	sess := &gatewaySession{}
	if result := a.initialize(ctx, client, c.ID, sess); result != nil {
		return *result
	}

	// Drive the tools/call sequence in order over the one session. A deny stops
	// the sequence and names the message; block still requires atomic proof.
	for i, toolsCall := range toolsCalls {
		// Freshness is part of the proof: do not expose or lease a future request
		// before every predecessor has completed.
		message, request, prepErr := prepareGatewayRequest(toolsCall)
		if prepErr != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/call request %d: %w", c.ID, i, prepErr)}
		}
		requests = append(requests, request)
		var releaseFinalSink func()
		if requireFinalSink && i == len(toolsCalls)-1 {
			releaseFinalSink, err = a.mcpHTTPFixture().AcquireFinalSinkLease(ctx, fixture.MCPRequestObservation{
				Identity: request.identity, Method: request.method, Fingerprint: request.fingerprint,
			})
			if err != nil {
				return gatewaySkip(c, "gateway final-sink lease failed: "+err.Error())
			}
		}
		result := a.send(ctx, client, c.ID, message, true, sess, &request, deliveryAbsent)
		if releaseFinalSink != nil {
			releaseFinalSink()
		}
		if result != nil {
			if requireFinalSink {
				a.attachSequenceEvidence(result, requests, len(toolsCalls), i)
				if result.Verdict == "block" && !a.sequencePrefixDelivered(requests[:i]) {
					result.Verdict = "skip"
					result.Evidence["reason"] = "sequence_prefix_unproven"
				}
			} else if len(toolsCalls) > 1 && result.Verdict == "block" && result.Evidence != nil {
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
			if requireFinalSink {
				final := requests[len(requests)-1]
				evidence["final_sink_request_identity"] = final.identity
				evidence["final_sink_reached"] = a.finalSinkExecuted(final)
			}
			return Result{Verdict: "skip", Evidence: evidence}
		}
	}
	evidence["request_identities"] = requestIdentities
	evidence["upstream_reached"] = true
	if requireFinalSink {
		final := requests[len(requests)-1]
		evidence["final_sink_request_identity"] = final.identity
		evidence["final_sink_reached"] = a.finalSinkExecuted(final)
		if evidence["final_sink_reached"] != true {
			evidence["upstream_reached"] = false
			evidence["reason"] = "final_sink_unproven"
			return Result{Verdict: "skip", Evidence: evidence}
		}
	}
	return Result{Verdict: "allow", Evidence: evidence}
}

func (a *MCPGatewayAdapter) sequencePrefixDelivered(requests []gatewayRequest) bool {
	for _, request := range requests {
		if delivered, proofAvailable := a.requestDelivered(request); !proofAvailable || !delivered {
			return false
		}
	}
	return true
}

func (a *MCPGatewayAdapter) attachSequenceEvidence(result *Result, requests []gatewayRequest, total, current int) {
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	identities := make([]string, 0, current+1)
	for _, request := range requests[:current+1] {
		identities = append(identities, request.identity)
	}
	result.Evidence["tools_call_count"] = total
	result.Evidence["request_identities"] = identities
	if current == total-1 {
		final := requests[len(requests)-1]
		result.Evidence["final_sink_request_identity"] = final.identity
		result.Evidence["final_sink_reached"] = a.finalSinkExecuted(final)
	}
	if result.Verdict == "block" {
		result.Evidence["blocked_message_index"] = current
	}
}

func (a *MCPGatewayAdapter) finalSinkExecuted(request gatewayRequest) bool {
	upstream := a.mcpHTTPFixture()
	if upstream == nil {
		return false
	}
	executions := upstream.FinalSinkExecution(request.identity)
	return len(executions) == 1 && executions[0] == (fixture.MCPRequestObservation{
		Identity: request.identity, Method: request.method, Fingerprint: request.fingerprint,
	})
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
	toolsList, request, err := prepareGatewayRequest(toolsList)
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
	identity, err := nextGatewayRequestIdentity()
	if err != nil {
		return &Result{Err: fmt.Errorf("case %s: prepare initialize request: %w", caseID, err)}
	}
	initialize := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      identity,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]string{"name": "agent-egress-bench", "version": "1"},
		},
	}
	// initialize carries an id, so it is a request and its response is
	// correlated and validated like any other. notifications/initialized below
	// carries none, so it stays a notification judged on HTTP status.
	initializeRequest := &gatewayRequest{identity: identity, method: "initialize"}
	if result := a.send(ctx, client, caseID, initialize, false, sess, initializeRequest, deliveryAbsent); result != nil {
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
	// Response validation is selected by whether a gatewayRequest was supplied,
	// so a caller that forgets one on a message carrying an id would silently
	// take the notification path and skip correlation entirely. That is a guard
	// bypassable by omission, which is the same shape as no guard at all. JSON-RPC
	// already says which messages are requests: those with an id. Disagreement
	// between the message and the caller is a programming error, so it fails
	// loudly here rather than degrading to an unvalidated response.
	if _, carriesID := message["id"]; carriesID != (request != nil) {
		return nil, &Result{Err: fmt.Errorf(
			"case %s: MCP message %v carries id=%t but gatewayRequest supplied=%t; a request must be correlated and a notification must not be",
			caseID, message["method"], carriesID, request != nil)}
	}
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
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: read MCP gateway response: %w", caseID, err)}
	}
	response, result := a.classifyGatewayResponse(resp, responseBody, nil, requireResponse, emptyResponseReason, request, expectation, caseID)
	if result != nil {
		return nil, result
	}
	// Capture the session id only after a valid initialize response. A header on
	// a rejected or malformed handshake is not a negotiated binding and must not
	// escape into a later tools/call.
	if sess != nil && sess.id == "" && message["method"] == "initialize" {
		if assigned := resp.Header.Get("Mcp-Session-Id"); assigned != "" {
			sess.id = assigned
		}
	}
	return response, nil
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
		if !requireResponse && request != nil {
			return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway %s response: %w", caseID, request.method, transportErr)}
		}
		if a.plugin.DenySignals.ConnectionClosedNoOut {
			// A connection failure has no response bound to the request. Even with
			// fixture evidence it is indistinguishable from a network failure, so it
			// cannot meet the correlation requirement for block.
			return nil, a.gatewaySkipWithObservation("connection_closed_without_output", request, 0, "")
		}
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway request: %w", caseID, transportErr)}
	}
	if !requireResponse {
		// A lifecycle message carrying an id is a JSON-RPC request, and its
		// response is subject to the same correlation and structure rules as any
		// other. A notification has no id, expects no response, and is correctly
		// judged on HTTP status alone. Distinguishing them by the presence of an
		// id is the protocol's own rule rather than an adapter convention.
		if request != nil {
			return a.classifyLifecycleResponse(resp, body, request, caseID)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return nil, a.gatewaySkipWithObservation("unclassified_initialization_status", request, resp.StatusCode, "")
		}
		return body, nil
	}
	var decodedResponse []byte
	if presentsJSONRPC(resp.Header.Get("Content-Type"), body) {
		var err error
		decodedResponse, err = decodeGatewayResponse(resp.Header.Get("Content-Type"), body, messageID(request))
		if err != nil {
			return nil, a.gatewayDecodeFailure(err, request, resp.StatusCode)
		}
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
	if decodedResponse == nil {
		var err error
		decodedResponse, err = decodeGatewayResponse(resp.Header.Get("Content-Type"), body, messageID(request))
		if err != nil {
			return nil, a.gatewayDecodeFailure(err, request, resp.StatusCode)
		}
	}
	if result := classifyGatewayJSONRPCError(decodedResponse, a.plugin.DenySignals.JSONRPCErrorCodeRange); result != nil {
		if result.Verdict == "block" {
			return nil, a.gatewayDeny("jsonrpc_error", request, expectation, resp.StatusCode, "")
		}
		a.attachObservation(result, request)
		return nil, result
	}
	return decodedResponse, nil
}

func presentsJSONRPC(contentType string, body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	return trimmed[0] == '{' || (err == nil && (mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") || mediaType == "text/event-stream"))
}

// classifyLifecycleResponse validates the response to a lifecycle REQUEST.
//
// A failure here is an adapter error rather than a verdict. The target has not
// refused the case; the session it would be measured through was never
// established, so there is nothing to score either way. Returning a verdict
// would attribute a measurement to a session that does not exist.
func (a *MCPGatewayAdapter) classifyLifecycleResponse(resp *http.Response, body []byte, request *gatewayRequest, caseID string) ([]byte, *Result) {
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway %s response status %d", caseID, request.method, resp.StatusCode)}
	}
	response, err := decodeGatewayResponse(resp.Header.Get("Content-Type"), body, messageID(request))
	if err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway %s response: %w", caseID, request.method, err)}
	}
	// decodeGatewayResponse uses jsonRPCMessageForRequest, the same correlation
	// and structure primitive as normal request handling. At this point a valid
	// message has exactly one of result or error; lifecycle errors establish no
	// session and are adapter errors rather than case verdicts.
	var outcome struct {
		Error *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(response, &outcome); err != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway %s response: %w", caseID, request.method, err)}
	}
	if outcome.Error != nil {
		return nil, &Result{Err: fmt.Errorf("case %s: MCP gateway %s response is a JSON-RPC error", caseID, request.method)}
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
	atomicAbsence := false
	if request != nil {
		delivered, proofAvailable = a.requestDelivered(*request)
		if expectation == deliveryAbsent && proofAvailable && !delivered {
			if a.denyBarrier != nil {
				var barrierErr error
				atomicAbsence, barrierErr = a.denyBarrier(func() bool {
					observed, available := a.requestDelivered(*request)
					return available && observed
				})
				if barrierErr != nil {
					return &Result{Verdict: "skip", Evidence: map[string]interface{}{
						"product_surface": "mcp_gateway_streamable_http",
						"deny_signal":     signal,
						"reason":          "deny_barrier_failed",
					}}
				}
				delivered, proofAvailable = a.requestDelivered(*request)
			}
		}
	}
	evidence := map[string]interface{}{"product_surface": "mcp_gateway_streamable_http", "deny_signal": signal}
	if status != 0 {
		evidence["http_status"] = status
	}
	if marker != "" {
		evidence["body_marker"] = marker
	}
	a.attachObservationEvidence(evidence, request, delivered, proofAvailable)
	if expectation == deliveryAbsent {
		evidence["atomic_non_delivery_proof"] = atomicAbsence
		if !atomicAbsence {
			evidence["reason"] = "atomic_non_delivery_proof_unavailable"
			return &Result{Verdict: "skip", Evidence: evidence}
		}
	}
	if !proofAvailable || delivered != bool(expectation) {
		evidence["reason"] = "deny_delivery_unproven"
		return &Result{Verdict: "skip", Evidence: evidence}
	}
	return &Result{Verdict: "block", Evidence: evidence, DeliveryProven: true, VerdictObserved: true}
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
	var duplicateSSE *duplicateSSEJSONRPCResponseError
	if errors.As(err, &duplicateSSE) {
		reason = "duplicate_sse_response"
	} else if errors.As(err, &mismatch) {
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
	mediaType, _, mediaErr := mime.ParseMediaType(contentType)
	wantedID, err := json.Marshal(requestID)
	if err != nil {
		return nil, fmt.Errorf("marshal request id: %w", err)
	}
	if mediaErr != nil || mediaType != "text/event-stream" {
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

// duplicateSSEJSONRPCResponseError marks a stream that contains more than one
// JSON-RPC response for a single request. JSON-RPC permits one response per
// request; accepting one would leave the other unscored.
type duplicateSSEJSONRPCResponseError struct{ wantedID []byte }

func (e *duplicateSSEJSONRPCResponseError) Error() string {
	return fmt.Sprintf("SSE response contains multiple JSON-RPC messages for request id %s", e.wantedID)
}

func jsonRPCMessageFromSSE(body, wantedID []byte) ([]byte, error) {
	var dataLines [][]byte
	var mismatch error
	var matched []byte
	processEvent := func() error {
		message, matchesRequest, err := matchingSSEJSONRPCMessage(dataLines, wantedID)
		if matchesRequest {
			if err != nil {
				return err
			}
			if matched != nil {
				return &duplicateSSEJSONRPCResponseError{wantedID: wantedID}
			}
			matched = message
			return nil
		}
		if err != nil {
			var correlation *responseCorrelationError
			if errors.As(err, &correlation) {
				mismatch = err
				return nil
			}
			// A malformed event without a usable, different request id might be
			// part of this response, so it is ambiguous evidence and cannot score.
			return err
		}
		return nil
	}
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
		if err := processEvent(); err != nil {
			return nil, err
		}
		dataLines = nil
	}
	if err := processEvent(); err != nil {
		return nil, err
	}
	if matched != nil {
		return matched, nil
	}
	if mismatch != nil {
		return nil, mismatch
	}
	return nil, &malformedSSEResponseError{err: fmt.Errorf("SSE response has no JSON-RPC message for request id %s", wantedID)}
}

func matchingSSEJSONRPCMessage(dataLines [][]byte, wantedID []byte) ([]byte, bool, error) {
	if len(dataLines) == 0 {
		return nil, false, nil
	}
	message := bytes.Join(dataLines, []byte("\n"))
	var response map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimSpace(message), &response); err != nil {
		return nil, false, fmt.Errorf("invalid JSON-RPC response: %w", err)
	}
	id, hasID := response["id"]
	if !hasID || len(id) == 0 {
		if err := validateSSEJSONRPCNotification(response); err != nil {
			return nil, false, err
		}
		// ID-less JSON-RPC notifications, including progress updates, are not
		// responses and may share this stream without affecting the verdict.
		return nil, false, nil
	}
	var got, wanted interface{}
	if err := json.Unmarshal(id, &got); err != nil {
		return nil, false, fmt.Errorf("decode response id: %w", err)
	}
	if err := json.Unmarshal(wantedID, &wanted); err != nil {
		return nil, false, fmt.Errorf("decode request id: %w", err)
	}
	if !jsonRPCIDsEqual(got, wanted) {
		return nil, false, &responseCorrelationError{err: fmt.Errorf("JSON-RPC response id %s does not match request id %s", id, wantedID)}
	}
	if _, err := jsonRPCMessageForRequest(message, wantedID); err != nil {
		return nil, true, err
	}
	return message, true, nil
}

func validateSSEJSONRPCNotification(message map[string]json.RawMessage) error {
	version, ok := message["jsonrpc"]
	if !ok || !bytes.Equal(bytes.TrimSpace(version), []byte(`"2.0"`)) {
		return errors.New("JSON-RPC notification must contain jsonrpc 2.0")
	}
	method, ok := message["method"]
	if !ok {
		return errors.New("JSON-RPC notification must contain method")
	}
	var methodName string
	if err := json.Unmarshal(method, &methodName); err != nil || methodName == "" {
		return errors.New("JSON-RPC notification method must be a non-empty string")
	}
	if _, hasResult := message["result"]; hasResult {
		return errors.New("JSON-RPC notification must not contain result")
	}
	if _, hasError := message["error"]; hasError {
		return errors.New("JSON-RPC notification must not contain error")
	}
	return nil
}

// duplicateJSONMemberName reports the first object member name that appears
// more than once in the same object, anywhere in the document. Decoding into a
// map silently keeps one of them, so a target could carry two results for one
// request and leave the runner reporting a verdict on content that a client
// parsing the same bytes need not agree with. RFC 8259 says object names SHOULD
// be unique, so rejecting the ambiguity costs no correct server anything.
func duplicateJSONMemberName(data []byte) (string, bool) {
	type frame struct {
		object    bool
		expectKey bool
		names     map[string]struct{}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var stack []*frame
	for {
		token, err := decoder.Token()
		if err != nil {
			// Malformed input is reported by the caller's own decode, which runs
			// next and produces the precise error.
			return "", false
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				stack = append(stack, &frame{object: true, expectKey: true, names: map[string]struct{}{}})
				continue
			case '[':
				stack = append(stack, &frame{})
				continue
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				if len(stack) > 0 && stack[len(stack)-1].object {
					stack[len(stack)-1].expectKey = true
				}
				continue
			}
		}
		if len(stack) == 0 {
			continue
		}
		top := stack[len(stack)-1]
		if !top.object {
			continue
		}
		if !top.expectKey {
			top.expectKey = true
			continue
		}
		name, ok := token.(string)
		if !ok {
			return "", false
		}
		if _, seen := top.names[name]; seen {
			return name, true
		}
		top.names[name] = struct{}{}
		top.expectKey = false
	}
}

func jsonRPCMessageForRequest(message, wantedID []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(message)
	if name, duplicate := duplicateJSONMemberName(trimmed); duplicate {
		return nil, fmt.Errorf("JSON-RPC response repeats object member %q, so its content is ambiguous", name)
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &response); err != nil {
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
