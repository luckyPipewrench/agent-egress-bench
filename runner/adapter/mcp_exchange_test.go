package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

func TestMCPHTTPExchangeRetentionTemporal(t *testing.T) {
	upstream, err := fixture.StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("X-Session-Credential", "AEB_SYNTHETIC_SESSION_CREDENTIAL")
		if handleMCPHTTPTestLifecycle(t, w, r, upstream.URL(), body) {
			return
		}
		response := postMCPHTTPTestUpstream(r.Context(), t, upstream.URL(), r.Header.Get("Mcp-Session-Id"), body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(response)
	}))
	defer listener.Close()
	a := &ProxyAdapter{}
	a.SetMCPHTTPURL(listener.URL)
	a.SetMCPHTTPFixture(upstream)
	c := gatewayTemporalInventoryCase("exchange-temporal", "Before.", "After.")
	baseline := a.Run(c, time.Second)
	if baseline.Err != nil || baseline.Verdict != "allow" || baseline.MCPHTTPExchanges != nil {
		t.Fatalf("baseline: %+v", baseline)
	}
	a.SetRetainMCPHTTPExchanges(true)
	result := a.Run(c, time.Second)
	if result.Err != nil || result.Verdict != baseline.Verdict || result.DeliveryProven != baseline.DeliveryProven || result.VerdictObserved != baseline.VerdictObserved {
		t.Fatalf("diagnostics changed result: %+v", result)
	}
	if err := ValidateMCPHTTPExchanges(result.MCPHTTPExchanges); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(result.MCPHTTPExchanges.PlannedMethods, []string{"initialize", "notifications/initialized", "tools/list", "tools/list"}) {
		t.Fatalf("methods: %v", result.MCPHTTPExchanges.PlannedMethods)
	}
	encoded, err := json.Marshal(result.MCPHTTPExchanges)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.MCPHTTPExchanges.Exchanges {
		if bytes.Contains(entry.Request, []byte("AEB_SYNTHETIC_SESSION_CREDENTIAL")) || bytes.Contains(entry.Response, []byte("AEB_SYNTHETIC_SESSION_CREDENTIAL")) {
			t.Fatal("retained session credential bytes")
		}
	}
	if bytes.Contains(encoded, []byte("AEB_SYNTHETIC_SESSION_CREDENTIAL")) {
		t.Fatal("retained session credential")
	}
	public, _ := json.Marshal(result)
	if bytes.Contains(public, []byte("planned_methods")) {
		t.Fatal("public result leaked exchanges")
	}
	for _, mutation := range []string{"missing", "truncated", "wrong-id", "malformed", "wrong-method", "bad-status", "bad-media"} {
		t.Run(mutation, func(t *testing.T) {
			var record MCPHTTPExchanges
			if err := json.Unmarshal(encoded, &record); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				record.Exchanges = record.Exchanges[:3]
			case "truncated":
				record.Exchanges[3].Complete = false
			case "wrong-id":
				record.Exchanges[3].Response = []byte(`{"jsonrpc":"2.0","id":"unrelated","result":{"tools":[]}}`)
			case "malformed":
				record.Exchanges[3].Response = []byte("{")
			case "wrong-method":
				record.PlannedMethods[3] = "tools/call"
			case "bad-status":
				record.Exchanges[3].Status = 0
			case "bad-media":
				record.Exchanges[3].MediaType = "application/private"
			}
			if err := ValidateMCPHTTPExchanges(&record); err == nil {
				t.Fatal("invalid exchange accepted")
			}
		})
	}
}

func TestMCPHTTPExchangeRetentionResponsePaths(t *testing.T) {
	for _, inputType := range []string{"mcp_tool_definition", "mcp_tool_result"} {
		t.Run(inputType, func(t *testing.T) {
			upstream, err := fixture.StartMCPHTTP()
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			a := &ProxyAdapter{}
			a.SetMCPHTTPURL(upstream.URL())
			a.SetMCPHTTPFixture(upstream)
			a.SetRetainMCPHTTPExchanges(true)
			payload := map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"tools": []interface{}{map[string]interface{}{"name": "fixture", "inputSchema": map[string]interface{}{"type": "object"}}}}}
			if inputType == "mcp_tool_result" {
				payload["result"] = map[string]interface{}{"content": []interface{}{map[string]interface{}{"type": "text", "text": "synthetic local output"}}}
			}
			result := a.Run(Case{ID: "exchange-response", Transport: "mcp_http", InputType: inputType, Payload: map[string]interface{}{"jsonrpc_messages": []interface{}{payload}}}, time.Second)
			if result.Err != nil || result.Verdict != "allow" {
				t.Fatalf("result: %+v", result)
			}
			if err := ValidateMCPHTTPExchanges(result.MCPHTTPExchanges); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMCPHTTPExchangeBodyTruncationDoesNotChangeReads(t *testing.T) {
	raw := strings.Repeat("a", decisionBodyCap+1)
	entry := MCPHTTPExchange{}
	body := &exchangeBody{ReadCloser: io.NopCloser(strings.NewReader(raw)), entry: &entry}
	received, err := io.ReadAll(body)
	if err != nil || string(received) != raw {
		t.Fatalf("read changed: %v", err)
	}
	if entry.Complete || len(entry.Response) != decisionBodyCap {
		t.Fatal("oversized observation declared complete")
	}
}

func TestMCPHTTPExchangeDecodeRejectsMalformedMetadata(t *testing.T) {
	for _, body := range []string{`{"complete":true,"unknown":1}`, `{"complete":true} {}`, `{}`, `null`} {
		if _, err := DecodeMCPHTTPExchanges([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func TestMCPHTTPExchangeValidationSSEAndUnreadBody(t *testing.T) {
	record := &MCPHTTPExchanges{Complete: true, PlannedMethods: []string{"initialize", "tools/list"}, Exchanges: []MCPHTTPExchange{
		{Request: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","method":"initialize"}`), Status: 200, MediaType: "application/octet-stream", Complete: true},
		{Request: []byte(`{"jsonrpc":"2.0","id":"synthetic-list","method":"tools/list"}`), Response: []byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"synthetic-list\",\"result\":{\"tools\":[]}}\n\n"), Status: 200, MediaType: "text/event-stream", Complete: true},
	}}
	if err := ValidateMCPHTTPExchanges(record); err != nil {
		t.Fatal(err)
	}
	record.Exchanges[1].Response = append(record.Exchanges[1].Response, record.Exchanges[1].Response...)
	if err := ValidateMCPHTTPExchanges(record); err == nil {
		t.Fatal("duplicate SSE response accepted")
	}
	entry := MCPHTTPExchange{}
	body := &exchangeBody{ReadCloser: io.NopCloser(strings.NewReader("unread")), entry: &entry}
	_ = body.Close()
	if entry.Complete {
		t.Fatal("unread response declared complete")
	}
}

func TestMCPHTTPExchangeSetupExceptionIsFirstInitializeOnly(t *testing.T) {
	record := &MCPHTTPExchanges{Complete: true, PlannedMethods: []string{"initialize", "tools/list"}, Exchanges: []MCPHTTPExchange{
		{Request: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","method":"initialize"}`), Status: 200, MediaType: "application/octet-stream", Complete: true},
		{Request: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","method":"tools/list"}`), Response: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","result":{"tools":[]}}`), Status: 200, MediaType: "application/json", Complete: true},
	}}
	if err := ValidateMCPHTTPExchanges(record); err != nil {
		t.Fatal(err)
	}
	record.Exchanges[1].Response = []byte("{")
	if err := ValidateMCPHTTPExchanges(record); err == nil {
		t.Fatal("setup ID bypassed case response decoding")
	}
}

func TestMCPHTTPExchangeAggregateBudgetPreservesReads(t *testing.T) {
	record := &MCPHTTPExchanges{retainedBytes: mcpExchangeByteCap - 2}
	entry := MCPHTTPExchange{}
	body := &exchangeBody{ReadCloser: io.NopCloser(strings.NewReader("abcdef")), entry: &entry, record: record}
	received, err := io.ReadAll(body)
	if err != nil || string(received) != "abcdef" {
		t.Fatalf("read changed: %q %v", received, err)
	}
	if string(entry.Response) != "ab" || entry.Complete || !record.captureIncomplete || record.retainedBytes != mcpExchangeByteCap {
		t.Fatalf("budget failed: %+v %+v", entry, record)
	}
}

func TestMCPHTTPExchangeCountBudgetStillForwards(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("forwarded")) }))
	defer server.Close()
	for _, budget := range []string{"count", "bytes"} {
		t.Run(budget, func(t *testing.T) {
			record := &MCPHTTPExchanges{}
			if budget == "count" {
				record.Exchanges = make([]MCPHTTPExchange, mcpExchangeCountCap)
			} else {
				record.retainedBytes = mcpExchangeByteCap
			}
			count := len(record.Exchanges)
			request, err := http.NewRequestWithContext(context.WithValue(context.Background(), exchangeContextKey{}, record), http.MethodPost, server.URL, strings.NewReader("request"))
			if err != nil {
				t.Fatal(err)
			}
			response, err := (mcpExchangeTransport{}).RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			received, err := io.ReadAll(response.Body)
			if err != nil || string(received) != "forwarded" || !record.captureIncomplete || len(record.Exchanges) != count {
				t.Fatalf("budget changed forwarding or retained more: %q %v %+v", received, err, record)
			}
		})
	}
}

func TestMCPHTTPExchangePlannedSequenceBudget(t *testing.T) {
	for _, variant := range []string{"count", "method"} {
		t.Run(variant, func(t *testing.T) {
			messages := make([]interface{}, mcpExchangeCountCap+1)
			for i := range messages {
				messages[i] = map[string]interface{}{"method": "tools/list"}
			}
			if variant == "method" {
				messages = []interface{}{map[string]interface{}{"method": strings.Repeat("a", 257)}}
			}
			a := &ProxyAdapter{retainMCPHTTPExchanges: true}
			ctx, finish := a.recordMCPHTTPExchanges(context.Background(), Case{Payload: map[string]interface{}{"jsonrpc_messages": messages}})
			record := ctx.Value(exchangeContextKey{}).(*MCPHTTPExchanges)
			if len(record.PlannedMethods) > mcpExchangeCountCap || !record.captureIncomplete || finish(true).Complete {
				t.Fatalf("unbounded metadata or complete record: %+v", record)
			}
		})
	}
}

func TestMCPHTTPExchangeVerifierRejectsAggregateOverflow(t *testing.T) {
	record := &MCPHTTPExchanges{Complete: true, PlannedMethods: []string{"initialize", "tools/list"}, Exchanges: []MCPHTTPExchange{{Complete: true, Status: 200, MediaType: "application/json", Request: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","method":"initialize"}`), Response: bytes.Repeat([]byte("a"), mcpExchangeByteCap+1)}, {Complete: true, Status: 200, MediaType: "application/json", Request: []byte(`{"jsonrpc":"2.0","method":"tools/list"}`)}}}
	if err := ValidateMCPHTTPExchanges(record); err == nil {
		t.Fatal("oversized forged capture accepted")
	}
}
