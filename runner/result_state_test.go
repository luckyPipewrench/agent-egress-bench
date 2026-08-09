package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

type stateTestAdapter struct {
	routes []adapter.DeliveryTuple
	result adapter.Result
	calls  int
}

func (a *stateTestAdapter) DeliveryTuples() []adapter.DeliveryTuple { return a.routes }

func (a *stateTestAdapter) Run(adapter.Case, time.Duration) adapter.Result {
	a.calls++
	return a.result
}

func stateTestCase() Case {
	return Case{
		ID:              "result-state-malicious-001",
		Transport:       "fetch_proxy",
		InputType:       "url",
		ExpectedVerdict: "block",
		Payload:         map[string]interface{}{"method": "GET", "url": "https://fixture.example/"},
	}
}

func stateTestProfile() Profile {
	return Profile{Tool: "state-test", ToolVersion: "1.0"}
}

func runStateTestCase(t *testing.T, adapt adapter.Adapter) ([]CaseResult, int, string) {
	t.Helper()
	var output bytes.Buffer
	results, unreachable, _, err := runCases([]Case{stateTestCase()}, stateTestProfile(), adapt, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	return results, len(unreachable), output.String()
}

func TestResultState_NoRouteIsUnreachableNotErrorOrNotApplicable(t *testing.T) {
	adapt := &stateTestAdapter{}
	results, unreachable, output := runStateTestCase(t, adapt)
	if adapt.calls != 0 {
		t.Fatalf("adapter Run calls = %d, want 0 without a declared route", adapt.calls)
	}
	if len(results) != 0 || unreachable != 1 {
		t.Fatalf("results=%d unreachable=%d, want 0 scoreable rows and 1 unreachable row", len(results), unreachable)
	}
	var emitted CaseResult
	if err := json.Unmarshal([]byte(output), &emitted); err != nil {
		t.Fatalf("decode emitted result: %v\n%s", err, output)
	}
	if emitted.ActualVerdict != "unreachable" || emitted.Score != "error" {
		t.Fatalf("emitted result = %+v, want unreachable state distinct from an error or N/A", emitted)
	}
	if emitted.Evidence["result_state"] != string(ResultStateUnreachable) {
		t.Fatalf("result_state = %#v, want %q", emitted.Evidence["result_state"], ResultStateUnreachable)
	}
}

func TestResultState_RemovingDeliveryProofRecordsError(t *testing.T) {
	c := stateTestCase()
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "allow", VerdictObserved: true},
	}
	results, unreachable, _ := runStateTestCase(t, adapt)
	if unreachable != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one coverage error", len(results), unreachable)
	}
	got := results[0]
	if got.ActualVerdict != "error" || got.Score != "error" || got.Evidence["result_state"] != string(ResultStateDeliveryUnavailable) {
		t.Fatalf("result = %+v, want delivery-unavailable error rather than allow or unreachable", got)
	}
}

func TestResultState_BrokenFixtureRouteRecordsErrorWithNoObservedVerdict(t *testing.T) {
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatal(err)
	}
	defer fm.Close()

	// This local gateway returns a syntactically valid tools/list answer but
	// deliberately never forwards it to the leased fixture route.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "tools/list":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"poisoned_tool"}]}}`, request.ID)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, request.ID)
		}
	}))
	defer server.Close()
	adapt, err := adapter.NewMCPGatewayAdapter(adapter.GatewayPlugin{
		Name: "local non-forwarder", Transport: "streamable_http", Client: adapter.GatewayClient{Endpoint: server.URL},
	}, fm)
	if err != nil {
		t.Fatalf("NewMCPGatewayAdapter: %v", err)
	}
	c := Case{
		ID:              "result-state-broken-fixture-001",
		Transport:       "mcp_http",
		InputType:       "mcp_tool_definition",
		ExpectedVerdict: "block",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      "case-tools-list",
				"result": map[string]interface{}{
					"tools": []interface{}{map[string]interface{}{"name": "poisoned_tool"}},
				},
			}},
		},
	}
	var output bytes.Buffer
	results, unreachable, _, err := runCases([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if len(unreachable) != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one coverage error", len(results), len(unreachable))
	}
	if calls := fm.MCPHTTP().Calls(); calls != 0 {
		t.Fatalf("fixture calls = %d, want 0 after the gateway route broke", calls)
	}
	got := results[0]
	if got.ActualVerdict != "error" || got.Evidence["result_state"] != string(ResultStateDeliveryUnavailable) {
		t.Fatalf("result = %+v, want delivery-unavailable error", got)
	}
	observed := 0
	for _, result := range results {
		if result.Evidence["result_state"] == string(ResultStateObserved) {
			observed++
		}
	}
	if observed != 0 {
		t.Fatalf("observed verdict count = %d, want 0 after the fixture route broke", observed)
	}
}

func TestResultState_ObservedAllowForMaliciousCaseFails(t *testing.T) {
	c := stateTestCase()
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "allow", DeliveryProven: true, VerdictObserved: true},
	}
	results, unreachable, _ := runStateTestCase(t, adapt)
	if unreachable != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one observed result", len(results), unreachable)
	}
	got := results[0]
	if got.ActualVerdict != "allow" || got.Score != "fail" || got.Evidence["result_state"] != string(ResultStateObserved) {
		t.Fatalf("result = %+v, want observed allow scored as a containment failure", got)
	}
}

func TestResultStateSelectionIgnoresProfileAndCapabilityMetadata(t *testing.T) {
	c := stateTestCase()
	c.CapabilityTags = []string{"mcp_chain"}
	c.Requires = []string{"mcp_chain_memory"}
	profile := stateTestProfile()
	profile.Claims = []string{"url_dlp"}
	profile.Supports = map[string]bool{"fetch_proxy": false, "mcp_chain_memory": false}
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "block", DeliveryProven: true, VerdictObserved: true},
	}
	var output bytes.Buffer
	results, unreachable, notApplicable, err := runCases([]Case{c}, profile, adapt, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if len(unreachable) != 0 || len(notApplicable) != 0 || len(results) != 1 {
		t.Fatalf("selection used profile/capability metadata: results=%d unreachable=%d N/A=%v", len(results), len(unreachable), notApplicable)
	}
	if results[0].ActualVerdict != "block" || results[0].Score != "pass" {
		t.Fatalf("result = %+v, want adapter-proven block to score despite profile metadata", results[0])
	}
}
