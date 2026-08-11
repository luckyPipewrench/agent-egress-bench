package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMCPHTTPFixtureCountsTotalPostsAndOperationCallsSeparately(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.SetTools([]json.RawMessage{json.RawMessage(`{"name":"fixture_tool"}`)})

	for _, request := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture_tool"}}`,
	} {
		response := postMCPFixture(t, f.URL(), request)
		if len(response) == 0 {
			t.Fatal("fixture returned an empty MCP response")
		}
		if bytes.Contains([]byte(request), []byte(`"tools/list"`)) && !bytes.Contains(response, []byte(`"fixture_tool"`)) {
			t.Fatalf("tools/list response %s does not contain configured tool", response)
		}
	}
	// Calls() is the total POST count the proxy MCP HTTP proof relies on
	// (one per sent message). ToolCalls() and ListCalls() are operation-specific
	// proof counters for gateway adapter paths. initialize + tools/list +
	// tools/call = 3 total POSTs, one of each operation-specific request.
	if got := f.Calls(); got != 3 {
		t.Fatalf("Calls() = %d, want 3 total POSTs (initialize+tools/list+tools/call)", got)
	}
	if got := f.ToolCalls(); got != 1 {
		t.Fatalf("ToolCalls() = %d, want 1 tools/call request", got)
	}
	if got := f.ListCalls(); got != 1 {
		t.Fatalf("ListCalls() = %d, want 1 tools/list request", got)
	}
}

func TestMCPHTTPFixtureInitializeMintsIdentityBoundSession(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const identity = "aeb-request-session-proof"
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.URL(),
		bytes.NewBufferString(`{"jsonrpc":"2.0","id":"`+identity+`","method":"initialize","params":{"_meta":{"aeb_request_identity":"`+identity+`"}}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got, want := resp.Header.Get("Mcp-Session-Id"), "aeb-session-"+identity; got != want {
		t.Fatalf("Mcp-Session-Id = %q, want %q", got, want)
	}
}

func TestMCPHTTPFixtureToolDefinitionLeaseResetsInventory(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	release, err := f.AcquireToolDefinitionLease(context.Background(), "leased-list", []json.RawMessage{json.RawMessage(`{"name":"leased_tool"}`)})
	if err != nil {
		t.Fatalf("AcquireToolDefinitionLease: %v", err)
	}
	response := postMCPFixture(t, f.URL(), `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"aeb_request_identity":"leased-list"}}}`)
	if !bytes.Contains(response, []byte(`"leased_tool"`)) {
		t.Fatalf("leased tools/list response = %s, want leased_tool", response)
	}
	release()

	response = postMCPFixture(t, f.URL(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if bytes.Contains(response, []byte(`"leased_tool"`)) {
		t.Fatalf("released tools/list response = %s, must not retain previous inventory", response)
	}
}

func TestMCPHTTPFixtureSessionToolDefinitionLeaseRequiresExactSession(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	const identity = "session-list"
	release, err := f.AcquireSessionToolDefinitionLease(context.Background(), identity, "aeb-session-live", []json.RawMessage{json.RawMessage(`{"name":"leased_tool"}`)})
	if err != nil {
		t.Fatalf("AcquireSessionToolDefinitionLease: %v", err)
	}
	defer release()
	request := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"aeb_request_identity":"` + identity + `"}}}`

	for _, sessionID := range []string{"", "aeb-session-other"} {
		status, response := postMCPFixtureWithSession(t, f.URL(), request, sessionID)
		if status != http.StatusBadRequest || !bytes.Contains(response, []byte("missing or invalid MCP session")) {
			t.Fatalf("session %q status/body = %d/%s, want rejected", sessionID, status, response)
		}
		if got := f.Observation(identity); len(got) != 0 {
			t.Fatalf("rejected session %q recorded observations: %+v", sessionID, got)
		}
	}

	status, response := postMCPFixtureWithSession(t, f.URL(), request, "aeb-session-live")
	if status != http.StatusOK || !bytes.Contains(response, []byte(`"leased_tool"`)) {
		t.Fatalf("exact session status/body = %d/%s, want leased inventory", status, response)
	}
	if got := f.Observation(identity); len(got) != 1 {
		t.Fatalf("exact session observations = %+v, want one", got)
	}
}

func TestMCPHTTPFixtureToolResultLeaseResetsResponse(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	release, err := f.AcquireToolResultLease(context.Background(), "leased-request", json.RawMessage(`{"content":[{"type":"text","text":"leased"}]}`))
	if err != nil {
		t.Fatalf("AcquireToolResultLease: %v", err)
	}
	assertToolCallResultContains(t, f.URL(), "leased-request", "leased")
	release()
	assertToolCallResultContains(t, f.URL(), "later-request", `"ok":true`)
}

func TestMCPHTTPFixtureFinalSinkLeaseRequiresExactSingleExecution(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	exact := `{"jsonrpc":"2.0","id":"sink-1","method":"tools/call","params":{"name":"send","arguments":{"value":"final"},"_meta":{"aeb_request_identity":"sink-1"}}}`
	fingerprint, err := MCPRequestFingerprint([]byte(exact))
	if err != nil {
		t.Fatal(err)
	}
	release, err := f.AcquireFinalSinkLease(context.Background(), MCPRequestObservation{
		Identity: "sink-1", Method: "tools/call", Fingerprint: fingerprint,
	})
	if err != nil {
		t.Fatalf("AcquireFinalSinkLease: %v", err)
	}
	defer release()

	postMCPFixture(t, f.URL(), strings.Replace(exact, `"final"`, `"changed"`, 1))
	if got := f.FinalSinkExecution("sink-1"); len(got) != 0 {
		t.Fatalf("changed payload recorded final sink execution: %+v", got)
	}
	postMCPFixture(t, f.URL(), exact)
	got := f.FinalSinkExecution("sink-1")
	if len(got) != 1 || got[0].Fingerprint != fingerprint {
		t.Fatalf("final sink executions = %+v, want one exact execution", got)
	}
}

func TestMCPHTTPFixtureToolsSnapshotIsIndependent(t *testing.T) {
	f := &MCPHTTPFixture{}
	f.SetTools([]json.RawMessage{json.RawMessage(`{"name":"first_tool"}`)})

	snapshot := f.toolsSnapshot()
	f.SetTools([]json.RawMessage{json.RawMessage(`{"name":"second_tool"}`)})

	if got := string(snapshot[0]); got != `{"name":"first_tool"}` {
		t.Fatalf("snapshot changed to %s after SetTools reused the backing array", got)
	}
}

func assertToolCallResultContains(t *testing.T, endpoint, identity, wanted string) {
	t.Helper()
	body := postMCPFixture(t, endpoint, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fixture_tool","arguments":{},"_meta":{"aeb_request_identity":"`+identity+`"}}}`)
	if !bytes.Contains(body, []byte(wanted)) {
		t.Fatalf("response = %s, want substring %q", body, wanted)
	}
}

func postMCPFixture(t *testing.T, endpoint, request string) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewBufferString(request))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fixture status = %d, body = %s", resp.StatusCode, body)
	}
	return body
}

func postMCPFixtureWithSession(t *testing.T, endpoint, request, sessionID string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewBufferString(request))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}
