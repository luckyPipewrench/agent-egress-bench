package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
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

func TestMCPHTTPFixtureToolsListCopiesConcurrentInventory(t *testing.T) {
	f, err := StartMCPHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// SetTools rewrites the backing array in place, so a handler that aliases
	// f.tools rather than copying it races with a concurrent update. The writer
	// runs until the reads finish rather than for a fixed count: a bounded
	// writer loop completes in microseconds while the first HTTP round trip is
	// still in flight, so the two never overlap and the test proves nothing.
	//
	// This is a probabilistic detector, not a gate. Measured against a
	// deliberately neutralized handler it reported the race in 2 of 5 runs, and
	// neither more read iterations nor more concurrent writers moved that rate.
	// So it will catch a reintroduced alias across repeated CI runs but can pass
	// on any single one; do not read one green run as proof the copy is intact.
	const iterations = 50
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				f.SetTools([]json.RawMessage{json.RawMessage(`{"name":"fixture_tool"}`)})
			}
		}
	}()
	for i := 0; i < iterations; i++ {
		body := postMCPFixture(t, f.URL(), `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		if !bytes.Contains(body, []byte(`"tools"`)) {
			t.Fatalf("tools/list response = %s, want tools inventory", body)
		}
	}
	close(done)
	wg.Wait()
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
