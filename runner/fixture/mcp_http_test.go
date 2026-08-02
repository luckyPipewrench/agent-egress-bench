package fixture

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func TestMCPHTTPFixtureCountsTotalPostsAndToolCallsSeparately(t *testing.T) {
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
	// (one per sent message); ToolCalls() is the tools/call-specific count
	// the gateway adapter proves an allow by. initialize + tools/list +
	// tools/call = 3 total POSTs, 1 of them a tools/call.
	if got := f.Calls(); got != 3 {
		t.Fatalf("Calls() = %d, want 3 total POSTs (initialize+tools/list+tools/call)", got)
	}
	if got := f.ToolCalls(); got != 1 {
		t.Fatalf("ToolCalls() = %d, want 1 tools/call request", got)
	}
}

func postMCPFixture(t *testing.T, endpoint, request string) []byte {
	t.Helper()
	resp, err := http.Post(endpoint, "application/json", bytes.NewBufferString(request))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("fixture status = %d, body = %s", resp.StatusCode, body)
	}
	return body
}
