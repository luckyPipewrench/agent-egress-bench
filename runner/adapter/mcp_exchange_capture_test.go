package adapter

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPHTTPExchangeCaptureFailurePersists(t *testing.T) {
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("{}"))
	}))
	defer listener.Close()
	for _, captureFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "capture-failed"}[captureFails], func(t *testing.T) {
			p := &ProxyAdapter{}
			p.SetRetainMCPHTTPExchanges(true)
			ctx, finish := p.recordMCPHTTPExchanges(context.Background(), Case{ID: "capture-test", InputType: "mcp_tool_definition"})
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, listener.URL, strings.NewReader(`{"jsonrpc":"2.0","id":"case","method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			if captureFails {
				req.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("synthetic capture failure") }
			}
			resp, err := (mcpExchangeTransport{}).RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_, err = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			record := finish(true)
			if record.Complete == captureFails {
				t.Fatalf("capture failure overwritten: complete=%v", record.Complete)
			}
		})
	}
}

func TestMCPHTTPExchangeCaseRequestBoundary(t *testing.T) {
	for _, method := range []string{"initialize", "notifications/initialized", "tools/list"} {
		request := `{"jsonrpc":"2.0","method":"` + method + `"}`
		record := &MCPHTTPExchanges{Complete: true, PlannedMethods: []string{"initialize", method}, Exchanges: []MCPHTTPExchange{
			{Complete: true, Status: 200, MediaType: "application/json", Request: []byte(`{"jsonrpc":"2.0","method":"initialize"}`)},
			{Complete: true, Status: 200, MediaType: "application/json", Request: []byte(request)},
		}}
		err := ValidateMCPHTTPExchanges(record)
		if method == "tools/list" && err != nil {
			t.Fatal(err)
		}
		if method != "tools/list" && (err == nil || !strings.Contains(err.Error(), "lacks a case request")) {
			t.Fatalf("%s: %v", method, err)
		}
	}
}

func TestMCPHTTPExchangeHTTPRefusalBoundary(t *testing.T) {
	for _, status := range []int{200, 299, 300, 403, 500} {
		record := &MCPHTTPExchanges{Complete: true, PlannedMethods: []string{"initialize", "tools/list"}, Exchanges: []MCPHTTPExchange{
			{Complete: true, Status: 200, MediaType: "application/json", Request: []byte(`{"jsonrpc":"2.0","method":"initialize"}`)},
			{Complete: true, Status: status, MediaType: "application/json", Request: []byte(`{"jsonrpc":"2.0","id":"case","method":"tools/list"}`), Response: []byte("non-JSON HTTP refusal")},
		}}
		err := ValidateMCPHTTPExchanges(record)
		if status >= 300 && err != nil {
			t.Fatalf("HTTP refusal needs no RPC correlation: %v", err)
		}
		if status < 300 && err == nil {
			t.Fatalf("successful HTTP response bypassed correlation: %d", status)
		}
	}
}
