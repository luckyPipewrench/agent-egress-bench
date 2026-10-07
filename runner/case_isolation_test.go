package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

func isolatedTestAdapter(t *testing.T, command string) *caseIsolatedProxyAdapter {
	t.Helper()
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fm.Close)
	pa, err := adapter.NewProxyAdapter("127.0.0.1:1", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	pa.SetMCPHTTPUpstreamCallCounter(fm.MCPHTTP().Calls)
	pa.SetMCPHTTPFixture(fm.MCPHTTP())
	return &caseIsolatedProxyAdapter{proxy: pa, fixtures: fm, mcpHTTPCommand: command}
}

func isolationCase(id string, names ...string) adapter.Case {
	messages := make([]interface{}, 0, len(names))
	for i, name := range names {
		messages = append(messages, map[string]interface{}{"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": map[string]interface{}{"name": name, "arguments": map[string]interface{}{}}})
	}
	return adapter.Case{ID: id, Transport: "mcp_http", InputType: "mcp_tool_sequence", Payload: map[string]interface{}{"jsonrpc_messages": messages}}
}

func isolationHelperCommand() string {
	return fmt.Sprintf("exec %s -test.run=^TestIsolationTargetHelper$", strconv.Quote(os.Args[0]))
}

func TestCaseIsolationResetsBetweenCasesButKeepsSequence(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "listeners")
	t.Setenv("AEB_ISOLATION_TARGET_HELPER", "1")
	t.Setenv("AEB_ISOLATION_LISTENERS", marker)
	a := isolatedTestAdapter(t, isolationHelperCommand())
	for _, c := range []adapter.Case{isolationCase("poison", "poison"), isolationCase("clean", "clean"), isolationCase("repeat-clean", "clean")} {
		result := a.Run(c, 3*time.Second)
		if result.Err != nil || result.Verdict != "allow" || !result.DeliveryProven || !result.VerdictObserved {
			t.Fatalf("%s did not run against a fresh reachable target: %+v", c.ID, result)
		}
		if result.Evidence["mcp_http_case_isolation"] != "fresh_managed_process" {
			t.Fatalf("missing lifecycle evidence: %+v", result)
		}
	}
	result := a.Run(isolationCase("temporal", "poison", "clean"), 3*time.Second)
	if result.Err != nil || result.Verdict != "block" || !result.VerdictObserved {
		t.Fatalf("sequence lost in-case history: %+v", result)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var listeners []string
	for _, line := range strings.Fields(string(data)) {
		listeners = append(listeners, line)
	}
	if len(listeners) != 4 {
		t.Fatalf("started %d listeners, want 4", len(listeners))
	}
	for _, addr := range listeners {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("case target %s survived teardown", addr)
		}
	}
}

func TestCaseIsolationStartupFailureDoesNotCreateVerdict(t *testing.T) {
	a := isolatedTestAdapter(t, "exit 1")
	result := a.Run(isolationCase("failed", "clean"), 100*time.Millisecond)
	if result.Err == nil || result.VerdictObserved || result.DeliveryProven || result.Verdict == "allow" || result.Verdict == "block" {
		t.Fatalf("startup failure became a verdict: %+v", result)
	}
	if result.Evidence["mcp_http_case_isolation"] != "startup_failed" {
		t.Fatalf("missing failure diagnostic: %+v", result)
	}
}

func TestCaseIsolationExternalListenerIsUnverified(t *testing.T) {
	a := isolatedTestAdapter(t, "")
	result := a.Run(isolationCase("external", "clean"), time.Second)
	if result.Evidence["mcp_http_case_isolation"] != "external_listener_unverified" {
		t.Fatalf("external target claimed isolation: %+v", result)
	}
}

func TestCaseIsolationNonMCPDoesNotLaunchTarget(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "unexpected")
	a := isolatedTestAdapter(t, "touch "+strconv.Quote(marker))
	_ = a.Run(adapter.Case{ID: "unrelated", Transport: "fetch_proxy", InputType: "url", Payload: map[string]interface{}{"url": "https://fixture.example.com/"}}, 100*time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("unrelated case started MCP target: %v", err)
	}
}

func TestCaseIsolationConcurrentCalls(t *testing.T) {
	t.Setenv("AEB_ISOLATION_TARGET_HELPER", "1")
	a := isolatedTestAdapter(t, isolationHelperCommand())
	var wg sync.WaitGroup
	results := make(chan adapter.Result, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results <- a.Run(isolationCase(fmt.Sprint(i), "poison"), 3*time.Second) }(i)
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.Err != nil || result.Verdict != "allow" || !result.VerdictObserved {
			t.Fatalf("concurrent case inherited state or wrong endpoint: %+v", result)
		}
	}
}

// This real subprocess deliberately retains state globally, even across
// initialize calls. It exposes the contamination a fresh client token cannot fix.
func TestIsolationTargetHelper(t *testing.T) {
	if os.Getenv("AEB_ISOLATION_TARGET_HELPER") == "" {
		return
	}
	ln, err := net.Listen("tcp", os.Getenv("AEB_MCP_HTTP_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if marker := os.Getenv("AEB_ISOLATION_LISTENERS"); marker != "" {
		f, err := os.OpenFile(marker, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = fmt.Fprintln(f, ln.Addr().String())
		_ = f.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	upstream, err := url.Parse(os.Getenv("AEB_MCP_HTTP_FIXTURE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var mu sync.Mutex
	poisoned := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := json.RawMessage{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var message struct {
			Method string          `json:"method"`
			ID     json.RawMessage `json:"id"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &message)
		if message.Method == "tools/call" {
			mu.Lock()
			deny := poisoned
			if message.Params.Name == "poison" {
				poisoned = true
			}
			mu.Unlock()
			if deny {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":"policy denied: previous call poisoned this process"}}`, message.ID)
				return
			}
		}
		r.Body = http.NoBody
		// Restore exactly the request bytes before forwarding to the fixture.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		proxy.ServeHTTP(w, r)
	})
	_ = http.Serve(ln, handler)
}
