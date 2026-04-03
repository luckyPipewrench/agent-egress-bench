package adapter

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClassifyResponse(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		verdict string
	}{
		{"403 blocked", http.StatusForbidden, `{"blocked":true}`, "block"},
		{"403 plain", http.StatusForbidden, "Forbidden", "block"},
		{"400 bad request", http.StatusBadRequest, "", "block"},
		{"502 bad gateway", http.StatusBadGateway, "", "block"},
		{"200 ok", http.StatusOK, "ok", "allow"},
		{"301 redirect", http.StatusMovedPermanently, "", "allow"},
		{"404 passthrough", http.StatusNotFound, "not found", "allow"},
		{"500 passthrough", http.StatusInternalServerError, "", "allow"},
		{"429 passthrough", http.StatusTooManyRequests, "", "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyResponse(tt.status, tt.body)
			if result.Verdict != tt.verdict {
				t.Errorf("classifyResponse(%d) verdict = %q, want %q", tt.status, result.Verdict, tt.verdict)
			}
		})
	}
}

func TestIsScanDeny(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"deny", true},
		{"block", true},
		{"allow", false},
		{"", false},
		{"warn", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isScanDeny(tt.input); got != tt.want {
				t.Errorf("isScanDeny(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewProxyAdapter(t *testing.T) {
	a, err := NewProxyAdapter("127.0.0.1:8888", "127.0.0.1:9990", "tok", "cmd -- cat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.proxyURL.Host != "127.0.0.1:8888" {
		t.Errorf("proxyURL host = %q, want 127.0.0.1:8888", a.proxyURL.Host)
	}
	if a.scanURL != "http://127.0.0.1:9990" {
		t.Errorf("scanURL = %q, want http://127.0.0.1:9990", a.scanURL)
	}
}

func TestNewProxyAdapter_ScanAddrFallback(t *testing.T) {
	a, err := NewProxyAdapter("127.0.0.1:8888", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.scanURL != "http://127.0.0.1:8888" {
		t.Errorf("scanURL should fall back to proxy addr, got %q", a.scanURL)
	}
}

func TestRunFetchProxy_SkipsNonGET(t *testing.T) {
	a := &ProxyAdapter{}
	c := Case{
		ID:        "test-post",
		Transport: "fetch_proxy",
		Payload: map[string]interface{}{
			"url":    "https://example.com/upload",
			"method": "POST",
		},
	}
	result := a.runFetchProxy(c, 5*time.Second)
	if result.Verdict != "skip" {
		t.Errorf("expected skip for POST fetch_proxy, got %q", result.Verdict)
	}
}

func TestRunFetchProxy_AllowsGET(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	c := Case{
		ID:        "test-get",
		Transport: "fetch_proxy",
		Payload:   map[string]interface{}{"url": "https://example.com"},
	}
	result := a.runFetchProxy(c, 5*time.Second)
	// The mock server acts as the proxy's /fetch endpoint. It returns 200.
	if result.Verdict != "allow" {
		t.Errorf("expected allow, got %q (err: %v)", result.Verdict, result.Err)
	}
}

func TestRunMCPStdio_NoMCPCmd(t *testing.T) {
	a := &ProxyAdapter{}
	c := Case{
		ID:      "test-no-cmd",
		Payload: map[string]interface{}{"jsonrpc_messages": []interface{}{map[string]interface{}{"method": "tools/call"}}},
	}
	result := a.runMCPStdio(c, 5*time.Second)
	if result.Verdict != "skip" {
		t.Errorf("expected skip without mcp-cmd, got %q", result.Verdict)
	}
}

func TestRunMCPStdio_MockInjectionFailFast(t *testing.T) {
	a := &ProxyAdapter{mcpCmd: "some-command-without-separator"}
	c := Case{
		ID: "test-no-sep",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{
				map[string]interface{}{"result": map[string]interface{}{"tools": []interface{}{}}, "id": 1},
			},
		},
	}
	result := a.runMCPStdio(c, 5*time.Second)
	if result.Err == nil {
		t.Fatal("expected error when --mcp-cmd has no ' -- ' separator")
	}
}

func TestRunScanAPIWithKind_DenyVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"completed","decision":"deny","kind":"dlp"}`)
	}))
	defer srv.Close()

	a := &ProxyAdapter{scanURL: srv.URL, scanToken: "test"}
	c := Case{
		ID:      "test-deny",
		Payload: map[string]interface{}{"agent_card": map[string]interface{}{"description": "test content"}},
	}
	result := a.runScanAPIWithKind(c, 5*time.Second, "prompt_injection")
	if result.Verdict != "block" {
		t.Errorf("expected block for deny verdict, got %q", result.Verdict)
	}
}

func TestRunScanAPIWithKind_AllowVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status":"completed","decision":"allow","kind":"dlp"}`)
	}))
	defer srv.Close()

	a := &ProxyAdapter{scanURL: srv.URL, scanToken: "test"}
	c := Case{
		ID:      "test-allow",
		Payload: map[string]interface{}{"agent_card": map[string]interface{}{"description": "benign content"}},
	}
	result := a.runScanAPIWithKind(c, 5*time.Second, "dlp")
	if result.Verdict != "allow" {
		t.Errorf("expected allow, got %q", result.Verdict)
	}
}

func TestRunScanAPIWithKind_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = fmt.Fprint(w, "internal error")
	}))
	defer srv.Close()

	a := &ProxyAdapter{scanURL: srv.URL}
	c := Case{
		ID:      "test-500",
		Payload: map[string]interface{}{"agent_card": map[string]interface{}{"description": "test"}},
	}
	result := a.runScanAPIWithKind(c, 5*time.Second, "dlp")
	if result.Err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func TestRunA2AViaMCP_ExtractsText(t *testing.T) {
	a := &ProxyAdapter{} // no mcpCmd → will skip in runMCPStdio
	c := Case{
		ID: "test-a2a",
		Payload: map[string]interface{}{
			"agent_card": map[string]interface{}{
				"description": "test agent",
				"skills": []interface{}{
					map[string]interface{}{"description": "skill one"},
				},
			},
		},
	}
	result := a.runA2AViaMCP(c, 5*time.Second)
	// Without mcpCmd, runMCPStdio returns skip.
	if result.Verdict != "skip" {
		t.Errorf("expected skip (no mcp-cmd), got %q (err: %v)", result.Verdict, result.Err)
	}
}

func TestExtractTextFromPayload_AgentCard(t *testing.T) {
	payload := map[string]interface{}{
		"agent_card": map[string]interface{}{
			"description": "main desc",
			"skills": []interface{}{
				map[string]interface{}{"description": "skill A"},
				map[string]interface{}{"description": "skill B"},
			},
		},
	}
	text := extractTextFromPayload(payload)
	if text != "main desc\nskill A\nskill B" {
		t.Errorf("unexpected text: %q", text)
	}
}

func TestExtractTextFromPayload_A2AMessage(t *testing.T) {
	payload := map[string]interface{}{
		"jsonrpc_messages": []interface{}{
			map[string]interface{}{
				"method": "message/send",
				"params": map[string]interface{}{
					"message": map[string]interface{}{
						"parts": []interface{}{
							map[string]interface{}{"text": "hello world"},
						},
					},
				},
			},
		},
	}
	text := extractTextFromPayload(payload)
	if text != "hello world" {
		t.Errorf("unexpected text: %q", text)
	}
}

func TestExtractTextFromPayload_Fallback(t *testing.T) {
	payload := map[string]interface{}{"foo": "bar"}
	text := extractTextFromPayload(payload)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		t.Errorf("fallback should return valid JSON, got: %q", text)
	}
}

func TestJSONRPCPolicyVsProtocolErrors(t *testing.T) {
	// Policy block: -32001 (pipelock MCP input scanning block)
	policyLine := `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"pipelock: request blocked"}}`
	// Protocol error: -32601 (method not found)
	protocolLine := `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`
	// Normal response
	okLine := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`

	tests := []struct {
		name    string
		output  string
		verdict string
		isErr   bool
	}{
		{"policy block", policyLine, "block", false},
		{"protocol error", protocolLine, "", true},
		{"normal response", okLine, "allow", false},
		{"policy block among ok", okLine + "\n" + policyLine, "block", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate what runMCPStdio does with the output lines.
			lines := splitLines(tt.output)
			result := classifyMCPOutput(lines, "test-case")
			if tt.isErr {
				if result.Err == nil {
					t.Fatalf("expected error, got verdict=%q", result.Verdict)
				}
				return
			}
			if result.Err != nil {
				t.Fatalf("unexpected error: %v", result.Err)
			}
			if result.Verdict != tt.verdict {
				t.Errorf("verdict = %q, want %q", result.Verdict, tt.verdict)
			}
		})
	}
}

// splitLines mirrors the split in runMCPStdio.
func splitLines(s string) []string {
	var lines []string
	for _, l := range split(s) {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func split(s string) []string {
	return splitByNewline(s)
}

func splitByNewline(s string) []string {
	result := []string{}
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// classifyMCPOutput extracts the verdict from MCP subprocess output lines,
// mirroring the logic in runMCPStdio after cmd.Wait().
func classifyMCPOutput(lines []string, caseID string) Result {
	if len(lines) == 0 {
		return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "no_output"}}
	}

	for _, respLine := range lines {
		var rpcResp struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal([]byte(respLine), &rpcResp); jsonErr == nil && rpcResp.Error != nil {
			code := rpcResp.Error.Code
			if code >= -32099 && code <= -32000 {
				return Result{
					Verdict: "block",
					Evidence: map[string]interface{}{
						"error_code":    code,
						"error_message": rpcResp.Error.Message,
					},
				}
			}
			if code <= -32600 {
				return Result{Err: fmt.Errorf("case %s: JSON-RPC protocol error %d: %s", caseID, code, rpcResp.Error.Message)}
			}
		}
	}

	return Result{
		Verdict:  "allow",
		Evidence: map[string]interface{}{"response_lines": len(lines)},
	}
}
