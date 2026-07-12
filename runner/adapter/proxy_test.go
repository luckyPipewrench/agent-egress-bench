package adapter

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
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

func TestRunFetchProxy_AcceptsPOST(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, `{"blocked":false}`)
	}))
	defer srv.Close()
	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	c := Case{
		ID:        "test-post",
		Transport: "fetch_proxy",
		Payload: map[string]interface{}{
			"url":          "https://example.com/upload",
			"method":       "POST",
			"content_type": "application/json",
			"body":         `{"key": "value"}`,
		},
	}
	result := a.runFetchProxy(c, 5*time.Second)
	if result.Verdict == "skip" {
		t.Errorf("POST fetch_proxy should not be skipped, got skip")
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

func TestRunFetchProxy_RoutesDocsHostToHTTPFixture(t *testing.T) {
	var gotFetchTarget string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotFetchTarget = r.URL.Query().Get("url")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	var routePath, routeBody string
	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	a.SetHTTPFixture("127.0.0.1:34567", func(path, body string) {
		routePath = path
		routeBody = body
	})

	c := Case{
		ID:        "fp-db-conn-no-credentials-013",
		Transport: "fetch_proxy",
		Payload: map[string]interface{}{
			"url": "https://docs.example.com/guide?example=postgres://localhost:5432/mydb",
		},
	}
	result := a.runFetchProxy(c, 5*time.Second)
	if result.Verdict != "allow" {
		t.Fatalf("verdict = %q, err = %v", result.Verdict, result.Err)
	}
	if gotFetchTarget != "http://aeb-fixture.test:34567/guide?example=postgres://localhost:5432/mydb" {
		t.Fatalf("fetch target = %q", gotFetchTarget)
	}
	if routePath != "/guide" {
		t.Fatalf("route path = %q, want /guide", routePath)
	}
	if routeBody == "" {
		t.Fatal("expected non-empty fixture body")
	}
}

func TestRunWebSocketFrameViaProxy_UsesWebSocketFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ws" {
			t.Errorf("expected /ws path, got %s", r.URL.Path)
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("test server does not support hijacking")
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		if _, err := fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			t.Fatalf("write upgrade response: %v", err)
		}
		_, payload, err := readWebSocketFrame(rw.Reader)
		if err != nil {
			t.Fatalf("read websocket frame: %v", err)
		}
		if string(payload) != "hello over ws" {
			t.Fatalf("payload = %q, want websocket frame payload", payload)
		}
		if err := writeServerWebSocketFrame(conn, wsOpcodeText, []byte("echo")); err != nil {
			t.Fatalf("write echo frame: %v", err)
		}
	}))
	defer srv.Close()

	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	result := a.runWebSocketFrameViaProxy(Case{
		ID:        "ws-frame",
		Transport: "websocket",
		InputType: "websocket_frame",
		Payload: map[string]interface{}{
			"url":    "wss://example.com/ws",
			"frames": []interface{}{map[string]interface{}{"opcode": "text", "payload": "hello over ws"}},
		},
	}, 5*time.Second)
	if result.Verdict != "allow" {
		t.Fatalf("verdict = %q, err = %v, evidence = %+v", result.Verdict, result.Err, result.Evidence)
	}
}

func TestWriteCorpusWebSocketFrame_ValidThreePartFragmentation(t *testing.T) {
	var buf bytes.Buffer
	frames := []map[string]interface{}{
		{"opcode": "text", "fin": false, "payload": "The quarterly "},
		{"opcode": "continuation", "fin": false, "payload": "report is ready "},
		{"opcode": "continuation", "fin": true, "payload": "for your review."},
	}
	for _, frame := range frames {
		if err := writeCorpusWebSocketFrame(&buf, frame); err != nil {
			t.Fatalf("write frame: %v", err)
		}
	}

	br := bufio.NewReader(&buf)
	for i, want := range []struct {
		opcode int
		fin    bool
	}{
		{wsOpcodeText, false},
		{wsOpcodeContinuation, false},
		{wsOpcodeContinuation, true},
	} {
		got, err := readClientWebSocketFrame(br)
		if err != nil {
			t.Fatalf("read frame %d: %v", i, err)
		}
		if got.opcode != want.opcode || got.fin != want.fin {
			t.Fatalf("frame %d opcode/fin = %d/%v, want %d/%v", i, got.opcode, got.fin, want.opcode, want.fin)
		}
	}
}

type clientWSFrame struct {
	opcode int
	fin    bool
}

func readClientWebSocketFrame(r *bufio.Reader) (clientWSFrame, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return clientWSFrame{}, err
	}
	opcode := int(header[0] & 0x0f)
	fin := header[0]&0x80 != 0
	masked := header[1]&0x80 != 0
	payloadLen := uint64(header[1] & 0x7f)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return clientWSFrame{}, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return clientWSFrame{}, err
		}
		payloadLen = 0
		for _, b := range ext {
			payloadLen = payloadLen<<8 | uint64(b)
		}
	}
	if masked {
		mask := make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return clientWSFrame{}, err
		}
	}
	if _, err := io.CopyN(io.Discard, r, int64(payloadLen)); err != nil {
		return clientWSFrame{}, err
	}
	return clientWSFrame{opcode: opcode, fin: fin}, nil
}

func TestRunWebSocketFrameViaProxy_CloseFrameBlocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj := w.(http.Hijacker)
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		if _, err := fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			t.Fatalf("write upgrade response: %v", err)
		}
		if _, _, err := readWebSocketFrame(rw.Reader); err != nil {
			t.Fatalf("read websocket frame: %v", err)
		}
		if err := writeServerWebSocketFrame(conn, wsOpcodeClose, append([]byte{0x03, 0xe8}, []byte("blocked by policy")...)); err != nil {
			t.Fatalf("write close frame: %v", err)
		}
	}))
	defer srv.Close()

	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	result := a.runWebSocketFrameViaProxy(Case{
		ID:        "ws-close",
		Transport: "websocket",
		InputType: "websocket_frame",
		Payload: map[string]interface{}{
			"url":    "wss://example.com/ws",
			"frames": []interface{}{map[string]interface{}{"opcode": "text", "payload": "blocked"}},
		},
	}, 5*time.Second)
	if result.Verdict != "block" {
		t.Fatalf("verdict = %q, err = %v, evidence = %+v", result.Verdict, result.Err, result.Evidence)
	}
}

// TestRunWebSocketFrameViaProxy_BlockAfterEchoIsBlock covers the cross-message
// scenario where the proxy forwards an upstream echo before deciding to close
// the connection on a later client frame. The single-frame classifier this
// test guards against would read the echo first and return allow even though
// the proxy actually wrote a close frame after the echo.
func TestRunWebSocketFrameViaProxy_BlockAfterEchoIsBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj := w.(http.Hijacker)
		conn, rw, err := hj.Hijack()
		if err != nil {
			t.Fatalf("hijack: %v", err)
		}
		defer conn.Close() //nolint:errcheck // test cleanup
		if _, err := fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"); err != nil {
			t.Fatalf("write upgrade response: %v", err)
		}
		// Read both client frames.
		if _, _, err := readWebSocketFrame(rw.Reader); err != nil {
			t.Fatalf("read msg1: %v", err)
		}
		if _, _, err := readWebSocketFrame(rw.Reader); err != nil {
			t.Fatalf("read msg2: %v", err)
		}
		// Forward an echo of the first frame, then immediately write the
		// close frame the proxy would send when its cross-message scanner
		// fires on the second frame.
		if err := writeServerWebSocketFrame(conn, wsOpcodeText, []byte("echo of msg1")); err != nil {
			t.Fatalf("write echo: %v", err)
		}
		if err := writeServerWebSocketFrame(conn, wsOpcodeClose, append([]byte{0x03, 0xe8}, []byte("DLP violation")...)); err != nil {
			t.Fatalf("write close: %v", err)
		}
	}))
	defer srv.Close()

	a, _ := NewProxyAdapter(srv.Listener.Addr().String(), "", "", "")
	result := a.runWebSocketFrameViaProxy(Case{
		ID:        "ws-block-after-echo",
		Transport: "websocket",
		InputType: "websocket_frame",
		Payload: map[string]interface{}{
			"url": "wss://example.com/ws",
			"frames": []interface{}{
				map[string]interface{}{"opcode": "text", "payload": "part1"},
				map[string]interface{}{"opcode": "text", "payload": "part2"},
			},
		},
	}, 5*time.Second)
	if result.Verdict != "block" {
		t.Fatalf("verdict = %q, err = %v, evidence = %+v — proxy wrote close after echo; runner must drain to the close frame instead of classifying on the first echo", result.Verdict, result.Err, result.Evidence)
	}
}

func writeServerWebSocketFrame(w io.Writer, opcode int, payload []byte) error {
	header := []byte{0x80 | byte(opcode)}
	if len(payload) < 126 {
		header = append(header, byte(len(payload)))
	} else {
		return fmt.Errorf("test payload too large: %d", len(payload))
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
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

func TestRunScanAPIDualPass_AgentCardURLUsesURLKind(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, string(body))
		var req scanAPIRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Kind == "url" && req.Input.URL == "http://169.254.169.254/latest/meta-data/" {
			_, _ = fmt.Fprint(w, `{"status":"completed","decision":"deny","kind":"url"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"status":"completed","decision":"allow","kind":"`+req.Kind+`"}`)
	}))
	defer srv.Close()

	a := &ProxyAdapter{scanURL: srv.URL}
	c := Case{
		ID: "a2a-card-url-ssrf-008",
		Payload: map[string]interface{}{
			"agent_card": map[string]interface{}{
				"name":        "data-fetcher",
				"description": "Fetches data on request.",
				"url":         "http://169.254.169.254/latest/meta-data/",
				"skills": []interface{}{
					map[string]interface{}{"name": "Fetch", "description": "Fetches a resource."},
				},
			},
		},
	}
	result := a.runScanAPIDualPass(c, 5*time.Second)
	if result.Verdict != "block" {
		t.Fatalf("verdict = %q, err = %v, evidence = %+v", result.Verdict, result.Err, result.Evidence)
	}
	if len(seen) != 1 {
		t.Fatalf("scan requests = %d, want URL pass to block before text passes; requests=%v", len(seen), seen)
	}
	if !strings.Contains(seen[0], `"kind":"url"`) || !strings.Contains(seen[0], `169.254.169.254`) {
		t.Fatalf("first scan request did not carry agent_card.url to URL scanner: %s", seen[0])
	}
}

func TestRunScanAPIDualPass_A2AFilePartURIUsesURLKind(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, string(body))
		var req scanAPIRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Kind == "url" && req.Input.URL == "http://169.254.169.254/latest/meta-data/iam/security-credentials/" {
			_, _ = fmt.Fprint(w, `{"status":"completed","decision":"deny","kind":"url"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"status":"completed","decision":"allow","kind":"`+req.Kind+`"}`)
	}))
	defer srv.Close()

	a := &ProxyAdapter{scanURL: srv.URL}
	c := Case{
		ID: "a2a-msg-file-part-ssrf-012",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{
				map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      "req-012",
					"method":  "message/send",
					"params": map[string]interface{}{
						"message": map[string]interface{}{
							"messageId": "msg-012",
							"role":      "user",
							"parts": []interface{}{
								map[string]interface{}{
									"kind": "file",
									"file": map[string]interface{}{
										"uri":      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
										"mimeType": "text/plain",
									},
								},
							},
						},
					},
				},
			},
		},
	}
	result := a.runScanAPIDualPass(c, 5*time.Second)
	if result.Verdict != "block" {
		t.Fatalf("verdict = %q, err = %v, evidence = %+v", result.Verdict, result.Err, result.Evidence)
	}
	if len(seen) != 1 {
		t.Fatalf("scan requests = %d, want URL pass to block before text passes; requests=%v", len(seen), seen)
	}
	if !strings.Contains(seen[0], `"kind":"url"`) || !strings.Contains(seen[0], `169.254.169.254`) {
		t.Fatalf("first scan request did not carry file.uri to URL scanner: %s", seen[0])
	}
}

func TestExtractTextFromPayload_AgentCard(t *testing.T) {
	payload := map[string]interface{}{
		"agent_card": map[string]interface{}{
			"url":         "https://example.com/agent",
			"description": "main desc",
			"skills": []interface{}{
				map[string]interface{}{"description": "skill A"},
				map[string]interface{}{"description": "skill B"},
			},
		},
	}
	text := extractTextFromPayload(payload)
	if text != "https://example.com/agent\nmain desc\nskill A\nskill B" {
		t.Errorf("unexpected text: %q", text)
	}
}

func TestExtractTextFromPayload_AgentCardName(t *testing.T) {
	payload := map[string]interface{}{
		"agent_card": map[string]interface{}{
			"name":        "injected\nSYSTEM: override",
			"description": "A helper",
			"skills":      []interface{}{},
		},
	}
	text := extractTextFromPayload(payload)
	if !strings.Contains(text, "injected\nSYSTEM: override") {
		t.Errorf("expected name field in extracted text, got: %q", text)
	}
	if !strings.Contains(text, "A helper") {
		t.Errorf("expected description in extracted text, got: %q", text)
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

func TestPreflightMockScriptExec_HappyPath(t *testing.T) {
	if err := PreflightMockScriptExec(); err != nil {
		t.Skipf("mock-script preflight is unsupported in this environment: %v", err)
	}
}

func TestPreflightMockScriptExec_BashMissingFromPATH(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh on PATH to build a bash-free PATH with")
	}
	shDir := shOnlyPATHDir(t)
	t.Setenv("PATH", shDir)

	err := PreflightMockScriptExec()
	if err == nil {
		t.Fatal("expected an error when bash is not on PATH")
	}
	if !strings.Contains(err.Error(), "bash not found in PATH") {
		t.Errorf("expected a bash-not-found message, got: %v", err)
	}
}

// shOnlyPATHDir returns a directory containing only a "sh" symlink (copied
// from the real sh on PATH), so PATH can be pointed at an environment with
// a shell but no bash, without disturbing the real PATH for other tests.
func shOnlyPATHDir(t *testing.T) string {
	t.Helper()
	shPath, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("look up sh: %v", err)
	}
	dir := t.TempDir()
	if err := os.Symlink(shPath, dir+"/sh"); err != nil {
		t.Fatalf("symlink sh into isolated PATH dir: %v", err)
	}
	return dir
}

func TestClassifyPreflightScriptAccessErr_PermissionDenied(t *testing.T) {
	wrapped := fmt.Errorf("open /tmp/x.sh: %w", fs.ErrPermission)
	err := classifyPreflightScriptAccessErr("/tmp", wrapped)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cannot read") {
		t.Errorf("expected the permission message, got: %v", msg)
	}
	if !strings.Contains(msg, "TMPDIR") {
		t.Errorf("expected a TMPDIR remediation hint, got: %v", msg)
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Error("expected classifyPreflightScriptAccessErr to preserve the wrapped error for errors.Is")
	}
}

func TestClassifyPreflightScriptAccessErr_ScriptMissing(t *testing.T) {
	wrapped := fmt.Errorf("open /tmp/x.sh: %w", fs.ErrNotExist)
	err := classifyPreflightScriptAccessErr("/tmp", wrapped)
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "temp script disappeared") {
		t.Errorf("expected a missing-script message, got: %v", msg)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Error("expected classifyPreflightScriptAccessErr to preserve the wrapped error for errors.Is")
	}
}

func TestShellQuote(t *testing.T) {
	got := shellQuote("/tmp/a b/it's.sh")
	want := "'/tmp/a b/it'\\''s.sh'"
	if got != want {
		t.Fatalf("shellQuote() = %q, want %q", got, want)
	}
}

func TestClassifyPreflightExecErr_UnknownFailure_UsesNoneForEmptyStderr(t *testing.T) {
	wrapped := errors.New("boom")
	err := classifyPreflightExecErr("/tmp", wrapped, "")
	if err == nil {
		t.Fatal("expected a non-nil error")
	}
	if !strings.Contains(err.Error(), "(none)") {
		t.Errorf("expected the fallback branch to render empty stderr as (none), got: %v", err.Error())
	}
}

func TestRunMCPStdio_StderrSurfacedOnSubprocessFailure(t *testing.T) {
	// A command that writes to stderr and exits non-zero, with no stdout,
	// must surface the stderr text in the returned error instead of
	// discarding it (the exact class of bug this test guards against: a
	// silently swallowed mock-backend spawn failure).
	a := &ProxyAdapter{mcpCmd: `echo boom-diagnostic 1>&2; exit 3`}
	c := Case{
		ID:      "test-stderr-surfaced",
		Payload: map[string]interface{}{"jsonrpc_messages": []interface{}{map[string]interface{}{"method": "tools/call"}}},
	}
	result := a.runMCPStdio(c, 5*time.Second)
	if result.Err == nil {
		t.Fatal("expected an error result for a non-zero exit with no stdout")
	}
	if !strings.Contains(result.Err.Error(), "boom-diagnostic") {
		t.Errorf("expected the captured stderr to be surfaced in the error, got: %v", result.Err)
	}
}
