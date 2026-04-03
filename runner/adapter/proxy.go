// Package adapter — proxy adapter sends cases through an HTTP proxy.
//
// Works with any tool that operates as an HTTP/HTTPS proxy with a scan API
// (pipelock, or any tool implementing the same endpoints). Point --proxy-addr
// at the tool's listen address and the adapter sends real traffic through it.
//
// Transport mapping:
//   - fetch_proxy  → GET /fetch?url=...
//   - http_proxy   → CONNECT tunnel via HTTPS_PROXY
//   - websocket    → GET /ws?url=... (connection attempt)
//   - mcp_stdio    → POST /api/v1/scan (kind: tool_call or text)
//   - mcp_http     → POST /api/v1/scan (kind: tool_call or text)
//   - a2a          → POST /api/v1/scan (kind: text)
package adapter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ProxyAdapter sends benchmark cases through an HTTP proxy and checks
// whether the proxy blocked or allowed the request.
type ProxyAdapter struct {
	proxyURL  *url.URL
	scanURL   string // base URL for scan API (e.g. http://127.0.0.1:9990)
	scanToken string // bearer token for scan API auth
	mcpCmd    string // MCP proxy command (e.g. "pipelock mcp proxy --config /tmp/bench.yaml -- cat")
}

// NewProxyAdapter creates a proxy adapter. proxyAddr is for HTTP traffic,
// scanAddr is for the scan API, mcpCmd is for MCP/A2A/shell cases.
func NewProxyAdapter(proxyAddr, scanAddr, scanToken, mcpCmd string) (*ProxyAdapter, error) {
	u, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %w", proxyAddr, err)
	}
	scanBase := "http://" + proxyAddr
	if scanAddr != "" {
		scanBase = "http://" + scanAddr
	}
	return &ProxyAdapter{proxyURL: u, scanURL: scanBase, scanToken: scanToken, mcpCmd: mcpCmd}, nil
}

// Run sends the case payload through the proxy and returns the verdict.
func (p *ProxyAdapter) Run(c Case, timeout time.Duration) Result {
	switch c.Transport {
	case "fetch_proxy":
		return p.runFetchProxy(c, timeout)
	case "http_proxy":
		return p.runHTTPProxy(c, timeout)
	case "websocket":
		return p.runWebSocket(c, timeout)
	case "mcp_stdio", "mcp_http":
		return p.runMCPStdio(c, timeout)
	case "a2a":
		// A2A: scan API first (fast), then MCP proxy (deeper DLP with encoding decode).
		result := p.runScanAPIDualPass(c, timeout)
		if result.Verdict == "block" || result.Err != nil {
			return result
		}
		// Scan API allowed — try routing through MCP proxy for wider coverage.
		if p.mcpCmd != "" {
			return p.runA2AViaMCP(c, timeout)
		}
		return result
	default:
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": fmt.Sprintf("unknown transport %q", c.Transport)},
		}
	}
}

// runFetchProxy sends a request to the proxy's /fetch endpoint.
// The fetch endpoint only supports GET — cases declaring other methods are skipped.
func (p *ProxyAdapter) runFetchProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}

	// The /fetch endpoint only accepts GET. Skip cases that require other methods.
	if m, ok := payloadString(c.Payload, "method"); ok && m != "" && m != http.MethodGet {
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": fmt.Sprintf("fetch endpoint does not support %s", m)},
		}
	}

	fetchURL := fmt.Sprintf("%s/fetch?url=%s", p.proxyURL.String(), url.QueryEscape(targetURL))

	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", c.ID, err)}
	}

	if hdrs, ok := c.Payload["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
			return Result{
				Verdict:  "skip",
				Evidence: map[string]interface{}{"reason": "fetch_timeout", "detail": truncate(errStr, 120)},
			}
		}
		return Result{Err: fmt.Errorf("case %s: fetch proxy: %w", c.ID, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classifyResponse(resp.StatusCode, string(body))
}

// runHTTPProxy sends a request through the proxy as HTTPS_PROXY (CONNECT tunnel).
func (p *ProxyAdapter) runHTTPProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}

	method, _ := payloadString(c.Payload, "method")
	if method == "" {
		method = http.MethodGet
	}

	var bodyReader io.Reader
	if b, ok := c.Payload["body"].(string); ok && b != "" {
		bodyReader = strings.NewReader(b)
	}

	req, err := http.NewRequest(method, targetURL, bodyReader)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", c.ID, err)}
	}

	if hdrs, ok := c.Payload["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(p.proxyURL),
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		// Proxy actively rejected the CONNECT (policy decision).
		if strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "blocked") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Method Not Allowed") || strings.Contains(errStr, "405") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "proxy_rejected"}}
		}
		// Proxy or upstream connection reset — may be an active block.
		if strings.Contains(errStr, "reset by peer") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "connection_reset"}}
		}
		// Proxy unreachable — adapter infrastructure problem.
		if strings.Contains(errStr, "connection refused") {
			return Result{Err: fmt.Errorf("case %s: proxy unreachable: %w", c.ID, err)}
		}
		// Upstream unreachable (DNS, TLS, timeout) — the proxy allowed the
		// CONNECT but the upstream doesn't exist. Skip, not error.
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "upstream_unreachable", "detail": truncate(errStr, 120)},
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classifyResponse(resp.StatusCode, string(body))
}

// runWebSocket attempts a WebSocket connection through the proxy's /ws endpoint.
func (p *ProxyAdapter) runWebSocket(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}

	wsURL := fmt.Sprintf("%s/ws?url=%s", p.proxyURL.String(), url.QueryEscape(targetURL))

	req, err := http.NewRequest(http.MethodGet, wsURL, nil)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", c.ID, err)}
	}

	if hdrs, ok := c.Payload["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				req.Header.Set(k, s)
			}
		}
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		// Proxy unreachable — adapter infrastructure problem.
		if strings.Contains(errStr, "connection refused") {
			return Result{Err: fmt.Errorf("case %s: ws proxy unreachable: %w", c.ID, err)}
		}
		// Upstream WS server unreachable (timeout, DNS). Skip, not error.
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "ws_upstream_unreachable", "detail": truncate(errStr, 120)},
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return classifyResponse(resp.StatusCode, string(body))
}

// runMCPStdio sends JSON-RPC messages through the MCP proxy subprocess.
//
// The proxy sits between client (stdin) and server (subprocess backend).
// Case payloads contain jsonrpc_messages which may be:
//   - Client→server requests (tools/call): written to stdin, proxy scans them
//   - Server→client responses (tools/list result): need the mock to return them
//
// For tool poisoning cases (messages with "result" field), the adapter creates
// a mock that returns the poisoned payload as the server response, then sends
// the corresponding request through the client side.
func (p *ProxyAdapter) runMCPStdio(c Case, timeout time.Duration) Result {
	if p.mcpCmd == "" {
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "no --mcp-cmd configured"},
		}
	}

	msgs, ok := c.Payload["jsonrpc_messages"]
	if !ok {
		msgs = []interface{}{c.Payload}
	}

	msgList, ok := msgs.([]interface{})
	if !ok || len(msgList) == 0 {
		return Result{Err: fmt.Errorf("case %s: no jsonrpc_messages in payload", c.ID)}
	}

	// Separate client requests from server responses.
	var clientMsgs []interface{}
	var serverResponses []interface{}
	for _, msg := range msgList {
		m, ok := msg.(map[string]interface{})
		if !ok {
			clientMsgs = append(clientMsgs, msg)
			continue
		}
		if _, hasResult := m["result"]; hasResult {
			serverResponses = append(serverResponses, msg)
		} else if _, hasError := m["error"]; hasError {
			serverResponses = append(serverResponses, msg)
		} else {
			clientMsgs = append(clientMsgs, msg)
		}
	}

	// Build the MCP command. For tool poisoning (server responses in payload),
	// create a temp-file-based mock that returns the poisoned responses.
	// This avoids shell escaping issues with complex JSON payloads.
	mcpCmd := p.mcpCmd
	var tempFiles []string // cleaned up after cmd.Wait
	if len(serverResponses) > 0 {
		// Write server responses to a temp file (one JSON line per response).
		respFile, respErr := os.CreateTemp("", "mock-responses-*.jsonl")
		if respErr != nil {
			return Result{Err: fmt.Errorf("case %s: create temp response file: %w", c.ID, respErr)}
		}
		tempFiles = append(tempFiles, respFile.Name())
		for _, sr := range serverResponses {
			line, _ := json.Marshal(sr)
			_, _ = respFile.Write(line)
			_, _ = respFile.Write([]byte("\n"))
		}
		_ = respFile.Close()

		// Write a mock script that reads the response file.
		// For each input line, output the next line from the response file.
		mockScript, scriptErr := os.CreateTemp("", "mock-script-*.sh")
		if scriptErr != nil {
			return Result{Err: fmt.Errorf("case %s: create temp script: %w", c.ID, scriptErr)}
		}
		tempFiles = append(tempFiles, mockScript.Name())
		_, _ = fmt.Fprintf(mockScript, "#!/bin/bash\n_n=0\nwhile IFS= read -r _input; do\n  _n=$((_n+1))\n  sed -n \"${_n}p\" '%s'\ndone\n",
			respFile.Name())
		_ = mockScript.Close()
		_ = os.Chmod(mockScript.Name(), 0o750)

		// Replace the backend command with our custom mock script.
		if idx := strings.Index(mcpCmd, " -- "); idx >= 0 {
			mcpCmd = mcpCmd[:idx] + " -- " + mockScript.Name()
		} else {
			return Result{Err: fmt.Errorf("case %s: --mcp-cmd missing ' -- ' separator, cannot inject mock backend", c.ID)}
		}

		// If no client messages, send a tools/list request to trigger the response.
		if len(clientMsgs) == 0 {
			clientMsgs = append(clientMsgs, map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "tools/list",
				"id":      1,
			})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", mcpCmd) //nolint:gosec // command from trusted CLI flag
	cmd.Stderr = io.Discard

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: stdin pipe: %w", c.ID, err)}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: stdout pipe: %w", c.ID, err)}
	}

	if startErr := cmd.Start(); startErr != nil {
		return Result{Err: fmt.Errorf("case %s: start MCP cmd: %w", c.ID, startErr)}
	}

	outputCh := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(stdout)
		outputCh <- data
	}()

	for _, msg := range clientMsgs {
		line, _ := json.Marshal(msg)
		_, _ = stdin.Write(line)
		_, _ = stdin.Write([]byte("\n"))
	}
	_ = stdin.Close()

	waitErr := cmd.Wait()
	for _, tf := range tempFiles {
		_ = os.Remove(tf)
	}
	output := <-outputCh

	// Context timeout is expected (subprocess runs until stdin closes).
	// But other wait errors with no output indicate a real failure.
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		if waitErr != nil && ctx.Err() == nil {
			return Result{Err: fmt.Errorf("case %s: MCP subprocess failed: %w", c.ID, waitErr)}
		}
		return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "no_output"}}
	}

	// Check response lines for policy-block JSON-RPC errors.
	// Pipelock uses -32000 to -32009 for policy decisions (scan block, chain, etc.).
	// Standard JSON-RPC errors (-32700 to -32600) are protocol issues, not blocks.
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
				// Policy block from the proxy (-32000 to -32099 range).
				return Result{
					Verdict: "block",
					Evidence: map[string]interface{}{
						"error_code":    code,
						"error_message": rpcResp.Error.Message,
					},
				}
			}
			if code <= -32600 {
				// Standard JSON-RPC protocol error — not a policy decision.
				return Result{Err: fmt.Errorf("case %s: JSON-RPC protocol error %d: %s", c.ID, code, rpcResp.Error.Message)}
			}
		}
	}

	return Result{
		Verdict:  "allow",
		Evidence: map[string]interface{}{"response_lines": len(lines)},
	}
}

// scanAPIRequest is the JSON body for POST /api/v1/scan.
type scanAPIRequest struct {
	Kind  string       `json:"kind"`
	Input scanAPIInput `json:"input"`
}

type scanAPIInput struct {
	URL       string          `json:"url,omitempty"`
	Text      string          `json:"text,omitempty"`
	Content   string          `json:"content,omitempty"`
	ToolName  string          `json:"tool_name,omitempty"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// runScanAPIDualPass runs the scan API twice: once for DLP, once for injection.
// A2A cases may contain both secrets and injection in the same payload.
func (p *ProxyAdapter) runScanAPIDualPass(c Case, timeout time.Duration) Result {
	// First pass: try prompt_injection (catches card poisoning + injection).
	cInjection := c
	result := p.runScanAPIWithKind(cInjection, timeout, "prompt_injection")
	if result.Verdict == "block" || result.Err != nil {
		return result
	}
	// Second pass: try DLP (catches secrets in messages).
	return p.runScanAPIWithKind(c, timeout, "dlp")
}

// runScanAPIWithKind runs the scan API with a specific forced kind.
func (p *ProxyAdapter) runScanAPIWithKind(c Case, timeout time.Duration, kind string) Result {
	text := extractTextFromPayload(c.Payload)
	if text == "" {
		return Result{Verdict: "allow", Evidence: map[string]interface{}{"reason": "no_text_extracted"}}
	}

	var input scanAPIInput
	if kind == "prompt_injection" {
		input.Content = text
	} else {
		input.Text = text
	}
	scanReq := scanAPIRequest{Kind: kind, Input: input}
	body, _ := json.Marshal(scanReq)

	scanURL := fmt.Sprintf("%s/api/v1/scan", p.scanURL)
	req, err := http.NewRequest(http.MethodPost, scanURL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", c.ID, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	if p.scanToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.scanToken)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: scan API (%s): %w", c.ID, kind, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		return Result{Err: fmt.Errorf("case %s: scan API (%s) returned %d: %s", c.ID, kind, resp.StatusCode, truncate(string(respBody), 120))}
	}

	var scanResp struct {
		Verdict  string `json:"verdict"`
		Action   string `json:"action"`
		Decision string `json:"decision"`
	}
	if jsonErr := json.Unmarshal(respBody, &scanResp); jsonErr == nil {
		decision := scanResp.Decision
		if decision == "" {
			decision = scanResp.Verdict
		}
		if isScanDeny(decision) || isScanDeny(scanResp.Action) {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"kind": kind, "decision": decision}}
		}
		if decision != "" {
			return Result{Verdict: "allow", Evidence: map[string]interface{}{"kind": kind}}
		}
	}

	return Result{Err: fmt.Errorf("case %s: scan API (%s) returned unparseable response: %s", c.ID, kind, truncate(string(respBody), 120))}
}

// runA2AViaMCP wraps A2A content in a fake tools/call message and sends
// it through the MCP proxy. The MCP input scanner runs full DLP including
// encoding decode, which catches secrets that the scan API DLP misses.
func (p *ProxyAdapter) runA2AViaMCP(c Case, timeout time.Duration) Result {
	text := extractTextFromPayload(c.Payload)
	if text == "" {
		return Result{Verdict: "allow", Evidence: map[string]interface{}{"reason": "no_text_extracted"}}
	}
	// Wrap in a tools/call JSON-RPC message.
	wrapped := Case{
		ID:              c.ID,
		ExpectedVerdict: c.ExpectedVerdict,
		Transport:       "mcp_stdio",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{
				map[string]interface{}{
					"jsonrpc": "2.0",
					"method":  "tools/call",
					"id":      1,
					"params": map[string]interface{}{
						"name": "a2a_relay",
						"arguments": map[string]interface{}{
							"content": text,
						},
					},
				},
			},
		},
	}
	return p.runMCPStdio(wrapped, timeout)
}

// extractTextFromPayload pulls scannable text from any payload format.
func extractTextFromPayload(payload map[string]interface{}) string {
	// A2A agent cards — scan name, description, and skill descriptions.
	if card, ok := payload["agent_card"].(map[string]interface{}); ok {
		var texts []string
		if name, ok := card["name"].(string); ok {
			texts = append(texts, name)
		}
		if desc, ok := card["description"].(string); ok {
			texts = append(texts, desc)
		}
		if skills, ok := card["skills"].([]interface{}); ok {
			for _, s := range skills {
				skill, _ := s.(map[string]interface{})
				if name, ok := skill["name"].(string); ok {
					texts = append(texts, name)
				}
				if desc, ok := skill["description"].(string); ok {
					texts = append(texts, desc)
				}
			}
		}
		return strings.Join(texts, "\n")
	}

	// A2A messages (jsonrpc_messages with message/send).
	if msgs, ok := payload["jsonrpc_messages"].([]interface{}); ok {
		var texts []string
		for _, msg := range msgs {
			m, _ := msg.(map[string]interface{})
			params, _ := m["params"].(map[string]interface{})
			message, _ := params["message"].(map[string]interface{})
			parts, _ := message["parts"].([]interface{})
			for _, part := range parts {
				p, _ := part.(map[string]interface{})
				if text, ok := p["text"].(string); ok {
					texts = append(texts, text)
				}
				if data, ok := p["data"].(map[string]interface{}); ok {
					dataJSON, _ := json.Marshal(data)
					texts = append(texts, string(dataJSON))
				}
			}
		}
		if len(texts) > 0 {
			return strings.Join(texts, "\n")
		}
	}

	// Fallback: serialize entire payload.
	b, _ := json.Marshal(payload)
	return string(b)
}

// classifyResponse determines block vs allow from the HTTP response.
func classifyResponse(statusCode int, body string) Result {
	evidence := map[string]interface{}{
		"status_code": statusCode,
	}

	if statusCode == http.StatusForbidden {
		evidence["reason"] = "http_403"
		if strings.Contains(body, "block_reason") || strings.Contains(body, "blocked") {
			evidence["body_snippet"] = truncate(body, 200)
		}
		return Result{Verdict: "block", Evidence: evidence}
	}

	if statusCode == http.StatusBadRequest || statusCode == http.StatusBadGateway {
		evidence["reason"] = fmt.Sprintf("http_%d", statusCode)
		return Result{Verdict: "block", Evidence: evidence}
	}

	if statusCode >= 200 && statusCode < 400 {
		return Result{Verdict: "allow", Evidence: evidence}
	}

	// 4xx/5xx that aren't 400/403/502 — the request reached the upstream and
	// got an error response. The proxy allowed it through (not a policy block).
	// 404, 429, 500, etc. all mean the proxy didn't intervene.
	evidence["reason"] = fmt.Sprintf("http_%d_passthrough", statusCode)
	return Result{Verdict: "allow", Evidence: evidence}
}

func payloadString(payload map[string]interface{}, key string) (string, bool) {
	v, ok := payload[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isScanDeny returns true if the verdict string indicates a block/deny.
// Pipelock's scan API uses "deny"; older or alternative engines may use "block".
func isScanDeny(v string) bool {
	return v == "deny" || v == "block"
}
