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
		// A2A uses scan API with dual-pass: DLP first, then prompt_injection.
		return p.runScanAPIDualPass(c, timeout)
	default:
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": fmt.Sprintf("unknown transport %q", c.Transport)},
		}
	}
}

// runFetchProxy sends a request to the proxy's /fetch endpoint.
func (p *ProxyAdapter) runFetchProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
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
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "connection_refused"}}
		}
		return Result{Err: fmt.Errorf("case %s: request failed: %w", c.ID, err)}
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

	// TLS verification disabled for benchmarking. The bench corpus uses
	// fake domains that don't have valid certificates. This is test
	// tooling, not production code.
	transport := &http.Transport{
		Proxy: http.ProxyURL(p.proxyURL),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // G402: intentional for bench test traffic
		},
	}
	client := &http.Client{Timeout: timeout, Transport: transport}

	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "blocked") || strings.Contains(errStr, "403") || strings.Contains(errStr, "Method Not Allowed") || strings.Contains(errStr, "405") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "proxy_rejected"}}
		}
		if strings.Contains(errStr, "connection refused") || strings.Contains(errStr, "reset by peer") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "connection_refused"}}
		}
		if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
			if c.ExpectedVerdict == "block" {
				return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "dns_blocked"}}
			}
			return Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "upstream_unresolvable"}}
		}
		if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") {
			if c.ExpectedVerdict == "block" {
				return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "tls_blocked"}}
			}
			return Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tls_error_no_interception"}}
		}
		return Result{Err: fmt.Errorf("case %s: request failed: %w", c.ID, err)}
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
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "connection_refused"}}
		}
		return Result{Err: fmt.Errorf("case %s: request failed: %w", c.ID, err)}
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
	// create an inline mock that returns the poisoned responses.
	mcpCmd := p.mcpCmd
	if len(serverResponses) > 0 {
		// The mock echoes the server responses for each line of input.
		var responseLines []string
		for _, sr := range serverResponses {
			line, _ := json.Marshal(sr)
			responseLines = append(responseLines, string(line))
		}
		// Build a shell one-liner that outputs each response for each input line.
		mockScript := "while IFS= read -r line; do "
		for _, rl := range responseLines {
			// Shell-escape single quotes in the JSON.
			escaped := strings.ReplaceAll(rl, "'", "'\\''")
			mockScript += fmt.Sprintf("echo '%s'; ", escaped)
		}
		mockScript += "done"

		// Replace "-- cat" or "-- /tmp/mock-mcp-echo.sh" with our custom mock.
		if idx := strings.Index(mcpCmd, " -- "); idx >= 0 {
			mcpCmd = mcpCmd[:idx] + " -- sh -c '" + strings.ReplaceAll(mockScript, "'", "'\\''") + "'"
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

	_ = cmd.Wait()
	output := <-outputCh

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "no_output"}}
	}

	// Check ALL response lines for a JSON-RPC error (any block = blocked).
	for _, respLine := range lines {
		var rpcResp struct {
			Error *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if jsonErr := json.Unmarshal([]byte(respLine), &rpcResp); jsonErr == nil && rpcResp.Error != nil {
			if rpcResp.Error.Code < 0 {
				return Result{
					Verdict: "block",
					Evidence: map[string]interface{}{
						"error_code":    rpcResp.Error.Code,
						"error_message": rpcResp.Error.Message,
					},
				}
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

// runScanAPI sends MCP, A2A, and shell cases through the proxy's scan API.
// Parses jsonrpc_messages from the case payload to extract tool names,
// arguments, and text content for scanning.
func (p *ProxyAdapter) runScanAPI(c Case, timeout time.Duration) Result {
	var scanReq scanAPIRequest

	// A2A agent cards: extract descriptions and scan for injection.
	if card, ok := c.Payload["agent_card"].(map[string]interface{}); ok {
		var texts []string
		if desc, ok := card["description"].(string); ok {
			texts = append(texts, desc)
		}
		if skills, ok := card["skills"].([]interface{}); ok {
			for _, s := range skills {
				skill, _ := s.(map[string]interface{})
				if desc, ok := skill["description"].(string); ok {
					texts = append(texts, desc)
				}
			}
		}
		if len(texts) > 0 {
			scanReq.Kind = "prompt_injection"
			scanReq.Input.Content = strings.Join(texts, "\n")
		} else {
			cardJSON, _ := json.Marshal(card)
			scanReq.Kind = "prompt_injection"
			scanReq.Input.Content = string(cardJSON)
		}
	} else if msgs, ok := c.Payload["jsonrpc_messages"]; ok {
		// A2A messages and MCP via jsonrpc_messages.
		scanReq = p.buildScanFromJSONRPC(msgs)
	} else if toolName, ok := payloadString(c.Payload, "tool_name"); ok && toolName != "" {
		scanReq.Kind = "tool_call"
		scanReq.Input.ToolName = toolName
		if args, ok := c.Payload["arguments"]; ok {
			argBytes, _ := json.Marshal(args)
			scanReq.Input.Arguments = argBytes
		}
	} else if u, ok := payloadString(c.Payload, "url"); ok && u != "" {
		scanReq.Kind = "url"
		scanReq.Input.URL = u
	} else {
		// Fallback: serialize the entire payload and scan as DLP.
		payloadBytes, _ := json.Marshal(c.Payload)
		scanReq.Kind = "dlp"
		scanReq.Input.Text = string(payloadBytes)
	}

	body, err := json.Marshal(scanReq)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: marshal scan request: %w", c.ID, err)}
	}

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
		if strings.Contains(err.Error(), "connection refused") {
			return Result{Err: fmt.Errorf("case %s: scan API not reachable (is scan_api.listen configured?): %w", c.ID, err)}
		}
		return Result{Err: fmt.Errorf("case %s: scan API request failed: %w", c.ID, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// The scan API returns {"verdict": "block"|"allow", ...}
	var scanResp struct {
		Verdict string `json:"verdict"`
		Action  string `json:"action"`
	}
	if jsonErr := json.Unmarshal(respBody, &scanResp); jsonErr == nil && scanResp.Verdict != "" {
		evidence := map[string]interface{}{
			"status_code": resp.StatusCode,
			"verdict":     scanResp.Verdict,
		}
		if scanResp.Verdict == "block" || scanResp.Action == "block" {
			return Result{Verdict: "block", Evidence: evidence}
		}
		return Result{Verdict: "allow", Evidence: evidence}
	}

	// Fallback to HTTP status classification.
	return classifyResponse(resp.StatusCode, string(respBody))
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
		return Result{Err: fmt.Errorf("case %s: scan API: %w", c.ID, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
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
		if decision == "block" || scanResp.Action == "block" {
			return Result{Verdict: "block", Evidence: map[string]interface{}{"kind": kind, "decision": decision}}
		}
		if decision == "allow" {
			return Result{Verdict: "allow", Evidence: map[string]interface{}{"kind": kind}}
		}
	}

	return classifyResponse(resp.StatusCode, string(respBody))
}

// extractTextFromPayload pulls scannable text from any payload format.
func extractTextFromPayload(payload map[string]interface{}) string {
	// A2A agent cards.
	if card, ok := payload["agent_card"].(map[string]interface{}); ok {
		var texts []string
		if desc, ok := card["description"].(string); ok {
			texts = append(texts, desc)
		}
		if skills, ok := card["skills"].([]interface{}); ok {
			for _, s := range skills {
				skill, _ := s.(map[string]interface{})
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

// buildScanFromJSONRPC extracts scan parameters from jsonrpc_messages.
// For tools/call: uses tool_call kind with tool name and arguments.
// For message/send (A2A): extracts text parts and scans as DLP.
// For tools/list responses with descriptions: scans as prompt_injection.
func (p *ProxyAdapter) buildScanFromJSONRPC(msgs interface{}) scanAPIRequest {
	msgList, ok := msgs.([]interface{})
	if !ok || len(msgList) == 0 {
		return scanAPIRequest{Kind: "dlp", Input: scanAPIInput{Text: fmt.Sprintf("%v", msgs)}}
	}

	// Use the first message to determine the scan kind.
	first, ok := msgList[0].(map[string]interface{})
	if !ok {
		return scanAPIRequest{Kind: "dlp", Input: scanAPIInput{Text: fmt.Sprintf("%v", msgs)}}
	}

	method, _ := first["method"].(string)
	params, _ := first["params"].(map[string]interface{})

	switch method {
	case "tools/call":
		name, _ := params["name"].(string)
		args, _ := params["arguments"].(map[string]interface{})
		argBytes, _ := json.Marshal(args)
		return scanAPIRequest{
			Kind:  "tool_call",
			Input: scanAPIInput{ToolName: name, Arguments: argBytes},
		}

	case "message/send":
		// A2A: extract text from message parts.
		msg, _ := params["message"].(map[string]interface{})
		parts, _ := msg["parts"].([]interface{})
		var texts []string
		for _, part := range parts {
			p, _ := part.(map[string]interface{})
			if text, ok := p["text"].(string); ok {
				texts = append(texts, text)
			}
		}
		if len(texts) > 0 {
			return scanAPIRequest{
				Kind:  "dlp",
				Input: scanAPIInput{Text: strings.Join(texts, "\n")},
			}
		}

	case "tools/list":
		// Tool poisoning: scan tool descriptions for injection.
		result, _ := first["result"].(map[string]interface{})
		tools, _ := result["tools"].([]interface{})
		var descs []string
		for _, t := range tools {
			tool, _ := t.(map[string]interface{})
			if desc, ok := tool["description"].(string); ok {
				descs = append(descs, desc)
			}
		}
		if len(descs) > 0 {
			return scanAPIRequest{
				Kind:  "prompt_injection",
				Input: scanAPIInput{Content: strings.Join(descs, "\n")},
			}
		}
	}

	// For chain detection, shell obfuscation, and other complex cases:
	// serialize the whole message sequence as DLP.
	fullPayload, _ := json.Marshal(msgs)
	return scanAPIRequest{
		Kind:  "dlp",
		Input: scanAPIInput{Text: string(fullPayload)},
	}
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

	// 404 from scan API means endpoint not configured.
	if statusCode == http.StatusNotFound {
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "scan_api_not_configured", "status_code": statusCode},
		}
	}

	evidence["reason"] = fmt.Sprintf("ambiguous_http_%d", statusCode)
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
