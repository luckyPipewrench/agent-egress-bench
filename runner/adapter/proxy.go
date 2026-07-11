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
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// fixtureHostname is the canonical name the runner uses when routing fixture
// cases through the proxy. Benchmark configs are expected
// to map this hostname to 127.0.0.1 (or wherever the runner's WS fixture
// publishes) via the tool's hostname-resolution override, and to grant it
// SSRF exemption via the tool's trusted-domain primitive. Keeping the
// rewrite under a stable hostname instead of a raw loopback IP lets the
// tool reject SSRF attacks that target loopback directly while still
// reaching the benign fixture under test.
const fixtureHostname = "aeb-fixture.test"
const wsFixtureHostname = fixtureHostname

// ProxyAdapter sends benchmark cases through an HTTP proxy and checks
// whether the proxy blocked or allowed the request.
type ProxyAdapter struct {
	proxyURL        *url.URL
	scanURL         string                  // base URL for scan API (e.g. http://127.0.0.1:9990)
	scanToken       string                  // bearer token for scan API auth
	mcpCmd          string                  // MCP proxy command (e.g. "pipelock mcp proxy --config /tmp/bench.yaml -- cat")
	httpFixtureAddr string                  // HTTP fixture for response-mitm via fetch
	setHTTPRoute    func(path, body string) // callback to register HTTP fixture routes
	wsAddr          string                  // WS fixture for websocket cases
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

// SetHTTPFixture configures the HTTP response fixture for response-mitm cases.
// Cases with response_body are routed through the fetch endpoint to this server.
func (p *ProxyAdapter) SetHTTPFixture(addr string, setRoute func(path, body string)) {
	p.httpFixtureAddr = addr
	p.setHTTPRoute = setRoute
}

// SetWSFixture configures the WS fixture address for websocket cases.
func (p *ProxyAdapter) SetWSFixture(addr string) { p.wsAddr = addr }

// Run sends the case payload through the proxy and returns the verdict.
func (p *ProxyAdapter) Run(c Case, timeout time.Duration) Result {
	// Payload-only surfaces should be scanned directly. Sending their fake
	// upstream URLs over the network turns scanner coverage into DNS/TLS/SSRF
	// fixture noise and hides whether the tool can inspect the supplied data.
	switch c.InputType {
	case "response_content":
		return p.runResponseContentViaScanAPI(c, timeout)
	case "request_body", "header":
		return p.runBodyViaScanAPI(c, timeout)
	case "websocket_frame":
		return p.runWebSocketFrameViaProxy(c, timeout)
	}
	switch c.Transport {
	case "fetch_proxy":
		return p.runFetchProxy(c, timeout)
	case "http_proxy":
		result := p.runHTTPProxy(c, timeout)
		if result.Verdict == "skip" && c.InputType == "url" {
			return p.runFetchProxy(c, timeout)
		}
		return result
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

// runResponseContentViaScanAPI scans the response_body field directly. These
// cases model fetched or intercepted response content, so the benchmark input
// is the body itself rather than the availability of the example URL.
func (p *ProxyAdapter) runResponseContentViaScanAPI(c Case, timeout time.Duration) Result {
	body, ok := payloadString(c.Payload, "response_body")
	if !ok || body == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'response_body'", c.ID)}
	}
	result := p.runScanAPITextWithKind(c.ID, body, timeout, "prompt_injection")
	if result.Verdict == "block" || result.Err != nil {
		return result
	}
	return p.runScanAPITextWithKind(c.ID, body, timeout, "dlp")
}

// runWebSocketFrameViaProxy performs a real WebSocket upgrade through the
// proxy and writes the corpus frames on the proxied connection.
func (p *ProxyAdapter) runWebSocketFrameViaProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}
	if p.wsAddr != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if u.Host == "example.com" || u.Host == "echo.websocket.org" || strings.HasSuffix(u.Host, ".example.com") {
				// Route through the canonical fixture hostname rather than
				// the literal loopback IP. A correctly-configured benchmark
				// pipelock instance maps wsFixtureHostname to 127.0.0.1 via
				// dns.host_overrides and grants it trusted_domains, so the
				// SSRF check permits the connection without exempting raw
				// IP literals — attacks that hit 127.0.0.1 directly are
				// still blocked. Tools without a hostname-override or
				// fixture-DNS equivalent should configure their runner
				// environment to resolve wsFixtureHostname to p.wsAddr's
				// host address before enabling the fixture-backed WS cases.
				_, port, splitErr := net.SplitHostPort(p.wsAddr)
				if splitErr != nil || port == "" {
					targetURL = "ws://" + p.wsAddr + "/echo"
				} else {
					targetURL = "ws://" + net.JoinHostPort(wsFixtureHostname, port) + "/echo"
				}
			}
		}
	}

	conn, err := net.DialTimeout("tcp", p.proxyURL.Host, timeout)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: ws proxy unreachable: %w", c.ID, err)}
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return Result{Err: fmt.Errorf("case %s: ws deadline: %w", c.ID, err)}
	}
	br := bufio.NewReader(conn)
	if err := p.writeWebSocketUpgrade(conn, targetURL); err != nil {
		return Result{Err: fmt.Errorf("case %s: ws upgrade request: %w", c.ID, err)}
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: ws upgrade response: %w", c.ID, err)}
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return classifyResponse(resp.StatusCode, string(body))
	}
	_ = resp.Body.Close()

	frames, ok := c.Payload["frames"].([]interface{})
	if !ok || len(frames) == 0 {
		return Result{Verdict: "allow", Evidence: map[string]interface{}{"reason": "no_frame_payload"}}
	}
	for _, raw := range frames {
		frame, _ := raw.(map[string]interface{})
		if err := writeCorpusWebSocketFrame(conn, frame); err != nil {
			return Result{
				Verdict: "block",
				Evidence: map[string]interface{}{
					"scanner": "websocket_proxy",
					"reason":  "connection_closed_while_writing_frame",
					"detail":  truncate(err.Error(), 120),
				},
			}
		}
	}

	// Drain frames until we either observe a close (definitive block signal)
	// or the wire goes idle (allow). A single-read classifier races the
	// upstream echo against the proxy's close frame: if the proxy blocks on
	// a later client frame (e.g. cross-message DLP firing on frame N), the
	// echo of an earlier forwarded frame can arrive before the close,
	// producing a false "allow" verdict. The fix is to keep reading until
	// the wire actually goes quiet.
	//
	// Budget: the first frame gets the full timeout (proxy may need time to
	// reassemble fragments and run scanners). Subsequent reads use a short
	// idle window so allow-cases don't pay the full timeout per case.
	firstReadDeadline := time.Now().Add(timeout)
	const idleWindow = 500 * time.Millisecond
	var lastFrame struct {
		opcode       int
		payloadBytes int
		seen         bool
	}
	for {
		var dl time.Time
		if lastFrame.seen {
			dl = time.Now().Add(idleWindow)
		} else {
			dl = firstReadDeadline
		}
		if deadlineErr := conn.SetReadDeadline(dl); deadlineErr != nil {
			return Result{Err: fmt.Errorf("case %s: ws read deadline: %w", c.ID, deadlineErr)}
		}
		opcode, payload, err := readWebSocketFrame(br)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				ev := map[string]interface{}{
					"scanner": "websocket_proxy",
					"reason":  "no_close_frame",
				}
				if lastFrame.seen {
					ev["opcode"] = lastFrame.opcode
					ev["bytes"] = lastFrame.payloadBytes
				}
				return Result{Verdict: "allow", Evidence: ev}
			}
			// Connection closed without a close frame. If we already
			// received at least one frame from the proxy, treat the
			// closure as a clean upstream goaway (allow) — proxies that
			// permit traffic do not synthesize close frames on behalf of
			// the upstream, so an EOF after the echo means "the wire ended,
			// the proxy did not actively block." If we never received any
			// frame, an abrupt closure suggests the proxy actively dropped
			// the connection (RST or close without frame) — block.
			if lastFrame.seen {
				return Result{
					Verdict: "allow",
					Evidence: map[string]interface{}{
						"scanner": "websocket_proxy",
						"reason":  "upstream_closed_after_echo",
						"opcode":  lastFrame.opcode,
						"bytes":   lastFrame.payloadBytes,
					},
				}
			}
			return Result{
				Verdict: "block",
				Evidence: map[string]interface{}{
					"scanner": "websocket_proxy",
					"reason":  "connection_closed",
					"detail":  truncate(err.Error(), 120),
				},
			}
		}
		if opcode == wsOpcodeClose {
			return Result{
				Verdict: "block",
				Evidence: map[string]interface{}{
					"scanner":      "websocket_proxy",
					"block_reason": truncate(webSocketCloseReason(payload), 160),
				},
			}
		}
		lastFrame.opcode = opcode
		lastFrame.payloadBytes = len(payload)
		lastFrame.seen = true
	}
}

// runFetchProxy sends a request to the proxy's /fetch endpoint.
// Supports GET (URL scanning) and POST (request body scanning).
func (p *ProxyAdapter) runFetchProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}
	targetURL = p.routeFetchFixtureURL(targetURL)

	fetchURL := fmt.Sprintf("%s/fetch?url=%s", p.proxyURL.String(), url.QueryEscape(targetURL))

	method := http.MethodGet
	if m, ok := payloadString(c.Payload, "method"); ok && m != "" {
		method = m
	}

	var bodyReader io.Reader
	if bodyStr, ok := payloadString(c.Payload, "body"); ok && bodyStr != "" {
		bodyReader = strings.NewReader(bodyStr)
	}

	req, err := http.NewRequest(method, fetchURL, bodyReader)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", c.ID, err)}
	}

	if ct, ok := payloadString(c.Payload, "content_type"); ok && ct != "" {
		req.Header.Set("Content-Type", ct)
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

	// The fetch endpoint returns JSON with blocked, block_reason, and scanner fields.
	var fetchResp struct {
		Blocked     bool   `json:"blocked"`
		BlockReason string `json:"block_reason"`
		Scanner     string `json:"scanner"`
	}
	if jsonErr := json.Unmarshal(body, &fetchResp); jsonErr == nil && fetchResp.Blocked {
		ev := map[string]interface{}{"reason": "fetch_blocked"}
		if fetchResp.BlockReason != "" {
			ev["block_reason"] = fetchResp.BlockReason
		}
		if fetchResp.Scanner != "" {
			ev["scanner"] = fetchResp.Scanner
		}
		return Result{Verdict: "block", Evidence: ev}
	}

	return classifyResponse(resp.StatusCode, string(body))
}

func (p *ProxyAdapter) routeFetchFixtureURL(targetURL string) string {
	if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
		return targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil || u.Hostname() != "docs.example.com" {
		return targetURL
	}

	routePath := u.EscapedPath()
	if routePath == "" {
		routePath = "/"
	}
	p.setHTTPRoute(routePath, "benchmark documentation fixture")

	_, port, splitErr := net.SplitHostPort(p.httpFixtureAddr)
	if splitErr != nil || port == "" {
		return targetURL
	}
	u.Scheme = "http"
	u.Host = net.JoinHostPort(fixtureHostname, port)
	return u.String()
}

// runHTTPProxy sends a request through the proxy as HTTPS_PROXY (CONNECT tunnel).
func (p *ProxyAdapter) runHTTPProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}

	// Response-MITM cases have a response_body field. Route through the
	// fetch endpoint + HTTP fixture so the proxy scans the response content.
	if respBody, ok := payloadString(c.Payload, "response_body"); ok && respBody != "" {
		if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
			return Result{
				Verdict:  "skip",
				Evidence: map[string]interface{}{"reason": "no_response_fixture"},
			}
		}
		path := "/" + c.ID
		p.setHTTPRoute(path, respBody)
		// Route through fetch endpoint instead of CONNECT tunnel.
		fixtureURL := "http://" + p.httpFixtureAddr + path
		fetchCase := Case{
			ID:              c.ID,
			ExpectedVerdict: c.ExpectedVerdict,
			Transport:       "fetch_proxy",
			Payload:         map[string]interface{}{"url": fixtureURL},
		}
		return p.runFetchProxy(fetchCase, timeout)
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
			ev := map[string]interface{}{"reason": "proxy_rejected"}
			extractBlockEvidence(errStr, ev)
			return Result{Verdict: "block", Evidence: ev}
		}
		// Proxy or upstream connection reset — may be an active block.
		if strings.Contains(errStr, "reset by peer") {
			ev := map[string]interface{}{"reason": "connection_reset"}
			extractBlockEvidence(errStr, ev)
			return Result{Verdict: "block", Evidence: ev}
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

	// If WS fixture is available, rewrite fake upstream URLs to the echo server.
	if p.wsAddr != "" {
		if u, err := url.Parse(targetURL); err == nil {
			if u.Host == "example.com" || u.Host == "echo.websocket.org" || strings.HasSuffix(u.Host, ".example.com") {
				targetURL = "ws://" + p.wsAddr + "/echo"
			}
		}
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

const (
	wsOpcodeContinuation = 0
	wsOpcodeText         = 1
	wsOpcodeBinary       = 2
	wsOpcodeClose        = 8
)

func (p *ProxyAdapter) writeWebSocketUpgrade(conn net.Conn, targetURL string) error {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate websocket key: %w", err)
	}
	path := "/ws?url=" + url.QueryEscape(targetURL)
	_, err := fmt.Fprintf(conn,
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, p.proxyURL.Host, base64.StdEncoding.EncodeToString(keyBytes))
	return err
}

func writeCorpusWebSocketFrame(w io.Writer, frame map[string]interface{}) error {
	var opcode int
	switch op, _ := frame["opcode"].(string); op {
	case "continuation":
		opcode = wsOpcodeContinuation
	case "binary":
		opcode = wsOpcodeBinary
	case "text", "":
		opcode = wsOpcodeText
	default:
		return fmt.Errorf("unsupported websocket opcode %q", op)
	}

	payload, _ := frame["payload"].(string)
	data := []byte(payload)
	if opcode == wsOpcodeBinary {
		if enc, _ := frame["encoding"].(string); enc == "base64" {
			decoded, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				return fmt.Errorf("decode binary frame payload: %w", err)
			}
			data = decoded
		}
	}

	fin := true
	if v, ok := frame["fin"].(bool); ok {
		fin = v
	}
	rsv1, _ := frame["rsv1"].(bool)
	return writeMaskedWebSocketFrame(w, opcode, fin, rsv1, data)
}

func writeMaskedWebSocketFrame(w io.Writer, opcode int, fin, rsv1 bool, payload []byte) error {
	header := []byte{byte(opcode)}
	if fin {
		header[0] |= 0x80
	}
	if rsv1 {
		header[0] |= 0x40
	}

	payloadLen := len(payload)
	switch {
	case payloadLen < 126:
		header = append(header, 0x80|byte(payloadLen))
	case payloadLen <= 0xffff:
		header = append(header, 0x80|126, byte(payloadLen>>8), byte(payloadLen))
	default:
		header = append(header, 0x80|127,
			byte(uint64(payloadLen)>>56), byte(uint64(payloadLen)>>48),
			byte(uint64(payloadLen)>>40), byte(uint64(payloadLen)>>32),
			byte(uint64(payloadLen)>>24), byte(uint64(payloadLen)>>16),
			byte(uint64(payloadLen)>>8), byte(uint64(payloadLen)))
	}

	mask := []byte{0, 0, 0, 0}
	if _, err := rand.Read(mask); err != nil {
		return fmt.Errorf("generate websocket mask: %w", err)
	}
	header = append(header, mask...)
	masked := make([]byte, len(payload))
	for i, b := range payload {
		masked[i] = b ^ mask[i%4]
	}
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

func readWebSocketFrame(r *bufio.Reader) (int, []byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	opcode := int(header[0] & 0x0f)
	masked := header[1]&0x80 != 0
	payloadLen := uint64(header[1] & 0x7f)
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = 0
		for _, b := range ext {
			payloadLen = payloadLen<<8 | uint64(b)
		}
	}
	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return 0, nil, err
		}
	}
	if payloadLen > 1<<20 {
		return 0, nil, fmt.Errorf("websocket response frame too large: %d", payloadLen)
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func webSocketCloseReason(payload []byte) string {
	if len(payload) <= 2 {
		return "websocket closed"
	}
	return string(payload[2:])
}

// PreflightMockScriptExec verifies that the current environment can create a
// temp script and run it with bash from PATH, matching runMCPStdio's mock MCP
// backend injection for tool-poisoning cases.
//
// If bash is missing or the temp script cannot be created/read, that mechanism
// silently breaks every in-scope MCP tool-poisoning case: with stderr discarded
// (the bug this preflight exists to catch; see the stderr capture in
// runMCPStdio) the failure surfaces, if at all, as a bare unexplained exit
// code, or the case simply times out and gets scored as a "block" with no
// indication that nothing was ever actually run. Call this once, before those
// cases run, so that failure is loud, specific, and actionable instead of
// silently corrupting case results.
//
// Callers should invoke this only when the proxy adapter is configured with
// an MCP command (i.e. tool-poisoning cases will actually exercise this
// mechanism); it is a no-op safety check, not part of scoring.
func PreflightMockScriptExec() error {
	tmpDir := os.TempDir()

	bashPath, lookErr := exec.LookPath("bash")
	if lookErr != nil {
		return fmt.Errorf(
			"preflight failed: bash not found in PATH (%w).\n"+
				"the proxy adapter's MCP mock-backend script (used for tool-poisoning\n"+
				"cases) is run as \"bash <temp-script>\"; install bash or ensure it is\n"+
				"on PATH and retry",
			lookErr)
	}

	f, err := os.CreateTemp(tmpDir, "aeb-preflight-mock-*.sh")
	if err != nil {
		return fmt.Errorf("preflight failed: cannot create a temp file in %s: %w", tmpDir, err)
	}
	scriptPath := f.Name()
	defer func() { _ = os.Remove(scriptPath) }()

	if _, writeErr := f.WriteString("exit 0\n"); writeErr != nil {
		_ = f.Close()
		return fmt.Errorf("preflight failed: cannot write temp script %s: %w", scriptPath, writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return fmt.Errorf("preflight failed: cannot close temp script %s: %w", scriptPath, closeErr)
	}

	var stderrBuf bytes.Buffer
	cmd := exec.Command(bashPath, scriptPath) //nolint:gosec // fixed bash path and a script this function just created
	cmd.Stderr = &stderrBuf
	runErr := cmd.Run()
	if runErr == nil {
		return nil
	}
	return classifyPreflightExecErr(tmpDir, runErr, strings.TrimSpace(stderrBuf.String()))
}

// classifyPreflightExecErr turns a failed exec of the preflight script into
// a specific, actionable error message, keyed off the wrapped OS error so
// the message names the likely root cause instead of a bare exit code. Split
// out from PreflightMockScriptExec so the classification can be unit-tested
// with synthetic errors, since reliably reproducing permission and path races
// in a portable test is impractical.
func classifyPreflightExecErr(tmpDir string, runErr error, detail string) error {
	switch {
	case errors.Is(runErr, fs.ErrPermission):
		return fmt.Errorf(
			"preflight failed: bash cannot read a script written to the temp directory\n"+
				"%s (%w).\n"+
				"the current user most likely lacks read permission on files created there.\n"+
				"The proxy adapter runs a mock MCP backend script from a freshly created\n"+
				"temp file for tool-poisoning cases; if bash cannot read it, those cases\n"+
				"will silently misclassify or hang until timeout instead of producing a\n"+
				"real verdict, with no indication why.\n"+
				"Fix: point TMPDIR at a writable directory and retry, e.g.:\n"+
				"  mkdir -p \"$HOME/.cache/aeb-tmp\" && TMPDIR=\"$HOME/.cache/aeb-tmp\" <run command>\n"+
				"stderr from the failed script: %s",
			tmpDir, runErr, orNoneIfEmpty(detail))
	case errors.Is(runErr, fs.ErrNotExist):
		return fmt.Errorf(
			"preflight failed: cannot run bash with a temp script in %s (%w).\n"+
				"bash was found on PATH, but either that executable or the temp script was\n"+
				"not available when preflight tried to run it; check PATH, TMPDIR, and\n"+
				"filesystem cleanup policy, then retry.\n"+
				"stderr from the failed script: %s",
			tmpDir, runErr, orNoneIfEmpty(detail))
	default:
		return fmt.Errorf(
			"preflight failed: could not run a test script from the temp directory\n"+
				"%s (%w).\n"+
				"the proxy adapter's MCP mock-backend mechanism needs to create temp\n"+
				"scripts and run them with bash for tool-poisoning cases; fix the\n"+
				"underlying environment issue and retry.\n"+
				"stderr from the failed script: %s",
			tmpDir, runErr, orNoneIfEmpty(detail))
	}
}

// orNoneIfEmpty returns "(none)" for an empty diagnostic string so error
// messages never end with a dangling, easy-to-miss empty field.
func orNoneIfEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
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
		_, _ = fmt.Fprintf(mockScript, "_n=0\nwhile IFS= read -r _input; do\n  _n=$((_n+1))\n  sed -n \"${_n}p\" '%s'\ndone\n",
			respFile.Name())
		_ = mockScript.Close()

		// Replace the backend command with our custom mock script. Invoke it
		// through bash from PATH instead of relying on a hardcoded shebang path.
		if idx := strings.Index(mcpCmd, " -- "); idx >= 0 {
			mcpCmd = mcpCmd[:idx] + " -- bash " + shellQuote(mockScript.Name())
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
	// Capture stderr instead of discarding it. Discarding it here previously
	// swallowed the diagnostic output from a mock-backend spawn failure (e.g.
	// bash missing), leaving nothing but a bare, unexplained exit code or a
	// silent timeout. See PreflightMockScriptExec for the guard that catches
	// this class of failure loudly before the in-scope corpus cases run, and
	// the two branches below that now surface this buffer's contents when a
	// case comes back empty.
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

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
	stderrOutput := strings.TrimSpace(stderrBuf.String())

	// Context timeout is expected (subprocess runs until stdin closes).
	// But other wait errors with no output indicate a real failure.
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		if waitErr != nil && ctx.Err() == nil {
			if stderrOutput != "" {
				return Result{Err: fmt.Errorf("case %s: MCP subprocess failed: %w (stderr: %s)", c.ID, waitErr, stderrOutput)}
			}
			return Result{Err: fmt.Errorf("case %s: MCP subprocess failed: %w", c.ID, waitErr)}
		}
		// No output and no reported wait error (or a timeout) is treated as a
		// block, since many proxies express "block" by simply closing the
		// connection without writing anything. That is a real, valid signal
		// for a well-behaved tool — but it is also exactly what a silently
		// failed mock-backend spawn looks like, so any captured stderr is
		// attached here as a diagnostic hint rather than changing the
		// verdict itself.
		evidence := map[string]interface{}{"reason": "no_output"}
		if stderrOutput != "" {
			evidence["stderr"] = stderrOutput
		}
		return Result{Verdict: "block", Evidence: evidence}
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

// runScanAPIDualPass runs URL, injection, and DLP scans for A2A payloads.
// A2A cases may contain URLs, secrets, and injection in the same payload.
func (p *ProxyAdapter) runScanAPIDualPass(c Case, timeout time.Duration) Result {
	for _, rawURL := range extractURLsFromPayload(c.Payload) {
		result := p.runScanAPITextWithKind(c.ID, rawURL, timeout, "url")
		if result.Verdict == "block" || result.Err != nil {
			return result
		}
	}
	// First pass: try prompt_injection (catches card poisoning + injection).
	cInjection := c
	result := p.runScanAPIWithKind(cInjection, timeout, "prompt_injection")
	if result.Verdict == "block" || result.Err != nil {
		return result
	}
	// Second pass: try DLP (catches secrets in messages).
	return p.runScanAPIWithKind(c, timeout, "dlp")
}

func extractURLsFromPayload(payload map[string]interface{}) []string {
	var urls []string
	if rawURL, ok := payloadString(payload, "url"); ok && rawURL != "" {
		urls = append(urls, rawURL)
	}
	if card, ok := payload["agent_card"].(map[string]interface{}); ok {
		if rawURL, ok := card["url"].(string); ok && rawURL != "" {
			urls = append(urls, rawURL)
		}
	}
	if msgs, ok := payload["jsonrpc_messages"].([]interface{}); ok {
		for _, msg := range msgs {
			m, _ := msg.(map[string]interface{})
			params, _ := m["params"].(map[string]interface{})
			message, _ := params["message"].(map[string]interface{})
			parts, _ := message["parts"].([]interface{})
			for _, part := range parts {
				p, _ := part.(map[string]interface{})
				file, _ := p["file"].(map[string]interface{})
				if rawURL, ok := file["uri"].(string); ok && rawURL != "" {
					urls = append(urls, rawURL)
				}
			}
		}
	}
	return urls
}

// runScanAPIWithKind runs the scan API with a specific forced kind.
func (p *ProxyAdapter) runScanAPIWithKind(c Case, timeout time.Duration, kind string) Result {
	text := extractTextFromPayload(c.Payload)
	if text == "" {
		return Result{Verdict: "allow", Evidence: map[string]interface{}{"reason": "no_text_extracted"}}
	}
	if kind == "url" {
		if rawURL, ok := payloadString(c.Payload, "url"); ok {
			text = rawURL
		}
	}

	return p.runScanAPITextWithKind(c.ID, text, timeout, kind)
}

func (p *ProxyAdapter) runScanAPITextWithKind(caseID, text string, timeout time.Duration, kind string) Result {
	var input scanAPIInput
	switch kind {
	case "prompt_injection":
		input.Content = text
	case "url":
		input.URL = text
	default:
		input.Text = text
	}
	scanReq := scanAPIRequest{Kind: kind, Input: input}
	body, _ := json.Marshal(scanReq)

	scanURL := fmt.Sprintf("%s/api/v1/scan", p.scanURL)
	req, err := http.NewRequest(http.MethodPost, scanURL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", caseID, err)}
	}
	req.Header.Set("Content-Type", "application/json")
	if p.scanToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.scanToken)
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: scan API (%s): %w", caseID, kind, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		return Result{Err: fmt.Errorf("case %s: scan API (%s) returned %d: %s", caseID, kind, resp.StatusCode, truncate(string(respBody), 120))}
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

	return Result{Err: fmt.Errorf("case %s: scan API (%s) returned unparseable response: %s", caseID, kind, truncate(string(respBody), 120))}
}

// runBodyViaScanAPI routes request_body and header cases through the scan
// API for DLP checking. Falls back to the scan API text path since the fetch
// endpoint only scans URLs, not request bodies.
func (p *ProxyAdapter) runBodyViaScanAPI(c Case, timeout time.Duration) Result {
	if p.scanURL == "" {
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "scan API not configured for body/header DLP"},
		}
	}

	var texts []string

	// Extract body text.
	if bodyStr, ok := payloadString(c.Payload, "body"); ok && bodyStr != "" {
		texts = append(texts, bodyStr)
	}

	// Extract header values.
	if hdrs, ok := c.Payload["headers"].(map[string]interface{}); ok {
		for k, v := range hdrs {
			if s, ok := v.(string); ok {
				texts = append(texts, k+": "+s)
			}
		}
	}

	if len(texts) == 0 {
		return Result{Verdict: "allow", Evidence: map[string]interface{}{"reason": "no_body_or_headers"}}
	}

	// Also scan the URL if present (catch URL DLP + body DLP together).
	if u, ok := payloadString(c.Payload, "url"); ok && u != "" {
		urlResult := p.runFetchProxy(c, timeout)
		if urlResult.Verdict == "block" {
			return urlResult
		}
	}

	// Dual-pass scan: DLP first, then prompt_injection for body content
	// that may contain injection patterns.
	text := strings.Join(texts, "\n")
	result := p.runScanAPITextWithKind(c.ID, text, timeout, "dlp")
	if result.Verdict == "block" || result.Err != nil {
		return result
	}
	return p.runScanAPITextWithKind(c.ID, text, timeout, "prompt_injection")
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
	// A2A agent cards — scan name, URL, description, and skill descriptions.
	if card, ok := payload["agent_card"].(map[string]interface{}); ok {
		var texts []string
		if name, ok := card["name"].(string); ok {
			texts = append(texts, name)
		}
		if rawURL, ok := card["url"].(string); ok {
			texts = append(texts, rawURL)
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

// extractBlockEvidence parses a block response body for scanner and reason fields.
// Pipelock returns these in multiple formats depending on transport:
//   - Fetch JSON: {"blocked":true,"block_reason":"DLP match: AWS","scanner":"dlp"}
//   - Forward proxy text: "blocked by DLP: AWS Access ID" or "SSRF: private IP"
//   - Kill switch: "kill switch active"
func extractBlockEvidence(body string, ev map[string]interface{}) {
	// Try JSON first (fetch endpoint responses).
	var jsonResp struct {
		BlockReason string `json:"block_reason"`
		Scanner     string `json:"scanner"`
	}
	if json.Unmarshal([]byte(body), &jsonResp) == nil {
		if jsonResp.BlockReason != "" {
			ev["block_reason"] = jsonResp.BlockReason
		}
		if jsonResp.Scanner != "" {
			ev["scanner"] = jsonResp.Scanner
		}
		return
	}

	// Text body classification by keyword matching.
	lower := strings.ToLower(body)
	switch {
	case strings.Contains(lower, "dlp") || strings.Contains(lower, "secret") || strings.Contains(lower, "credential"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "dlp"
	case strings.Contains(lower, "ssrf") || strings.Contains(lower, "private ip") || strings.Contains(lower, "metadata"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "ssrf"
	case strings.Contains(lower, "injection") || strings.Contains(lower, "prompt"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "response_injection"
	case strings.Contains(lower, "entropy"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "entropy"
	case strings.Contains(lower, "blocklist") || strings.Contains(lower, "blocked domain"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "blocklist"
	case strings.Contains(lower, "kill switch"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "kill_switch"
	case strings.Contains(lower, "airlock"):
		ev["block_reason"] = truncate(body, 120)
		ev["scanner"] = "airlock"
	case len(body) > 0:
		ev["block_reason"] = truncate(body, 120)
	}
}

// classifyResponse determines block vs allow from the HTTP response.
func classifyResponse(statusCode int, body string) Result {
	evidence := map[string]interface{}{
		"status_code": statusCode,
	}

	if statusCode == http.StatusForbidden || statusCode == http.StatusBadRequest || statusCode == http.StatusBadGateway {
		evidence["reason"] = fmt.Sprintf("http_%d", statusCode)
		// Extract structured block details from response body.
		extractBlockEvidence(body, evidence)
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
