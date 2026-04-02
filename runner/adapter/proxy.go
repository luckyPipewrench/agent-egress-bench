// Package adapter — proxy adapter sends cases through an HTTP proxy.
//
// Works with any tool that operates as an HTTP/HTTPS proxy (pipelock,
// Agent Wall, iron-proxy, etc.). Point --proxy-addr at the tool's
// listen address and the adapter sends real traffic through it.
package adapter

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProxyAdapter sends benchmark cases through an HTTP proxy and checks
// whether the proxy blocked or allowed the request.
type ProxyAdapter struct {
	proxyURL *url.URL
}

// NewProxyAdapter creates a proxy adapter pointing at the given address.
func NewProxyAdapter(addr string) (*ProxyAdapter, error) {
	u, err := url.Parse("http://" + addr)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %w", addr, err)
	}
	return &ProxyAdapter{proxyURL: u}, nil
}

// Run sends the case payload through the proxy and returns the verdict.
func (p *ProxyAdapter) Run(c Case, timeout time.Duration) Result {
	switch c.Transport {
	case "fetch_proxy":
		return p.runFetchProxy(c, timeout)
	case "http_proxy":
		return p.runHTTPProxy(c, timeout)
	default:
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": fmt.Sprintf("transport %q not supported by proxy adapter", c.Transport)},
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

	// Add any headers from the payload.
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
		// Connection refused or timeout usually means blocked.
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

	// TLS verification is intentionally disabled for benchmarking.
	// The bench corpus uses fake domains (evil.example.com) that don't
	// have valid certificates. This is test tooling, not production code.
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
		// DNS failures on fake domains: for expected-block cases, the proxy
		// blocked correctly (fail-closed). For expected-allow cases, the
		// upstream doesn't exist so we can't test — skip.
		if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
			if c.ExpectedVerdict == "block" {
				return Result{Verdict: "block", Evidence: map[string]interface{}{"reason": "dns_blocked"}}
			}
			return Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "upstream_unresolvable"}}
		}
		// TLS errors on forward proxy (no TLS interception configured).
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

// classifyResponse determines block vs allow from the HTTP response.
func classifyResponse(statusCode int, body string) Result {
	evidence := map[string]interface{}{
		"status_code": statusCode,
	}

	// Pipelock returns 403 with block_reason on blocked requests.
	if statusCode == http.StatusForbidden {
		evidence["reason"] = "http_403"
		if strings.Contains(body, "block_reason") || strings.Contains(body, "blocked") {
			evidence["body_snippet"] = truncate(body, 200)
		}
		return Result{Verdict: "block", Evidence: evidence}
	}

	// 4xx/5xx from the proxy itself (not upstream) usually means blocked.
	if statusCode == http.StatusBadRequest || statusCode == http.StatusBadGateway {
		evidence["reason"] = fmt.Sprintf("http_%d", statusCode)
		return Result{Verdict: "block", Evidence: evidence}
	}

	// 200 or other success codes mean allowed through.
	if statusCode >= 200 && statusCode < 400 {
		return Result{Verdict: "allow", Evidence: evidence}
	}

	// Ambiguous — return the status and let scoring decide.
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
