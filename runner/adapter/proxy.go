// Package adapter implements the runner's built-in proxy-shaped adapter.
//
// The proxy adapter is not a generic integration layer for every HTTP-facing
// tool. It can drive a tool that exposes the concrete benchmark surfaces below:
//
// Transport mapping:
//   - fetch_proxy: HTTP request to /fetch?url=... on the configured proxy address
//   - http_proxy: CONNECT tunnel to the same configured proxy address. The
//     runner sets the proxy on its own HTTP transport and does not export
//     HTTPS_PROXY, so the tool only has to accept CONNECT on that address.
//   - websocket: GET /ws?url=... plus runner-managed WebSocket fixtures
//   - mcp_stdio: configured MCP stdio proxy command with JSON-RPC on stdio
//   - mcp_http: JSON-RPC POST endpoint set with SetMCPHTTPURL. Response-shaped
//     and temporal inventory cases also require SetMCPHTTPFixture so the runner
//     can serve and independently observe the upstream side of the exchange.
//
// Tool-specific block signals are normalized by the runner after the requested
// transport has been exercised. A reverse proxy or API gateway with
// listen/upstream routing semantics is not drivable by this adapter today, nor
// is an in-process SDK without a runner that presents one of these surfaces.
//
// Unimplemented execution paths return skip. The runner upgrades that to an
// error when the tool profile declared the case applicable. Transports are never
// substituted because that would turn a scanner result into false evidence that
// the requested transport was exercised.
package adapter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// fixtureHostname is the canonical name the runner uses when routing fixture
// cases through the proxy. Benchmark configs are expected
// to map this hostname to 127.0.0.1 (or wherever the runner's WS fixture
// publishes) via the tool's hostname-resolution override, and to grant it
// SSRF exemption via the tool's trusted-domain primitive. Keeping the
// rewrite under a stable hostname instead of a raw loopback IP lets the
// tool reject SSRF attacks that target loopback directly while still
// reaching the benign fixture under test.
const (
	fixtureHostname           = "aeb-fixture.test"
	hostnameExfilFixtureHost  = "cdn.fixture.example.com"
	wsFixtureHostname         = fixtureHostname
	WSUntrustedSinkHostname   = "ws-exfil-sink.test"
	A2AUntrustedSinkHostname  = "a2a-exfil-sink.test"
	a2aMessageDefaultEndpoint = "/message:send"
)

// ProxyAdapter sends benchmark cases through an HTTP proxy and checks
// whether the proxy blocked or allowed the request.
type ProxyAdapter struct {
	proxyURL   *url.URL
	scanURL    string // base URL for scan API (e.g. http://127.0.0.1:9990)
	scanToken  string // bearer token for scan API auth
	mcpCmd     string // MCP proxy command that wraps an upstream stdio server
	mcpHTTPURL string // MCP-over-HTTP JSON-RPC listener URL
	// Declared by the target, zero for every target that declares nothing.
	// Zero means the runner replays no token and recognizes no refusal, while
	// the ordinary MCP initialize still happens.
	session             ListenerSessionDeclaration
	httpFixtureAddr     string                  // HTTP fixture for response-mitm via fetch
	setHTTPRoute        func(path, body string) // callback to register HTTP fixture routes
	setHTTPRouteCT      func(path, body, contentType string)
	tlsFixtureAddr      string // HTTPS fixture for CONNECT interception cases
	tlsCAFile           string
	setTLSRoute         func(path, body string)
	setTLSRouteCT       func(path, body, contentType string)
	setTLSRouteHost     func(host, path, body, contentType string)
	tlsRequests         func() int64               // requests the TLS fixture has served
	httpFixtureRequests func(string, string) int64 // trusted-listener deliveries for one route and token
	wsAddr              string                     // trusted WS fixture for websocket cases
	wsUntrustedAddr     string                     // untrusted WS fixture for reserved sink cases
	responseRouteID     atomic.Uint64              // unique low-entropy response fixture route

	wsUpstreamMessages   func() int64             // runner-managed WS fixture message counter
	wsRSV1Outcome        func(string) (int, bool) // marked permissive-fixture outcome
	mcpHTTPUpstreamCalls func() int64             // runner-managed MCP HTTP fixture request counter
	mcpHTTPFixture       *fixture.MCPHTTPFixture
}

// DeliveryTuples declares the exact corpus inputs the proxy adapter can drive.
// The declaration only determines whether a run can be attempted. Result state
// still requires the per-case execution path to prove delivery and observe a
// verdict before the runner can score it.
func (p *ProxyAdapter) DeliveryTuples() []DeliveryTuple {
	tuple := func(transport, surface string) DeliveryTuple {
		lifecycle := "single_request"
		if transport == "mcp_stdio" || transport == "mcp_http" {
			lifecycle = "mcp_session"
		}
		return DeliveryTuple{WireTransport: transport, SemanticSurface: surface, Lifecycle: lifecycle}
	}

	var routes []DeliveryTuple
	for _, transport := range []string{"fetch_proxy", "http_proxy"} {
		for _, surface := range []string{"url", "request_body", "header", "response_content"} {
			routes = append(routes, tuple(transport, surface))
		}
	}
	for _, surface := range []string{"websocket_frame", "url", "header"} {
		routes = append(routes, tuple("websocket", surface))
	}
	for _, transport := range []string{"mcp_stdio", "mcp_http"} {
		for _, surface := range []string{"mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "mcp_tool_sequence", "mcp_tool_sequence_temporal"} {
			routes = append(routes, tuple(transport, surface))
		}
	}
	for _, surface := range []string{"a2a_message", "a2a_agent_card"} {
		routes = append(routes, tuple("a2a", surface))
	}
	return routes
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

// SetHTTPFixtureWithContentType configures the HTTP fixture with content types.
func (p *ProxyAdapter) SetHTTPFixtureWithContentType(addr string, setRoute func(path, body, contentType string)) {
	p.httpFixtureAddr = addr
	p.setHTTPRouteCT = setRoute
	p.setHTTPRoute = func(path, body string) {
		setRoute(path, body, "text/html; charset=utf-8")
	}
}

// SetHTTPFixtureRequestCounter lets response-shaped transports prove the
// runner-owned HTTP fixture served the case. A configured route alone proves
// only that the runner attempted setup; the proxy can still synthesize a
// response without contacting the fixture.
//
// The counter is scoped to the trusted listener, one route, and one delivery
// token. A fixture-wide total is advanced by any other route; a path-only
// counter is advanced by the untrusted sink serving the same route table, and
// by another case sharing a declared endpoint. Either way a synthesized
// response inherits someone else's delivery and scores as observed.
func (p *ProxyAdapter) SetHTTPFixtureRequestCounter(counter func(string, string) int64) {
	p.httpFixtureRequests = counter
}

// deliveryProof identifies one fixture interaction: the route it registered
// and the token that route's URL carries.
type deliveryProof struct {
	path     string
	token    string
	baseline int64
}

// beginHTTPFixtureDelivery mints a token for this interaction and snapshots
// its counter. The token is what makes attribution exact when cases share a
// declared path or a target fetches asynchronously.
func (p *ProxyAdapter) beginHTTPFixtureDelivery(path string) (deliveryProof, error) {
	token, err := nextHTTPDeliveryToken()
	if err != nil {
		return deliveryProof{}, err
	}
	proof := deliveryProof{path: path, token: token}
	if p.httpFixtureRequests != nil {
		proof.baseline = p.httpFixtureRequests(path, token)
	}
	return proof, nil
}

// nextHTTPDeliveryToken keeps the fixed-width decimal encoding of the 256-bit
// opaque identity but removes its human-readable prefix. The token is appended
// to the URL under test; a human-readable prefix raises its Shannon entropy
// above a strict scanner's threshold and makes the benchmark's own delivery
// proof block before the declared case reaches the fixture.
func nextHTTPDeliveryToken() (string, error) {
	identity, err := nextGatewayRequestIdentity()
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(identity, "aeb-request-"), nil
}

// annotate appends the delivery token to a fixture URL, leaving the query the
// case declared byte-for-byte intact.
//
// It appends to RawQuery rather than going through url.Values, because
// Values.Encode sorts parameters and rewrites their encoding: a bare key gains
// an "=", a space may flip between "%20" and "+", and the order changes. For a
// query-sensitive or signed endpoint that is a different request than the case
// declared, so the runner would be scoring input it altered.
//
// Known compatibility cost, stated rather than hidden: a target that strips
// unknown query parameters while forwarding will not carry the token, and the
// case scores unproven instead of allowed. That is the safe direction and it
// is loud, since the evidence names the token that never arrived.
func (d deliveryProof) annotate(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	appended := fixture.DeliveryTokenParam + "=" + url.QueryEscape(d.token)
	if parsed.RawQuery == "" {
		parsed.RawQuery = appended
	} else {
		parsed.RawQuery += "&" + appended
	}
	return parsed.String(), nil
}

func (p *ProxyAdapter) httpFixtureServed(proof deliveryProof) bool {
	return p.httpFixtureRequests != nil &&
		p.httpFixtureRequests(proof.path, proof.token) > proof.baseline
}

// requireHTTPFixtureDelivery turns a superficially normal response into an
// unproven result when the fixture did not serve this exact interaction. This
// is used only for response-shaped cases, where fixture delivery is part of
// the named control's input rather than an optional upstream side effect.
//
// What this proves, stated narrowly so the result is not read as more: the
// fixture served THIS route under THIS interaction's token. It does not prove
// the target's response was derived from that content. A target that fetches
// the route and then answers from something else still satisfies it, so this
// is attribution of delivery, not proof of content flow.
//
// Closing that gap needs the fixture response bound into the answer, for
// example a per-interaction canary the target must echo. That is a larger
// change to how cases declare expected output and is deliberately not
// attempted here; without it a cooperative target is measured correctly and a
// determined one can still stage the fetch.
func (p *ProxyAdapter) requireHTTPFixtureDelivery(result Result, proof deliveryProof, reason string) Result {
	if result.Err != nil || (result.Verdict != "allow" && result.Verdict != "block") {
		return result
	}
	if p.httpFixtureServed(proof) {
		return result
	}
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	result.Evidence["reason"] = reason
	result.Evidence["upstream_reached"] = false
	result.Evidence["expected_delivery_token"] = proof.token
	result.Verdict = "skip"
	result.DeliveryProven = false
	result.VerdictObserved = false
	return result
}

// SetTLSFixture configures the HTTPS fixture for CONNECT interception cases.
func (p *ProxyAdapter) SetTLSFixture(addr, caFile string, setRoute func(path, body string)) {
	p.tlsFixtureAddr = addr
	p.tlsCAFile = caFile
	p.setTLSRoute = setRoute
}

// SetTLSFixtureWithContentType configures the HTTPS fixture with content types.
// setRouteHost registers a host-scoped route so TLS-intercept request cases that
// preserve their declared hostname cannot collide on path alone.
func (p *ProxyAdapter) SetTLSFixtureWithContentType(addr, caFile string, setRoute func(path, body, contentType string), setRouteHost func(host, path, body, contentType string)) {
	p.tlsFixtureAddr = addr
	p.tlsCAFile = caFile
	p.setTLSRouteCT = setRoute
	p.setTLSRouteHost = setRouteHost
	p.setTLSRoute = func(path, body string) {
		setRoute(path, body, "application/json")
	}
}

// SetTLSRequestCounter supplies a runner-managed counter of requests the TLS
// fixture has served. Without it, a response carrying an error status cannot be
// distinguished from one the proxy synthesized without ever forwarding, so the
// adapter withholds the verdict rather than crediting a passthrough allow.
func (p *ProxyAdapter) SetTLSRequestCounter(count func() int64) {
	p.tlsRequests = count
}

// tlsFixtureServed reports whether the TLS fixture served a request since the
// supplied baseline. It fails closed: with no counter wired, the answer is no.
func (p *ProxyAdapter) tlsFixtureServed(before int64) bool {
	if p.tlsRequests == nil {
		return false
	}
	return p.tlsRequests() > before
}

// tlsRequestBaseline snapshots the fixture counter before a request is sent.
func (p *ProxyAdapter) tlsRequestBaseline() int64 {
	if p.tlsRequests == nil {
		return 0
	}
	return p.tlsRequests()
}

// SetWSFixture configures the WS fixture address for websocket cases.
func (p *ProxyAdapter) SetWSFixture(addr string) { p.SetWSFixtures(addr, "") }

// SetWSFixtures configures trusted and untrusted WS fixture addresses.
func (p *ProxyAdapter) SetWSFixtures(trustedAddr, untrustedAddr string) {
	p.wsAddr = trustedAddr
	p.wsUntrustedAddr = untrustedAddr
}

// SetWSUpstreamMessageCounter lets the adapter prove a WebSocket payload reached
// the runner-managed upstream fixture before scoring an allow.
func (p *ProxyAdapter) SetWSUpstreamMessageCounter(counter func() int64) {
	p.wsUpstreamMessages = counter
}

// SetWSRSV1Outcome lets the adapter distinguish a proxy rejection from a
// destination that received the marked RSV1 frame and then closed.
func (p *ProxyAdapter) SetWSRSV1Outcome(outcome func(string) (int, bool)) {
	p.wsRSV1Outcome = outcome
}

// SetMCPHTTPURL configures the MCP-over-HTTP JSON-RPC listener URL.
func (p *ProxyAdapter) SetMCPHTTPURL(rawURL string) { p.mcpHTTPURL = rawURL }

// SetMCPHTTPListenerSession declares how a target issues its MCP HTTP session
// token and how it refuses a stateful request that arrives without one. Leave
// it unset for a target that has no such mechanism, which is the default.
//
// An unset declaration disables token extraction and replay. It does NOT
// suppress the MCP initialize request, which every client sends and which is
// protocol conformance rather than an accommodation.
//
// Both the token header and the refusal signature live here, in a per-run
// declaration, rather than in shared runner code. Declaring only the token
// header is not enough for neutrality: the runner also has to recognize a
// refusal to tell a setup failure apart from a real policy block, and leaving
// that recognition hardcoded to one vendor means a target that refuses
// differently has its setup failures scored as blocks it never made.
func (p *ProxyAdapter) SetMCPHTTPListenerSession(d ListenerSessionDeclaration) {
	p.session = d
}

// ListenerSessionDeclaration is one target's session mechanism, declared per
// run. The zero value means the target has none.
type ListenerSessionDeclaration struct {
	// TokenHeader is the response header the target issues its token in, and
	// the request header the runner replays it in.
	TokenHeader string
	// TokenFormat names the issued token's shape so a malformed value is not
	// replayed. Empty accepts any header-safe value.
	TokenFormat string
	// RefusalHeader and RefusalValue identify a refusal the target emits
	// BEFORE it forwards a request, which is transport failure rather than a
	// decision about the case. Prefer a structured field the target documents
	// over matching human-readable text, which drifts with wording.
	RefusalHeader string
	RefusalValue  string
}

// declaredRefusal reports whether this response is the target's own declared
// session refusal.
//
// Undeclared means unrecognized, deliberately. Guessing a refusal shape for a
// target that never declared one is how vendor semantics leak back into the
// shared path.
func (d ListenerSessionDeclaration) declaredRefusal(header http.Header) bool {
	if d.RefusalHeader == "" || d.RefusalValue == "" {
		return false
	}
	return header.Get(d.RefusalHeader) == d.RefusalValue
}

// SetMCPHTTPUpstreamCallCounter lets the adapter prove the protected MCP HTTP
// backend handled the request before scoring an allow.
func (p *ProxyAdapter) SetMCPHTTPUpstreamCallCounter(counter func() int64) {
	p.mcpHTTPUpstreamCalls = counter
}

// SetMCPHTTPFixture enables response-shaped MCP HTTP cases to be delivered by
// the runner-owned upstream. A Streamable HTTP client never POSTs a JSON-RPC
// response to the gateway: it sends a request and receives that response from
// its upstream. Keeping the fixture here makes that wire direction explicit.
func (p *ProxyAdapter) SetMCPHTTPFixture(upstream *fixture.MCPHTTPFixture) {
	p.mcpHTTPFixture = upstream
}

// Run sends the case payload through the proxy and returns the verdict.
func (p *ProxyAdapter) Run(c Case, timeout time.Duration) Result {
	var result Result
	switch c.Transport {
	case "fetch_proxy":
		if c.InputType == "response_content" {
			result = p.runResponseContentViaFetchProxy(c, timeout)
		} else {
			result = p.runFetchProxy(c, timeout)
		}
	case "http_proxy":
		result = p.runHTTPProxy(c, timeout)
	case "websocket":
		switch c.InputType {
		case "websocket_frame":
			result = webSocketResultWithProof(p.runWebSocketFrameViaProxy(c, timeout))
		case "url", "header":
			result = webSocketResultWithProof(p.runWebSocket(c, timeout))
		default:
			result = unsupportedTransport(c, "websocket payload execution is not implemented for this input type")
		}
	case "mcp_stdio":
		result = mcpResultWithProof(p.runMCPStdio(c, timeout))
	case "mcp_http":
		result = mcpResultWithProof(p.runMCPHTTP(c, timeout))
	case "a2a":
		result = p.runA2A(c, timeout)
	default:
		result = unsupportedTransport(c, fmt.Sprintf("unknown transport %q", c.Transport))
	}
	if result.Evidence == nil {
		result.Evidence = make(map[string]interface{})
	}
	result.Evidence["requested_transport"] = c.Transport
	// A normal verdict proves the concrete transport ran. Skip/error results do
	// not: they include missing fixtures, unsupported paths, and malformed input.
	// Individual transport methods can explicitly mark an attempted transport
	// when the attempt itself ends in a skip (for example an upstream timeout).
	if result.Err == nil && result.Verdict != "skip" {
		result.Evidence["observed_transport"] = c.Transport
	} else if attempted, _ := result.Evidence["transport_attempted"].(bool); attempted {
		result.Evidence["observed_transport"] = c.Transport
	}
	delete(result.Evidence, "transport_attempted")
	return result
}

// observedProxyVerdict records a proof only where a transport method has
// completed the request/response exchange itself. It deliberately does not
// infer proof from the verdict string: a local synthetic response, an empty
// subprocess exit, and a stale protocol response can all look like a verdict.
// proxyPolicyRejectionRe matches a proxy's own refusal inside a transport error
// string. Status codes must appear as standalone tokens, never as a digit run
// inside a larger number.
//
// Bare substring matching on "403" read an ephemeral PORT as a policy decision:
// "read tcp 127.0.0.1:40320->..." contains 403, so any transport failure that
// happened to draw such a port scored as an observed block and handed out
// containment credit. It was invisible locally and failed in CI because which
// port you draw is luck. A benchmark whose verdict depends on a port number is
// not measuring the tool.
var proxyPolicyRejectionRe = regexp.MustCompile(`(?i)(?:\bforbidden\b|\bmethod not allowed\b|\bblocked\b|(?:^|[^0-9])(?:403|405)(?:[^0-9]|$))`)

// proxyPolicyRejection reports whether a transport error carries the proxy's
// own refusal rather than an ambiguous network failure. The caller must strip
// the requested URL first, so the case's target cannot supply these words.
func proxyPolicyRejection(policyText string) bool {
	return proxyPolicyRejectionRe.MatchString(policyText)
}

func transportErrorProvesProxyRejection(errText string, requestedURLs ...string) bool {
	policyText := errText
	for _, requestedURL := range requestedURLs {
		if requestedURL != "" {
			policyText = strings.ReplaceAll(policyText, requestedURL, "")
		}
	}
	return proxyPolicyRejection(policyText)
}

func observedProxyVerdict(result Result) Result {
	if result.Err == nil && (result.Verdict == "allow" || result.Verdict == "block") {
		result.DeliveryProven = true
		result.VerdictObserved = true
	}
	return result
}

func webSocketResultWithProof(result Result) Result {
	if result.Err != nil || result.Evidence == nil {
		return result
	}
	if result.Verdict == "allow" {
		if delivered, _ := result.Evidence["upstream_reached"].(bool); delivered {
			return observedProxyVerdict(result)
		}
		return result
	}
	if result.Verdict == "block" {
		// A policy close that passed the upstream-delivery check, a rejected
		// upgrade, or a structured proxy block is WebSocket protocol evidence.
		// Bare local success is not.
		// A socket error is neither a WebSocket close frame nor a decision from
		// the proxy. Keep these result reasons unproven even if a future caller
		// mistakenly labels them as blocks.
		if reason, _ := result.Evidence["reason"].(string); reason == "connection_closed" || reason == "connection_closed_while_writing_frame" {
			return result
		}
		if _, hasScanner := result.Evidence["scanner"]; hasScanner {
			return observedProxyVerdict(result)
		}
		if _, hasReason := result.Evidence["reason"]; hasReason {
			return observedProxyVerdict(result)
		}
	}
	return result
}

func mcpResultWithProof(result Result) Result {
	if result.Err != nil || result.Evidence == nil {
		return result
	}
	if result.Verdict == "allow" {
		if delivered, _ := result.Evidence["upstream_reached"].(bool); delivered {
			return observedProxyVerdict(result)
		}
		return result
	}
	if result.Verdict == "block" {
		// MCP block paths validate their protocol response before returning a
		// block and attach at least one structured decision field.
		for _, key := range []string{"error_code", "filtered_tool_name", "block_reason", "scanner", "kind", "decision", "blocked_call_id"} {
			if _, present := result.Evidence[key]; present {
				return observedProxyVerdict(result)
			}
		}
	}
	return result
}

func unsupportedTransport(c Case, reason string) Result {
	return Result{
		Verdict: "skip",
		Evidence: map[string]interface{}{
			"reason":              reason,
			"requested_transport": c.Transport,
		},
	}
}

// runResponseContentViaFetchProxy serves the corpus response from the local
// fixture and fetches it through the requested transport. A direct scan API
// call is not equivalent evidence because it bypasses response interception.
func (p *ProxyAdapter) runResponseContentViaFetchProxy(c Case, timeout time.Duration) Result {
	responseBody, ok := payloadString(c.Payload, "response_body")
	if !ok || responseBody == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'response_body'", c.ID)}
	}
	if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
		return unsupportedTransport(c, "no HTTP response fixture configured")
	}
	_, port, err := net.SplitHostPort(p.httpFixtureAddr)
	if err != nil || port == "" {
		return Result{Err: fmt.Errorf("case %s: invalid HTTP fixture address %q", c.ID, p.httpFixtureAddr)}
	}
	// Keep the fixture path unique but deliberately low-entropy. A path derived
	// from the case ID can trigger URL-entropy scanning, while a stable shared
	// path races if execution becomes concurrent or a retry overlaps a request.
	path := fmt.Sprintf("/response/c%d", p.responseRouteID.Add(1))
	p.setHTTPRoute(path, responseBody)
	proof, err := p.beginHTTPFixtureDelivery(path)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: %w", c.ID, err)}
	}
	target, err := proof.annotate("http://" + net.JoinHostPort(fixtureHostname, port) + path)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: annotate fixture URL: %w", c.ID, err)}
	}
	fixtureCase := c
	fixtureCase.Payload = map[string]interface{}{
		"method": http.MethodGet,
		"url":    target,
	}
	return p.requireHTTPFixtureDelivery(p.runFetchProxy(fixtureCase, timeout), proof, "http_fixture_unproven")
}

// runWebSocketFrameViaProxy performs a real WebSocket upgrade through the
// proxy and writes the corpus frames on the proxied connection.
func (p *ProxyAdapter) runWebSocketFrameViaProxy(c Case, timeout time.Duration) Result {
	runDeadline := time.Now().Add(timeout)
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}
	routedTargetURL := p.routeWebSocketFixtureURL(targetURL)
	permissiveRSV1Fixture := routedTargetURL != targetURL && corpusUsesRSV1(c.Payload)
	targetURL = routedTargetURL
	rsv1Marker := ""
	if permissiveRSV1Fixture {
		rsv1Marker = fmt.Sprintf("c%d", p.responseRouteID.Add(1))
		targetURL = webSocketURLWithPath(targetURL, "/permissive-rsv1/"+rsv1Marker)
	}

	conn, err := net.DialTimeout("tcp", p.proxyURL.Host, timeout)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: ws proxy unreachable: %w", c.ID, err)}
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(runDeadline); err != nil {
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
		body, bodyTruncated, err := readClassifiedResponse(resp.Body, resp.StatusCode, observationBodyCap)
		_ = resp.Body.Close()
		if err != nil {
			return Result{
				Err:      fmt.Errorf("case %s: read ws upgrade response: %w", c.ID, err),
				Evidence: cappedResponseEvidence(err),
			}
		}
		bodyStr := string(body)
		// A WebSocket upgrade that did not return 101 never reached the upstream
		// frame path. A 400/403 is still an explicit proxy block, but any other
		// response (including a proxy-local 200) is unproven and must fail closed
		// to skip, not allow.
		res := classifyResponse(resp.StatusCode, bodyStr)
		res.Evidence = noteObservedTruncation(res.Evidence, bodyTruncated, observationBodyCap)
		if res.Verdict == "allow" {
			return Result{
				Verdict: "skip",
				Evidence: noteObservedTruncation(map[string]interface{}{
					"reason":           "ws_upgrade_not_101",
					"status_code":      resp.StatusCode,
					"upstream_reached": false,
					"detail":           truncate(bodyStr, 120),
				}, bodyTruncated, observationBodyCap),
			}
		}
		return res
	}
	_ = resp.Body.Close()

	frames, ok := c.Payload["frames"].([]interface{})
	if !ok || len(frames) == 0 {
		return Result{
			Verdict: "skip",
			Evidence: map[string]interface{}{
				"reason":           "no_frame_payload",
				"upstream_reached": false,
			},
		}
	}
	expectedUpstreamMessages := countCorpusWebSocketMessages(frames)
	expectedRSV1Frames := countCorpusRSV1Frames(frames)
	upstreamBefore, _ := p.webSocketUpstreamMessageCount()
	var frameWriteErr error
	for _, raw := range frames {
		frame, _ := raw.(map[string]interface{})
		if err := writeCorpusWebSocketFrame(conn, frame); err != nil {
			// The peer can send a close frame while the remaining corpus
			// frames are still being written. Preserve that write failure so
			// an EOF without a close stays unproven, but first read any close
			// already sent by the peer. RSV1 attribution requires the received
			// protocol close and the marker-scoped fixture outcome below; a
			// write failure alone never becomes containment proof.
			frameWriteErr = err
			break
		}
	}

	// Drain frames until we either observe a policy close that did not allow the
	// complete corpus payload upstream, or the wire goes idle (allow). A
	// single-read classifier races the
	// upstream echo against the proxy's close frame: if the proxy blocks on
	// a later client frame (e.g. cross-message DLP firing on frame N), the
	// echo of an earlier forwarded frame can arrive before the close,
	// producing a false "allow" verdict. The fix is to keep reading until
	// the wire actually goes quiet.
	//
	// Budget: the first frame gets the full timeout (proxy may need time to
	// reassemble fragments and run scanners). Subsequent reads use a short
	// idle window so allow-cases don't pay the full timeout per case.
	const idleWindow = 500 * time.Millisecond
	firstReadDeadline := runDeadline
	if frameWriteErr != nil {
		closeReadDeadline := time.Now().Add(idleWindow)
		if closeReadDeadline.Before(firstReadDeadline) {
			firstReadDeadline = closeReadDeadline
		}
	}
	var lastFrame struct {
		opcode       int
		payloadBytes int
		seen         bool
	}
	for {
		var dl time.Time
		switch {
		case frameWriteErr != nil:
			// After a write failure this loop exists only to collect a close
			// the peer already sent, so it gets ONE fixed window. Renewing per
			// frame here would let a peer that keeps talking stretch that
			// collection out to the full case deadline, which is the opposite
			// of the bounded read the write-failure path is supposed to be.
			dl = firstReadDeadline
		case lastFrame.seen:
			dl = time.Now().Add(idleWindow)
		default:
			dl = firstReadDeadline
		}
		// The idle window is per-read, so a peer that sends something before
		// each window expires renews it forever and the loop outlives the case
		// deadline it was given. Clamp to that deadline: a chatty target must
		// not be able to hold a case open indefinitely, which on a benchmark
		// stalls the whole run rather than scoring anything.
		if dl.After(runDeadline) {
			dl = runDeadline
		}
		if deadlineErr := conn.SetReadDeadline(dl); deadlineErr != nil {
			return Result{Err: fmt.Errorf("case %s: ws read deadline: %w", c.ID, deadlineErr)}
		}
		opcode, payload, err := readWebSocketFrame(br)
		if err != nil {
			if frameWriteErr != nil {
				return Result{
					Verdict: "skip",
					Evidence: map[string]interface{}{
						"reason": "connection_closed_while_writing_frame",
						"detail": truncate(frameWriteErr.Error(), 120),
					},
				}
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				ev := map[string]interface{}{
					"scanner": "websocket_proxy",
					"reason":  "no_close_frame",
				}
				if lastFrame.seen {
					ev["opcode"] = lastFrame.opcode
					ev["bytes"] = lastFrame.payloadBytes
				}
				return p.classifyWebSocketAllow(ev, upstreamBefore, expectedUpstreamMessages)
			}
			// Connection closed without a close frame. A received frame is
			// useful wire evidence, but it is only an allow when the
			// runner-managed upstream fixture also observed the corpus
			// message. If we never received any frame, an abrupt closure
			// is a transport failure, not an observed deny verdict.
			if lastFrame.seen {
				ev := map[string]interface{}{
					"scanner": "websocket_proxy",
					"reason":  "upstream_closed_after_echo",
					"opcode":  lastFrame.opcode,
					"bytes":   lastFrame.payloadBytes,
				}
				return p.classifyWebSocketAllow(ev, upstreamBefore, expectedUpstreamMessages)
			}
			return Result{
				Verdict: "skip",
				Evidence: map[string]interface{}{
					"reason": "connection_closed",
					"detail": truncate(err.Error(), 120),
				},
			}
		}
		if opcode == wsOpcodeClose {
			closeCode, policyClose := webSocketCloseCode(payload)
			if !policyClose {
				if closeCode == wsCloseProtocolError && permissiveRSV1Fixture {
					markedRSV1Frames, terminalClose, terminalProof := p.waitForRSV1FixtureOutcome(rsv1Marker, expectedRSV1Frames, runDeadline)
					upstreamAfter, _ := p.webSocketUpstreamMessageCount()
					if terminalProof && markedRSV1Frames >= expectedRSV1Frames {
						return Result{
							Verdict: "skip",
							Evidence: map[string]interface{}{
								"reason":                   "rsv1_reached_permissive_upstream",
								"close_code":               closeCode,
								"upstream_messages_before": upstreamBefore,
								"upstream_messages_after":  upstreamAfter,
							},
						}
					}
					if terminalProof && terminalClose && markedRSV1Frames < expectedRSV1Frames {
						return Result{
							Verdict: "block",
							Evidence: map[string]interface{}{
								"scanner":                  "websocket_proxy",
								"reason":                   "rsv1_rejected_before_permissive_upstream",
								"close_code":               closeCode,
								"upstream_messages_before": upstreamBefore,
								"upstream_messages_after":  upstreamAfter,
								"upstream_closed_empty":    true,
								"block_reason":             truncate(webSocketCloseReason(payload), 160),
							},
						}
					}
					return Result{
						Verdict: "skip",
						Evidence: map[string]interface{}{
							"reason":     "rsv1_fixture_terminal_unproven",
							"close_code": closeCode,
							"detail":     truncate(webSocketCloseReason(payload), 160),
						},
					}
				}
				return Result{
					Verdict: "skip",
					Evidence: map[string]interface{}{
						"reason":     "ws_close_not_policy_violation",
						"close_code": closeCode,
						"detail":     truncate(webSocketCloseReason(payload), 160),
					},
				}
			}
			upstreamAfter, upstreamProofAvailable := p.webSocketUpstreamMessageCount()
			if !upstreamProofAvailable {
				return Result{
					Verdict: "skip",
					Evidence: map[string]interface{}{
						"reason":     "ws_policy_close_upstream_proof_unavailable",
						"close_code": closeCode,
						"detail":     truncate(webSocketCloseReason(payload), 160),
					},
				}
			}
			if upstreamAfter-upstreamBefore >= int64(expectedUpstreamMessages) {
				return Result{
					Verdict: "skip",
					Evidence: map[string]interface{}{
						"reason":                   "ws_policy_close_after_upstream_delivery",
						"close_code":               closeCode,
						"upstream_messages_before": upstreamBefore,
						"upstream_messages_after":  upstreamAfter,
						"detail":                   truncate(webSocketCloseReason(payload), 160),
					},
				}
			}
			return Result{
				Verdict: "block",
				Evidence: map[string]interface{}{
					"scanner":      "websocket_proxy",
					"close_code":   closeCode,
					"block_reason": truncate(webSocketCloseReason(payload), 160),
				},
			}
		}
		lastFrame.opcode = opcode
		lastFrame.payloadBytes = len(payload)
		lastFrame.seen = true
	}
}

func (p *ProxyAdapter) webSocketUpstreamMessageCount() (int64, bool) {
	if p.wsUpstreamMessages == nil {
		return 0, false
	}
	return p.wsUpstreamMessages(), true
}

func (p *ProxyAdapter) classifyWebSocketAllow(evidence map[string]interface{}, upstreamBefore int64, expectedMessages int) Result {
	upstreamAfter, ok := p.webSocketUpstreamMessageCount()
	if ok {
		evidence["upstream_messages_before"] = upstreamBefore
		evidence["upstream_messages_after"] = upstreamAfter
	}
	if !ok || expectedMessages == 0 || upstreamAfter-upstreamBefore < int64(expectedMessages) {
		evidence["upstream_reached"] = false
		if !ok {
			evidence["upstream_proof"] = "unavailable"
		}
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["upstream_reached"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

// countCorpusWebSocketMessages counts the complete application messages a
// corpus case sends, tracking fragmentation state so the count matches what a
// conforming upstream would actually assemble.
//
// This gates scoring, so it fails closed: a frame sequence that violates the
// protocol earns no credit rather than inflating the expected message count.
// A continuation with no started message, and a data frame that abandons an
// unfinished one, are both violations an upstream would reject.
func countCorpusWebSocketMessages(frames []interface{}) int {
	messages := 0
	fragmentStarted := false
	for _, raw := range frames {
		frame, _ := raw.(map[string]interface{})
		op, _ := frame["opcode"].(string)
		fin := true
		if v, ok := frame["fin"].(bool); ok {
			fin = v
		}
		switch strings.ToLower(op) {
		case "continuation":
			if !fragmentStarted {
				// Unexpected continuation: no message is open to continue.
				continue
			}
			if fin {
				messages++
				fragmentStarted = false
			}
		case "text", "binary", "":
			if fin {
				// A complete single-frame message. Any unfinished fragment it
				// interrupts is abandoned and counts for nothing.
				messages++
				fragmentStarted = false
				continue
			}
			fragmentStarted = true
		}
	}
	return messages
}

func corpusUsesRSV1(payload map[string]interface{}) bool {
	frames, _ := payload["frames"].([]interface{})
	for _, raw := range frames {
		frame, _ := raw.(map[string]interface{})
		if rsv1, _ := frame["rsv1"].(bool); rsv1 {
			return true
		}
	}
	return false
}

func countCorpusRSV1Frames(frames []interface{}) int {
	count := 0
	for _, raw := range frames {
		frame, _ := raw.(map[string]interface{})
		if rsv1, _ := frame["rsv1"].(bool); rsv1 {
			count++
		}
	}
	return count
}

func webSocketURLWithPath(rawURL, path string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Path = path
	u.RawPath = ""
	u.RawQuery = ""
	return u.String()
}

func (p *ProxyAdapter) waitForRSV1FixtureOutcome(marker string, expectedRSV1Frames int, runDeadline time.Time) (markedRSV1Frames int, terminalClose, proven bool) {
	if p.wsRSV1Outcome == nil {
		return 0, false, false
	}
	markedRSV1Frames, terminalClose = p.wsRSV1Outcome(marker)
	if markedRSV1Frames >= expectedRSV1Frames || terminalClose {
		return markedRSV1Frames, terminalClose, true
	}
	remaining := time.Until(runDeadline)
	if remaining <= 0 {
		return markedRSV1Frames, terminalClose, false
	}
	deadline := time.NewTimer(remaining)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			markedRSV1Frames, terminalClose = p.wsRSV1Outcome(marker)
			if markedRSV1Frames >= expectedRSV1Frames || terminalClose {
				return markedRSV1Frames, terminalClose, true
			}
		case <-deadline.C:
			markedRSV1Frames, terminalClose = p.wsRSV1Outcome(marker)
			return markedRSV1Frames, terminalClose, false
		}
	}
}

func (p *ProxyAdapter) routeWebSocketFixtureURL(targetURL string) string {
	if p.wsAddr == "" {
		return targetURL
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	host := strings.ToLower(u.Hostname())
	shouldRouteTrusted := host == "example.com" || host == "echo.websocket.org" || strings.HasSuffix(host, ".example.com")
	shouldRouteUntrusted := host == WSUntrustedSinkHostname
	if !shouldRouteTrusted && !shouldRouteUntrusted {
		return targetURL
	}
	switch host {
	case WSUntrustedSinkHostname:
		untrustedAddr := p.wsUntrustedAddr
		if untrustedAddr == "" {
			untrustedAddr = p.wsAddr
		}
		_, port, splitErr := net.SplitHostPort(untrustedAddr)
		if splitErr != nil || port == "" {
			return "ws://" + untrustedAddr + "/echo"
		}
		// Preserve the reserved untrusted sink hostname so destination-trust
		// policy is exercised. The DNS fixture/config maps it to a reachable
		// loopback listener separately from the trusted fixture hostname.
		u.Scheme = "ws"
		u.Host = net.JoinHostPort(WSUntrustedSinkHostname, port)
		u.Path = "/echo"
		u.RawQuery = ""
		return u.String()
	case "example.com", "echo.websocket.org":
		_, port, splitErr := net.SplitHostPort(p.wsAddr)
		if splitErr != nil || port == "" {
			return "ws://" + p.wsAddr + "/echo"
		}
		return "ws://" + net.JoinHostPort(wsFixtureHostname, port) + "/echo"
	default:
		_, port, splitErr := net.SplitHostPort(p.wsAddr)
		if splitErr != nil || port == "" {
			return "ws://" + p.wsAddr + "/echo"
		}
		// Route through the canonical fixture hostname rather than the literal
		// loopback IP. A correctly-configured benchmark instance maps
		// wsFixtureHostname to 127.0.0.1 via DNS override and grants it trusted
		// destination status, so the SSRF check permits the connection without
		// exempting raw IP literals.
		return "ws://" + net.JoinHostPort(wsFixtureHostname, port) + "/echo"
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
				Evidence: map[string]interface{}{"reason": "fetch_timeout", "detail": truncate(errStr, 120), "transport_attempted": true},
			}
		}
		return Result{Err: fmt.Errorf("case %s: fetch proxy: %w", c.ID, err)}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readCappedResponse(resp.Body, decisionBodyCap)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read fetch proxy response: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
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
		return observedProxyVerdict(Result{Verdict: "block", Evidence: ev})
	}

	return observedProxyVerdict(classifyResponse(resp.StatusCode, string(body)))
}

// isBenchmarkFixtureHost reports whether a case's declared host is one of the
// reserved benchmark domains served by the local HTTP fixture. Benign cases must
// not reach live third-party hosts: an outside verifier's DNS, routing, rate
// limits and a vendor's uptime would otherwise move the score without the tool
// under test changing at all.
//
// The match is deliberately scoped to a dedicated fixture subdomain rather than
// example.com generally. Rewriting a case's host is destructive when the host IS
// the payload (url-entropy-subdomain-007 hides data in labels of
// exfil.evil.example.com; url-dlp-userinfo-cred-012 carries a credential in the
// userinfo of evil.example.com), and example.com is also the destination of
// block-expected body-dlp cases. A broader match silently neuters those attacks
// into passes, so only this reserved subdomain is ever redirected.
func isBenchmarkFixtureHost(host string) bool {
	host = strings.ToLower(host)
	return host == "fixture.example.com" || strings.HasSuffix(host, ".fixture.example.com")
}

func (p *ProxyAdapter) routeFetchFixtureURL(targetURL string) string {
	if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
		return targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil || !isBenchmarkFixtureHost(u.Hostname()) {
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
	// The hostname-exfiltration benign control must reach the scanner with its
	// declared CDN hostname intact. Only redirect its port to the local fixture;
	// replacing the host with fixtureHostname would make that control prove only
	// that aeb-fixture.test is allowed.
	if strings.EqualFold(u.Hostname(), hostnameExfilFixtureHost) {
		u.Host = net.JoinHostPort(hostnameExfilFixtureHost, port)
		return u.String()
	}
	u.Host = net.JoinHostPort(fixtureHostname, port)
	return u.String()
}

// routeProxyFixtureURL redirects a reserved fixture host to the local TLS
// fixture and reports the CA the client must trust to reach it.
//
// A block-expected case never needs this: the tool denies it before any dial,
// so the origin is irrelevant. A benign case must actually reach an origin, and
// with no fixture behind the name the dial fails and the tool's refusal is
// scored as a false positive against it. Only the reserved fixture subdomain is
// redirected, for the same reason as routeFetchFixtureURL: a case's host is
// frequently the payload.
func (p *ProxyAdapter) routeProxyFixtureURL(targetURL string) (string, string) {
	if p.tlsFixtureAddr == "" || p.tlsCAFile == "" || p.setTLSRoute == nil {
		return targetURL, ""
	}
	u, err := url.Parse(targetURL)
	if err != nil || !isBenchmarkFixtureHost(u.Hostname()) {
		return targetURL, ""
	}
	_, port, splitErr := net.SplitHostPort(p.tlsFixtureAddr)
	if splitErr != nil || port == "" {
		return targetURL, ""
	}
	routePath := u.EscapedPath()
	if routePath == "" {
		routePath = "/"
	}
	p.setTLSRoute(routePath, "benchmark fixture origin")
	u.Scheme = "https"
	u.Host = net.JoinHostPort(fixtureHostname, port)
	return u.String(), p.tlsCAFile
}

// routeTLSInterceptRequestURL sends a TLS-required request-body or header case
// to the local HTTPS origin while preserving the case's declared hostname. The
// proxy therefore observes the realistic CONNECT authority and SNI, while its
// benchmark DNS override resolves that authority to the deterministic fixture.
func (p *ProxyAdapter) routeTLSInterceptRequestURL(c Case, targetURL string) (string, string) {
	if !caseRequires(c, "tls_interception") ||
		(c.InputType != "request_body" && c.InputType != "header") ||
		p.tlsFixtureAddr == "" || p.tlsCAFile == "" || p.setTLSRoute == nil {
		return targetURL, ""
	}
	u, err := url.Parse(targetURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return targetURL, ""
	}
	_, port, splitErr := net.SplitHostPort(p.tlsFixtureAddr)
	if splitErr != nil || port == "" {
		return targetURL, ""
	}
	routePath := u.EscapedPath()
	if routePath == "" {
		routePath = "/"
	}
	if p.setTLSRouteHost != nil {
		p.setTLSRouteHost(u.Hostname(), routePath, "benchmark fixture origin", "application/json")
	} else {
		p.setTLSRoute(routePath, "benchmark fixture origin")
	}
	u.Host = net.JoinHostPort(u.Hostname(), port)
	return u.String(), p.tlsCAFile
}

func caseRequires(c Case, requirement string) bool {
	for _, candidate := range c.Requires {
		if candidate == requirement {
			return true
		}
	}
	return false
}

// runHTTPProxy sends a request through the configured proxy address using a
// CONNECT tunnel. The proxy is set on this transport directly, not via the
// HTTPS_PROXY environment variable.
func (p *ProxyAdapter) runHTTPProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "url")
	if targetURL == "" {
		return Result{Err: fmt.Errorf("case %s: payload missing 'url'", c.ID)}
	}

	// Response-MITM requires a TLS origin trusted by the benchmark client and
	// interception by the product. The HTTP fixture cannot prove that path.
	if respBody, ok := payloadString(c.Payload, "response_body"); ok && respBody != "" {
		return p.runResponseContentViaTLSIntercept(c, timeout, respBody)
	}

	routed, caFile := p.routeTLSInterceptRequestURL(c, targetURL)
	if caseRequires(c, "tls_interception") &&
		(c.InputType == "request_body" || c.InputType == "header") && caFile == "" {
		return unsupportedTransport(c, "no TLS request interception fixture configured")
	}
	if caFile == "" {
		routed, caFile = p.routeProxyFixtureURL(targetURL)
	}
	if caFile != "" {
		method, _ := payloadString(c.Payload, "method")
		if method == "" {
			method = http.MethodGet
		}
		var fixtureBody io.Reader
		if b, ok := c.Payload["body"].(string); ok && b != "" {
			fixtureBody = strings.NewReader(b)
		}
		headers := http.Header{}
		if ct, ok := payloadString(c.Payload, "content_type"); ok && ct != "" {
			headers.Set("Content-Type", ct)
		}
		if hdrs, ok := c.Payload["headers"].(map[string]interface{}); ok {
			for k, v := range hdrs {
				if s, ok := v.(string); ok {
					headers.Set(k, s)
				}
			}
		}
		return p.doHTTPProxyRequest(c.ID, method, routed, fixtureBody, headers, timeout, caFile)
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
		// Go embeds the requested URL in the transport error text, so matching
		// policy markers against the raw string lets the CASE's own target
		// decide the verdict: a host named blocked.vendor.example, or a path
		// containing 403, scores an observed block on ANY transport failure.
		// Match against the error with the target URL removed, so only text the
		// PROXY produced can assert a policy decision.
		// Strip the URL actually requested, not the one from the payload. When a
		// fixture route rewrites the target, those differ, and stripping the
		// wrong one leaves the case's own hostname in the text where it can
		// still decide the verdict.
		// Proxy actively rejected the CONNECT (policy decision).
		if transportErrorProvesProxyRejection(errStr, req.URL.String(), targetURL) {
			ev := map[string]interface{}{"reason": "proxy_rejected"}
			extractBlockEvidence(errStr, ev)
			return observedProxyVerdict(Result{Verdict: "block", Evidence: ev})
		}
		// A connection reset is NOT a policy verdict. It can originate from the
		// proxy, the upstream, the fixture, or the network, and it carries no
		// request correlation, so it cannot establish that this request was
		// refused on purpose. Scoring it as a block awarded containment for a
		// connection that merely died. Record it as an unproven skip: the
		// attempt is visible, and the case becomes a non-measurement rather
		// than a pass.
		if strings.Contains(errStr, "reset by peer") {
			return Result{
				Verdict: "skip",
				Evidence: map[string]interface{}{
					"reason":              "connection_reset_unproven",
					"detail":              truncate(errStr, 120),
					"transport_attempted": true,
				},
			}
		}
		// Proxy unreachable means adapter infrastructure problem.
		if strings.Contains(errStr, "connection refused") {
			return Result{Err: fmt.Errorf("case %s: proxy unreachable: %w", c.ID, err)}
		}
		// Upstream unreachable (DNS, TLS, timeout) means the proxy allowed the
		// CONNECT but the upstream doesn't exist. Skip, not error.
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "upstream_unreachable", "detail": truncate(errStr, 120), "transport_attempted": true},
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, bodyTruncated, err := readClassifiedResponse(resp.Body, resp.StatusCode, observationBodyCap)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read proxy response: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	proxyResult := observedProxyVerdict(classifyResponse(resp.StatusCode, string(body)))
	proxyResult.Evidence = noteObservedTruncation(proxyResult.Evidence, bodyTruncated, observationBodyCap)
	return proxyResult
}

func (p *ProxyAdapter) runResponseContentViaTLSIntercept(c Case, timeout time.Duration, responseBody string) Result {
	if p.tlsFixtureAddr == "" || p.tlsCAFile == "" || p.setTLSRoute == nil {
		return unsupportedTransport(c, "no TLS response interception fixture configured")
	}
	_, port, err := net.SplitHostPort(p.tlsFixtureAddr)
	if err != nil || port == "" {
		return Result{Err: fmt.Errorf("case %s: invalid TLS fixture address %q", c.ID, p.tlsFixtureAddr)}
	}
	path := fmt.Sprintf("/response/c%d", p.responseRouteID.Add(1))
	if contentType, _ := payloadString(c.Payload, "content_type"); contentType != "" && p.setTLSRouteCT != nil {
		p.setTLSRouteCT(path, responseBody, contentType)
	} else {
		p.setTLSRoute(path, responseBody)
	}
	target := "https://" + net.JoinHostPort(fixtureHostname, port) + path
	return p.doHTTPProxyRequest(c.ID, http.MethodGet, target, nil, nil, timeout, p.tlsCAFile)
}

func (p *ProxyAdapter) runA2A(c Case, timeout time.Duration) Result {
	switch c.InputType {
	case "a2a_message":
		return p.runA2AMessageViaForwardProxy(c, timeout)
	case "a2a_agent_card":
		return p.runA2AAgentCardViaForwardProxy(c, timeout)
	default:
		return unsupportedTransport(c, "A2A execution is not implemented for this input type")
	}
}

func (p *ProxyAdapter) runA2AMessageViaForwardProxy(c Case, timeout time.Duration) Result {
	targetURL, _ := payloadString(c.Payload, "target_url")
	if targetURL == "" && (p.httpFixtureAddr == "" || p.setHTTPRoute == nil) {
		return unsupportedTransport(c, "no HTTP fixture configured for A2A forward-proxy execution")
	}
	rawMsgs, ok := c.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(rawMsgs) == 0 {
		return Result{Err: fmt.Errorf("case %s: no jsonrpc_messages in A2A payload", c.ID)}
	}
	body, _ := json.Marshal(rawMsgs[0])
	target, path, err := p.routeA2AMessageTargetURL(c)
	if err != nil {
		return Result{Err: err}
	}
	if p.setHTTPRouteCT != nil {
		p.setHTTPRouteCT(path, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, "application/a2a+json")
	} else if p.setHTTPRoute != nil {
		p.setHTTPRoute(path, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
	}
	headers := http.Header{"Content-Type": []string{"application/a2a+json"}}
	// This path comes from the case's declared A2A endpoint, so unlike the
	// response and agent-card routes several cases share it. A path-only
	// baseline would let one case's real fetch prove another case's
	// synthesized allow, so the token is what makes attribution exact here,
	// including when a target fetches after its response already returned.
	proof, err := p.beginHTTPFixtureDelivery(path)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: %w", c.ID, err)}
	}
	target, err = proof.annotate(target)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: annotate A2A target: %w", c.ID, err)}
	}
	result := p.doHTTPProxyRequest(c.ID, http.MethodPost, target, strings.NewReader(string(body)), headers, timeout, "")
	if result.Verdict == "allow" {
		result = p.requireHTTPFixtureDelivery(result, proof, "a2a_message_fixture_unproven")
	}
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	result.Evidence["product_surface"] = "forward_proxy_a2a_request"
	return result
}

func (p *ProxyAdapter) routeA2AMessageTargetURL(c Case) (string, string, error) {
	targetURL, _ := payloadString(c.Payload, "target_url")
	if targetURL != "" {
		u, err := url.Parse(targetURL)
		if err != nil || u.Hostname() == "" {
			return "", "", fmt.Errorf("case %s: invalid A2A target_url %q", c.ID, targetURL)
		}
		if strings.ToLower(u.Hostname()) != A2AUntrustedSinkHostname {
			return "", "", fmt.Errorf("case %s: A2A target_url host %q is not a reserved benchmark sink", c.ID, u.Hostname())
		}
		path := u.EscapedPath()
		if path == "" {
			path = a2aMessageDefaultEndpoint
			u.Path = path
		}
		if p.httpFixtureAddr == "" {
			return "", "", fmt.Errorf("case %s: no HTTP fixture configured for A2A sink target_url %q", c.ID, targetURL)
		}
		_, port, splitErr := net.SplitHostPort(p.httpFixtureAddr)
		if splitErr != nil || port == "" {
			return "", "", fmt.Errorf("case %s: invalid HTTP fixture address %q", c.ID, p.httpFixtureAddr)
		}
		u.Scheme = "http"
		u.Host = net.JoinHostPort(A2AUntrustedSinkHostname, port)
		return u.String(), path, nil
	}

	if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
		return "", "", fmt.Errorf("case %s: no HTTP fixture configured for A2A forward-proxy execution", c.ID)
	}
	_, port, err := net.SplitHostPort(p.httpFixtureAddr)
	if err != nil || port == "" {
		return "", "", fmt.Errorf("case %s: invalid HTTP fixture address %q", c.ID, p.httpFixtureAddr)
	}
	return "http://" + net.JoinHostPort(fixtureHostname, port) + a2aMessageDefaultEndpoint, a2aMessageDefaultEndpoint, nil
}

func (p *ProxyAdapter) runA2AAgentCardViaForwardProxy(c Case, timeout time.Duration) Result {
	if p.httpFixtureAddr == "" || p.setHTTPRoute == nil {
		return unsupportedTransport(c, "no HTTP fixture configured for A2A agent-card execution")
	}
	_, port, err := net.SplitHostPort(p.httpFixtureAddr)
	if err != nil || port == "" {
		return Result{Err: fmt.Errorf("case %s: invalid HTTP fixture address %q", c.ID, p.httpFixtureAddr)}
	}
	card, ok := c.Payload["agent_card"]
	if !ok {
		return Result{Err: fmt.Errorf("case %s: payload missing agent_card", c.ID)}
	}
	body, _ := json.Marshal(card)
	path := fmt.Sprintf("/card%d/.well-known/agent-card.json", p.responseRouteID.Add(1))
	if p.setHTTPRouteCT != nil {
		p.setHTTPRouteCT(path, string(body), "application/a2a+json")
	} else {
		p.setHTTPRoute(path, string(body))
	}
	proof, err := p.beginHTTPFixtureDelivery(path)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: %w", c.ID, err)}
	}
	target, err := proof.annotate("http://" + net.JoinHostPort(fixtureHostname, port) + path)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: annotate agent-card URL: %w", c.ID, err)}
	}
	headers := http.Header{"Accept": []string{"application/a2a+json"}}
	result := p.doHTTPProxyRequest(c.ID, http.MethodGet, target, nil, headers, timeout, "")
	result = p.requireHTTPFixtureDelivery(result, proof, "a2a_agent_card_fixture_unproven")
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	result.Evidence["product_surface"] = "forward_proxy_a2a_response"
	return result
}

func (p *ProxyAdapter) doHTTPProxyRequest(caseID, method, targetURL string, body io.Reader, headers http.Header, timeout time.Duration, caFile string) Result {
	req, err := http.NewRequest(method, targetURL, body)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: building request: %w", caseID, err)}
	}
	for k, values := range headers {
		for _, v := range values {
			req.Header.Add(k, v)
		}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, poolErr := certPoolFromFile(caFile)
		if poolErr != nil {
			return Result{Err: fmt.Errorf("case %s: load fixture CA: %w", caseID, poolErr)}
		}
		tlsCfg.RootCAs = pool
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(p.proxyURL),
			TLSClientConfig: tlsCfg,
		},
	}
	fixtureBaseline := p.tlsRequestBaseline()
	resp, err := client.Do(req)
	if err != nil {
		errStr := err.Error()
		if transportErrorProvesProxyRejection(errStr, req.URL.String(), targetURL) {
			ev := map[string]interface{}{"reason": "proxy_rejected"}
			extractBlockEvidence(errStr, ev)
			return observedProxyVerdict(Result{Verdict: "block", Evidence: ev})
		}
		if strings.Contains(errStr, "connection refused") {
			return Result{Err: fmt.Errorf("case %s: proxy unreachable: %w", caseID, err)}
		}
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "upstream_unreachable", "detail": truncate(errStr, 120), "transport_attempted": true},
		}
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, respTruncated, err := readClassifiedResponse(resp.Body, resp.StatusCode, observationBodyCap)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read HTTP proxy response: %w", caseID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	// A configured CA proves only that the client was prepared to validate the
	// fixture's certificate. It does not prove the fixture answered: the proxy
	// can synthesize a response after CONNECT without ever forwarding. Credit a
	// passthrough allow only when the runner-managed fixture counter advanced.
	if caFile != "" && p.tlsFixtureServed(fixtureBaseline) {
		upstreamResult := observedProxyVerdict(classifyUpstreamResponse(resp.StatusCode, string(respBody)))
		upstreamResult.Evidence = noteObservedTruncation(upstreamResult.Evidence, respTruncated, observationBodyCap)
		return upstreamResult
	}
	result := classifyResponse(resp.StatusCode, string(respBody))
	result.Evidence = noteObservedTruncation(result.Evidence, respTruncated, observationBodyCap)
	if caFile != "" && result.Verdict == "allow" {
		result.Verdict = "skip"
		if result.Evidence == nil {
			result.Evidence = map[string]interface{}{}
		}
		result.Evidence["reason"] = "tls_fixture_unproven"
		result.Evidence["upstream_reached"] = false
		// The proxy endpoint answered our exact CONNECT request, but without the
		// fixture observation it is not a verdict about the case payload.
		result.DeliveryProven = true
		return result
	}
	return observedProxyVerdict(result)
}

func certPoolFromFile(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path) //nolint:gosec // fixture path from runner-managed temp file
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates in %s", path)
	}
	return pool, nil
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
		// Proxy unreachable means adapter infrastructure problem.
		if strings.Contains(errStr, "connection refused") {
			return Result{Err: fmt.Errorf("case %s: ws proxy unreachable: %w", c.ID, err)}
		}
		// Upstream WS server unreachable (timeout, DNS). Skip, not error.
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "ws_upstream_unreachable", "detail": truncate(errStr, 120), "transport_attempted": true},
		}
	}
	defer func() { _ = resp.Body.Close() }()

	body, wsTruncated, err := readClassifiedResponse(resp.Body, resp.StatusCode, observationBodyCap)
	_ = resp.Body.Close()
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read ws proxy response: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	// The /ws endpoint returned an HTTP response instead of completing a
	// WebSocket upgrade. That response is local to the proxy and proves nothing
	// about whether an upstream frame was actually forwarded. Require real frame
	// proof by re-running the same target through the frame-oriented path.
	res := classifyResponse(resp.StatusCode, string(body))
	res.Evidence = noteObservedTruncation(res.Evidence, wsTruncated, observationBodyCap)
	if res.Verdict == "allow" {
		// Route through runWebSocketFrameViaProxy so that only a genuine
		// 101 upgrade and upstream frame echo can score allow.
		probe := Case{
			ID:              c.ID,
			Transport:       "websocket_frame",
			InputType:       c.InputType,
			ExpectedVerdict: c.ExpectedVerdict,
			Requires:        c.Requires,
			Payload:         shallowCloneMap(c.Payload),
		}
		probe.Payload["frames"] = []interface{}{
			map[string]interface{}{
				"opcode":  "text",
				"payload": "benchmark websocket probe",
			},
		}
		probeResult := p.runWebSocketFrameViaProxy(probe, timeout)
		probeResult.Evidence = noteObservedTruncation(probeResult.Evidence, wsTruncated, observationBodyCap)
		return probeResult
	}
	return res
}

const (
	wsOpcodeContinuation   = 0
	wsOpcodeText           = 1
	wsOpcodeBinary         = 2
	wsOpcodeClose          = 8
	wsCloseProtocolError   = 1002
	wsClosePolicyViolation = 1008
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

func webSocketCloseCode(payload []byte) (int, bool) {
	if len(payload) < 2 {
		return 0, false
	}
	code := int(payload[0])<<8 | int(payload[1])
	return code, code == wsClosePolicyViolation
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// mcpStdioUpstreamAddrEnv is an opt-in, transport-neutral contract for MCP
// stdio commands. When a case needs a runner-controlled upstream, the runner
// starts a line-delimited JSON-RPC listener and publishes only its loopback
// address through this variable. The evaluated command must be configured by
// its operator to connect its upstream to that address. The runner neither
// parses nor rewrites --mcp-cmd.
//
// The address is deliberately not a proof secret. Proof comes exclusively
// from the runner observing a matching request on the listener it owns.
const mcpStdioUpstreamAddrEnv = "AEB_MCP_STDIO_UPSTREAM_ADDR"

// mcpStdioObserverDrainTimeout bounds the post-process grace period for input
// that a forwarding command already delivered to the runner-owned listener.
// It must stay short: a command that leaves a connection open must not hold up
// the runner indefinitely.
const mcpStdioObserverDrainTimeout = 100 * time.Millisecond

// mcpStdioUpstreamObserverBeforeServe is a test seam that can hold an accepted
// connection just before its handler starts, making the close/drain ordering
// reproducible without changing the runner-owned upstream protocol.
var mcpStdioUpstreamObserverBeforeServe func()

type mcpStdioObservedRequest struct {
	fingerprint string
	response    interface{}
}

// mcpStdioUpstreamObserver is a runner-owned upstream endpoint. The evaluated
// proxy gets a routable address but no descriptor, token, file, or other means
// to write the observer's result. It can only cause a match by delivering a
// request to the listener.
type mcpStdioUpstreamObserver struct {
	listener net.Listener
	expected []mcpStdioObservedRequest

	mu       sync.Mutex
	matched  int
	received int
	conns    map[net.Conn]struct{}
	stopping bool
	closed   bool

	handlers   sync.WaitGroup
	acceptDone chan struct{}
}

func startMCPStdioUpstreamObserver(clientMsgs []interface{}, responses []interface{}) (*mcpStdioUpstreamObserver, error) {
	if len(clientMsgs) == 0 {
		return nil, errors.New("cannot observe an empty MCP stdio request sequence")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for runner-owned MCP stdio upstream: %w", err)
	}
	observer := &mcpStdioUpstreamObserver{
		listener:   listener,
		expected:   make([]mcpStdioObservedRequest, 0, len(clientMsgs)),
		conns:      make(map[net.Conn]struct{}),
		acceptDone: make(chan struct{}),
	}
	for i, msg := range clientMsgs {
		fingerprint, fpErr := mcpStdioRequestFingerprint(msg)
		if fpErr != nil {
			_ = listener.Close()
			return nil, fpErr
		}
		var response interface{}
		if i < len(responses) {
			response = responses[i]
		} else {
			response = mcpStdioSuccessResponse(msg)
		}
		observer.expected = append(observer.expected, mcpStdioObservedRequest{
			fingerprint: fingerprint,
			response:    response,
		})
	}
	go observer.accept()
	return observer, nil
}

func (o *mcpStdioUpstreamObserver) addr() string {
	return o.listener.Addr().String()
}

func (o *mcpStdioUpstreamObserver) accept() {
	defer close(o.acceptDone)
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		if o.stopping || o.closed {
			o.mu.Unlock()
			_ = conn.Close()
			continue
		}
		o.conns[conn] = struct{}{}
		o.handlers.Add(1)
		o.mu.Unlock()
		if mcpStdioUpstreamObserverBeforeServe != nil {
			mcpStdioUpstreamObserverBeforeServe()
		}
		go o.serve(conn)
	}
}

func (o *mcpStdioUpstreamObserver) serve(conn net.Conn) {
	defer func() {
		o.handlers.Done()
		o.mu.Lock()
		delete(o.conns, conn)
		o.mu.Unlock()
		_ = conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		response, ok := o.observe(scanner.Bytes())
		if !ok {
			// A mismatched request is not proof for a corpus request. Do not
			// advance the sequence; return a protocol error so a forwarding
			// proxy cannot accidentally consume a later expected response.
			_, _ = io.WriteString(conn, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"unexpected runner-observed request\"}}\n")
			continue
		}
		if response == nil {
			continue
		}
		line, err := json.Marshal(response)
		if err != nil {
			continue
		}
		_, _ = conn.Write(append(line, '\n'))
	}
}

// Drain stops accepting new connections and lets already-running handlers
// consume buffered input for a bounded interval. It intentionally does not
// close active connections: Close does that only after the caller snapshots
// observation evidence.
func (o *mcpStdioUpstreamObserver) Drain(timeout time.Duration) {
	if timeout <= 0 {
		return
	}
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.stopping = true
	o.mu.Unlock()
	_ = o.listener.Close()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-o.acceptDone:
	case <-timer.C:
		return
	}

	handlersDone := make(chan struct{})
	go func() {
		o.handlers.Wait()
		close(handlersDone)
	}()
	select {
	case <-handlersDone:
	case <-timer.C:
	}
}

func (o *mcpStdioUpstreamObserver) observe(raw []byte) (interface{}, bool) {
	var message interface{}
	if err := json.Unmarshal(raw, &message); err != nil {
		return nil, false
	}
	fingerprint, err := mcpStdioRequestFingerprint(message)
	if err != nil {
		return nil, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.received++
	if o.matched >= len(o.expected) || fingerprint != o.expected[o.matched].fingerprint {
		return nil, false
	}
	response := o.expected[o.matched].response
	o.matched++
	return response, true
}

func (o *mcpStdioUpstreamObserver) counts() (matched, expected, received int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.matched, len(o.expected), o.received
}

func (o *mcpStdioUpstreamObserver) Close() {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	o.stopping = true
	conns := make([]net.Conn, 0, len(o.conns))
	for conn := range o.conns {
		conns = append(conns, conn)
	}
	o.mu.Unlock()
	_ = o.listener.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

func mcpStdioSubprocessError(c Case, waitErr error, stderrOutput string) error {
	if stderrOutput != "" {
		return fmt.Errorf("case %s: MCP subprocess failed: %w (stderr: %s)", c.ID, waitErr, stderrOutput)
	}
	return fmt.Errorf("case %s: MCP subprocess failed: %w", c.ID, waitErr)
}

func mcpStdioRequestFingerprint(message interface{}) (string, error) {
	request, ok := message.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("runner-owned MCP upstream expected object request, got %T", message)
	}
	method, ok := request["method"].(string)
	if !ok || method == "" {
		return "", errors.New("runner-owned MCP upstream expected JSON-RPC method")
	}
	fingerprint := map[string]interface{}{
		"jsonrpc": request["jsonrpc"],
		"id":      request["id"],
		"method":  method,
	}
	if params, ok := request["params"]; ok {
		fingerprint["params"] = params
	}
	encoded, err := json.Marshal(fingerprint)
	if err != nil {
		return "", fmt.Errorf("encode runner-owned MCP upstream fingerprint: %w", err)
	}
	return string(encoded), nil
}

func mcpStdioSuccessResponse(request interface{}) map[string]interface{} {
	id := interface{}(nil)
	if message, ok := request.(map[string]interface{}); ok {
		id = message["id"]
	}
	return map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  map[string]interface{}{"content": []interface{}{}},
	}
}

// correlateMCPStdioSessionMessages assigns a fresh JSON-RPC ID to every
// request that expects a response. The corpus uses stable example IDs, which
// are part of its fixture data but cannot prove a subprocess read this run's
// input. Response fixtures are paired with client requests by position in
// startMCPStdioUpstreamObserver, so update the paired response ID as well.
func correlateMCPStdioSessionMessages(clientMsgs, serverResponses []interface{}) ([]interface{}, []interface{}, error) {
	correlatedClients := make([]interface{}, len(clientMsgs))
	copy(correlatedClients, clientMsgs)
	correlatedResponses := make([]interface{}, len(serverResponses))
	copy(correlatedResponses, serverResponses)

	for i, rawClient := range clientMsgs {
		client, ok := rawClient.(map[string]interface{})
		if !ok {
			continue
		}
		originalID, hasID := client["id"]
		if !hasID || originalID == nil {
			// JSON-RPC notifications carry no response ID and cannot establish a
			// policy-denial verdict through this branch.
			continue
		}
		identity, err := freshMCPStdioRequestIdentity()
		if err != nil {
			return nil, nil, err
		}
		correlatedClient := make(map[string]interface{}, len(client))
		for key, value := range client {
			correlatedClient[key] = value
		}
		correlatedClient["id"] = identity
		correlatedClients[i] = correlatedClient

		if i >= len(serverResponses) {
			continue
		}
		response, ok := serverResponses[i].(map[string]interface{})
		if !ok {
			continue
		}
		correlatedResponse := make(map[string]interface{}, len(response))
		for key, value := range response {
			correlatedResponse[key] = value
		}
		correlatedResponse["id"] = identity
		correlatedResponses[i] = correlatedResponse
	}

	return correlatedClients, correlatedResponses, nil
}

func freshMCPStdioRequestIdentity() (string, error) {
	return nextGatewayRequestIdentity()
}

func mcpStdioObservationEvidence(observer *mcpStdioUpstreamObserver) (map[string]interface{}, bool) {
	if observer == nil {
		return nil, false
	}
	matched, expected, received := observer.counts()
	evidence := map[string]interface{}{
		"upstream_requests_expected": expected,
		"upstream_requests_observed": matched,
	}
	if received != matched {
		evidence["upstream_requests_unmatched"] = received - matched
	}
	return evidence, matched == expected
}

func mcpStdioObservationMissingResult(observer *mcpStdioUpstreamObserver, evidence map[string]interface{}) Result {
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	observation, _ := mcpStdioObservationEvidence(observer)
	for key, value := range observation {
		evidence[key] = value
	}
	evidence["upstream_reached"] = false
	evidence["reason"] = "mcp_stdio_upstream_observation_missing"
	return Result{Verdict: "skip", Evidence: evidence}
}

// mcpStdioResponseRelayMissingResult keeps positive request-arrival proof
// intact when the proxy did reach the runner-owned upstream but omitted the
// response that the case requires it to relay.
func mcpStdioResponseRelayMissingResult(observer *mcpStdioUpstreamObserver, evidence map[string]interface{}) Result {
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	observation, upstreamObserved := mcpStdioObservationEvidence(observer)
	for key, value := range observation {
		evidence[key] = value
	}
	evidence["upstream_reached"] = upstreamObserved
	evidence["reason"] = "mcp_stdio_response_relay_missing"
	return Result{Verdict: "skip", Evidence: evidence}
}

// mcpStdioUpstreamCommandEnv removes an ambient observation endpoint before
// adding the runner-owned one. An empty addr deliberately means no endpoint:
// commands must never inherit a stale endpoint that this run does not own.
func mcpStdioUpstreamCommandEnv(addr string) []string {
	prefix := mcpStdioUpstreamAddrEnv + "="
	env := make([]string, 0, len(os.Environ())+1)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		env = append(env, entry)
	}
	if addr != "" {
		env = append(env, prefix+addr)
	}
	return env
}

// runMCPStdio sends JSON-RPC messages through the MCP proxy subprocess.
//
// The proxy sits between client (stdin) and server (subprocess backend).
// Case payloads contain jsonrpc_messages which may be:
//   - Client→server requests (tools/call): written to stdin, proxy scans them
//   - Server→client responses (tools/list result): need the mock to return them
//
// For tool poisoning cases (messages with "result" field), the adapter starts
// a runner-owned upstream listener that returns the poisoned payload only
// after observing the corresponding client request. The evaluated command opts
// into that neutral endpoint contract; the runner never rewrites its command.
func (p *ProxyAdapter) runMCPStdio(c Case, timeout time.Duration) (returned Result) {
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
	if isBudgetEnforcementCase(c) {
		return p.runMCPStdioBudgetSequence(c, msgList, timeout)
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

	// Every MCP stdio case gets an upstream endpoint under runner control. The
	// command string is deliberately left untouched: an integration opts in by
	// configuring its own proxy to use AEB_MCP_STDIO_UPSTREAM_ADDR. Blocks do
	// not need an observation, but every non-blocking result needs this endpoint
	// to prove that it really reached an upstream.
	var observer *mcpStdioUpstreamObserver
	// If no client messages, send a tools/list request to trigger the response.
	if len(clientMsgs) == 0 {
		clientMsgs = append(clientMsgs, map[string]interface{}{
			"jsonrpc": "2.0",
			"method":  "tools/list",
			"id":      1,
		})
	}
	// Corpus JSON-RPC IDs are stable fixture data, often small integers such as
	// 1. They cannot correlate a policy denial: a subprocess can print a stale
	// deny with that ID before it reads this run's stdin. The stdio adapter owns
	// this session-level correlation field, so replace request IDs with fresh
	// unpredictable values and keep paired fixture responses in the same
	// session. The attack payload, transport, method, and lifecycle stay intact.
	correlatedClientMsgs, correlatedServerResponses, correlationErr := correlateMCPStdioSessionMessages(clientMsgs, serverResponses)
	if correlationErr != nil {
		return Result{Err: fmt.Errorf("case %s: assign MCP stdio request identities: %w", c.ID, correlationErr)}
	}
	clientMsgs = correlatedClientMsgs
	serverResponses = correlatedServerResponses
	// A structured policy error is evidence only when it answers one of the
	// requests we wrote for this case. Without this correlation, a subprocess
	// can emit a stale deny before reading stdin and manufacture containment.
	expectedResponseIDs := make(map[string]struct{}, len(clientMsgs))
	for _, msg := range clientMsgs {
		if key := messageIDCorrelationKey(msg); key != "" {
			expectedResponseIDs[key] = struct{}{}
		}
	}
	var observeErr error
	observer, observeErr = startMCPStdioUpstreamObserver(clientMsgs, serverResponses)
	if observeErr != nil {
		return Result{Err: fmt.Errorf("case %s: start runner-owned MCP stdio upstream: %w", c.ID, observeErr)}
	}
	defer observer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", p.mcpCmd) //nolint:gosec // command from trusted CLI flag
	configureMCPCommand(cmd)
	upstreamAddr := ""
	if observer != nil {
		upstreamAddr = observer.addr()
	}
	cmd.Env = mcpStdioUpstreamCommandEnv(upstreamAddr)
	// Capture stderr so integration failures have an actionable diagnostic.
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
	stderrOutput := strings.TrimSpace(stderrBuf.String())
	// A subprocess failure invalidates the integration regardless of any output
	// it managed to print before exiting. Do not parse or score that output.
	if waitErr != nil && ctx.Err() == nil {
		return Result{Err: mcpStdioSubprocessError(c, waitErr, stderrOutput)}
	}
	output := <-outputCh
	defer func() {
		if len(output) > 0 {
			returned.ReturnedContent = append(returned.ReturnedContent, returnedContent(output, "application/json", "mcp_stdio_result"))
		}
	}()
	if observer != nil {
		observer.Drain(mcpStdioObserverDrainTimeout)
	}
	observationEvidence, upstreamObserved := mcpStdioObservationEvidence(observer)

	// Context timeout is handled as its normal unprovable outcome rather than an
	// adapter error. A bare clean exit without a structured deny is likewise
	// unprovable: it can be a no-op, misconfiguration, or discarded stdin.
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		// A block requires a structured, verifiable MCP policy deny. Silence is
		// not a deny protocol, so it must never award a block score.
		evidence := map[string]interface{}{"reason": "no_output"}
		if stderrOutput != "" {
			evidence["stderr"] = stderrOutput
		}
		for key, value := range observationEvidence {
			evidence[key] = value
		}
		if observer != nil {
			evidence["upstream_reached"] = upstreamObserved
		}
		if len(serverResponses) == 0 && upstreamObserved {
			// Client-only cases need no response payload to verify. The
			// runner-owned upstream observation is positive proof that the
			// request was forwarded even when a pipelining proxy exits before
			// reading its response.
			return Result{Verdict: "allow", Evidence: evidence}
		}
		if len(serverResponses) > 0 && upstreamObserved {
			return mcpStdioResponseRelayMissingResult(observer, evidence)
		}
		return mcpStdioObservationMissingResult(observer, evidence)
	}

	// JSON-RPC permits notifications alongside responses, but a request has at
	// most one response. A second result or error for a request we issued means
	// the proxy delivered content whose semantics we cannot represent with one
	// case response. Do not let a first policy error or matching result hide it.
	if duplicate := mcpStdioDuplicateRequestResponse(lines, expectedResponseIDs); duplicate != nil {
		for key, value := range observationEvidence {
			duplicate.Evidence[key] = value
		}
		if observer != nil {
			duplicate.Evidence["upstream_reached"] = upstreamObserved
		}
		return *duplicate
	}

	// Check response lines for policy-block JSON-RPC errors.
	// Tool-specific policy errors use the JSON-RPC server-error range.
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
				evidence := map[string]interface{}{
					"error_code":    code,
					"error_message": rpcResp.Error.Message,
				}
				responseIDKey := jsonRPCResponseIDCorrelationKey(respLine)
				if _, matchesRequest := expectedResponseIDs[responseIDKey]; !matchesRequest {
					evidence["reason"] = "mcp_stdio_policy_response_id_mismatch"
					return Result{Verdict: "skip", Evidence: evidence}
				}
				for key, value := range observationEvidence {
					evidence[key] = value
				}
				if observer != nil {
					evidence["upstream_reached"] = upstreamObserved
				}
				return Result{
					Verdict:  "block",
					Evidence: evidence,
				}
			}
			if code <= -32600 {
				// Standard JSON-RPC protocol error, not a policy decision.
				return Result{Err: fmt.Errorf("case %s: JSON-RPC protocol error %d: %s", c.ID, code, rpcResp.Error.Message)}
			}
		}
	}

	// At this point there are no policy blocks or protocol errors. An allow must
	// be backed by positive proof that every request reached the runner-owned
	// upstream listener, not a proxy-local JSON-RPC success.
	if len(serverResponses) == 0 {
		if observer == nil || !upstreamObserved {
			return mcpStdioObservationMissingResult(observer, nil)
		}
		return Result{Verdict: "allow", Evidence: map[string]interface{}{
			"upstream_reached":           true,
			"upstream_requests_expected": observationEvidence["upstream_requests_expected"],
			"upstream_requests_observed": observationEvidence["upstream_requests_observed"],
		}}
	}
	verified := verifyMCPStdioResponses(c.ID, lines, serverResponses)
	if verified.Verdict != "allow" {
		return verified
	}
	if observer == nil || !upstreamObserved {
		return mcpStdioObservationMissingResult(observer, verified.Evidence)
	}
	for key, value := range observationEvidence {
		verified.Evidence[key] = value
	}
	verified.Evidence["upstream_reached"] = true
	return verified
}

func isBudgetEnforcementCase(c Case) bool {
	if _, ok := c.Payload["budget_limit_calls"]; ok {
		return true
	}
	for _, req := range c.Requires {
		if req == "budget_enforcement" {
			return true
		}
	}
	return false
}

func (p *ProxyAdapter) runMCPStdioBudgetSequence(c Case, msgList []interface{}, timeout time.Duration) Result {
	limit, ok := positivePayloadInt(c.Payload["budget_limit_calls"])
	if !ok {
		return Result{Err: fmt.Errorf("case %s: budget_enforcement payload missing positive integer budget_limit_calls", c.ID)}
	}
	scope, _ := c.Payload["budget_scope"].(string)
	subjectID, _ := c.Payload["subject_id"].(string)

	overBudgetID, hasOverBudgetID := positivePayloadInt(c.Payload["over_budget_call_id"])
	overBudgetIndex := -1
	if c.ExpectedVerdict == "block" {
		if !hasOverBudgetID {
			return Result{Err: fmt.Errorf("case %s: block budget case missing positive integer over_budget_call_id", c.ID)}
		}
		for i, msg := range msgList {
			if messageIDString(msg) == fmt.Sprint(overBudgetID) {
				overBudgetIndex = i + 1
				break
			}
		}
		if overBudgetIndex == -1 {
			return Result{Err: fmt.Errorf("case %s: over_budget_call_id %d does not match any JSON-RPC message id", c.ID, overBudgetID)}
		}
	}

	for _, msg := range msgList {
		m, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasResult := m["result"]; hasResult {
			return Result{Err: fmt.Errorf("case %s: budget_enforcement sequences must contain client tool-call requests only", c.ID)}
		}
		if _, hasError := m["error"]; hasError {
			return Result{Err: fmt.Errorf("case %s: budget_enforcement sequences must contain client tool-call requests only", c.ID)}
		}
	}

	// A non-blocking budget sequence is meaningful only if the runner observes
	// every individual tool call at the upstream it owns. The command itself is
	// not rewritten: integrations opt in by routing their upstream to the
	// neutral AEB_MCP_STDIO_UPSTREAM_ADDR endpoint. A command that ignores it is
	// unscorable (skip), not a command-line error or a false allow.
	var observer *mcpStdioUpstreamObserver
	var observeErr error
	observer, observeErr = startMCPStdioUpstreamObserver(msgList, nil)
	if observeErr != nil {
		return Result{Err: fmt.Errorf("case %s: start runner-owned MCP stdio upstream: %w", c.ID, observeErr)}
	}
	defer observer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-c", p.mcpCmd) //nolint:gosec // command from trusted CLI flag
	configureMCPCommand(cmd)
	upstreamAddr := ""
	if observer != nil {
		upstreamAddr = observer.addr()
	}
	cmd.Env = mcpStdioUpstreamCommandEnv(upstreamAddr)
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

	scanner := bufio.NewScanner(stdout)
	for i, msg := range msgList {
		line, _ := json.Marshal(msg)
		if _, writeErr := stdin.Write(append(line, '\n')); writeErr != nil {
			_ = stdin.Close()
			waitErr := cmd.Wait()
			if waitErr != nil && ctx.Err() == nil {
				stderrOutput := strings.TrimSpace(stderrBuf.String())
				return Result{Err: mcpStdioSubprocessError(c, waitErr, stderrOutput)}
			}
			observer.Drain(mcpStdioObserverDrainTimeout)
			return mcpStdioObservationMissingResult(observer, map[string]interface{}{
				"budget_limit_calls": limit,
				"budget_scope":       scope,
				"subject_id":         subjectID,
				"calls_observed":     i,
				"reason":             "write_failed",
			})
		}

		if !scanner.Scan() {
			_ = stdin.Close()
			waitErr := cmd.Wait()
			if scanErr := scanner.Err(); scanErr != nil {
				return Result{Err: fmt.Errorf("case %s: reading MCP output for call %d: %w", c.ID, i+1, scanErr)}
			}
			if waitErr != nil && ctx.Err() == nil {
				stderrOutput := strings.TrimSpace(stderrBuf.String())
				return Result{Err: mcpStdioSubprocessError(c, waitErr, stderrOutput)}
			}
			observer.Drain(mcpStdioObserverDrainTimeout)
			return mcpStdioObservationMissingResult(observer, map[string]interface{}{
				"budget_limit_calls": limit,
				"budget_scope":       scope,
				"subject_id":         subjectID,
				"calls_observed":     i,
				"reason":             "no_output",
			})
		}

		respLine := scanner.Text()
		if result, handled, responseID := classifyMCPBudgetErrorLine(respLine, c.ID); handled {
			if result.Err != nil {
				_ = stdin.Close()
				_ = cmd.Wait()
				return result
			}
			_ = stdin.Close()
			waitErr := cmd.Wait()
			if waitErr != nil && ctx.Err() == nil {
				return Result{Err: mcpStdioSubprocessError(c, waitErr, strings.TrimSpace(stderrBuf.String()))}
			}
			expectedResponseID := messageIDString(msg)
			expectedResponseIDKey := messageIDCorrelationKey(msg)
			responseIDKey := jsonRPCResponseIDCorrelationKey(respLine)
			if responseID == "" || responseIDKey == "" || responseIDKey != expectedResponseIDKey {
				result.Evidence["expected_response_id"] = expectedResponseID
				result.Evidence["response_id"] = responseID
				result.Evidence["reason"] = "mcp_stdio_response_id_mismatch"
				return Result{Verdict: "skip", Evidence: result.Evidence}
			}
			blockedID := responseID
			blockedIndex := i + 1
			// A structured block before the configured budget is exhausted is
			// directly observable over-enforcement. It is a benchmark miss even
			// though the runner cannot prove which earlier calls reached upstream;
			// requiring that proof here would turn a real false positive into skip.
			if blockedIndex < overBudgetIndex {
				return budgetBlockResult(c, limit, scope, subjectID, overBudgetID, overBudgetIndex, blockedIndex, blockedID, result.Evidence)
			}
			// A structured block alone does not prove budget enforcement: the
			// proxy could fabricate all earlier successes locally. Drain the
			// runner-owned observer before scoring and require its ordered prefix
			// to equal the complete ordered prefix before this response. This is
			// intentionally based on global message position, not the per-subject
			// limit: interleaved subjects must not create an unobserved gap. The
			// blocked call and later calls must not reach upstream.
			if observer != nil {
				observer.Drain(mcpStdioObserverDrainTimeout)
				observationEvidence, _ := mcpStdioObservationEvidence(observer)
				for key, value := range observationEvidence {
					result.Evidence[key] = value
				}
				matched, _, received := observer.counts()
				result.Evidence["upstream_requests_observed_before_block"] = matched
				if matched != blockedIndex-1 || received != matched {
					return mcpStdioObservationMissingResult(observer, result.Evidence)
				}
			} else {
				result.Evidence["upstream_requests_observed_before_block"] = 0
				return mcpStdioObservationMissingResult(nil, result.Evidence)
			}
			return budgetBlockResult(c, limit, scope, subjectID, overBudgetID, overBudgetIndex, blockedIndex, blockedID, result.Evidence)
		}
	}

	_ = stdin.Close()
	waitErr := cmd.Wait()
	if waitErr != nil && ctx.Err() == nil {
		return Result{Err: mcpStdioSubprocessError(c, waitErr, strings.TrimSpace(stderrBuf.String()))}
	}
	if observer != nil {
		observer.Drain(mcpStdioObserverDrainTimeout)
	}

	evidence := map[string]interface{}{
		"budget_limit_calls": limit,
		"budget_scope":       scope,
		"subject_id":         subjectID,
		"calls_observed":     len(msgList),
	}
	if observer != nil {
		observationEvidence, upstreamObserved := mcpStdioObservationEvidence(observer)
		if !upstreamObserved {
			return mcpStdioObservationMissingResult(observer, evidence)
		}
		for key, value := range observationEvidence {
			evidence[key] = value
		}
		evidence["upstream_reached"] = true
	}
	return Result{
		Verdict:  "allow",
		Evidence: evidence,
	}
}

func budgetBlockResult(c Case, limit int, scope, subjectID string, overBudgetID, overBudgetIndex, blockedIndex int, blockedID string, evidence map[string]interface{}) Result {
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	evidence["budget_limit_calls"] = limit
	evidence["budget_scope"] = scope
	evidence["subject_id"] = subjectID
	evidence["blocked_call_index"] = blockedIndex
	if blockedIndex <= limit {
		evidence["over_blocked_index"] = blockedIndex
		evidence["budget_block_timing"] = "before_over_budget"
		// The tool issued a structured denial, but it denied a call the case
		// requires it to allow. Represent that as an expected-block miss so
		// both per-case and aggregate containment scoring lose the point.
		return Result{Verdict: "allow", Evidence: evidence}
	}
	if blockedID != "" {
		evidence["blocked_call_id"] = blockedID
	}
	if overBudgetID > 0 {
		evidence["over_budget_call_id"] = overBudgetID
		if overBudgetIndex > 0 {
			evidence["over_budget_call_index"] = overBudgetIndex
			switch {
			case blockedIndex < overBudgetIndex:
				evidence["budget_block_timing"] = "before_over_budget"
				return Result{Verdict: "allow", Evidence: evidence}
			case blockedIndex == overBudgetIndex:
				evidence["budget_block_timing"] = "at_over_budget"
			default:
				evidence["budget_block_timing"] = "after_over_budget"
				// The first forbidden call was already allowed to reach the
				// runner-owned upstream. A later denial is a containment miss,
				// even though it proves the tool eventually enforced a limit.
				return Result{Verdict: "allow", Evidence: evidence}
			}
		}
	}
	return Result{Verdict: "block", Evidence: evidence}
}

func positivePayloadInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n > 0
	case int64:
		return int(n), n > 0
	case float64:
		i := int(n)
		return i, n > 0 && float64(i) == n
	case json.Number:
		i, err := n.Int64()
		return int(i), err == nil && i > 0
	default:
		return 0, false
	}
}

func messageIDString(msg interface{}) string {
	m, ok := msg.(map[string]interface{})
	if !ok {
		return ""
	}
	return jsonRPCIDString(m["id"])
}

func messageIDCorrelationKey(msg interface{}) string {
	m, ok := msg.(map[string]interface{})
	if !ok {
		return ""
	}
	return jsonRPCIDCorrelationKey(m["id"])
}

func jsonRPCResponseIDCorrelationKey(line string) string {
	var response struct {
		ID interface{} `json:"id"`
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		return ""
	}
	return jsonRPCIDCorrelationKey(response.ID)
}

func jsonRPCIDCorrelationKey(id interface{}) string {
	if value, ok := id.(string); ok {
		return "string:" + value
	}
	if value := jsonRPCIDString(id); value != "" {
		return "number:" + value
	}
	return ""
}

func jsonRPCIDString(id interface{}) string {
	switch v := id.(type) {
	case string:
		return v
	case float64:
		i := int(v)
		if float64(i) == v {
			return fmt.Sprint(i)
		}
		return fmt.Sprint(v)
	case int:
		return fmt.Sprint(v)
	case int64:
		return fmt.Sprint(v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func (p *ProxyAdapter) runMCPHTTP(c Case, timeout time.Duration) (mcpResult Result) {
	if p.mcpHTTPURL == "" {
		return Result{
			Verdict:  "skip",
			Evidence: map[string]interface{}{"reason": "no MCP HTTP listener configured"},
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
	if c.InputType == "mcp_tool_sequence_temporal" {
		return p.runMCPHTTPTemporalInventory(c, timeout)
	}
	if c.InputType == "mcp_tool_definition" || c.InputType == "mcp_tool_result" {
		return p.runMCPHTTPResponseCase(c, timeout)
	}

	client := &http.Client{Timeout: timeout}
	// Establish the session before the case's own messages so a target that
	// requires an issued token evaluates them, rather than refusing every one
	// for want of a session and turning that refusal into a scored block.
	sessionToken, setupTruncated, err := p.establishMCPHTTPListenerSession(context.Background(), client)
	// Every return below must carry this, so merge on the way out rather than at
	// each exit: a single missed path drops the evidence silently.
	defer func() {
		mcpResult.Evidence = noteObservedTruncation(mcpResult.Evidence, setupTruncated, observationBodyCap)
	}()
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: establish MCP HTTP listener session: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	var responses int
	upstreamBefore, _ := p.mcpHTTPUpstreamCallCount()
	for _, rawMessage := range msgList {
		msg, requestID, err := correlateMCPHTTPRequest(rawMessage)
		if errors.Is(err, errUnsupportedMCPMessage) {
			return unsupportedTransport(c, "MCP HTTP scoring supports one JSON-RPC object per message, not a batch")
		}
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: correlate MCP HTTP request: %w", c.ID, err)}
		}
		line, _ := json.Marshal(msg)
		req, err := http.NewRequest(http.MethodPost, p.mcpHTTPURL, bytes.NewReader(line))
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: building MCP HTTP request: %w", c.ID, err)}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		p.setListenerSessionToken(req, sessionToken)
		resp, err := client.Do(req)
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: MCP HTTP request: %w", c.ID, err)}
		}
		body, err := readCappedResponse(resp.Body, decisionBodyCap)
		_ = resp.Body.Close()
		if err != nil {
			return Result{
				Err:      fmt.Errorf("case %s: read MCP HTTP response: %w", c.ID, err),
				Evidence: cappedResponseEvidence(err),
			}
		}
		// Test the declared refusal FIRST, before anything looks at the body.
		// Gating this on the body classifying as a block leaves the hole the
		// declaration exists to close: a target that sets its refusal header
		// but answers with a body this runner does not recognize falls through
		// to status-only classification, and a 403 there becomes a scored block
		// the target never made about the case.
		if p.session.declaredRefusal(resp.Header) {
			return listenerSessionUnprovenResult()
		}
		// A notification has no id, so nothing ties a response body back to
		// it. A deny-shaped body here could be a stale or generic listener
		// response to something else entirely, and crediting containment on
		// that would let an unrelated refusal score. Report it unproven
		// instead and let the loop's upstream accounting decide delivery.
		if requestID == "" {
			if resp.StatusCode >= 400 || classifyMCPHTTPBlock(body) != nil {
				return Result{Verdict: "skip", Evidence: map[string]interface{}{
					"product_surface":  "mcp_http_listener",
					"reason":           "mcp_http_notification_uncorrelated",
					"status_code":      resp.StatusCode,
					"upstream_reached": false,
				}}
			}
			continue
		}
		// An HTTP-level denial carrying a positive deny marker is scored
		// before correlation is required. HTTP already binds a response to
		// the request that produced it, so a 4xx on this exchange is this
		// case's answer whether or not it wraps a JSON-RPC envelope. Demanding
		// an echoed id here made every gateway that enforces at the HTTP layer
		// unscorable, which is the failure direction that gets a benchmark
		// dismissed rather than the one that inflates a score.
		//
		// Fresh-id correlation still governs 2xx JSON-RPC bodies below, which
		// is where a canned response echoing a well-known corpus id would
		// otherwise earn credit.
		if resp.StatusCode >= 400 && hasDenyMarker(string(body)) {
			if verdict := classifyMCPHTTPBlock(body); verdict != nil {
				verdict.Evidence["request_identity"] = requestID
				verdict.Evidence["correlation"] = "http_status"
				return *verdict
			}
			result := classifyResponse(resp.StatusCode, string(body))
			result.Evidence["request_identity"] = requestID
			result.Evidence["correlation"] = "http_status"
			return result
		}
		decoded, decodeErr := decodeGatewayResponse(resp.Header.Get("Content-Type"), body, requestID)
		if decodeErr != nil {
			return Result{Verdict: "skip", Evidence: map[string]interface{}{
				"product_surface":  "mcp_http_listener",
				"reason":           "mcp_http_response_uncorrelated",
				"request_identity": requestID,
				"status_code":      resp.StatusCode,
				"upstream_reached": false,
			}}
		}
		if resp.StatusCode >= 400 {
			if verdict := classifyMCPHTTPBlock(decoded); verdict != nil {
				verdict.Evidence["request_identity"] = requestID
				return *verdict
			}
			result := classifyResponse(resp.StatusCode, string(decoded))
			result.Evidence["request_identity"] = requestID
			return result
		}
		responses++
		if verdict := classifyMCPHTTPBlock(decoded); verdict != nil {
			verdict.Evidence["request_identity"] = requestID
			return *verdict
		}
	}
	upstreamAfter, proofAvailable := p.mcpHTTPUpstreamCallCount()
	evidence := map[string]interface{}{
		"product_surface": "mcp_http_listener",
		"response_count":  responses,
	}
	if proofAvailable {
		evidence["upstream_calls_before"] = upstreamBefore
		evidence["upstream_calls_after"] = upstreamAfter
	}
	if !proofAvailable || upstreamAfter-upstreamBefore < int64(len(msgList)) {
		evidence["upstream_reached"] = false
		if !proofAvailable {
			evidence["upstream_proof"] = "unavailable"
		}
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["upstream_reached"] = true
	return Result{
		Verdict:  "allow",
		Evidence: evidence,
	}
}

// correlateMCPHTTPRequest gives every request a fresh JSON-RPC ID before it
// crosses the target boundary. Corpus IDs are stable fixture data, so accepting
// a denial merely because it repeats one of them lets a stale response earn
// containment credit. JSON-RPC permits string IDs; only the correlation field
// changes, never the corpus method or payload.
// errUnsupportedMCPMessage marks a message shape this runner cannot score, as
// distinct from a failure. The caller turns it into an unscorable result
// rather than aborting the run.
var errUnsupportedMCPMessage = errors.New("unsupported MCP message shape")

// A notification carries no id by definition and receives no response, so it
// has nothing to correlate. It is sent exactly as the corpus declares it and
// returns an empty identity, which callers read as "expect no reply".
func correlateMCPHTTPRequest(rawMessage interface{}) (map[string]interface{}, string, error) {
	message, ok := rawMessage.(map[string]interface{})
	if !ok {
		// A batch is a JSON-RPC array. Correlating one means matching a
		// response array element-wise, which nothing in the corpus needs yet.
		// This is reported as unsupported so the case scores unscorable; a
		// runner error would abort the whole run over one case shape.
		return nil, "", errUnsupportedMCPMessage
	}
	if _, hasID := message["id"]; !hasID {
		return shallowCloneMap(message), "", nil
	}
	requestID, err := nextGatewayRequestIdentity()
	if err != nil {
		return nil, "", err
	}
	correlated := shallowCloneMap(message)
	correlated["id"] = requestID
	return correlated, requestID, nil
}

// runMCPHTTPTemporalInventory replays a before/after tools/list sequence in
// its real wire direction. The corpus responses are leased to the runner-owned
// upstream and only their matching tools/list requests are sent through the
// product. Posting the response snapshots as client requests would exercise
// invalid JSON-RPC handling instead of temporal inventory scanning.
func (p *ProxyAdapter) runMCPHTTPTemporalInventory(c Case, timeout time.Duration) Result {
	steps, err := temporalInventorySteps(c)
	if err != nil {
		return Result{Verdict: "skip", Evidence: map[string]interface{}{
			"reason": "MCP HTTP temporal inventory requires one before/after tools/list pair: " + err.Error(),
		}}
	}
	if p.mcpHTTPFixture == nil {
		return Result{Verdict: "skip", Evidence: map[string]interface{}{
			"reason": "no MCP HTTP upstream fixture configured for temporal inventory",
		}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	client := newMCPHTTPClient(timeout)
	evidence := map[string]interface{}{
		"product_surface":                       "mcp_http_listener",
		"session_bound":                         false,
		"upstream_reached":                      false,
		"original_inventory_delivered_to_agent": false,
		"changed_inventory_delivered_to_agent":  false,
	}
	initializeMessage, initializeRequest, err := prepareGatewayRequest(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "agent-egress-bench",
				"version": "1",
			},
		},
	})
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare MCP initialize request: %w", c.ID, err)}
	}
	initialize, err := p.sendMCPHTTPGatewayRequest(ctx, client, initializeMessage, "", "")
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: send MCP initialize request: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	if !proxyMCPHTTPDelivered(p.mcpHTTPFixture, initializeRequest) {
		evidence["reason"] = "temporal_initialize_upstream_unproven"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	initializeBody, decodeErr := decodeGatewayResponse(initialize.contentType, initialize.body, initializeRequest.identity)
	if decodeErr != nil || initialize.status < http.StatusOK || initialize.status >= http.StatusMultipleChoices || classifyMCPHTTPBlock(initializeBody) != nil || !validMCPInitializeResponse(initializeBody) {
		evidence["reason"] = "temporal_initialize_not_established"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	sessionID := initialize.sessionID
	if sessionID == "" {
		evidence["reason"] = "temporal_session_unbound"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["session_bound"] = true
	// This initialize is itself the setup frame, so any issued token arrives on
	// its response and is replayed on every later request in this session.
	// Opening a second session to obtain one would abandon this one.
	sessionToken := initialize.sessionToken

	initialized, err := p.sendMCPHTTPGatewayRequest(ctx, client, map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]interface{}{},
	}, sessionID, sessionToken)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: send MCP initialized notification: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	if initialized.status < http.StatusOK || initialized.status >= http.StatusMultipleChoices {
		evidence["reason"] = "temporal_initialized_notification_failed"
		return Result{Verdict: "skip", Evidence: evidence}
	}

	baselineMessage, baselineRequest, err := prepareGatewayRequest(steps[0].request)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare baseline tools/list request: %w", c.ID, err)}
	}
	baselineRelease, err := p.mcpHTTPFixture.AcquireSessionToolDefinitionLease(ctx, baselineRequest.identity, sessionID, steps[0].tools)
	if err != nil {
		evidence["reason"] = "baseline_inventory_lease_timeout"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	baseline, err := p.sendMCPHTTPGatewayRequest(ctx, client, baselineMessage, sessionID, sessionToken)
	baselineRelease()
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: send baseline tools/list request: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	baselineDelivered := proxyMCPHTTPDelivered(p.mcpHTTPFixture, baselineRequest)
	evidence["original_inventory_reached_upstream"] = baselineDelivered
	evidence["inventory_request_identities"] = []string{baselineRequest.identity}
	if !baselineDelivered {
		evidence["reason"] = "baseline_inventory_upstream_unproven"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	baselineBody, err := decodeGatewayResponse(baseline.contentType, baseline.body, baselineRequest.identity)
	if err != nil || baseline.status < http.StatusOK || baseline.status >= http.StatusMultipleChoices {
		evidence["reason"] = "baseline_inventory_not_established"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	baselineCanonical, baselineValid := toolsListCanonical(baselineBody)
	if !baselineValid || !bytes.Equal(baselineCanonical, steps[0].canonical) {
		evidence["reason"] = "baseline_inventory_not_established"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["original_inventory_delivered_to_agent"] = true

	changedMessage, changedRequest, err := prepareGatewayRequest(steps[1].request)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare changed tools/list request: %w", c.ID, err)}
	}
	changedRelease, err := p.mcpHTTPFixture.AcquireSessionToolDefinitionLease(ctx, changedRequest.identity, sessionID, steps[1].tools)
	if err != nil {
		evidence["reason"] = "changed_inventory_lease_timeout"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	changed, err := p.sendMCPHTTPGatewayRequest(ctx, client, changedMessage, sessionID, sessionToken)
	changedRelease()
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: send changed tools/list request: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	changedDelivered := proxyMCPHTTPDelivered(p.mcpHTTPFixture, changedRequest)
	evidence["changed_inventory_reached_upstream"] = changedDelivered
	evidence["inventory_request_identities"] = []string{baselineRequest.identity, changedRequest.identity}
	if !changedDelivered {
		evidence["reason"] = "changed_inventory_upstream_unproven"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	evidence["upstream_reached"] = true

	if changed.status < http.StatusOK || changed.status >= http.StatusMultipleChoices {
		if verdict := classifyMCPHTTPBlock(changed.body); verdict != nil {
			for key, value := range evidence {
				verdict.Evidence[key] = value
			}
			return *verdict
		}
		result := classifyResponse(changed.status, string(changed.body))
		for key, value := range evidence {
			result.Evidence[key] = value
		}
		if result.Verdict == "block" {
			return observedProxyVerdict(result)
		}
		return result
	}
	changedBody, err := decodeGatewayResponse(changed.contentType, changed.body, changedRequest.identity)
	if err != nil {
		evidence["reason"] = "malformed_or_uncorrelated_changed_inventory"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	if verdict := classifyMCPHTTPBlock(changedBody); verdict != nil {
		for key, value := range evidence {
			verdict.Evidence[key] = value
		}
		return *verdict
	}
	changedCanonical, changedValid := toolsListCanonical(changedBody)
	if !changedValid {
		evidence["reason"] = "malformed_changed_inventory"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	if !bytes.Equal(changedCanonical, steps[1].canonical) {
		evidence["reason"] = "changed_inventory_withheld_or_modified"
		return observedProxyVerdict(Result{Verdict: "block", Evidence: evidence})
	}
	evidence["changed_inventory_delivered_to_agent"] = true
	return Result{Verdict: "allow", Evidence: evidence}
}

// mcpHTTPGatewayResponse carries one listener response. The listener-issued
// session token is returned alongside the MCP session id because the two are
// distinct: the id is upstream routing data the client supplies, the token is
// the target's own proof that this client owns its state partition.
type mcpHTTPGatewayResponse struct {
	body         []byte
	contentType  string
	status       int
	sessionID    string
	sessionToken string
}

func (p *ProxyAdapter) sendMCPHTTPGatewayRequest(ctx context.Context, client *http.Client, message map[string]interface{}, sessionID, sessionToken string) (mcpHTTPGatewayResponse, error) {
	body, err := json.Marshal(message)
	if err != nil {
		return mcpHTTPGatewayResponse{}, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.mcpHTTPURL, bytes.NewReader(body))
	if err != nil {
		return mcpHTTPGatewayResponse{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	p.setListenerSessionToken(req, sessionToken)
	resp, err := client.Do(req)
	if err != nil {
		return mcpHTTPGatewayResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := readCappedResponse(resp.Body, decisionBodyCap)
	if err != nil {
		return mcpHTTPGatewayResponse{}, fmt.Errorf("read response: %w", err)
	}
	return mcpHTTPGatewayResponse{
		body:         responseBody,
		contentType:  resp.Header.Get("Content-Type"),
		status:       resp.StatusCode,
		sessionID:    resp.Header.Get("Mcp-Session-Id"),
		sessionToken: p.declaredSessionToken(resp.Header),
	}, nil
}

// A target that partitions retained per-client state by an authenticated
// principal cannot safely key that partition on client-supplied routing data,
// so it issues its own token during setup and requires it on later stateful
// requests. The runner replays whatever token the target issued; it never
// mints, guesses, or reuses one across cases.
//
// The header and token format are DECLARED per target, never compiled in. A
// benchmark is only worth its score if the path every target runs through is
// the same path, so shared runner code must not carry one vendor's mechanism.
// An undeclared session means no token is read or replayed and no refusal is
// recognized. No vendor header name, refusal value, or error wording appears
// below: every one of those is declared per target and lives with that target's
// configuration.
const (
	// A declared token shape: 256 bits of entropy, unpadded URL-safe base64,
	// so 43 characters. Named rather than assumed, so a target declaring a
	// different shape is checked against its own.
	listenerSessionFormatBase64URL256 = "base64url_256"
	// 256 bits in unpadded URL-safe base64 is 43 characters.
	listenerSessionTokenLengthBase64URL256 = 43
)

// establishMCPHTTPListenerSession performs the listener setup handshake and
// returns the token the target issued, or an empty string when the target
// issues none.
//
// An empty result is a normal outcome, not a failure: a target that keeps no
// per-client state, or one predating listener-issued tokens, answers setup
// without the header and then accepts stateful requests without it. Returning
// empty keeps those targets measurable on the same adapter, so one runner spans
// both, and a target that DOES require a token is driven correctly instead of
// having every stateful request refused and scored as a false positive.
//
// The setup frame is adapter transport setup, in the same class as opening the
// connection. It is not part of any case's wire input, and the caller still
// proves delivery of the case's own messages separately.
//
// Initialization is NOT conditional on the declaration. Every MCP client opens
// with initialize before it lists or calls tools, so a runner that skips it
// sends a protocol-invalid sequence, and a server that enforces the lifecycle
// rejects the case before it reaches the egress path under test. That turns a
// measurement into an error and looks like a finding. What IS conditional is
// reading and replaying a session token, because only that part belongs to a
// specific target rather than to MCP.
// The bool reports that the drained setup body was truncated. Setup does not
// depend on that body, so it is not an error, but the eventual case result must
// still say the observation was partial rather than silently complete.
func (p *ProxyAdapter) establishMCPHTTPListenerSession(ctx context.Context, client *http.Client) (string, bool, error) {
	// Setup is recognized only on a non-batch initialize that carries no
	// negotiated protocol version, so this frame must stay exactly that shape.
	// Do not add an Mcp-Protocol-Version header here: it makes the target treat
	// this as an already-negotiated request, skip setup, and issue no token.
	message := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      "aeb-listener-session-setup",
		"method":  "initialize",
		"params":  map[string]interface{}{},
	}
	body, err := json.Marshal(message)
	if err != nil {
		return "", false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.mcpHTTPURL, bytes.NewReader(body))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	// The body is drained and discarded. Only the issued token matters here,
	// and leaving it unread would strand the connection. Setup is decided by the
	// status and the declared token header alone, so truncating this drain cannot
	// change the outcome and must not fail an otherwise valid session: a large
	// 2xx setup response would otherwise error every MCP case in the run.
	_, setupTruncated, err := readObservedResponse(resp.Body, observationBodyCap)
	if err != nil {
		return "", false, fmt.Errorf("read listener session response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", setupTruncated, nil
	}
	// Read the token only from a declared header. An undeclared target completes
	// the same initialize and simply yields no token here.
	return p.declaredSessionToken(resp.Header), setupTruncated, nil
}

// declaredSessionToken reads an issued token from the declared header only.
// Without a declaration it reads nothing, so no response header of any target
// is interpreted as a session capability by accident.
func (p *ProxyAdapter) declaredSessionToken(header http.Header) string {
	if p.session.TokenHeader == "" {
		return ""
	}
	return header.Get(p.session.TokenHeader)
}

// setListenerSessionToken replays an issued token on a later stateful request.
// It is a no-op when nothing was declared or nothing was issued.
func (p *ProxyAdapter) setListenerSessionToken(req *http.Request, token string) {
	if p.session.TokenHeader == "" {
		return
	}
	if validListenerSessionToken(token, p.session.TokenFormat) {
		req.Header.Set(p.session.TokenHeader, token)
	}
}

// validListenerSessionToken checks an issued token against the format the
// target declared. Do not replay an arbitrary response header into a later
// request: a malformed value is not a session capability, and a target that
// rejects it before delivery turns a transport failure into a scored verdict.
//
// An undeclared or unrecognized format falls back to a transport-safety check
// rather than rejecting outright. Refusing a token the runner simply does not
// recognize would make every case unmeasurable against a target whose format
// this runner has never heard of, which is the same neutrality failure in a
// quieter form.
func validListenerSessionToken(token, format string) bool {
	if token == "" || len(token) > 4096 {
		return false
	}
	for i := 0; i < len(token); i++ {
		// Reject anything that cannot travel in a header value at all.
		if token[i] < 0x20 || token[i] == 0x7f {
			return false
		}
	}
	if format == listenerSessionFormatBase64URL256 {
		if len(token) != listenerSessionTokenLengthBase64URL256 {
			return false
		}
		for i := 0; i < len(token); i++ {
			if (token[i] < 'A' || token[i] > 'Z') &&
				(token[i] < 'a' || token[i] > 'z') &&
				(token[i] < '0' || token[i] > '9') &&
				token[i] != '-' && token[i] != '_' {
				return false
			}
		}
	}
	return true
}

// Validate reports why a declaration cannot be honored, so a misconfiguration
// stops the run instead of silently changing the score.
//
// Both failures below are quiet by construction, which is what makes them worth
// rejecting up front: a half-declared refusal never matches, so every refusal
// becomes a block the target never made, and an unrecognized format name falls
// back to the loose header-safety check, so a typo disables strict validation
// without saying so.
func (d ListenerSessionDeclaration) Validate() error {
	if (d.RefusalHeader == "") != (d.RefusalValue == "") {
		return fmt.Errorf("a declared session refusal needs both a header and a value, got header=%q value=%q", d.RefusalHeader, d.RefusalValue)
	}
	if d.TokenFormat != "" && d.TokenFormat != listenerSessionFormatBase64URL256 {
		return fmt.Errorf("unknown session token format %q, available: %s", d.TokenFormat, listenerSessionFormatBase64URL256)
	}
	return nil
}

func listenerSessionUnprovenResult() Result {
	return Result{Verdict: "skip", Evidence: map[string]interface{}{
		"product_surface":  "mcp_http_listener",
		"reason":           "listener_session_unproven",
		"upstream_reached": false,
	}}
}

func newMCPHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func validMCPInitializeResponse(body []byte) bool {
	var response struct {
		Result struct {
			ProtocolVersion string          `json:"protocolVersion"`
			Capabilities    json.RawMessage `json:"capabilities"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil || response.Result.ProtocolVersion != "2025-03-26" || response.Result.ServerInfo.Name == "" || response.Result.ServerInfo.Version == "" {
		return false
	}
	var capabilities map[string]interface{}
	return json.Unmarshal(response.Result.Capabilities, &capabilities) == nil && capabilities != nil
}

// runMCPHTTPResponseCase drives a response-shaped corpus case in its actual
// Streamable HTTP direction. The corpus fixture is installed at the upstream,
// then the adapter sends the corresponding client request through the product.
// Posting a JSON-RPC response to the product's listener would test only that a
// listener rejects an invalid client request, not response scanning.
func (p *ProxyAdapter) runMCPHTTPResponseCase(c Case, timeout time.Duration) (responseResult Result) {
	if p.mcpHTTPFixture == nil {
		return Result{Verdict: "skip", Evidence: map[string]interface{}{
			"reason": "no MCP HTTP upstream fixture configured for response case",
		}}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	identity, err := nextGatewayRequestIdentity()
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: prepare response request identity: %w", c.ID, err)}
	}
	// Establish the session before any tool-definition lease is held. The setup
	// frame reaches the upstream fixture, so running it inside a lease window
	// perturbs the very delivery proof the lease exists to make exact.
	responseClient := newMCPHTTPClient(timeout)
	sessionToken, responseSetupTruncated, err := p.establishMCPHTTPListenerSession(ctx, responseClient)
	defer func() {
		responseResult.Evidence = noteObservedTruncation(responseResult.Evidence, responseSetupTruncated, observationBodyCap)
	}()
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: establish MCP HTTP listener session: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	var (
		request       map[string]interface{}
		gatewayReq    gatewayRequest
		release       func()
		declaredNames []string
	)
	switch c.InputType {
	case "mcp_tool_definition":
		tools, names, parseErr := declaredTools(c)
		if parseErr != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/list response: %w", c.ID, parseErr)}
		}
		declaredNames = names
		request = map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      identity,
			"method":  "tools/list",
			"params":  map[string]interface{}{},
		}
		request, gatewayReq, err = withGatewayRequestIdentity(request, identity)
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/list request: %w", c.ID, err)}
		}
		release, err = p.mcpHTTPFixture.AcquireToolDefinitionLease(ctx, gatewayReq.identity, tools)
		if err != nil {
			return Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_definition_lease_timeout", "upstream_reached": false}}
		}
	case "mcp_tool_result":
		result, parseErr := declaredToolResult(c)
		if parseErr != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/call response: %w", c.ID, parseErr)}
		}
		request = map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      identity,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      "aeb_tool_result_fixture",
				"arguments": map[string]interface{}{},
			},
		}
		request, gatewayReq, err = withGatewayRequestIdentity(request, identity)
		if err != nil {
			return Result{Err: fmt.Errorf("case %s: prepare tools/call request: %w", c.ID, err)}
		}
		release, err = p.mcpHTTPFixture.AcquireToolResultLease(ctx, gatewayReq.identity, result)
		if err != nil {
			return Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_result_lease_timeout", "upstream_reached": false}}
		}
	}
	defer release()
	if c.InputType == "mcp_tool_result" {
		if result := p.primeMCPHTTPToolResultBaseline(ctx, sessionToken); result != nil {
			return *result
		}
	}

	body, err := json.Marshal(request)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: marshal response-trigger request: %w", c.ID, err)}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.mcpHTTPURL, bytes.NewReader(body))
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: build MCP HTTP request: %w", c.ID, err)}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	p.setListenerSessionToken(httpReq, sessionToken)
	resp, err := responseClient.Do(httpReq)
	if err != nil {
		return Result{Err: fmt.Errorf("case %s: MCP HTTP request: %w", c.ID, err)}
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := readCappedResponse(resp.Body, decisionBodyCap)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read MCP HTTP response: %w", c.ID, err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	defer func() {
		if len(responseBody) > 0 {
			path := "mcp_tools_call_result"
			if c.InputType == "mcp_tool_definition" {
				path = "mcp_tools_list"
			}
			responseResult.ReturnedContent = append(responseResult.ReturnedContent, returnedContent(responseBody, resp.Header.Get("Content-Type"), path))
		}
	}()

	delivered := proxyMCPHTTPDelivered(p.mcpHTTPFixture, gatewayReq)
	evidence := map[string]interface{}{
		"product_surface":  "mcp_http_listener",
		"request_identity": gatewayReq.identity,
		"upstream_reached": delivered,
	}
	if !delivered {
		evidence["reason"] = "response_upstream_unproven"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if verdict := classifyMCPHTTPBlock(responseBody); verdict != nil {
			for key, value := range evidence {
				verdict.Evidence[key] = value
			}
			return *verdict
		}
		return classifyResponse(resp.StatusCode, string(responseBody))
	}
	decoded, err := decodeGatewayResponse(resp.Header.Get("Content-Type"), responseBody, gatewayReq.identity)
	if err != nil {
		evidence["reason"] = "malformed_or_uncorrelated_response"
		return Result{Verdict: "skip", Evidence: evidence}
	}
	if verdict := classifyMCPHTTPBlock(decoded); verdict != nil {
		for key, value := range evidence {
			verdict.Evidence[key] = value
		}
		return *verdict
	}
	if c.InputType == "mcp_tool_definition" {
		returnedNames, validInventory := toolsListNames(decoded)
		if !validInventory {
			evidence["reason"] = "malformed_tools_list"
			return Result{Verdict: "skip", Evidence: evidence}
		}
		for _, declaredName := range declaredNames {
			if !containsNormalizedToolName(returnedNames, declaredName) {
				evidence["filtered_tool_name"] = declaredName
				return Result{Verdict: "block", Evidence: evidence}
			}
		}
	}
	return Result{Verdict: "allow", Evidence: evidence}
}

// primeMCPHTTPToolResultBaseline establishes the declared tool before asking
// it to return the fixture-owned result. This is part of the protocol path,
// not a workaround: gateways that bind calls to the last tools/list inventory
// must see the same ordinary discovery exchange a real MCP client performs.
// The caller passes the session token it already established, so one case
// opens exactly one session. Establishing a second one here would send another
// setup frame upstream and change the method sequence the fixture observes.
func (p *ProxyAdapter) primeMCPHTTPToolResultBaseline(ctx context.Context, sessionToken string) *Result {
	identity, err := nextGatewayRequestIdentity()
	if err != nil {
		return &Result{Err: fmt.Errorf("prepare tool-result baseline identity: %w", err)}
	}
	request := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      identity,
		"method":  "tools/list",
		"params":  map[string]interface{}{},
	}
	request, gatewayReq, err := withGatewayRequestIdentity(request, identity)
	if err != nil {
		return &Result{Err: fmt.Errorf("prepare tool-result baseline request: %w", err)}
	}
	baselineClient := newMCPHTTPClient(0)
	tools := []json.RawMessage{json.RawMessage(`{"name":"aeb_tool_result_fixture","description":"Runner-owned benchmark fixture tool.","inputSchema":{"type":"object"}}`)}
	release, err := p.mcpHTTPFixture.AcquireToolDefinitionLease(ctx, gatewayReq.identity, tools)
	if err != nil {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_result_baseline_lease_timeout", "upstream_reached": false}}
	}
	defer release()
	body, err := json.Marshal(request)
	if err != nil {
		return &Result{Err: fmt.Errorf("marshal tool-result baseline request: %w", err)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.mcpHTTPURL, bytes.NewReader(body))
	if err != nil {
		return &Result{Err: fmt.Errorf("build tool-result baseline request: %w", err)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	p.setListenerSessionToken(req, sessionToken)
	resp, err := baselineClient.Do(req)
	if err != nil {
		return &Result{Err: fmt.Errorf("send tool-result baseline request: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := readCappedResponse(resp.Body, decisionBodyCap)
	if err != nil {
		return &Result{
			Err:      fmt.Errorf("read tool-result baseline response: %w", err),
			Evidence: cappedResponseEvidence(err),
		}
	}
	if !proxyMCPHTTPDelivered(p.mcpHTTPFixture, gatewayReq) {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_result_baseline_unproven", "upstream_reached": false}}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_result_baseline_rejected", "upstream_reached": true}}
	}
	if _, err := decodeGatewayResponse(resp.Header.Get("Content-Type"), responseBody, gatewayReq.identity); err != nil {
		return &Result{Verdict: "skip", Evidence: map[string]interface{}{"reason": "tool_result_baseline_invalid_response", "upstream_reached": true}}
	}
	return nil
}

func proxyMCPHTTPDelivered(upstream *fixture.MCPHTTPFixture, request gatewayRequest) bool {
	observations := upstream.Observation(request.identity)
	if len(observations) != 1 {
		return false
	}
	observation := observations[0]
	return observation.Identity == request.identity && observation.Method == request.method && observation.Fingerprint == request.fingerprint
}

func (p *ProxyAdapter) mcpHTTPUpstreamCallCount() (int64, bool) {
	if p.mcpHTTPUpstreamCalls == nil {
		return 0, false
	}
	return p.mcpHTTPUpstreamCalls(), true
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

	respBody, err := readCappedResponse(resp.Body, decisionBodyCap)
	if err != nil {
		return Result{
			Err:      fmt.Errorf("case %s: read scan API (%s) response: %w", caseID, kind, err),
			Evidence: cappedResponseEvidence(err),
		}
	}

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
	// A2A agent cards: scan name, URL, description, and both the name and the
	// description of every declared skill.
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
// Supported block response formats include:
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

// hasDenyMarker reports whether a response body carries positive evidence that
// the tool made a deny decision, as opposed to merely being non-empty.
//
// This is deliberately NOT extractBlockEvidence: that helper ends in a
// `len(body) > 0` catch-all which stuffs any body into block_reason, so an
// upstream's "upstream error" string would read as a policy block. Ambiguous
// statuses must key off a real marker, never off the presence of some text.
func hasDenyMarker(body string) bool {
	var jsonResp struct {
		Blocked     *bool  `json:"blocked"`
		BlockReason string `json:"block_reason"`
		Scanner     string `json:"scanner"`
	}
	if json.Unmarshal([]byte(body), &jsonResp) == nil {
		if jsonResp.Blocked != nil {
			return *jsonResp.Blocked
		}
		return jsonResp.BlockReason != "" || jsonResp.Scanner != ""
	}
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"dlp", "secret", "credential", "ssrf", "private ip", "metadata",
		"injection", "prompt", "entropy", "blocklist", "blocked domain",
		"kill switch", "airlock",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// classifyResponse determines block vs allow from an HTTP response whose origin
// has not been proven. Context-free 4xx/5xx responses are not containment
// evidence because they may have been generated by the harness or proxy before
// any upstream contact.
func classifyResponse(statusCode int, body string) Result {
	return classifyHTTPResponse(statusCode, body, false)
}

// classifyUpstreamResponse determines block vs allow from an HTTP response
// after the transport path has proven the upstream endpoint answered.
func classifyUpstreamResponse(statusCode int, body string) Result {
	return classifyHTTPResponse(statusCode, body, true)
}

func classifyHTTPResponse(statusCode int, body string, upstreamReached bool) Result {
	evidence := map[string]interface{}{
		"status_code": statusCode,
	}

	if statusCode == http.StatusForbidden || statusCode == http.StatusBadRequest {
		// A status alone names no actor. An origin, reverse proxy, fixture, or
		// policy control can all return 400/403, so containment credit needs a
		// positive deny marker from the evaluated path.
		if hasDenyMarker(body) {
			evidence["reason"] = fmt.Sprintf("http_%d", statusCode)
			extractBlockEvidence(body, evidence)
			return Result{Verdict: "block", Evidence: evidence}
		}
		if upstreamReached {
			evidence["reason"] = fmt.Sprintf("http_%d_passthrough", statusCode)
			return Result{Verdict: "allow", Evidence: evidence}
		}
		evidence["reason"] = fmt.Sprintf("http_%d_origin_unconfirmed", statusCode)
		evidence["upstream_error"] = truncate(body, 120)
		return Result{Verdict: "skip", Evidence: evidence}
	}

	// 502 is ambiguous: the proxy returns it both for a policy block and for a
	// plain upstream failure (dial, TLS, timeout). Only a structured deny marker
	// proves the tool actually made a decision. Scoring a bare "upstream error"
	// as a block manufactures a false positive against the tool out of nothing
	// but a broken fixture, and docs/gauntlet.md requires an infrastructure
	// failure to score error rather than fail.
	if statusCode == http.StatusBadGateway {
		if hasDenyMarker(body) {
			evidence["reason"] = "http_502"
			extractBlockEvidence(body, evidence)
			return Result{Verdict: "block", Evidence: evidence}
		}
		evidence["reason"] = "http_502_upstream_failure"
		evidence["upstream_error"] = truncate(body, 120)
		return Result{Verdict: "skip", Evidence: evidence}
	}

	// 405 means this tool's endpoint could not execute the case as declared: the
	// payload was never scanned, so there is no verdict to report. Scoring it
	// "allow" passes a benign case that would pass with every scanner switched
	// off, and hands a malicious case a miss the tool never had a chance at.
	// README and docs/gauntlet.md both require an adapter that cannot execute
	// a declared-applicable case to score error, which makes the gap visible
	// instead of silently inflating the result.
	if statusCode == http.StatusMethodNotAllowed {
		evidence["reason"] = "http_405_method_not_supported"
		return Result{Verdict: "skip", Evidence: evidence}
	}

	if statusCode >= 200 && statusCode < 400 {
		return Result{Verdict: "allow", Evidence: evidence}
	}

	if !upstreamReached {
		// 4xx/5xx that aren't 400/403/405/502 only prove passthrough when the
		// caller knows an upstream origin answered. At this layer, proxy-local
		// fixture failures and true upstream responses are indistinguishable, so
		// fail away from allow.
		evidence["reason"] = fmt.Sprintf("http_%d_origin_unconfirmed", statusCode)
		evidence["upstream_error"] = truncate(body, 120)
		return Result{Verdict: "skip", Evidence: evidence}
	}

	// From a confirmed upstream origin, a 4xx/5xx that isn't 400/403/405/502 means
	// the request reached upstream and the error came from there. The proxy allowed
	// it through rather than blocking it: 404, 429, 500 and friends all mean the
	// proxy did not intervene.
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

func verifyMCPStdioResponses(caseID string, lines []string, expected []interface{}) Result {
	// Parse every JSON-RPC response line.
	var actual []map[string]interface{}
	for _, line := range lines {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		_, hasResult := m["result"]
		_, hasError := m["error"]
		if hasResult == hasError {
			// A JSON-RPC response contains exactly one of result or error. Ignore
			// notifications and malformed lines rather than treating either as
			// comparable upstream evidence.
			continue
		}
		actual = append(actual, m)
	}

	if len(expected) > 0 {
		expectedByID := make(map[string]map[string]interface{}, len(expected))
		for _, e := range expected {
			em, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			expectedByID[fmt.Sprint(em["id"])] = em
		}
		matched := 0
		var mismatched []map[string]interface{}
		for _, act := range actual {
			id := fmt.Sprint(act["id"])
			exp, ok := expectedByID[id]
			if !ok {
				mismatched = append(mismatched, act)
				continue
			}
			if !mcpResponseMatches(exp, act) {
				mismatched = append(mismatched, act)
				continue
			}
			matched++
			delete(expectedByID, id)
		}
		if matched == len(expected) && len(expectedByID) == 0 {
			return Result{
				Verdict:  "allow",
				Evidence: map[string]interface{}{"verified_responses": matched},
			}
		}
		return Result{
			Verdict: "skip",
			Evidence: map[string]interface{}{
				"reason":               "mcp_stdio_response_mismatch",
				"expected_responses":   len(expected),
				"matched_responses":    matched,
				"synthesized_response": true,
				"unmatched_responses":  mismatched,
			},
		}
	}

	// Without an injected mock response there is no runner-controlled receipt
	// channel. A non-empty JSON-RPC response can always be synthesized by the
	// proxy under test, so it must never score allow.
	return Result{
		Verdict: "skip",
		Evidence: map[string]interface{}{
			"reason":               "mcp_stdio_upstream_proof_unavailable",
			"synthesized_response": true,
		},
	}
}

// rootJSONRPCIDCandidateKeys returns a correlation key for every root-level id
// member in the line. A well-formed response has exactly one. When a line
// repeats the member, single-value decoding silently picks one of them, so the
// runner can correlate a response to a request nobody asked about while another
// parser correlates the same bytes to one we did. Enumerating the candidates is
// what lets the caller refuse that ambiguity instead of resolving it by luck.
func rootJSONRPCIDCandidateKeys(line string) []string {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return nil
	}
	if delim, ok := token.(json.Delim); !ok || delim != '{' {
		return nil
	}
	var keys []string
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return keys
		}
		name, ok := nameToken.(string)
		if !ok {
			return keys
		}
		var value interface{}
		if err := decoder.Decode(&value); err != nil {
			return keys
		}
		if name == "id" {
			keys = append(keys, jsonRPCIDCorrelationKey(value))
		}
	}
	return keys
}

// mcpStdioDuplicateRequestResponse rejects only duplicate JSON-RPC responses
// for a request from this run. Notifications, non-JSON log lines, and
// responses for other request IDs may legitimately share stdout and remain
// outside the case response contract.
// isJSONRPCResponseLine reports whether a stdout line is a well-formed JSON-RPC
// 2.0 response. Only a real response may consume a request's single answer, so
// anything malformed is ignored here rather than counted. Counting it would let
// one stray line make the following genuine response look like a duplicate and
// turn a legitimate server's output unscoreable, which is the same damage as
// missing the duplicate it was meant to catch.
func isJSONRPCResponseLine(line string) bool {
	var response struct {
		Version string          `json:"jsonrpc"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &response); err != nil {
		return false
	}
	if response.Version != "2.0" {
		return false
	}
	// Membership, not value. JSON-RPC permits any result value including null,
	// so treating a null result as an absent member would let a valid response
	// go uncounted and hide the duplicate that follows it. An error member is
	// different: the specification requires an Error Object there, so a null or
	// shapeless error is not a response at all.
	hasResult := response.Result != nil
	hasError := response.Error != nil
	if hasResult == hasError {
		return false
	}
	if hasError {
		var rpcError struct {
			Code    *int    `json:"code"`
			Message *string `json:"message"`
		}
		if err := json.Unmarshal(response.Error, &rpcError); err != nil {
			return false
		}
		if rpcError.Code == nil || rpcError.Message == nil {
			return false
		}
	}
	return true
}

func mcpStdioDuplicateRequestResponse(lines []string, requestIDs map[string]struct{}) *Result {
	seen := make(map[string]struct{}, len(requestIDs))
	for _, line := range lines {
		// A single line can be ambiguous on its own. Decoding keeps the last of
		// two members sharing a name, so the runner and the agent's own parser
		// need not agree on which one is the answer. Check this before the
		// response-shape test, because that test decodes and would inherit the
		// same silent choice.
		if name, duplicate := duplicateJSONMemberName([]byte(line)); duplicate {
			// Correlate against every candidate id, not the one decoding happened
			// to keep. A line repeating both a requested and an unrequested id
			// would otherwise be dismissed as somebody else's traffic.
			candidates := rootJSONRPCIDCandidateKeys(line)
			if len(candidates) == 0 {
				candidates = []string{jsonRPCResponseIDCorrelationKey(line)}
			}
			for _, candidate := range candidates {
				if _, requested := requestIDs[candidate]; requested {
					return &Result{Verdict: "skip", Evidence: map[string]interface{}{
						"reason":                "mcp_stdio_ambiguous_response",
						"duplicate_member":      name,
						"duplicate_response_id": candidate,
					}}
				}
			}
			continue
		}
		if !isJSONRPCResponseLine(line) {
			continue
		}
		id := jsonRPCResponseIDCorrelationKey(line)
		if _, requested := requestIDs[id]; !requested {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			return &Result{Verdict: "skip", Evidence: map[string]interface{}{
				"reason":                "mcp_stdio_duplicate_response",
				"duplicate_response_id": id,
			}}
		}
		seen[id] = struct{}{}
	}
	return nil
}

func mcpResponseMatches(expected, actual map[string]interface{}) bool {
	_, expectedResult := expected["result"]
	_, expectedError := expected["error"]
	_, actualResult := actual["result"]
	_, actualError := actual["error"]
	if expectedResult == expectedError || actualResult == actualError {
		return false
	}
	if expectedResult != actualResult {
		return false
	}
	if expectedResult {
		return mcpResultsEqual(expected["result"], actual["result"])
	}
	// Compare the complete error object, including code and message. This also
	// preserves future JSON-RPC error data fields instead of accepting any error
	// with a matching id.
	return mcpResultsEqual(expected["error"], actual["error"])
}

func mcpResultsEqual(a, b interface{}) bool {
	// Normalize numeric values and preserve deep equality.
	ja, err := json.Marshal(a)
	if err != nil {
		return false
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	var va, vb interface{}
	if err := json.Unmarshal(ja, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(jb, &vb); err != nil {
		return false
	}
	return reflect.DeepEqual(va, vb)
}

func shallowCloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isScanDeny returns true if the verdict string indicates a block/deny.
// Scan-style APIs commonly return either "deny" or "block".
func isScanDeny(v string) bool {
	return v == "deny" || v == "block"
}
