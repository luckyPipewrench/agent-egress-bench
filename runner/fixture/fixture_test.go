package fixture

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/websocket"
)

func TestHTTPFixtureCountsServedRequests(t *testing.T) {
	f, err := StartHTTP()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.SetRoute("/proof", "ok")

	if got := f.Requests(); got != 0 {
		t.Fatalf("requests before client call = %d, want 0", got)
	}
	resp, err := http.Get("http://" + f.Addr() + "/proof") //nolint:gosec,noctx // runner-owned fixture
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if got := f.Requests(); got != 1 {
		t.Fatalf("requests after client call = %d, want 1", got)
	}
}

func TestTLSFixture(t *testing.T) {
	f, err := StartTLS()
	if err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	defer f.Close()

	f.SetRoute("/api/data", `{"result": "injected payload"}`)

	// Connect with TLS (skip verify since it's a test CA).
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				InsecureSkipVerify: true, //nolint:gosec // test fixture
			},
		},
	}

	resp, err := client.Get("https://" + f.Addr() + "/api/data")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"result": "injected payload"}` {
		t.Errorf("body = %q, want injected payload", body)
	}

	// 404 for unregistered route.
	resp2, err := client.Get("https://" + f.Addr() + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp2.StatusCode)
	}

	// CA files exist.
	if f.CAFile() == "" || f.KeyFile() == "" {
		t.Error("CA/key file paths should not be empty")
	}
}

func TestTLSFixtureAllowedChannelHostnames(t *testing.T) {
	f, err := StartTLS()
	if err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	defer f.Close()
	f.SetRoute("/ok", "ok")

	caPEM, err := os.ReadFile(f.CAFile())
	if err != nil {
		t.Fatalf("read fixture CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("fixture CA did not contain a certificate")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", f.Addr())
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    pool,
			},
		},
	}
	for _, host := range []string{"allowed-code-api.test", "allowed-chat-webhook.test"} {
		resp, getErr := client.Get("https://" + host + "/ok")
		if getErr != nil {
			t.Fatalf("GET through fixture as %s: %v", host, getErr)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET through fixture as %s: status %d", host, resp.StatusCode)
		}
	}
}

func TestWSFixture(t *testing.T) {
	f, err := StartWS()
	if err != nil {
		t.Fatalf("StartWS: %v", err)
	}
	defer f.Close()

	// Health check.
	resp, err := http.Get("http://" + f.Addr() + "/health")
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	noProxyClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   5 * time.Second,
	}
	respUntrusted, err := noProxyClient.Get("http://" + f.UntrustedAddr() + "/health")
	if err != nil {
		t.Fatalf("untrusted health check: %v", err)
	}
	_ = respUntrusted.Body.Close()
	if respUntrusted.StatusCode != http.StatusOK {
		t.Fatalf("untrusted health status = %d", respUntrusted.StatusCode)
	}

	// WebSocket echo.
	ws, err := websocket.Dial("ws://"+f.Addr()+"/echo", "", "http://localhost/")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = ws.Close() }()

	msg := "test secret AKIA" + "IOSFODNN7EXAMPLE"
	if _, err := ws.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := ws.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != msg {
		t.Errorf("echo = %q, want %q", buf[:n], msg)
	}

	ws2, err := websocket.Dial("ws://"+f.UntrustedAddr()+"/echo", "", "http://localhost/")
	if err != nil {
		t.Fatalf("dial untrusted listener: %v", err)
	}
	_ = ws2.Close()
}

func TestHTTPFixture(t *testing.T) {
	f, err := StartHTTP()
	if err != nil {
		t.Fatalf("StartHTTP: %v", err)
	}
	defer f.Close()

	f.SetRoute("/api/data", `{"result": "test payload"}`)

	// Registered route returns content.
	resp, err := http.Get("http://" + f.Addr() + "/api/data")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"result": "test payload"}` {
		t.Errorf("body = %q, want test payload", body)
	}

	noProxyClient := &http.Client{
		Transport: &http.Transport{Proxy: nil},
		Timeout:   5 * time.Second,
	}
	respUntrusted, err := noProxyClient.Get("http://" + f.UntrustedAddr() + "/api/data")
	if err != nil {
		t.Fatalf("GET untrusted listener: %v", err)
	}
	defer func() { _ = respUntrusted.Body.Close() }()
	if respUntrusted.StatusCode != http.StatusOK {
		t.Errorf("untrusted status = %d, want 200", respUntrusted.StatusCode)
	}

	// Unregistered route returns 404.
	resp2, err := http.Get("http://" + f.Addr() + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown: %v", err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("unregistered status = %d, want 404", resp2.StatusCode)
	}
}

func TestDNSFixture(t *testing.T) {
	f, err := StartDNS()
	if err != nil {
		t.Fatalf("StartDNS: %v", err)
	}
	defer f.Close()

	// Configure rebinding: first query → public IP, second → loopback.
	if err := f.SetRebind("attacker.test", []string{"93.184.216.34", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}

	client := &dns.Client{Timeout: 2 * time.Second}

	// First query → public IP.
	msg1 := new(dns.Msg)
	msg1.SetQuestion("attacker.test.", dns.TypeA)
	resp1, _, err := client.Exchange(msg1, f.Addr())
	if err != nil {
		t.Fatalf("query 1: %v", err)
	}
	if len(resp1.Answer) == 0 {
		t.Fatal("query 1: no answer")
	}
	ip1 := resp1.Answer[0].(*dns.A).A.String()
	if ip1 != "93.184.216.34" {
		t.Errorf("query 1 IP = %s, want 93.184.216.34", ip1)
	}

	// Second query → loopback (rebinding!).
	resp2, _, err := client.Exchange(msg1, f.Addr())
	if err != nil {
		t.Fatalf("query 2: %v", err)
	}
	ip2 := resp2.Answer[0].(*dns.A).A.String()
	if ip2 != "127.0.0.1" {
		t.Errorf("query 2 IP = %s, want 127.0.0.1 (rebinding)", ip2)
	}

	// Third query wraps around.
	resp3, _, err := client.Exchange(msg1, f.Addr())
	if err != nil {
		t.Fatalf("query 3: %v", err)
	}
	ip3 := resp3.Answer[0].(*dns.A).A.String()
	if ip3 != "93.184.216.34" {
		t.Errorf("query 3 IP = %s, want 93.184.216.34 (wrap)", ip3)
	}

	// Unknown hostname → NXDOMAIN.
	msg2 := new(dns.Msg)
	msg2.SetQuestion("unknown.test.", dns.TypeA)
	resp4, _, err := client.Exchange(msg2, f.Addr())
	if err != nil {
		t.Fatalf("query unknown: %v", err)
	}
	if resp4.Rcode != dns.RcodeNameError {
		t.Errorf("unknown rcode = %d, want NXDOMAIN (%d)", resp4.Rcode, dns.RcodeNameError)
	}
}

func TestDNSFixture_ResolverIntegration(t *testing.T) {
	f, err := StartDNS()
	if err != nil {
		t.Fatalf("StartDNS: %v", err)
	}
	defer f.Close()

	if err := f.SetRebind("safe.test", []string{"93.184.216.34"}); err != nil {
		t.Fatal(err)
	}

	// Use Go's net.Resolver pointed at our fixture.
	host, port, _ := net.SplitHostPort(f.Addr())
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("udp", net.JoinHostPort(host, port))
		},
	}

	ips, err := resolver.LookupHost(t.Context(), "safe.test")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(ips) == 0 || ips[0] != "93.184.216.34" {
		t.Errorf("resolved = %v, want [93.184.216.34]", ips)
	}
}

// A whole-fixture counter is satisfied by any request to any route, so it
// cannot prove that one case's own content was delivered. RequestsFor must
// count the exact path and nothing else.
func TestHTTPFixture_RequestsForIsRouteScoped(t *testing.T) {
	f, err := StartHTTP()
	if err != nil {
		t.Fatalf("StartHTTP: %v", err)
	}
	defer f.Close()

	f.SetRoute("/response/c1", "case one body")
	f.SetRoute("/response/c2", "case two body")

	get := func(addr, path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	get(f.Addr(), "/response/c1")

	if got := f.RequestsFor("/response/c1"); got != 1 {
		t.Errorf("RequestsFor(/response/c1) = %d, want 1", got)
	}
	// The defect this guards: c2 was never requested, so it must not inherit
	// c1's delivery and score as observed.
	if got := f.RequestsFor("/response/c2"); got != 0 {
		t.Errorf("RequestsFor(/response/c2) = %d, want 0", got)
	}

	// The untrusted sink listener shares the counter surface. A request there
	// must not satisfy delivery proof for a trusted-listener route.
	if f.UntrustedAddr() != "" {
		get(f.UntrustedAddr(), "/response/c1")
		if got := f.RequestsFor("/response/c2"); got != 0 {
			t.Errorf("after untrusted request, RequestsFor(/response/c2) = %d, want 0", got)
		}
	}

	// An unregistered path 404s, which is not delivery of any case content.
	get(f.Addr(), "/response/never-registered")
	if got := f.RequestsFor("/response/never-registered"); got != 0 {
		t.Errorf("RequestsFor(unregistered) = %d, want 0", got)
	}

	// The whole-fixture total counts every one of the above, which is exactly
	// why it is the wrong signal for per-case delivery proof.
	if got := f.Requests(); got < 3 {
		t.Errorf("Requests() = %d, want at least 3", got)
	}
}
