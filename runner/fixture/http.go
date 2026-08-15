package fixture

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// HTTPFixture runs a plain HTTP server that returns configurable responses.
// Used for response-mitm cases: the adapter routes the case URL through
// the proxy's fetch endpoint pointing at this server. The proxy fetches
// the content and scans it for injection before returning to the agent.
type HTTPFixture struct {
	listener          net.Listener
	untrustedListener net.Listener
	server            *http.Server
	untrustedServer   *http.Server
	requests          atomic.Int64
	mu                sync.Mutex
	routes            map[string]HTTPRoute // path -> response metadata
	servedRoutes      map[string]int64     // trusted-listener deliveries, keyed by route and token
}

// DeliveryTokenParam is the query parameter carrying a per-interaction
// delivery token. The runner adds it to a fixture URL so the fixture can
// attribute a request to the exact case that asked for it.
const DeliveryTokenParam = "aeb_delivery"

func deliveryKey(path, token string) string { return path + "\x00" + token }

// Addr returns the listener address (host:port).
func (f *HTTPFixture) Addr() string { return f.listener.Addr().String() }

// Requests returns the number of requests that reached either fixture listener.
// This is a whole-fixture total and is NOT delivery evidence for a particular
// case: any route on either listener advances it. Use RequestsFor.
func (f *HTTPFixture) Requests() int64 { return f.requests.Load() }

// RequestsFor returns trusted-listener deliveries of one route carrying one
// delivery token.
//
// Three things scope this, and each closes a way a case could inherit someone
// else's delivery. The listener, because the untrusted sink serves the same
// route table and a request there says nothing about trusted content being
// fetched. The path, because any other route advances a fixture-wide total.
// The token, because cases share a declared endpoint: the A2A message path
// comes from the case itself, so two cases hit the same route, and a target
// may fetch asynchronously after its response is already returned.
//
// The failure direction is availability: a target that drops the query
// parameter when it forwards scores as unproven rather than allowed. That is
// the safe direction here and it is loud, since the evidence names the token
// that was expected and never arrived.
func (f *HTTPFixture) RequestsFor(path, token string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servedRoutes[deliveryKey(path, token)]
}

// UntrustedAddr returns the paired loopback listener used by reserved
// untrusted sink hostnames.
func (f *HTTPFixture) UntrustedAddr() string {
	if f.untrustedListener == nil {
		return ""
	}
	return f.untrustedListener.Addr().String()
}

// HTTPRoute is a fixture response.
type HTTPRoute struct {
	Body        string
	ContentType string
}

// SetRoute configures a response body for a given URL path.
func (f *HTTPFixture) SetRoute(path, body string) {
	f.SetRouteWithContentType(path, body, "text/html; charset=utf-8")
}

// SetRouteWithContentType configures a response for a given URL path.
func (f *HTTPFixture) SetRouteWithContentType(path, body, contentType string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = HTTPRoute{Body: body, ContentType: contentType}
}

// StartHTTP creates and starts an HTTP response fixture on a random port.
func StartHTTP() (*HTTPFixture, error) {
	ln, untrustedLn, err := listenLoopbackPair()
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &HTTPFixture{
		listener:          ln,
		untrustedListener: untrustedLn,
		routes:            make(map[string]HTTPRoute),
		servedRoutes:      make(map[string]int64),
	}

	// One handler per listener, differing only in whether a served route
	// counts as trusted delivery. Sharing a mux is what let an untrusted-sink
	// request satisfy a trusted-fixture proof.
	handler := func(trusted bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			f.requests.Add(1)
			f.mu.Lock()
			route, ok := f.routes[r.URL.Path]
			if ok && trusted {
				// Counted only on a served route on the trusted listener. A
				// 404 means the fixture never handed this case's content to
				// the target, so it is not delivery.
				token := r.URL.Query().Get(DeliveryTokenParam)
				f.servedRoutes[deliveryKey(r.URL.Path, token)]++
			}
			f.mu.Unlock()
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", route.ContentType)
			_, _ = fmt.Fprint(w, route.Body)
		}
	}

	trustedMux := http.NewServeMux()
	trustedMux.HandleFunc("/", handler(true))
	untrustedMux := http.NewServeMux()
	untrustedMux.HandleFunc("/", handler(false))

	// Separate *http.Server per listener: net/http tolerates one server across
	// multiple listeners, but two independent servers keep the trusted and
	// untrusted sink listeners fully isolated and unambiguously shut down.
	f.server = &http.Server{Handler: trustedMux, ReadHeaderTimeout: 5 * time.Second}
	f.untrustedServer = &http.Server{Handler: untrustedMux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = f.server.Serve(ln) }()
	go func() { _ = f.untrustedServer.Serve(untrustedLn) }()
	return f, nil
}

// Close stops both HTTP listeners.
func (f *HTTPFixture) Close() {
	_ = f.server.Close()
	_ = f.untrustedServer.Close()
}
