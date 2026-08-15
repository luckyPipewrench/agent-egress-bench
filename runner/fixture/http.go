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
	servedPaths       map[string]int64     // path -> requests observed for that exact path
}

// Addr returns the listener address (host:port).
func (f *HTTPFixture) Addr() string { return f.listener.Addr().String() }

// Requests returns the number of requests that reached either fixture listener.
// This is a whole-fixture total and is NOT delivery evidence for a particular
// case: any route on either listener advances it. Use RequestsFor.
func (f *HTTPFixture) Requests() int64 { return f.requests.Load() }

// RequestsFor returns the number of requests observed for one exact path.
// Delivery proof scopes to the route because a whole-fixture counter is
// satisfied by a request the case never made: another route, the untrusted
// sink listener, or a concurrently executing case. Callers give each case a
// per-run unique path, so a route counter identifies the case that owns it.
//
// The key is the path alone rather than host plus path on purpose. The runner
// reaches the fixture through the target proxy, so the Host header arrives
// however that proxy chose to write it, and keying on a normalized-away host
// would fail delivery proof for a request that did arrive. That direction is
// the damaging one: it scores a real result as unproven.
func (f *HTTPFixture) RequestsFor(path string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.servedPaths[path]
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
		servedPaths:       make(map[string]int64),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		f.mu.Lock()
		route, ok := f.routes[r.URL.Path]
		if ok {
			// Counted only on a served route. A 404 means the fixture never
			// handed this case's content to the target, so it is not delivery.
			f.servedPaths[r.URL.Path]++
		}
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", route.ContentType)
		_, _ = fmt.Fprint(w, route.Body)
	})

	// Separate *http.Server per listener: net/http tolerates one server across
	// multiple listeners, but two independent servers keep the trusted and
	// untrusted sink listeners fully isolated and unambiguously shut down.
	f.server = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	f.untrustedServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() { _ = f.server.Serve(ln) }()
	go func() { _ = f.untrustedServer.Serve(untrustedLn) }()
	return f, nil
}

// Close stops both HTTP listeners.
func (f *HTTPFixture) Close() {
	_ = f.server.Close()
	_ = f.untrustedServer.Close()
}
