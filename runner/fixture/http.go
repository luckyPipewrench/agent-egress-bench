package fixture

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPFixture runs a plain HTTP server that returns configurable responses.
// Used for response-mitm cases: the adapter routes the case URL through
// the proxy's fetch endpoint pointing at this server. The proxy fetches
// the content and scans it for injection before returning to the agent.
type HTTPFixture struct {
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
	routes   map[string]string // path → response body
}

// Addr returns the listener address (host:port).
func (f *HTTPFixture) Addr() string { return f.listener.Addr().String() }

// SetRoute configures a response body for a given URL path.
func (f *HTTPFixture) SetRoute(path, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[path] = body
}

// StartHTTP creates and starts an HTTP response fixture on a random port.
func StartHTTP() (*HTTPFixture, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &HTTPFixture{
		listener: ln,
		routes:   make(map[string]string),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, ok := f.routes[r.URL.Path]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = fmt.Fprint(w, body)
	})

	f.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { _ = f.server.Serve(ln) }()
	return f, nil
}

// Close stops the HTTP server.
func (f *HTTPFixture) Close() {
	_ = f.server.Close()
}
