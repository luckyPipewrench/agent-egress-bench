package fixture

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// MCPHTTPFixture runs a minimal Streamable HTTP MCP upstream.
type MCPHTTPFixture struct {
	listener net.Listener
	server   *http.Server
	calls    atomic.Int64
}

// Addr returns the listener address (host:port).
func (f *MCPHTTPFixture) Addr() string { return f.listener.Addr().String() }

// URL returns the upstream URL.
func (f *MCPHTTPFixture) URL() string { return "http://" + f.Addr() + "/" }

// Calls returns the number of POST requests that reached the upstream.
func (f *MCPHTTPFixture) Calls() int64 { return f.calls.Load() }

// StartMCPHTTP creates and starts a minimal MCP HTTP upstream on a random port.
func StartMCPHTTP() (*MCPHTTPFixture, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &MCPHTTPFixture{listener: ln}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
		}
		_ = json.Unmarshal(body, &req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage(`1`)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, id)
	})

	f.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = f.server.Serve(ln) }()
	return f, nil
}

// Close stops the MCP HTTP server.
func (f *MCPHTTPFixture) Close() {
	_ = f.server.Close()
}
