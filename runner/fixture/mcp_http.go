package fixture

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// MCPHTTPFixture runs a minimal Streamable HTTP MCP upstream.
type MCPHTTPFixture struct {
	listener net.Listener
	server   *http.Server
	calls    atomic.Int64
	toolsMu  sync.RWMutex
	tools    []json.RawMessage
}

// Addr returns the listener address (host:port).
func (f *MCPHTTPFixture) Addr() string { return f.listener.Addr().String() }

// URL returns the upstream URL.
func (f *MCPHTTPFixture) URL() string { return "http://" + f.Addr() + "/" }

// Calls returns the number of tools/call requests that reached the upstream.
func (f *MCPHTTPFixture) Calls() int64 { return f.calls.Load() }

// SetTools configures the tools returned by a later tools/list request.
func (f *MCPHTTPFixture) SetTools(tools []json.RawMessage) {
	f.toolsMu.Lock()
	defer f.toolsMu.Unlock()
	f.tools = append(f.tools[:0], tools...)
}

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
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage(`1`)
		}
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"aeb-mcp-fixture","version":"1"}}}`, id)
		case "tools/list":
			f.toolsMu.RLock()
			tools, err := json.Marshal(f.tools)
			f.toolsMu.RUnlock()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, id, tools)
		case "tools/call":
			f.calls.Add(1)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, id)
		default:
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"ok":true}}`, id)
		}
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
