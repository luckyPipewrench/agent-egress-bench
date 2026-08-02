package fixture

import (
	"context"
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
	listener  net.Listener
	server    *http.Server
	calls     atomic.Int64
	toolCalls atomic.Int64
	listCalls atomic.Int64
	// toolDefinitionLease leases the fixture-wide tools/list inventory to one
	// adapter run. The fixture is shared by all adapters in a gauntlet run, so
	// SetTools alone cannot keep simultaneous tool-definition cases isolated.
	// A channel permits acquisition to honor each case's deadline.
	toolDefinitionLease chan struct{}
	toolsMu             sync.RWMutex
	tools               []json.RawMessage
}

// Addr returns the listener address (host:port).
func (f *MCPHTTPFixture) Addr() string { return f.listener.Addr().String() }

// URL returns the upstream URL.
func (f *MCPHTTPFixture) URL() string { return "http://" + f.Addr() + "/" }

// Calls returns the total number of POST requests that reached the upstream.
// The proxy MCP HTTP proof relies on this total (one increment per sent
// message), so it must count every request, not only tools/call.
func (f *MCPHTTPFixture) Calls() int64 { return f.calls.Load() }

// ToolCalls returns the number of tools/call requests that reached the
// upstream. The gateway adapter proves an allow by this tool-call-specific
// count so an initialize/tools-list POST cannot inflate the proof.
func (f *MCPHTTPFixture) ToolCalls() int64 { return f.toolCalls.Load() }

// ListCalls returns the number of tools/list requests that reached the
// upstream. The gateway adapter uses this dedicated count to prove that a
// tools/list response was not generated locally by the gateway.
func (f *MCPHTTPFixture) ListCalls() int64 { return f.listCalls.Load() }

// SetTools configures the tools returned by a later tools/list request.
func (f *MCPHTTPFixture) SetTools(tools []json.RawMessage) {
	f.toolsMu.Lock()
	defer f.toolsMu.Unlock()
	f.tools = append(f.tools[:0], tools...)
}

// AcquireToolDefinitionLease installs a case's tools/list inventory and
// exclusively leases it until the returned release function is called. It
// returns promptly when ctx expires while another case owns the lease. Release
// resets the inventory so a completed case cannot influence a later one.
func (f *MCPHTTPFixture) AcquireToolDefinitionLease(ctx context.Context, tools []json.RawMessage) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.toolDefinitionLease:
	}
	if err := ctx.Err(); err != nil {
		f.toolDefinitionLease <- struct{}{}
		return nil, err
	}
	f.SetTools(tools)
	var released sync.Once
	return func() {
		released.Do(func() {
			f.SetTools(nil)
			f.toolDefinitionLease <- struct{}{}
		})
	}, nil
}

// StartMCPHTTP creates and starts a minimal MCP HTTP upstream on a random port.
func StartMCPHTTP() (*MCPHTTPFixture, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := &MCPHTTPFixture{
		listener:            ln,
		toolDefinitionLease: make(chan struct{}, 1),
	}
	f.toolDefinitionLease <- struct{}{}
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
			f.listCalls.Add(1)
			f.toolsMu.RLock()
			toolList := f.tools
			if toolList == nil {
				toolList = []json.RawMessage{}
			}
			tools, err := json.Marshal(toolList)
			f.toolsMu.RUnlock()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, id, tools)
		case "tools/call":
			f.toolCalls.Add(1)
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
