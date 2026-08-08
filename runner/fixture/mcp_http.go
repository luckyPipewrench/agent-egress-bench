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
	toolResultLease     chan struct{}
	toolsMu             sync.RWMutex
	tools               []json.RawMessage
	toolResultMu        sync.RWMutex
	toolResult          json.RawMessage
	deliveryMu          sync.RWMutex
	deliveryTokens      map[string]struct{}
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
// upstream. It remains useful fixture telemetry; gateway delivery proof uses
// DeliveryTokenSeen so another tools/call cannot satisfy a case's proof.
func (f *MCPHTTPFixture) ToolCalls() int64 { return f.toolCalls.Load() }

// ListCalls returns the number of tools/list requests that reached the
// upstream. It remains useful fixture telemetry; token proof identifies the
// exact tools/list request for a case.
func (f *MCPHTTPFixture) ListCalls() int64 { return f.listCalls.Load() }

// DeliveryTokenSeen reports whether this fixture received the exact token the
// adapter attached to a case request. Unlike a counter delta, another case's
// request cannot satisfy this proof.
func (f *MCPHTTPFixture) DeliveryTokenSeen(token string) bool {
	f.deliveryMu.RLock()
	defer f.deliveryMu.RUnlock()
	_, found := f.deliveryTokens[token]
	return found
}

func (f *MCPHTTPFixture) recordDeliveryToken(body []byte) {
	var request struct {
		Params struct {
			Meta struct {
				DeliveryToken string `json:"aeb_delivery_token"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &request) != nil || request.Params.Meta.DeliveryToken == "" {
		return
	}
	f.deliveryMu.Lock()
	f.deliveryTokens[request.Params.Meta.DeliveryToken] = struct{}{}
	f.deliveryMu.Unlock()
}

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

// AcquireToolResultLease installs a case's tools/call result and exclusively
// leases it until the returned release function is called. This prevents
// concurrent gateway cases from receiving one another's upstream responses.
func (f *MCPHTTPFixture) AcquireToolResultLease(ctx context.Context, result json.RawMessage) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.toolResultLease:
	}
	if err := ctx.Err(); err != nil {
		f.toolResultLease <- struct{}{}
		return nil, err
	}
	f.toolResultMu.Lock()
	f.toolResult = append(f.toolResult[:0], result...)
	f.toolResultMu.Unlock()
	var released sync.Once
	return func() {
		released.Do(func() {
			f.toolResultMu.Lock()
			f.toolResult = nil
			f.toolResultMu.Unlock()
			f.toolResultLease <- struct{}{}
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
		toolResultLease:     make(chan struct{}, 1),
		deliveryTokens:      make(map[string]struct{}),
	}
	f.toolDefinitionLease <- struct{}{}
	f.toolResultLease <- struct{}{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		f.recordDeliveryToken(body)
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
			f.toolResultMu.RLock()
			result := append(json.RawMessage(nil), f.toolResult...)
			f.toolResultMu.RUnlock()
			if len(result) == 0 {
				result = json.RawMessage(`{"ok":true}`)
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%s}`, id, result)
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
