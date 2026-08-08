package fixture

import (
	"context"
	"crypto/sha256"
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
	listener        net.Listener
	server          *http.Server
	calls           atomic.Int64
	toolCalls       atomic.Int64
	listCalls       atomic.Int64
	toolsMu         sync.RWMutex
	tools           []json.RawMessage
	requestMu       sync.RWMutex
	toolDefinitions map[string][]json.RawMessage
	toolResults     map[string]json.RawMessage
	observations    map[string][]MCPRequestObservation
}

// MCPRequestObservation is the runner-owned evidence recorded for an upstream
// MCP request. An identity alone is deliberately insufficient: a copied token
// must not prove a different method or payload was delivered.
type MCPRequestObservation struct {
	Identity    string
	Method      string
	Fingerprint string
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
// upstream. It remains fixture telemetry; adapter proof uses Observation.
func (f *MCPHTTPFixture) ToolCalls() int64 { return f.toolCalls.Load() }

// ListCalls returns the number of tools/list requests that reached the
// upstream. It remains fixture telemetry; adapter proof uses Observation.
func (f *MCPHTTPFixture) ListCalls() int64 { return f.listCalls.Load() }

// MCPRequestFingerprint produces the canonical fingerprint used by both the
// adapter and the fixture. JSON object key order is not evidence, so both ends
// normalize the JSON before hashing it.
func MCPRequestFingerprint(body []byte) (string, error) {
	var message interface{}
	if err := json.Unmarshal(body, &message); err != nil {
		return "", fmt.Errorf("decode MCP request: %w", err)
	}
	normalized, err := json.Marshal(message)
	if err != nil {
		return "", fmt.Errorf("normalize MCP request: %w", err)
	}
	sum := sha256.Sum256(normalized)
	return fmt.Sprintf("%x", sum[:]), nil
}

// Observation returns all arrivals bearing identity. Delivery is proven only
// when the adapter finds exactly one observation with its expected method and
// fingerprint. A replay therefore makes proof fail rather than satisfying it.
func (f *MCPHTTPFixture) Observation(identity string) []MCPRequestObservation {
	f.requestMu.RLock()
	defer f.requestMu.RUnlock()
	return append([]MCPRequestObservation(nil), f.observations[identity]...)
}

func (f *MCPHTTPFixture) recordObservation(body []byte) string {
	var request struct {
		Method string `json:"method"`
		Params struct {
			Meta struct {
				Identity string `json:"aeb_request_identity"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &request) != nil || request.Params.Meta.Identity == "" {
		return ""
	}
	fingerprint, err := MCPRequestFingerprint(body)
	if err != nil {
		return ""
	}
	f.requestMu.Lock()
	f.observations[request.Params.Meta.Identity] = append(f.observations[request.Params.Meta.Identity], MCPRequestObservation{
		Identity: request.Params.Meta.Identity, Method: request.Method, Fingerprint: fingerprint,
	})
	f.requestMu.Unlock()
	return request.Params.Meta.Identity
}

// SetTools configures the tools returned by a later tools/list request.
func (f *MCPHTTPFixture) SetTools(tools []json.RawMessage) {
	f.toolsMu.Lock()
	defer f.toolsMu.Unlock()
	f.tools = append(f.tools[:0], tools...)
}

// AcquireToolDefinitionLease installs a tools/list inventory for identity.
// Like tool results, inventories must route by request identity rather than a
// fixture-wide semaphore or one concurrent case can receive another's tools.
func (f *MCPHTTPFixture) AcquireToolDefinitionLease(ctx context.Context, identity string, tools []json.RawMessage) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if identity == "" {
		return nil, fmt.Errorf("tool-definition lease identity is required")
	}
	f.requestMu.Lock()
	if _, exists := f.toolDefinitions[identity]; exists {
		f.requestMu.Unlock()
		return nil, fmt.Errorf("tool-definition lease %q already exists", identity)
	}
	f.toolDefinitions[identity] = append([]json.RawMessage(nil), tools...)
	f.requestMu.Unlock()
	var released sync.Once
	return func() {
		released.Do(func() {
			f.requestMu.Lock()
			delete(f.toolDefinitions, identity)
			f.requestMu.Unlock()
		})
	}, nil
}

// AcquireToolResultLease installs a tools/call response for identity. The
// fixture routes the response only to that identity, so unrelated concurrent
// calls keep the default response rather than inheriting another case's lease.
func (f *MCPHTTPFixture) AcquireToolResultLease(ctx context.Context, identity string, result json.RawMessage) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if identity == "" {
		return nil, fmt.Errorf("tool-result lease identity is required")
	}
	f.requestMu.Lock()
	if _, exists := f.toolResults[identity]; exists {
		f.requestMu.Unlock()
		return nil, fmt.Errorf("tool-result lease %q already exists", identity)
	}
	f.toolResults[identity] = append(json.RawMessage(nil), result...)
	f.requestMu.Unlock()
	var released sync.Once
	return func() {
		released.Do(func() {
			f.requestMu.Lock()
			delete(f.toolResults, identity)
			f.requestMu.Unlock()
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
		listener:        ln,
		toolDefinitions: make(map[string][]json.RawMessage),
		toolResults:     make(map[string]json.RawMessage),
		observations:    make(map[string][]MCPRequestObservation),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		f.calls.Add(1)
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		identity := f.recordObservation(body)
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
			f.toolsMu.RUnlock()
			f.requestMu.RLock()
			if leased, found := f.toolDefinitions[identity]; found {
				toolList = leased
			}
			f.requestMu.RUnlock()
			if toolList == nil {
				toolList = []json.RawMessage{}
			}
			tools, err := json.Marshal(toolList)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, id, tools)
		case "tools/call":
			f.toolCalls.Add(1)
			f.requestMu.RLock()
			result := append(json.RawMessage(nil), f.toolResults[identity]...)
			f.requestMu.RUnlock()
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
