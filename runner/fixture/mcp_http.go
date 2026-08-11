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
	toolSessions    map[string]string
	toolResults     map[string]json.RawMessage
	observations    map[string][]MCPRequestObservation
	finalSinkLeases map[string]MCPRequestObservation
	finalSinks      map[string][]MCPRequestObservation
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

// FinalSinkExecution returns exact executions at the runner-owned terminal
// tools/call sink. Ordinary upstream arrival is not enough: the request must
// match a lease minted for the sequence's final call.
func (f *MCPHTTPFixture) FinalSinkExecution(identity string) []MCPRequestObservation {
	f.requestMu.RLock()
	defer f.requestMu.RUnlock()
	return append([]MCPRequestObservation(nil), f.finalSinks[identity]...)
}

// ActiveFinalSinkLeases reports the number of terminal effects currently
// armed. A dependent-sequence driver uses at most one, and only while its
// terminal request is being dispatched.
func (f *MCPHTTPFixture) ActiveFinalSinkLeases() int {
	f.requestMu.RLock()
	defer f.requestMu.RUnlock()
	return len(f.finalSinkLeases)
}

func (f *MCPHTTPFixture) recordObservation(body []byte) (MCPRequestObservation, bool) {
	var request struct {
		Method string `json:"method"`
		Params struct {
			Meta struct {
				Identity string `json:"aeb_request_identity"`
			} `json:"_meta"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &request) != nil || request.Params.Meta.Identity == "" {
		return MCPRequestObservation{}, false
	}
	fingerprint, err := MCPRequestFingerprint(body)
	if err != nil {
		return MCPRequestObservation{}, false
	}
	observation := MCPRequestObservation{
		Identity: request.Params.Meta.Identity, Method: request.Method, Fingerprint: fingerprint,
	}
	f.requestMu.Lock()
	f.observations[request.Params.Meta.Identity] = append(f.observations[request.Params.Meta.Identity], observation)
	f.requestMu.Unlock()
	return observation, true
}

// AcquireFinalSinkLease binds the terminal effect of one dependent sequence to
// the exact runner-owned identity, method, and canonical payload fingerprint.
// A copied identity, changed payload, replay, or an earlier call cannot satisfy
// the lease.
func (f *MCPHTTPFixture) AcquireFinalSinkLease(ctx context.Context, expected MCPRequestObservation) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if expected.Identity == "" || expected.Method != "tools/call" || expected.Fingerprint == "" {
		return nil, fmt.Errorf("final-sink lease requires an exact tools/call observation")
	}
	f.requestMu.Lock()
	if _, exists := f.finalSinkLeases[expected.Identity]; exists {
		f.requestMu.Unlock()
		return nil, fmt.Errorf("final-sink lease %q already exists", expected.Identity)
	}
	f.finalSinkLeases[expected.Identity] = expected
	f.requestMu.Unlock()
	var released sync.Once
	return func() {
		released.Do(func() {
			f.requestMu.Lock()
			delete(f.finalSinkLeases, expected.Identity)
			f.requestMu.Unlock()
		})
	}, nil
}

func (f *MCPHTTPFixture) recordFinalSinkExecution(observation MCPRequestObservation) {
	f.requestMu.Lock()
	defer f.requestMu.Unlock()
	expected, leased := f.finalSinkLeases[observation.Identity]
	if !leased || expected != observation {
		return
	}
	f.finalSinks[observation.Identity] = append(f.finalSinks[observation.Identity], observation)
}

// SetTools configures the tools returned by a later tools/list request.
func (f *MCPHTTPFixture) SetTools(tools []json.RawMessage) {
	f.toolsMu.Lock()
	defer f.toolsMu.Unlock()
	f.tools = append(f.tools[:0], tools...)
}

func (f *MCPHTTPFixture) toolsSnapshot() []json.RawMessage {
	f.toolsMu.RLock()
	defer f.toolsMu.RUnlock()
	return append([]json.RawMessage(nil), f.tools...)
}

// AcquireToolDefinitionLease installs a tools/list inventory for identity.
// Like tool results, inventories must route by request identity rather than a
// fixture-wide semaphore or one concurrent case can receive another's tools.
func (f *MCPHTTPFixture) AcquireToolDefinitionLease(ctx context.Context, identity string, tools []json.RawMessage) (func(), error) {
	return f.acquireToolDefinitionLease(ctx, identity, "", tools)
}

// AcquireSessionToolDefinitionLease binds a tools/list inventory to the live
// session that must arrive with the exact request identity.
func (f *MCPHTTPFixture) AcquireSessionToolDefinitionLease(ctx context.Context, identity, sessionID string, tools []json.RawMessage) (func(), error) {
	if sessionID == "" {
		return nil, fmt.Errorf("tool-definition lease session is required")
	}
	return f.acquireToolDefinitionLease(ctx, identity, sessionID, tools)
}

func (f *MCPHTTPFixture) acquireToolDefinitionLease(ctx context.Context, identity, sessionID string, tools []json.RawMessage) (func(), error) {
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
	if sessionID != "" {
		f.toolSessions[identity] = sessionID
	}
	f.requestMu.Unlock()
	var released sync.Once
	return func() {
		released.Do(func() {
			f.requestMu.Lock()
			delete(f.toolDefinitions, identity)
			delete(f.toolSessions, identity)
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
		toolSessions:    make(map[string]string),
		toolResults:     make(map[string]json.RawMessage),
		observations:    make(map[string][]MCPRequestObservation),
		finalSinkLeases: make(map[string]MCPRequestObservation),
		finalSinks:      make(map[string][]MCPRequestObservation),
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
		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Method  string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		var identityRequest struct {
			Params struct {
				Meta struct {
					Identity string `json:"aeb_request_identity"`
				} `json:"_meta"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &identityRequest)
		identity := identityRequest.Params.Meta.Identity
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage(`1`)
		}
		w.Header().Set("Content-Type", "application/json")
		f.requestMu.RLock()
		requiredSession, sessionBound := f.toolSessions[identity]
		f.requestMu.RUnlock()
		if sessionBound && r.Header.Get("Mcp-Session-Id") != requiredSession {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32001,"message":"missing or invalid MCP session"}}`, id)
			return
		}
		observation, observed := f.recordObservation(body)
		switch req.Method {
		case "initialize":
			if identity != "" {
				sessionID := "aeb-session-" + identity
				w.Header().Set("Mcp-Session-Id", sessionID)
			}
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"aeb-mcp-fixture","version":"1"}}}`, id)
		case "tools/list":
			f.listCalls.Add(1)
			toolList := f.toolsSnapshot()
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
			if observed {
				f.recordFinalSinkExecution(observation)
			}
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
