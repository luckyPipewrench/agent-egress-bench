package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// End-to-end: a gateway plugin with a managed lifecycle must start its gateway,
// register the benchmark fixture as upstream, and let the adapter drive a real
// tools/call case through the gateway to the fixture. The allow verdict here is
// earned by the fixture actually receiving the forwarded call, not assumed.
func TestBuildManagedGatewayAdapterDrivesCaseThroughStartedGateway(t *testing.T) {
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	defer fm.Close()

	// The gateway process is this test binary re-executed in forwarding mode; it
	// listens on $AEB_GATEWAY_ADDR and forwards tools/call to the fixture.
	t.Setenv("AEB_GATEWAY_HELPER", "forward")
	pluginPath := writeManagedGatewayPlugin(t, map[string]interface{}{
		"name":      "synthetic gateway",
		"transport": "streamable_http",
		"gateway": map[string]interface{}{
			"start_command": gatewayForwardHelperCommand(),
			"ready_addr":    "$AEB_GATEWAY_ADDR",
		},
		"client": map[string]interface{}{
			"endpoint": "$AEB_GATEWAY_URL",
		},
	})

	adapt, gw, err := buildManagedGatewayAdapter(pluginPath, fm, 5*time.Second)
	if err != nil {
		t.Fatalf("buildManagedGatewayAdapter: %v", err)
	}
	defer gw.Close()

	toolsCallCase := adapter.Case{
		ID:        "gw-e2e-001",
		InputType: "mcp_tool_call",
		Transport: "mcp_http",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{
				map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      "1",
					"method":  "tools/call",
					"params":  map[string]interface{}{"name": "echo", "arguments": map[string]interface{}{}},
				},
			},
		},
	}

	result := adapt.Run(toolsCallCase, 5*time.Second)
	if result.Err != nil {
		t.Fatalf("adapter run error: %v", result.Err)
	}
	if result.Verdict != "allow" {
		t.Fatalf("verdict = %q (evidence %v), want allow via managed gateway", result.Verdict, result.Evidence)
	}
	if reached, _ := result.Evidence["upstream_reached"].(bool); !reached {
		t.Fatalf("upstream_reached = %v, want true", result.Evidence["upstream_reached"])
	}
}

// An operator-started gateway declares no start command and supplies its own
// address through the process environment. The runner must not overwrite that
// $AEB_GATEWAY_URL with a freshly allocated loopback address it never started,
// which would point the adapter at a dead endpoint.
func TestBuildManagedGatewayAdapterKeepsOperatorEnvpointForUnmanagedPlugin(t *testing.T) {
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	defer fm.Close()

	operator := httptest.NewServer(forwardingGatewayHandler(fm.MCPHTTP().URL()))
	defer operator.Close()
	t.Setenv("AEB_GATEWAY_URL", operator.URL)

	pluginPath := writeManagedGatewayPlugin(t, map[string]interface{}{
		"name":      "operator gateway",
		"transport": "streamable_http",
		"client":    map[string]interface{}{"endpoint": "$AEB_GATEWAY_URL"},
	})

	adapt, gw, err := buildManagedGatewayAdapter(pluginPath, fm, 5*time.Second)
	if err != nil {
		t.Fatalf("buildManagedGatewayAdapter: %v", err)
	}
	if gw != nil {
		gw.Close()
		t.Fatal("unmanaged plugin must not produce a managed gateway")
	}

	result := adapt.Run(toolsCallCaseForGatewayTest(), 5*time.Second)
	if result.Err != nil {
		t.Fatalf("adapter run error: %v", result.Err)
	}
	if result.Verdict != "allow" {
		t.Fatalf("verdict = %q (evidence %v), want allow via the operator endpoint", result.Verdict, result.Evidence)
	}
}

func TestBuildManagedGatewayAdapterDoesNotCreditManagedDenyAsAtomicProof(t *testing.T) {
	fm, err := fixture.StartAll()
	if err != nil {
		t.Fatalf("StartAll: %v", err)
	}
	defer fm.Close()

	t.Setenv("AEB_GATEWAY_HELPER", "deny-late")
	pluginPath := writeManagedGatewayPlugin(t, map[string]interface{}{
		"name": "synthetic delayed deny gateway", "transport": "streamable_http",
		"gateway": map[string]interface{}{
			"start_command": gatewayForwardHelperCommand(), "ready_addr": "$AEB_GATEWAY_ADDR",
		},
		"client":       map[string]interface{}{"endpoint": "$AEB_GATEWAY_URL"},
		"deny_signals": map[string]interface{}{"jsonrpc_error_code_range": []int{-32099, -32000}},
	})

	adapt, gw, err := buildManagedGatewayAdapter(pluginPath, fm, 5*time.Second)
	if err != nil {
		t.Fatalf("buildManagedGatewayAdapter: %v", err)
	}
	defer gw.Close()
	sequence := toolsCallCaseForGatewayTest()
	sequence.ID = "gw-e2e-unproven-deny"
	sequence.InputType = "mcp_tool_sequence"

	result := adapt.Run(sequence, 5*time.Second)
	if result.Err != nil || result.Verdict != "skip" || result.Evidence["reason"] != "atomic_non_delivery_proof_unavailable" {
		t.Fatalf("result = %+v, want honest unproven-deny skip", result)
	}
	identity, _ := result.Evidence["final_sink_request_identity"].(string)
	if identity == "" {
		t.Fatalf("final sink identity missing: %+v", result.Evidence)
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for len(fm.MCPHTTP().Observation(identity)) == 0 {
		select {
		case <-deadline.C:
			t.Fatalf("delayed forward never reached fixture for %s", identity)
		case <-ticker.C:
		}
	}
}

// forwardingGatewayHandler answers initialize locally and forwards every other
// JSON-RPC message to upstream, mirroring the subprocess forwarding helper.
func forwardingGatewayHandler(upstream string) http.Handler {
	client := &http.Client{Timeout: 3 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "initialize" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}`, id)
			return
		}
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream, bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(upReq)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_, _ = w.Write(respBody)
	})
}

func toolsCallCaseForGatewayTest() adapter.Case {
	return adapter.Case{
		ID:        "gw-e2e-op-001",
		InputType: "mcp_tool_call",
		Transport: "mcp_http",
		Payload: map[string]interface{}{
			"jsonrpc_messages": []interface{}{
				map[string]interface{}{
					"jsonrpc": "2.0",
					"id":      "1",
					"method":  "tools/call",
					"params":  map[string]interface{}{"name": "echo", "arguments": map[string]interface{}{}},
				},
			},
		},
	}
}

// writeManagedGatewayPlugin writes a plugin JSON file for the managed-lifecycle
// tests in this package.
func writeManagedGatewayPlugin(t *testing.T, plugin map[string]interface{}) string {
	t.Helper()
	data, err := json.Marshal(plugin)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/plugin.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestGatewayForwardHelper is a synthetic MCP gateway used by managed-lifecycle
// tests. It listens on $AEB_GATEWAY_ADDR and answers initialize locally. The
// forward mode relays later requests; deny-late returns a policy error and then
// forwards anyway, proving that shell lifecycle is not atomic non-delivery proof.
func TestGatewayForwardHelper(t *testing.T) {
	mode := os.Getenv("AEB_GATEWAY_HELPER")
	if mode != "forward" && mode != "deny-late" {
		return
	}
	addr := os.Getenv("AEB_GATEWAY_ADDR")
	upstream := os.Getenv("AEB_MCP_HTTP_FIXTURE_URL")
	client := &http.Client{Timeout: 3 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		if req.Method == "initialize" {
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}`, id)
			return
		}
		if req.Method == "notifications/initialized" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if mode == "deny-late" {
			go func(delayed []byte) {
				timer := time.NewTimer(250 * time.Millisecond)
				defer timer.Stop()
				<-timer.C
				upReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, upstream, bytes.NewReader(delayed))
				if err != nil {
					return
				}
				upReq.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(upReq)
				if err == nil {
					_ = resp.Body.Close()
				}
			}(append([]byte(nil), body...))
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32042,"message":"policy denied"}}`, id)
			return
		}
		upReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, upstream, bytes.NewReader(body))
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(upReq)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_, _ = w.Write(respBody)
	})

	server := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	if lifetime, err := time.ParseDuration(os.Getenv("AEB_GATEWAY_HELPER_LIFETIME")); err == nil && lifetime > 0 {
		go func() {
			timer := time.NewTimer(lifetime)
			defer timer.Stop()
			<-timer.C
			_ = server.Shutdown(context.Background())
		}()
	}
	if err := server.ListenAndServe(); err != nil {
		if err == http.ErrServerClosed {
			return
		}
		_, _ = fmt.Fprintf(os.Stderr, "forwarding gateway helper exited: %v\n", err)
		return
	}
}

func gatewayForwardHelperCommand() string {
	return fmt.Sprintf("exec %q -test.run=TestGatewayForwardHelper", os.Args[0])
}
