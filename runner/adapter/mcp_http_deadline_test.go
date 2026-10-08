package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Session setup and sequence messages spend one case budget, even when each
// individual request would finish inside that budget.
func TestRunMCPHTTPSequenceSharesCaseDeadline(t *testing.T) {
	for _, session := range []bool{false, true} {
		t.Run(map[bool]string{false: "messages", true: "session-and-messages"}[session], func(t *testing.T) {
			var calls atomic.Int64
			listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var message map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&message); err != nil {
					t.Error(err)
					return
				}
				calls.Add(1)
				timer := time.NewTimer(200 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
				if message["method"] == "initialize" {
					w.Header().Set(testListenerSessionHeader, "0123456789012345678901234567890123456789012")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"jsonrpc": "2.0", "id": message["id"], "result": map[string]interface{}{}})
			}))
			defer listener.Close()
			a := &ProxyAdapter{}
			a.SetMCPHTTPURL(listener.URL)
			a.SetMCPHTTPUpstreamCallCounter(calls.Load)
			if session {
				a.SetMCPHTTPListenerSession(testListenerSessionDeclaration())
			}
			messages := make([]interface{}, 4)
			for i := range messages {
				messages[i] = map[string]interface{}{"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": map[string]interface{}{"name": "safe"}}
			}
			c := Case{ID: "sequence-deadline", Transport: "mcp_http", InputType: "mcp_tool_sequence", Payload: map[string]interface{}{"jsonrpc_messages": messages}}
			// A generous budget proves that all exchanges are valid and reachable.
			control := a.Run(c, 3*time.Second)
			if control.Err != nil || control.Verdict != "allow" || !control.DeliveryProven || !control.VerdictObserved {
				t.Fatalf("positive control: %+v", control)
			}
			before := calls.Load()
			started := time.Now()
			result := a.Run(c, 500*time.Millisecond)
			if !errors.Is(result.Err, context.DeadlineExceeded) {
				t.Fatalf("case exceeded its budget without a deadline error: elapsed=%s result=%+v", time.Since(started), result)
			}
			if result.VerdictObserved || result.DeliveryProven || result.Verdict == "allow" || result.Verdict == "block" {
				t.Fatalf("incomplete sequence became measured: %+v", result)
			}
			if got := calls.Load() - before; got >= 4 {
				t.Fatalf("continued sending after case budget: %d requests", got)
			}
		})
	}
}
