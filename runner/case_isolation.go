package main

import (
	"fmt"
	"sync"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// caseIsolatedProxyAdapter joins the existing managed process lifecycle to the
// logical case boundary. A temporal case still executes all its steps against
// one process; unrelated cases cannot inherit its in-memory target state.
type caseIsolatedProxyAdapter struct {
	proxy          *adapter.ProxyAdapter
	mcpHTTPCommand string

	// externalMCPHTTPURL is an operator-run endpoint the runner does not start.
	// Only a case actually sent to one is labelled unverified; with neither it
	// nor a managed command the adapter skips the case and claims nothing.
	externalMCPHTTPURL string
	fixtures           *fixture.Manager
	mu                 sync.Mutex
}

func (a *caseIsolatedProxyAdapter) DeliveryTuples() []adapter.DeliveryTuple {
	// Capability declarations are constant; they do not read the case endpoint.
	return a.proxy.DeliveryTuples()
}

func (a *caseIsolatedProxyAdapter) Run(c adapter.Case, timeout time.Duration) adapter.Result {
	// The adapter's listener URL and the fixture response are mutable. Serialize
	// the whole case, including teardown, even if a caller later runs in parallel.
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(timeout)
	if c.Transport != "mcp_http" {
		return a.proxy.Run(c, timeout)
	}
	if a.mcpHTTPCommand == "" {
		result := a.proxy.Run(c, timeout)
		if a.externalMCPHTTPURL != "" {
			if result.Evidence == nil {
				result.Evidence = map[string]interface{}{}
			}
			result.Evidence["mcp_http_case_isolation"] = "external_listener_unverified"
		}
		return result
	}
	managed, err := startManagedProcesses("", a.mcpHTTPCommand, a.fixtures, time.Until(deadline))
	if err != nil {
		return adapter.Result{
			Err:      fmt.Errorf("case %s: start isolated MCP HTTP target: %w", c.ID, err),
			Evidence: map[string]interface{}{"mcp_http_case_isolation": "startup_failed"},
		}
	}
	defer managed.Close()
	a.proxy.SetMCPHTTPURL(managed.mcpHTTPURL)
	defer a.proxy.SetMCPHTTPURL("")
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return adapter.Result{
			Err:      fmt.Errorf("case %s: timeout exhausted starting isolated MCP HTTP target", c.ID),
			Evidence: map[string]interface{}{"mcp_http_case_isolation": "startup_failed"},
		}
	}
	result := a.proxy.Run(c, remaining)
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	result.Evidence["mcp_http_case_isolation"] = "fresh_managed_process"
	return result
}
