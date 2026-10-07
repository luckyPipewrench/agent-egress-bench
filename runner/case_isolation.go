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
	fixtures       *fixture.Manager
	mu             sync.Mutex
}

func (a *caseIsolatedProxyAdapter) DeliveryTuples() []adapter.DeliveryTuple {
	return a.proxy.DeliveryTuples()
}

func (a *caseIsolatedProxyAdapter) Run(c adapter.Case, timeout time.Duration) adapter.Result {
	// The adapter's listener URL and the fixture response are mutable. Serialize
	// the whole case, including teardown, even if a caller later runs in parallel.
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.Transport != "mcp_http" {
		return a.proxy.Run(c, timeout)
	}
	if a.mcpHTTPCommand == "" {
		result := a.proxy.Run(c, timeout)
		if result.Evidence == nil {
			result.Evidence = map[string]interface{}{}
		}
		result.Evidence["mcp_http_case_isolation"] = "external_listener_unverified"
		return result
	}
	managed, err := startManagedProcesses("", a.mcpHTTPCommand, a.fixtures, timeout)
	if err != nil {
		return adapter.Result{
			Err:      fmt.Errorf("case %s: start isolated MCP HTTP target: %w", c.ID, err),
			Evidence: map[string]interface{}{"mcp_http_case_isolation": "startup_failed"},
		}
	}
	defer managed.Close()
	a.proxy.SetMCPHTTPURL(managed.mcpHTTPURL)
	defer a.proxy.SetMCPHTTPURL("")
	result := a.proxy.Run(c, timeout)
	if result.Evidence == nil {
		result.Evidence = map[string]interface{}{}
	}
	result.Evidence["mcp_http_case_isolation"] = "fresh_managed_process"
	return result
}
