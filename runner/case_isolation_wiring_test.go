package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A managed MCP HTTP command only has a consumer in the proxy adapter. Any other
// adapter used to start the process and ignore it; that silent no-op is refused.
func TestManagedMCPHTTPRefusedForOtherAdapters(t *testing.T) {
	t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
	err := runWithOptions(filepath.Join("..", "cases"), filepath.Join("..", "examples", "pipelock", "tool-profile.json"), filepath.Join(t.TempDir(), "summary.json"), 5*time.Second,
		"dryrun", "", "", "", "", "", "", "true", false, "", "", "", false, "")
	if err == nil || !strings.Contains(err.Error(), "requires the proxy adapter") {
		t.Fatalf("managed MCP HTTP command with a non-proxy adapter was accepted: %v", err)
	}
}

// TestManagedMCPHTTPWiringThroughRunEntrypoint drives the entrypoint the CLI
// uses with no --mcp-http-url. It proves the managed URL is applied per case
// after route planning, rather than being required when the adapter is built,
// and that every case in a poison/clean sequence is routed and measured.
func TestManagedMCPHTTPWiringThroughRunEntrypoint(t *testing.T) {
	t.Setenv("AEB_ISOLATION_TARGET_HELPER", "1")
	t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
	casesDir := t.TempDir()
	for _, id := range []string{"wire-1-poison", "wire-2-clean", "wire-3-clean-again"} {
		name := "clean"
		if id == "wire-1-poison" {
			name = "poison"
		}
		body := map[string]interface{}{
			"schema_version": 4, "id": id, "category": "mcp_chain", "title": id, "description": id,
			"input_type": "mcp_tool_sequence", "transport": "mcp_http",
			"payload": map[string]interface{}{"jsonrpc_messages": []interface{}{map[string]interface{}{
				"jsonrpc": "2.0", "id": 1, "method": "tools/call",
				"params": map[string]interface{}{"name": name, "arguments": map[string]interface{}{}},
			}}},
			"expected_verdict": "allow", "severity": "low", "capability_tags": []string{"benign"},
			"requires": []string{}, "false_positive_risk": "low", "why_expected": "benign", "source": "synthetic", "safe_example": true,
		}
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(casesDir, id+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outputPath := filepath.Join(t.TempDir(), "summary.json")
	err := runWithOptions(casesDir, filepath.Join("..", "examples", "pipelock", "tool-profile.json"), outputPath, 5*time.Second,
		"proxy", "127.0.0.1:1", "", "", "", "", "", isolationHelperCommand(), false, "", "", "", false, "")
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var summary GauntletSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.CaseCount.Unreachable != 0 || summary.CaseCount.Applicable != 3 || summary.CaseCount.Errors != 0 {
		t.Fatalf("managed MCP HTTP cases were declined or errored: %+v", summary.CaseCount)
	}
	// Every case expects allow. A target that kept the poison call's state would
	// refuse a later clean case and surface as a false positive.
	if rate := summary.Scores.Applicable.FalsePositiveRate; rate == nil || *rate != 0 {
		t.Fatalf("a later case inherited the earlier case's target state: false_positive_rate=%v", rate)
	}
}
