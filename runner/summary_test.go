package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildToolSupport(t *testing.T) {
	p := Profile{
		Claims: []string{"url_dlp", "ssrf"},
		Supports: map[string]bool{
			"fetch_proxy":              true,
			"http_proxy":               true,
			"mcp_stdio":               false,
			"mcp_http":                false,
			"websocket":               false,
			"a2a":                     false,
			"tls_interception":         true,
			"request_body_scanning":    false,
			"header_scanning":          false,
			"response_scanning":        false,
			"mcp_tool_baseline":        false,
			"mcp_chain_memory":         false,
			"websocket_frame_scanning": false,
			"a2a_scanning":             false,
			"shell_analysis":           false,
			"dns_rebinding_fixture":    false,
		},
	}

	ts := buildToolSupport(p)

	if len(ts.Claims) != 2 {
		t.Errorf("claims count = %d, want 2", len(ts.Claims))
	}

	// mcp_stdio, mcp_http, websocket, a2a are unsupported transports.
	expectedTransports := map[string]bool{
		"mcp_stdio": true, "mcp_http": true, "websocket": true, "a2a": true,
	}
	for _, ut := range ts.UnsupportedTransports {
		if !expectedTransports[ut] {
			t.Errorf("unexpected unsupported transport: %s", ut)
		}
	}
	if len(ts.UnsupportedTransports) != len(expectedTransports) {
		t.Errorf("unsupported transports count = %d, want %d",
			len(ts.UnsupportedTransports), len(expectedTransports))
	}
}

func TestComputeCorpusSHA256(t *testing.T) {
	dir := t.TempDir()

	// Write two case files.
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"id":"b"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	hash1, err := computeCorpusSHA256(dir)
	if err != nil {
		t.Fatalf("computeCorpusSHA256: %v", err)
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Same files = same hash.
	hash2, err := computeCorpusSHA256(dir)
	if err != nil {
		t.Fatalf("computeCorpusSHA256: %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("hash should be deterministic: %s != %s", hash1, hash2)
	}

	// Different content = different hash.
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"changed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	hash3, err := computeCorpusSHA256(dir)
	if err != nil {
		t.Fatalf("computeCorpusSHA256: %v", err)
	}
	if hash3 == hash1 {
		t.Error("hash should change with different content")
	}
}

func TestWriteSummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")

	containment := 0.95
	fpRate := 0.02
	detection := 0.0
	evidence := 0.0

	s := GauntletSummary{
		GauntletVersion: gauntletVersion,
		RunnerVersion:   runnerVersion,
		Tool:            "test-tool",
		ToolVersion:     "1.0.0",
		CorpusVersion:   "v1.0.0",
		CorpusSHA256:    "abc123",
		Date:            "2026-03-28T00:00:00Z",
		CaseCount: CaseCount{
			Total:         100,
			Applicable:    90,
			NotApplicable: 10,
			NotApplicableReasons: map[string]int{
				"missing_capability": 5,
				"missing_requires":   3,
				"unsupported_transport": 2,
			},
			Errors: 0,
		},
		ToolSupport: ToolSupport{
			Claims:                []string{"url_dlp"},
			UnsupportedTransports: []string{"a2a"},
			UnsupportedRequires:   []string{"dns_rebinding_fixture"},
		},
		Scores: Scores{
			Containment:       &containment,
			FalsePositiveRate: &fpRate,
			Detection:         &detection,
			Evidence:          &evidence,
		},
		Sufficient:  true,
		PerCategory: map[string]CategoryScores{},
	}

	if err := writeSummary(s, path); err != nil {
		t.Fatalf("writeSummary: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}

	var parsed GauntletSummary
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("parsing written summary: %v", err)
	}

	if parsed.Tool != "test-tool" {
		t.Errorf("tool = %q, want test-tool", parsed.Tool)
	}
	if parsed.Sufficient != true {
		t.Error("sufficient should be true")
	}
	if parsed.Scores.Containment == nil || *parsed.Scores.Containment != 0.95 {
		t.Errorf("containment = %v, want 0.95", ptrVal(parsed.Scores.Containment))
	}

	// Verify file permissions.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file perm = %o, want 0600", perm)
	}
}
