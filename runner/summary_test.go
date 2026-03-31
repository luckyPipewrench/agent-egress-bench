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

func TestBuildToolSupportNilClaims(t *testing.T) {
	p := Profile{
		Claims:   nil,
		Supports: map[string]bool{},
	}
	ts := buildToolSupport(p)
	if ts.Claims == nil {
		t.Error("claims should not be nil")
	}
	if ts.UnsupportedTransports == nil {
		t.Error("unsupported_transports should not be nil")
	}
	if ts.UnsupportedRequires == nil {
		t.Error("unsupported_requires should not be nil")
	}
}

func TestBuildToolSupportAllSupported(t *testing.T) {
	supports := map[string]bool{
		"fetch_proxy": true, "http_proxy": true, "mcp_stdio": true,
		"mcp_http": true, "websocket": true, "a2a": true,
		"tls_interception": true, "request_body_scanning": true,
		"header_scanning": true, "response_scanning": true,
		"mcp_tool_baseline": true, "mcp_chain_memory": true,
		"websocket_frame_scanning": true, "a2a_scanning": true,
		"shell_analysis": true, "dns_rebinding_fixture": true,
	}
	p := Profile{Claims: []string{"url_dlp"}, Supports: supports}
	ts := buildToolSupport(p)
	if len(ts.UnsupportedTransports) != 0 {
		t.Errorf("expected no unsupported transports, got %v", ts.UnsupportedTransports)
	}
	if len(ts.UnsupportedRequires) != 0 {
		t.Errorf("expected no unsupported requires, got %v", ts.UnsupportedRequires)
	}
}

func TestComputeCorpusSHA256NonexistentDir(t *testing.T) {
	_, err := computeCorpusSHA256("/nonexistent/dir")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestWriteSummaryBadPath(t *testing.T) {
	s := GauntletSummary{Tool: "test"}
	err := writeSummary(s, "/nonexistent/dir/summary.json")
	if err == nil {
		t.Fatal("expected error for bad path")
	}
}

func TestBuildSummaryErrorPath(t *testing.T) {
	p := Profile{Tool: "test", ToolVersion: "1.0"}
	_, err := buildSummary(p, nil, nil, nil, 0, "/nonexistent/dir", nil, "/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for nonexistent cases dir")
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

func TestComputeProfileSHA256(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	hash1, err := computeProfileSHA256(path)
	if err != nil {
		t.Fatalf("computeProfileSHA256: %v", err)
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Same content = same hash.
	hash2, err := computeProfileSHA256(path)
	if err != nil {
		t.Fatalf("computeProfileSHA256: %v", err)
	}
	if hash1 != hash2 {
		t.Errorf("hash should be deterministic: %s != %s", hash1, hash2)
	}
}

func TestComputeProfileSHA256BadPath(t *testing.T) {
	_, err := computeProfileSHA256("/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for nonexistent path")
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
		GauntletVersion:   gauntletVersion,
		ScoringVersion:    scoringVersion,
		RunnerVersion:     runnerVersion,
		Tool:              "test-tool",
		ToolVersion:       "1.0.0",
		CorpusVersion:     "v2.0.0",
		CorpusSHA256:      "abc123",
		ToolProfileSHA256: "def456",
		Date:              "2026-03-28T00:00:00Z",
		CaseCount: CaseCount{
			Total:         100,
			Applicable:    90,
			NotApplicable: 10,
			NotApplicableReasons: map[string]int{
				"missing_capability":    5,
				"missing_requires":      3,
				"unsupported_transport": 2,
			},
			Errors: 0,
		},
		ToolSupport: ToolSupport{
			Claims:                []string{"url_dlp"},
			UnsupportedTransports: []string{"a2a"},
			UnsupportedRequires:   []string{"dns_rebinding_fixture"},
		},
		Scores: DualScores{
			Full: Scores{
				Containment:       &containment,
				FalsePositiveRate: &fpRate,
				Detection:         &detection,
				Evidence:          &evidence,
			},
			Applicable: Scores{
				Containment:       &containment,
				FalsePositiveRate: &fpRate,
				Detection:         &detection,
				Evidence:          &evidence,
			},
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
	if parsed.ScoringVersion != scoringVersion {
		t.Errorf("scoring_version = %q, want %q", parsed.ScoringVersion, scoringVersion)
	}
	if parsed.ToolProfileSHA256 != "def456" {
		t.Errorf("tool_profile_sha256 = %q, want def456", parsed.ToolProfileSHA256)
	}
	if parsed.Scores.Full.Containment == nil || *parsed.Scores.Full.Containment != 0.95 {
		t.Errorf("full containment = %v, want 0.95", ptrVal(parsed.Scores.Full.Containment))
	}
	if parsed.Scores.Applicable.Containment == nil || *parsed.Scores.Applicable.Containment != 0.95 {
		t.Errorf("applicable containment = %v, want 0.95", ptrVal(parsed.Scores.Applicable.Containment))
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
