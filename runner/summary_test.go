package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func summaryTestSupports(v bool) map[string]bool {
	keys := []string{
		"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a",
		"tls_interception",
		"url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning",
		"response_prompt_injection_scanning",
		"mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning",
		"mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning",
		"mcp_tool_poison_scanning", "mcp_tool_baseline", "mcp_chain_memory",
		"mcp_cross_server_chain_memory", "mcp_data_class_labels",
		"a2a_dlp_scanning", "a2a_prompt_injection_scanning",
		"a2a_card_prompt_injection_scanning", "a2a_card_drift_scanning",
		"a2a_ssrf_scanning",
		"websocket_dlp_scanning", "websocket_prompt_injection_scanning",
		"ssrf_scanning", "ssrf_bypass_scanning", "domain_blocklist",
		"entropy_scanning", "encoding_evasion_scanning", "shell_analysis",
		"crypto_dlp_scanning", "hostname_exfil_scanning", "dns_rebinding_fixture",
		"budget_enforcement",
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = v
	}
	return out
}

func TestBuildToolSupport(t *testing.T) {
	supports := summaryTestSupports(false)
	supports["fetch_proxy"] = true
	supports["http_proxy"] = true
	supports["tls_interception"] = true

	p := Profile{
		Claims:   []string{"url_dlp", "ssrf"},
		Supports: supports,
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
	supports := summaryTestSupports(true)
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
	_, err := computeCorpusSHA256("/nonexistent/dir", "")
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

func TestWriteSummaryRejectsPreV3Artifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	if err := writeSummary(GauntletSummary{SchemaVersion: 2, Tool: "test"}, path); err == nil {
		t.Fatal("writeSummary accepted a pre-v3 summary")
	}
}

func TestBuildSummaryErrorPath(t *testing.T) {
	p := Profile{Tool: "test", ToolVersion: "1.0"}
	_, err := buildSummary(p, nil, nil, nil, nil, "/nonexistent/dir", "", nil, "/nonexistent/profile.json", RunProvenance{})
	if err == nil {
		t.Fatal("expected error for nonexistent cases dir")
	}
}

func TestCountErrorsDerivesFromApplicableResults(t *testing.T) {
	results := []CaseResult{
		{CaseID: "pass", ActualVerdict: "block", Score: "pass"},
		{CaseID: "failed", ActualVerdict: "allow", Score: "fail"},
		{CaseID: "errored", ActualVerdict: "error", Score: "error"},
	}
	got, err := countErrors(results)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("countErrors() = %d, want 1", got)
	}
}

func TestCountErrorsRejectsInconsistentResult(t *testing.T) {
	_, err := countErrors([]CaseResult{{CaseID: "laundered", ActualVerdict: "error", Score: "pass"}})
	if err == nil {
		t.Fatal("countErrors() accepted an error verdict with a non-error score")
	}
}

func TestBuildSummaryUsesFixedDateEnv(t *testing.T) {
	t.Setenv(summaryDateEnv, "2026-07-13T20:00:00Z")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := buildSummary(
		Profile{Tool: "test", ToolVersion: "1.0", Supports: summaryTestSupports(true)},
		[]Case{{ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		nil,
		nil,
		nil,
		dir,
		"",
		map[string]Case{"a": {ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		profilePath,
		RunProvenance{},
	)
	if err != nil {
		t.Fatalf("buildSummary: %v", err)
	}
	if summary.Date != "2026-07-13T20:00:00Z" {
		t.Fatalf("date = %q, want fixed env date", summary.Date)
	}
}

func TestBuildSummaryRejectsInvalidFixedDateEnv(t *testing.T) {
	t.Setenv(summaryDateEnv, "not-rfc3339")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := buildSummary(
		Profile{Tool: "test", ToolVersion: "1.0", Supports: summaryTestSupports(true)},
		[]Case{{ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		nil,
		nil,
		nil,
		dir,
		"",
		map[string]Case{"a": {ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		profilePath,
		RunProvenance{},
	)
	if err == nil || !strings.Contains(err.Error(), "must be empty or RFC3339") {
		t.Fatalf("buildSummary error = %v, want invalid fixed-date rejection", err)
	}
}

func TestBuildSummaryKeepsUnreachableOutsideScoreableErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := buildSummary(
		Profile{Tool: "test", ToolVersion: "1.0", Supports: summaryTestSupports(true)},
		[]Case{{ID: "a", Category: "url", ExpectedVerdict: "block"}},
		nil,
		map[string]struct{}{"a": {}},
		nil,
		dir,
		"",
		map[string]Case{"a": {ID: "a", Category: "url", ExpectedVerdict: "block"}},
		profilePath,
		RunProvenance{},
	)
	if err != nil {
		t.Fatalf("buildSummary: %v", err)
	}
	if summary.CaseCount.Applicable != 0 || summary.CaseCount.Unreachable != 1 || summary.CaseCount.Errors != 0 {
		t.Fatalf("case count = %+v, want unreachable distinct from scoreable errors", summary.CaseCount)
	}
	if summary.Sufficient {
		t.Fatal("summary with an unreachable case must be insufficient")
	}
}

func TestWriteSummaryOmitsEmptyDate(t *testing.T) {
	t.Setenv(summaryDateEnv, "")

	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	if err := writeSummary(GauntletSummary{Tool: "test", Date: ""}, path); err != nil {
		t.Fatalf("writeSummary: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}
	if strings.Contains(string(data), `"date"`) {
		t.Fatalf("date field should be omitted when empty: %s", string(data))
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

	hash1, err := computeCorpusSHA256(dir, "")
	if err != nil {
		t.Fatalf("computeCorpusSHA256: %v", err)
	}
	if hash1 == "" {
		t.Error("hash should not be empty")
	}

	// Same files = same hash.
	hash2, err := computeCorpusSHA256(dir, "")
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
	hash3, err := computeCorpusSHA256(dir, "")
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
		CorpusVersion:     corpusVersion,
		CorpusSHA256:      "abc123",
		ToolProfileSHA256: "def456",
		Date:              "2026-03-28T00:00:00Z",
		CaseCount: CaseCount{
			Total:         100,
			Applicable:    90,
			NotApplicable: 10,
			NotApplicableReasons: map[string]int{
				"missing_requires":      8,
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
	if parsed.SchemaVersion != activeSchemaVersion {
		t.Errorf("summary schema_version = %d, want %d", parsed.SchemaVersion, activeSchemaVersion)
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
