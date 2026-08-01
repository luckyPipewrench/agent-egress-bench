package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCases(t *testing.T) {
	dir := t.TempDir()

	caseJSON := `{
		"schema_version": 2,
		"id": "test-case-001",
		"category": "url",
		"title": "Test case",
		"description": "A test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["url_dlp"],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "test",
		"notes": "",
		"source": "test"
	}`

	if err := os.WriteFile(filepath.Join(dir, "test-case-001.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	if cases[0].ID != "test-case-001" {
		t.Errorf("expected ID test-case-001, got %s", cases[0].ID)
	}
	if cases[0].ExpectedVerdict != "block" {
		t.Errorf("expected verdict block, got %s", cases[0].ExpectedVerdict)
	}
}

func TestLoadCasesEmpty(t *testing.T) {
	dir := t.TempDir()
	_, err := loadCases(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	profileJSON := `{
		"schema_version": 2,
		"tool": "test-tool",
		"tool_version": "1.0.0",
		"runner_version": "v1",
		"claims": ["url_dlp"],
		"supports": {
			"fetch_proxy": true,
			"http_proxy": true,
			"mcp_stdio": false,
			"mcp_http": false,
			"websocket": false,
			"a2a": false,
			"tls_interception": false,
			"request_body_dlp_scanning": false,
			"header_dlp_scanning": false,
			"response_prompt_injection_scanning": false,
			"mcp_tool_baseline": false,
			"mcp_chain_memory": false,
			"websocket_dlp_scanning": false,
			"a2a_dlp_scanning": false,
			"shell_analysis": false,
			"dns_rebinding_fixture": false
		}
	}`
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := loadProfile(path)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if p.Tool != "test-tool" {
		t.Errorf("expected tool test-tool, got %s", p.Tool)
	}
	if len(p.Claims) != 1 || p.Claims[0] != "url_dlp" {
		t.Errorf("unexpected claims: %v", p.Claims)
	}
}

func TestLoadCasesInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCases(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadCasesNonexistentDir(t *testing.T) {
	_, err := loadCases("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadCasesSkipsNonJSON(t *testing.T) {
	dir := t.TempDir()
	// Write a valid case and a non-JSON file.
	caseJSON := `{"schema_version":2,"id":"test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"test"}`
	if err := os.WriteFile(filepath.Join(dir, "test-001.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a case"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected 1 case (skip .txt), got %d", len(cases))
	}
}

func TestLoadProfileNotFound(t *testing.T) {
	_, err := loadProfile("/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestLoadProfileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProfile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProfileRejectsUnknownReceiptEvidenceField(t *testing.T) {
	dir := t.TempDir()
	profileJSON := `{
		"schema_version": 1,
		"tool": "test-tool",
		"tool_version": "1.0.0",
		"runner_version": "v1",
		"claims": [],
		"supports": {},
		"receipt_evidence": {
			"evidence_dir": "/tmp/evidence",
			"file_glob": "*.jsonl",
			"jsonl_record_type": "action_receipt",
			"detail_json_pointer": "/detail",
			"detail_encoding": "object_or_json_string",
			"record_identifier_json_pointer": "/action_record/target",
			"case_identifier_json_pointer": "/payload/url",
			"verify_command": ["receipt-verify", "{evidence_file}"],
			"verify_timeout_seconds": 10,
			"valid_exit_codes": [0],
			"unexpected": true
		}
	}`
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProfile(path)
	if err == nil {
		t.Fatal("expected error for unknown receipt_evidence field")
	}
}

func TestCheckApplicability(t *testing.T) {
	profile := Profile{
		Claims: []string{"url_dlp", "benign"},
		Supports: map[string]bool{
			"fetch_proxy":               true,
			"http_proxy":                true,
			"mcp_stdio":                 false,
			"tls_interception":          true,
			"request_body_dlp_scanning": false,
			"dns_rebinding_fixture":     false,
		},
	}

	tests := []struct {
		name      string
		c         Case
		wantNA    NAKind
		wantApply bool
	}{
		{
			name: "fully applicable",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"tls_interception"},
				Transport:      "fetch_proxy",
			},
			wantApply: true,
		},
		{
			name: "capability tags do not affect applicability",
			c: Case{
				CapabilityTags: []string{"mcp_input_scan"},
				Requires:       []string{},
				Transport:      "fetch_proxy",
			},
			wantApply: true,
		},
		{
			name: "missing requires",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"request_body_dlp_scanning"},
				Transport:      "fetch_proxy",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
		{
			name: "unsupported transport",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAUnsupportedTransport,
			wantApply: false,
		},
		{
			name: "requires checked before transport",
			c: Case{
				CapabilityTags: []string{"mcp_input_scan"},
				Requires:       []string{"request_body_dlp_scanning"},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
		{
			name: "requires checked before transport with claimed tag",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"dns_rebinding_fixture"},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, applicable := checkApplicability(tt.c, profile)
			if applicable != tt.wantApply {
				t.Errorf("applicable = %v, want %v", applicable, tt.wantApply)
			}
			if !applicable && reason != tt.wantNA {
				t.Errorf("reason = %q, want %q", reason, tt.wantNA)
			}
		})
	}
}

func TestNeedsMCPMockBackendPreflight(t *testing.T) {
	profile := Profile{
		Claims: []string{"mcp_tool_poison", "url_dlp"},
		Supports: map[string]bool{
			"fetch_proxy":              true,
			"mcp_stdio":                true,
			"mcp_http":                 true,
			"mcp_tool_poison_scanning": true,
		},
	}

	tests := []struct {
		name  string
		cases []Case
		want  bool
	}{
		{
			name: "mcp server response in scope",
			cases: []Case{{
				CapabilityTags: []string{"mcp_tool_poison"},
				Requires:       []string{"mcp_tool_poison_scanning"},
				Transport:      "mcp_stdio",
				Payload: map[string]interface{}{
					"jsonrpc_messages": []interface{}{
						map[string]interface{}{"result": map[string]interface{}{"tools": []interface{}{}}},
					},
				},
			}},
			want: true,
		},
		{
			name: "fetch-only case does not need mcp preflight",
			cases: []Case{{
				CapabilityTags: []string{"url_dlp"},
				Transport:      "fetch_proxy",
				Payload:        map[string]interface{}{"url": "https://example.com"},
			}},
			want: false,
		},
		{
			name: "unsupported mcp case does not need preflight",
			cases: []Case{{
				CapabilityTags: []string{"unsupported_capability"},
				Requires:       []string{"unsupported_capability"},
				Transport:      "mcp_stdio",
				Payload: map[string]interface{}{
					"jsonrpc_messages": []interface{}{
						map[string]interface{}{"result": map[string]interface{}{"tools": []interface{}{}}},
					},
				},
			}},
			want: false,
		},
		{
			name: "mcp client-only request does not inject mock backend",
			cases: []Case{{
				CapabilityTags: []string{"mcp_tool_poison"},
				Requires:       []string{"mcp_tool_poison_scanning"},
				Transport:      "mcp_stdio",
				Payload: map[string]interface{}{
					"jsonrpc_messages": []interface{}{
						map[string]interface{}{"method": "tools/call"},
					},
				},
			}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := needsMCPMockBackendPreflight(tt.cases, profile); got != tt.want {
				t.Fatalf("needsMCPMockBackendPreflight() = %v, want %v", got, tt.want)
			}
		})
	}
}
