package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestLoadCases(t *testing.T) {
	dir := t.TempDir()

	caseJSON := `{
		"schema_version": 3,
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

func TestScorerRejectsV2CaseButHistoricalReaderPreservesIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "historical-v2.json")
	v2 := `{"schema_version":2,"id":"historical-v2","category":"url","title":"Historical","description":"Frozen v2 record","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"historical","notes":"","source":"original"}`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadCases(dir); err == nil {
		t.Fatal("scorer accepted a v2 case instead of rejecting the active/historical version mix")
	}
	historical, err := readHistoricalCase(path)
	if err != nil {
		t.Fatalf("readHistoricalCase: %v", err)
	}
	if historical.SchemaVersion != 2 || historical.ID != "historical-v2" {
		t.Fatalf("historical record changed while reading: %#v", historical)
	}

	v3Path := filepath.Join(dir, "active-v3.json")
	if err := os.WriteFile(v3Path, []byte(strings.Replace(v2, `"schema_version":2`, `"schema_version":3`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHistoricalCase(v3Path); err == nil {
		t.Fatal("historical reader accepted an active v3 case")
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
		"schema_version": 3,
		"tool": "test-tool",
		"tool_version": "1.0.0",
		"runner_version": "v1",
		"claims": ["url_dlp"],
		"supports": {"fetch_proxy":true,"http_proxy":true,"mcp_stdio":false,"mcp_http":false,"websocket":false,"a2a":false,"tls_interception":false,"url_dlp_scanning":false,"request_body_dlp_scanning":false,"header_dlp_scanning":false,"response_prompt_injection_scanning":false,"mcp_input_dlp_scanning":false,"mcp_input_prompt_injection_scanning":false,"mcp_tool_policy":false,"mcp_tool_result_prompt_injection_scanning":false,"mcp_tool_poison_scanning":false,"mcp_tool_baseline":false,"mcp_chain_memory":false,"mcp_cross_server_chain_memory":false,"mcp_data_class_labels":false,"a2a_dlp_scanning":false,"a2a_prompt_injection_scanning":false,"a2a_card_prompt_injection_scanning":false,"a2a_card_drift_scanning":false,"a2a_ssrf_scanning":false,"websocket_dlp_scanning":false,"websocket_prompt_injection_scanning":false,"ssrf_scanning":false,"ssrf_bypass_scanning":false,"domain_blocklist":false,"entropy_scanning":false,"encoding_evasion_scanning":false,"shell_analysis":false,"crypto_dlp_scanning":false,"hostname_exfil_scanning":false,"dns_rebinding_fixture":false,"budget_enforcement":false}
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

func TestLoadProfileRejectsPreV3Artifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2,"tool":"old-tool","tool_version":"1.0.0","runner_version":"v1","claims":[],"supports":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil {
		t.Fatal("scorer accepted a pre-v3 profile")
	}
}

func TestLoadProfileRejectsOmittedSupportsKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data, err := os.ReadFile("../examples/pipelock/tool-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(data), `"mcp_http": true,`, ``, 1)
	if err := os.WriteFile(path, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), `missing required supports key "mcp_http"`) {
		t.Fatalf("loadProfile error = %v, want named omitted supports key", err)
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
	caseJSON := `{"schema_version": 3,"id":"test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"test"}`
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
		"schema_version": 3,
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

// The denial-of-wallet cases used to gate on budget_enforcement, an enforcement
// claim rather than an observation surface. Because the Pipelock profile
// declines that claim, all three -- including the benign control that measures
// over-blocking -- were rendered not_applicable, so a tool could opt out of the
// family by not claiming it. They now gate on the chain surface their nine
// malicious siblings already use, and the benign control gates on nothing.
//
// This test previously asserted the opposite (that the three were
// not_applicable), which locked the escape hatch in place. It is inverted
// deliberately: a test that encodes the dodge is a liability, not coverage.
func TestPipelockDenialOfWalletCasesAreApplicable(t *testing.T) {
	profile, err := loadProfile("../examples/pipelock/tool-profile.json")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}

	wantIDs := map[string]bool{
		"mcp-chain-dow-budget-exceeded-010":             true,
		"mcp-chain-dow-under-budget-011":                true,
		"mcp-chain-dow-interleaved-budget-exceeded-012": true,
	}
	seen := make(map[string]bool)
	for _, c := range cases {
		// Identify the family by capability tag, not by requires: the whole
		// point of the fix is that requires no longer names the feature.
		if !slices.Contains(c.CapabilityTags, "denial_of_wallet") {
			continue
		}
		seen[c.ID] = true

		if _, applicable := checkApplicability(c, profile); !applicable {
			t.Errorf("case %s is not applicable to the Pipelock profile; a denial-of-wallet case must not be skippable by declining budget_enforcement", c.ID)
		}
		if slices.Contains(c.Requires, "budget_enforcement") {
			t.Errorf("case %s gates on budget_enforcement; applicability must gate on the observation surface, not the enforcement claim under test", c.ID)
		}
	}

	if len(seen) != len(wantIDs) {
		t.Fatalf("denial_of_wallet case IDs = %v, want %v", seen, wantIDs)
	}
	for id := range wantIDs {
		if !seen[id] {
			t.Errorf("missing denial-of-wallet case %s", id)
		}
	}
}
