package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCases(t *testing.T) {
	dir := t.TempDir()

	caseJSON := `{
		"schema_version": 4,
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

func TestLoadCasesNormalizesSchemaV4WarnToAllow(t *testing.T) {
	dir := t.TempDir()
	caseJSON := `{"schema_version":4,"id":"warn-case","expected_verdict":"warn"}`
	if err := os.WriteFile(filepath.Join(dir, "warn-case.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 || cases[0].ExpectedVerdict != "allow" {
		t.Fatalf("warn case = %+v, want one allow-normalized case", cases)
	}
}

func TestLoadCasesDoesNotFilterSupersession(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		// Must track activeSchemaVersion: loadCases returns an error rather than
		// skipping on a version mismatch, so a stale version here makes this test
		// fail on its own loadCases call before it tests supersession at all.
		"old.json": `{"schema_version":4,"id":"old"}`,
		"new.json": `{"schema_version":4,"id":"new","supersedes":"old"}`,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("expected both sides of supersession to load, got %d cases", len(cases))
	}

	loaded := make(map[string]Case, len(cases))
	for _, c := range cases {
		loaded[c.ID] = c
	}
	if _, ok := loaded["old"]; !ok {
		t.Fatal("superseded case was filtered from the executable corpus")
	}
	if _, ok := loaded["new"]; !ok {
		t.Fatal("superseding case was not loaded")
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

	v4Path := filepath.Join(dir, "active-v4.json")
	if err := os.WriteFile(v4Path, []byte(strings.Replace(v2, `"schema_version":2`, `"schema_version":4`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHistoricalCase(v4Path); err == nil {
		t.Fatal("historical reader accepted an active v4 case")
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
	path := filepath.Join(dir, "profile.json")
	data, err := os.ReadFile(filepath.Join("..", "examples", "runner-template", "tool-profile-template.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := loadProfile(path)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if p.Tool != "YOUR_TOOL_NAME" {
		t.Errorf("expected tool YOUR_TOOL_NAME, got %s", p.Tool)
	}
	if len(p.Claims) != 0 {
		t.Errorf("unexpected claims: %v", p.Claims)
	}
}

func TestLoadProfileRejectsMissingRunField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	profileJSON := `{"schema_version":4,"tool":"test-tool","tool_version":"1.0.0","claims":[]}`
	if err := os.WriteFile(path, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "missing required field runner_version") {
		t.Fatalf("loadProfile error = %v, want missing runner_version", err)
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
	caseJSON := `{"schema_version": 4,"id":"test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"test"}`
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
		"schema_version": 4,
		"tool": "test-tool",
		"tool_version": "1.0.0",
		"runner_version": "v1",
		"claims": [],
		"capability_registry": {"id":"aeb.core-capabilities","format":1,"revision":1,"sha256":"f5ae9fa9cbb79e8539d50f0284e584eb6ea834232e801d3e1c269411a9527e9b"},
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

func TestMCPToolResultDLPCasesAreReportingLabeledAndProfileIndependent(t *testing.T) {
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}

	want := map[string]string{
		"mcp-tool-result-credential-014":                "block",
		"mcp-tool-result-credential-base64-015":         "block",
		"mcp-tool-result-credential-hex-016":            "block",
		"fp-mcp-tool-result-credential-placeholder-019": "allow",
	}
	seen := make(map[string]bool, len(want))
	for _, c := range cases {
		expected, ok := want[c.ID]
		if !ok {
			continue
		}
		seen[c.ID] = true
		if c.SchemaVersion != activeSchemaVersion || c.Transport != "mcp_stdio" || c.InputType != "mcp_tool_result" {
			t.Errorf("case %s active route = v%d/%s/%s", c.ID, c.SchemaVersion, c.Transport, c.InputType)
		}
		if c.ExpectedVerdict != expected {
			t.Errorf("case %s expected verdict = %q, want %q", c.ID, c.ExpectedVerdict, expected)
		}
		if len(c.Requires) != 0 {
			t.Errorf("case %s requires = %v, want no profile-controlled prerequisite", c.ID, c.Requires)
		}
		if !containsString(c.CapabilityTags, "mcp_tool_result_dlp_scanning") {
			t.Errorf("case %s capability_tags = %v, want mcp_tool_result_dlp_scanning", c.ID, c.CapabilityTags)
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("tool-result DLP case IDs = %v, want %v", seen, want)
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
