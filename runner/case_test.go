package main

import (
	"encoding/json"
	"fmt"
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

func TestCaseLoadersPreserveLargeMCPInitializeIDs(t *testing.T) {
	dir := t.TempDir()
	caseJSON := []byte(`{
		"schema_version": 4,
		"id": "mcp-large-initialize-id-001",
		"category": "mcp_tool",
		"title": "Large initialize ID",
		"description": "Preserves an exact JSON-RPC identifier",
		"input_type": "mcp_initialize_response",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [
			{"jsonrpc": "2.0", "id": 9007199254740993, "method": "initialize"},
			{"jsonrpc": "2.0", "id": 9007199254740993, "result": {}}
		]},
		"expected_verdict": "allow",
		"severity": "low",
		"capability_tags": [],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "test",
		"notes": "",
		"source": "test"
	}`)
	path := filepath.Join(dir, "mcp-large-initialize-id-001.json")
	if err := os.WriteFile(path, caseJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	fromDisk, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	fromSnapshot, err := loadCasesFromSnapshot([]corpusFile{{hashPath: hashPath{path: "mcp-tool/mcp-large-initialize-id-001.json"}, data: caseJSON}}, nil)
	if err != nil {
		t.Fatalf("loadCasesFromSnapshot: %v", err)
	}

	for name, loaded := range map[string][]Case{"disk": fromDisk, "snapshot": fromSnapshot} {
		t.Run(name, func(t *testing.T) {
			if len(loaded) != 1 {
				t.Fatalf("loaded cases = %d, want 1", len(loaded))
			}
			messages, ok := loaded[0].Payload["jsonrpc_messages"].([]interface{})
			if !ok || len(messages) != 2 {
				t.Fatalf("jsonrpc_messages = %#v, want request and response", loaded[0].Payload["jsonrpc_messages"])
			}
			for index, raw := range messages {
				message, ok := raw.(map[string]interface{})
				if !ok {
					t.Fatalf("message %d = %#v, want object", index, raw)
				}
				id, ok := message["id"].(json.Number)
				if !ok || id.String() != "9007199254740993" {
					t.Fatalf("message %d id = %#v, want exact json.Number", index, message["id"])
				}
			}
		})
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
	// Built from activeCaseSchemaVersion rather than a literal. loadCases returns
	// an error rather than skipping on a version mismatch, so a hardcoded version
	// makes this test fail inside its own loadCases call the first time the case
	// family moves, reporting a version problem where the subject is supersession.
	files := map[string]string{
		"old.json": fmt.Sprintf(`{"schema_version":%d,"id":"old"}`, activeCaseSchemaVersion),
		"new.json": fmt.Sprintf(`{"schema_version":%d,"id":"new","supersedes":"old"}`, activeCaseSchemaVersion),
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
		if c.SchemaVersion != activeCaseSchemaVersion || c.Transport != "mcp_stdio" || c.InputType != "mcp_tool_result" {
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

// The runner and the validator must accept exactly the same field set. A
// permissive runner would execute a case with an undeclared field silently
// dropped, so the same file would behave differently depending on whether the
// validator gate ran first.
func TestLoadCasesRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	caseJSON := fmt.Sprintf(`{"schema_version":%d,"id":"unknown-field-case","expected_verdict":"block","expected_verdet":"allow"}`, activeCaseSchemaVersion)
	if err := os.WriteFile(filepath.Join(dir, "unknown-field-case.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := loadCases(dir)
	if err == nil {
		t.Fatal("loadCases accepted an undeclared field; the validator rejects it")
	}
	if !strings.Contains(err.Error(), "expected_verdet") {
		t.Errorf("error should name the undeclared field, got %v", err)
	}
}

// supersedes is declared by the validator and carries no scoring meaning, so
// strict decoding must still accept it. Without the matching runner field a
// case the validator calls valid would fail to execute.
func TestLoadCasesAcceptsSupersedes(t *testing.T) {
	dir := t.TempDir()
	caseJSON := fmt.Sprintf(`{"schema_version":%d,"id":"superseding-case","expected_verdict":"block","supersedes":"old-case-001"}`, activeCaseSchemaVersion)
	if err := os.WriteFile(filepath.Join(dir, "superseding-case.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases rejected a validator-accepted field: %v", err)
	}
	if len(cases) != 1 || cases[0].Supersedes != "old-case-001" {
		t.Fatalf("supersedes not parsed: %+v", cases)
	}
}

func TestAllowlistedHelperCasesAreReportingLabeledAndProfileIndependent(t *testing.T) {
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	type want struct {
		verdict string
		input   string
		tag     string
	}
	wants := map[string]want{
		"ssrf-relay-nested-target-014":              {"block", "url", "ssrf"},
		"url-covert-webdav-path-015":                {"block", "url", "operation_policy"},
		"request-body-write-to-fetch-only-host-016": {"block", "request_body", "operation_policy"},
		"url-relay-app-second-hop-017":              {"block", "url", "ssrf"},
		"fp-mirror-package-fetch-018":               {"allow", "url", "benign"},
		"fp-fetch-only-registry-read-020":           {"allow", "url", "benign"},
	}
	seen := make(map[string]Case, len(wants))
	for _, c := range cases {
		w, ok := wants[c.ID]
		if !ok {
			continue
		}
		seen[c.ID] = c
		if c.SchemaVersion != activeCaseSchemaVersion || c.Transport != "http_proxy" || c.InputType != w.input {
			t.Errorf("case %s active route = v%d/%s/%s", c.ID, c.SchemaVersion, c.Transport, c.InputType)
		}
		if c.ExpectedVerdict != w.verdict {
			t.Errorf("case %s expected verdict = %q, want %q", c.ID, c.ExpectedVerdict, w.verdict)
		}
		if !containsString(c.CapabilityTags, w.tag) {
			t.Errorf("case %s capability_tags = %v, want %s", c.ID, c.CapabilityTags, w.tag)
		}
		// requires must stay delivery-only: no enforcement-claim tokens.
		for _, r := range c.Requires {
			if r == "budget_enforcement" || r == "ssrf_bypass_scanning" || r == "operation_policy" {
				t.Errorf("case %s requires carries enforcement token %q", c.ID, r)
			}
		}
	}
	if len(seen) != len(wants) {
		t.Fatalf("allowlisted-helper case IDs = %v, want %v", seen, wants)
	}
	writeCase := seen["request-body-write-to-fetch-only-host-016"]
	readCase := seen["fp-fetch-only-registry-read-020"]
	if writeCase.Payload["method"] != "PUT" || readCase.Payload["method"] != "GET" {
		t.Fatalf("fetch-only method pair = write %v/read %v, want PUT/GET", writeCase.Payload["method"], readCase.Payload["method"])
	}
	if writeCase.Payload["url"] != "https://allowed-package-registry.test/packages/agent-collab/1.0.0" ||
		readCase.Payload["url"] != writeCase.Payload["url"] {
		t.Fatalf("fetch-only pair no longer uses the exact same URL: write %v/read %v", writeCase.Payload["url"], readCase.Payload["url"])
	}
}
