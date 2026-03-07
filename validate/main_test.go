package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// writeCase writes a JSON case file and returns the path.
func writeCase(t *testing.T, dir, subdir, filename, content string) string {
	t.Helper()
	casedir := filepath.Join(dir, subdir)
	if err := os.MkdirAll(casedir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(casedir, filename)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidCase(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-test-001.json", `{
		"schema_version": 1,
		"id": "url-test-001",
		"category": "url",
		"title": "Test URL case",
		"description": "Valid URL test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com/test"},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["url_dlp"],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-test-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors, got: %v", errors)
	}
}

func TestValidBenignCase(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-benign-001.json", `{
		"schema_version": 1,
		"id": "url-benign-001",
		"category": "url",
		"title": "Benign URL case",
		"description": "Valid benign URL test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://api.example.com/data"},
		"expected_verdict": "allow",
		"severity": "low",
		"capability_tags": ["benign"],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "normal_api_call",
		"safe_example": true,
		"notes": "",
		"source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-benign-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors, got: %v", errors)
	}
}

func TestMissingPayloadFields(t *testing.T) {
	tests := []struct {
		name      string
		subdir    string
		filename  string
		json      string
		wantError string
	}{
		{
			name:     "header case missing payload.headers",
			subdir:   "headers",
			filename: "header-test-001.json",
			json: `{
				"schema_version": 1, "id": "header-test-001", "category": "headers",
				"title": "T", "description": "D", "input_type": "header",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["header_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload missing required key "headers"`,
		},
		{
			name:     "url case missing payload.url",
			subdir:   "url",
			filename: "url-test-001.json",
			json: `{
				"schema_version": 1, "id": "url-test-001", "category": "url",
				"title": "T", "description": "D", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload missing required key "url"`,
		},
		{
			name:     "request_body case missing payload.body",
			subdir:   "request-body",
			filename: "body-test-001.json",
			json: `{
				"schema_version": 1, "id": "body-test-001", "category": "request_body",
				"title": "T", "description": "D", "input_type": "request_body",
				"transport": "fetch_proxy",
				"payload": {"method": "POST", "url": "https://example.com", "content_type": "application/json"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["request_body_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload missing required key "body"`,
		},
		{
			name:     "response case missing payload.response_body",
			subdir:   "response-fetch",
			filename: "response-test-001.json",
			json: `{
				"schema_version": 1, "id": "response-test-001", "category": "response_fetch",
				"title": "T", "description": "D", "input_type": "response_content",
				"transport": "fetch_proxy",
				"payload": {"url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["response_injection"], "requires": ["response_scanning"],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload missing required key "response_body"`,
		},
		{
			name:     "MCP case missing payload.jsonrpc_messages",
			subdir:   "mcp-input",
			filename: "mcp-test-001.json",
			json: `{
				"schema_version": 1, "id": "mcp-test-001", "category": "mcp_input",
				"title": "T", "description": "D", "input_type": "mcp_tool_call",
				"transport": "mcp_stdio",
				"payload": {"something": "else"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["mcp_input_scan"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload missing required key "jsonrpc_messages"`,
		},
		{
			name:     "MCP case with empty jsonrpc_messages array",
			subdir:   "mcp-input",
			filename: "mcp-test-002.json",
			json: `{
				"schema_version": 1, "id": "mcp-test-002", "category": "mcp_input",
				"title": "T", "description": "D", "input_type": "mcp_tool_call",
				"transport": "mcp_stdio",
				"payload": {"jsonrpc_messages": []},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["mcp_input_scan"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: `payload.jsonrpc_messages must not be empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCase(t, dir, tt.subdir, tt.filename, tt.json)
			ids := make(map[string]string)
			path := filepath.Join(dir, tt.subdir, tt.filename)
			errors := validateFile(path, ids)
			if len(errors) == 0 {
				t.Fatal("expected validation error, got none")
			}
			found := false
			for _, e := range errors {
				if containsStr(e, tt.wantError) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected error containing %q, got: %v", tt.wantError, errors)
			}
		})
	}
}

func TestCategoryInputTypeMismatch(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-tool", "mcp-bad-001.json", `{
		"schema_version": 1, "id": "mcp-bad-001", "category": "mcp_tool",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_tool_poison"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-tool", "mcp-bad-001.json")
	errors := validateFile(path, ids)

	wantInputErr := `category "mcp_tool" does not allow input_type "url"`
	wantTransportErr := `category "mcp_tool" does not allow transport "fetch_proxy"`

	if len(errors) < 2 {
		t.Fatalf("expected at least 2 errors, got %d: %v", len(errors), errors)
	}
	if !containsStr(errors[0], wantInputErr) && !containsStr(errors[1], wantInputErr) {
		t.Errorf("expected error containing %q, got: %v", wantInputErr, errors)
	}
	if !containsStr(errors[0], wantTransportErr) && !containsStr(errors[1], wantTransportErr) {
		t.Errorf("expected error containing %q, got: %v", wantTransportErr, errors)
	}
}

func TestBenignCaseMissingSafeExample(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-benign-bad-001.json", `{
		"schema_version": 1, "id": "url-benign-bad-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "allow", "severity": "low",
		"capability_tags": ["benign"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-benign-bad-001.json")
	errors := validateFile(path, ids)
	if len(errors) == 0 {
		t.Fatal("expected error for missing safe_example, got none")
	}
	found := false
	for _, e := range errors {
		if containsStr(e, "safe_example") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected error about safe_example, got: %v", errors)
	}
}

func TestDuplicateID(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-dup-001.json", `{
		"schema_version": 1, "id": "url-dup-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := map[string]string{"url-dup-001": "some/other/path.json"}
	path := filepath.Join(dir, "url", "url-dup-001.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if containsStr(e, "duplicate id") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected duplicate ID error, got: %v", errors)
	}
}

func TestIDFilenameMismatch(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "wrong-name.json", `{
		"schema_version": 1, "id": "url-test-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "wrong-name.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if containsStr(e, "does not match filename") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected filename mismatch error, got: %v", errors)
	}
}

func TestPayloadHeadersMustBeObject(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "headers", "header-bad-001.json", `{
		"schema_version": 1, "id": "header-bad-001", "category": "headers",
		"title": "T", "description": "D", "input_type": "header",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com", "headers": "not-an-object"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["header_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "headers", "header-bad-001.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if containsStr(e, "payload.headers must be an object") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected object type error, got: %v", errors)
	}
}

func TestWebsocketTransportAllowedForHTTPCategories(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-ws-001.json", `{
		"schema_version": 1, "id": "url-ws-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "websocket",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-ws-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("websocket should be valid for url category, got errors: %v", errors)
	}
}

func TestWebsocketTransportRejectedForMCPCategories(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-input", "mcp-ws-001.json", `{
		"schema_version": 1, "id": "mcp-ws-001", "category": "mcp_input",
		"title": "T", "description": "D", "input_type": "mcp_tool_call",
		"transport": "websocket",
		"payload": {"jsonrpc_messages": [{"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_input_scan"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-input", "mcp-ws-001.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if containsStr(e, `does not allow transport "websocket"`) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected transport rejection for mcp_input+websocket, got: %v", errors)
	}
}

func TestMITMOnlyAllowsHTTPProxy(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "response-mitm", "response-mitm-bad-001.json", `{
		"schema_version": 1, "id": "response-mitm-bad-001", "category": "response_mitm",
		"title": "T", "description": "D", "input_type": "response_content",
		"transport": "fetch_proxy",
		"payload": {"url": "https://example.com", "response_body": "test"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["response_injection"], "requires": ["response_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "response-mitm", "response-mitm-bad-001.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if containsStr(e, `does not allow transport "fetch_proxy"`) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected transport rejection for response_mitm+fetch_proxy, got: %v", errors)
	}
}

func TestCLIRequiresArgument(t *testing.T) {
	// Build the validator binary
	binPath := filepath.Join(t.TempDir(), "validate")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run with no arguments
	cmd := exec.Command(binPath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit code with no arguments")
	}
	if !containsStr(string(output), "usage:") {
		t.Errorf("expected usage message, got: %s", output)
	}
}

func TestAllExistingCasesValid(t *testing.T) {
	// Validate the actual corpus to make sure the validator doesn't break real cases.
	casesDir := "../cases"
	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found (running outside repo)")
	}

	ids := make(map[string]string)
	var allErrors []string

	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(info.Name()) != ".json" {
			return nil
		}
		fileErrors := validateFile(path, ids)
		allErrors = append(allErrors, fileErrors...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk error: %v", err)
	}
	if len(allErrors) > 0 {
		for _, e := range allErrors {
			t.Errorf("validation error: %s", e)
		}
	}
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
