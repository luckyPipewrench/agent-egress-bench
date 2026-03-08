// validate checks all case JSON files against the agent-egress-bench spec.
// stdlib-only. No external dependencies.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Valid enum values for v1 schema.
var (
	validCategories = map[string]bool{
		"url": true, "request_body": true, "headers": true,
		"response_fetch": true, "response_mitm": true,
		"mcp_input": true, "mcp_tool": true, "mcp_chain": true,
	}

	validInputTypes = map[string]bool{
		"url": true, "request_body": true, "header": true,
		"response_content": true, "mcp_tool_call": true, "mcp_tool_result": true,
		"mcp_tool_definition": true, "mcp_tool_sequence": true,
	}

	validTransports = map[string]bool{
		"fetch_proxy": true, "http_proxy": true,
		"mcp_stdio": true, "mcp_http": true, "websocket": true,
	}

	validVerdicts = map[string]bool{
		"block": true, "allow": true,
	}

	validSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true,
	}

	validFPRisk = map[string]bool{
		"low": true, "medium": true, "high": true,
	}

	validCapabilityTags = map[string]bool{
		"url_dlp": true, "request_body_dlp": true, "header_dlp": true,
		"response_injection": true, "mcp_input_scan": true, "mcp_tool_poison": true,
		"mcp_chain": true, "ssrf": true, "domain_blocklist": true,
		"entropy": true, "encoding_evasion": true, "benign": true,
	}

	validRequires = map[string]bool{
		"tls_interception": true, "request_body_scanning": true,
		"header_scanning": true, "response_scanning": true,
		"mcp_tool_baseline": true, "mcp_chain_memory": true,
	}

	validActualVerdicts = map[string]bool{
		"block": true, "allow": true, "not_applicable": true, "error": true,
	}

	validScores = map[string]bool{
		"pass": true, "fail": true, "not_applicable": true, "error": true,
	}

	validSupportsKeys = map[string]bool{
		"fetch_proxy": true, "http_proxy": true, "mcp_stdio": true, "mcp_http": true,
		"websocket": true, "tls_interception": true, "request_body_scanning": true,
		"header_scanning": true, "response_scanning": true, "mcp_tool_baseline": true,
		"mcp_chain_memory": true,
	}

	// Valid category → input_type combinations per SPEC.md.
	validCategoryInputType = map[string][]string{
		"url":            {"url"},
		"request_body":   {"request_body"},
		"headers":        {"header"},
		"response_fetch": {"response_content"},
		"response_mitm":  {"response_content"},
		"mcp_input":      {"mcp_tool_call"},
		"mcp_tool":       {"mcp_tool_result", "mcp_tool_definition"},
		"mcp_chain":      {"mcp_tool_sequence"},
	}

	// Valid category → transport combinations.
	// HTTP categories use fetch_proxy, http_proxy, or websocket.
	// MCP categories use mcp_stdio or mcp_http.
	// response_mitm specifically requires http_proxy (MITM needs CONNECT tunnel).
	validCategoryTransport = map[string][]string{
		"url":            {"fetch_proxy", "http_proxy", "websocket"},
		"request_body":   {"fetch_proxy", "http_proxy", "websocket"},
		"headers":        {"fetch_proxy", "http_proxy", "websocket"},
		"response_fetch": {"fetch_proxy", "http_proxy", "websocket"},
		"response_mitm":  {"http_proxy"},
		"mcp_input":      {"mcp_stdio", "mcp_http"},
		"mcp_tool":       {"mcp_stdio", "mcp_http"},
		"mcp_chain":      {"mcp_stdio", "mcp_http"},
	}
)

// Case represents a single benchmark case.
type Case struct {
	SchemaVersion   int                    `json:"schema_version"`
	ID              string                 `json:"id"`
	Category        string                 `json:"category"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	InputType       string                 `json:"input_type"`
	Transport       string                 `json:"transport"`
	Payload         map[string]interface{} `json:"payload"`
	ExpectedVerdict string                 `json:"expected_verdict"`
	Severity        string                 `json:"severity"`
	CapabilityTags  []string               `json:"capability_tags"`
	Requires        []string               `json:"requires"`
	FPRisk          string                 `json:"false_positive_risk"`
	WhyExpected     string                 `json:"why_expected"`
	SafeExample     *bool                  `json:"safe_example,omitempty"`
	Notes           string                 `json:"notes"`
	Source          string                 `json:"source"`
}

const usageText = `usage: validate <command> <target>

commands:
  cases   <dir>    validate case JSON files in a directory
  results <file>   validate a runner results JSONL file
  profile <file>   validate a tool profile JSON file

for backwards compatibility, 'validate <dir>' works as 'validate cases <dir>'.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "cases":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "usage: validate cases <cases-directory>\n")
			os.Exit(1)
		}
		os.Exit(runCases(os.Args[2]))
	case "results":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "usage: validate results <results-file>\n")
			os.Exit(1)
		}
		os.Exit(runResults(os.Args[2]))
	case "profile":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "usage: validate profile <profile-file>\n")
			os.Exit(1)
		}
		os.Exit(runProfile(os.Args[2]))
	default:
		// Backward compatibility: treat bare argument as cases directory.
		os.Exit(runCases(subcmd))
	}
}

func runCases(casesDir string) int {
	ids := make(map[string]string)
	var errors []string
	fileCount := 0

	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		fileCount++
		fileErrors := validateFile(path, ids)
		errors = append(errors, fileErrors...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error walking cases directory: %v\n", err)
		return 1
	}
	if fileCount == 0 {
		fmt.Fprintf(os.Stderr, "no case files found in %s\n", casesDir)
		return 1
	}
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "validation failed with %d error(s):\n\n", len(errors))
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return 1
	}
	fmt.Printf("validated %d case files. all passed.\n", fileCount)
	return 0
}

func runResults(path string) int {
	errors := validateResultsFile(path)
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "validation failed with %d error(s):\n\n", len(errors))
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return 1
	}
	fmt.Println("results file validated. all passed.")
	return 0
}

func runProfile(path string) int {
	errors := validateProfileFile(path)
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "validation failed with %d error(s):\n\n", len(errors))
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		return 1
	}
	fmt.Println("profile file validated. all passed.")
	return 0
}

func validateFile(path string, ids map[string]string) []string {
	var errors []string
	addErr := func(msg string) {
		errors = append(errors, fmt.Sprintf("%s: %s", path, msg))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		addErr(fmt.Sprintf("read error: %v", err))
		return errors
	}

	var c Case
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		addErr(fmt.Sprintf("JSON parse error: %v", err))
		return errors
	}

	// Required fields
	if c.SchemaVersion != 1 {
		addErr(fmt.Sprintf("schema_version must be 1, got %d", c.SchemaVersion))
	}
	if c.ID == "" {
		addErr("missing id")
	}
	if c.Title == "" {
		addErr("missing title")
	}
	if c.Description == "" {
		addErr("missing description")
	}
	if c.WhyExpected == "" {
		addErr("missing why_expected")
	}
	if c.Payload == nil {
		addErr("missing payload")
	}

	// ID must match filename
	expectedFilename := c.ID + ".json"
	actualFilename := filepath.Base(path)
	if expectedFilename != actualFilename {
		addErr(fmt.Sprintf("id %q does not match filename %q", c.ID, actualFilename))
	}

	// Unique ID check
	if prev, exists := ids[c.ID]; exists {
		addErr(fmt.Sprintf("duplicate id %q (also in %s)", c.ID, prev))
	} else if c.ID != "" {
		ids[c.ID] = path
	}

	// Enum validation
	if !validCategories[c.Category] {
		addErr(fmt.Sprintf("invalid category: %q", c.Category))
	}
	if !validInputTypes[c.InputType] {
		addErr(fmt.Sprintf("invalid input_type: %q", c.InputType))
	}
	if !validTransports[c.Transport] {
		addErr(fmt.Sprintf("invalid transport: %q", c.Transport))
	}
	if !validVerdicts[c.ExpectedVerdict] {
		addErr(fmt.Sprintf("invalid expected_verdict: %q", c.ExpectedVerdict))
	}
	if !validSeverities[c.Severity] {
		addErr(fmt.Sprintf("invalid severity: %q", c.Severity))
	}
	if !validFPRisk[c.FPRisk] {
		addErr(fmt.Sprintf("invalid false_positive_risk: %q", c.FPRisk))
	}

	// Capability tags
	if len(c.CapabilityTags) == 0 {
		addErr("capability_tags must not be empty")
	}
	for _, tag := range c.CapabilityTags {
		if !validCapabilityTags[tag] {
			addErr(fmt.Sprintf("invalid capability_tag: %q", tag))
		}
	}

	// Requires
	for _, req := range c.Requires {
		if !validRequires[req] {
			addErr(fmt.Sprintf("invalid requires value: %q", req))
		}
	}

	// Category directory consistency
	expectedDir := categoryToDir(c.Category)
	actualDir := filepath.Base(filepath.Dir(path))
	if expectedDir != "" && expectedDir != actualDir {
		addErr(fmt.Sprintf("category %q expects directory %q, found in %q", c.Category, expectedDir, actualDir))
	}

	// Benign cases must have safe_example: true
	if c.ExpectedVerdict == "allow" && (c.SafeExample == nil || !*c.SafeExample) {
		addErr("benign cases (expected_verdict=allow) must have safe_example: true")
	}

	// Category ↔ input_type consistency
	if validCategories[c.Category] && validInputTypes[c.InputType] {
		allowed := validCategoryInputType[c.Category]
		if !contains(allowed, c.InputType) {
			addErr(fmt.Sprintf("category %q does not allow input_type %q (valid: %s)",
				c.Category, c.InputType, strings.Join(allowed, ", ")))
		}
	}

	// Category ↔ transport consistency
	if validCategories[c.Category] && validTransports[c.Transport] {
		allowed := validCategoryTransport[c.Category]
		if !contains(allowed, c.Transport) {
			addErr(fmt.Sprintf("category %q does not allow transport %q (valid: %s)",
				c.Category, c.Transport, strings.Join(allowed, ", ")))
		}
	}

	// Payload shape validation per input_type
	if c.Payload != nil && validInputTypes[c.InputType] {
		payloadErrors := validatePayload(c.InputType, c.Payload)
		for _, pe := range payloadErrors {
			addErr(pe)
		}
	}

	return errors
}

// validatePayload checks that the payload has the required fields for the given input_type.
func validatePayload(inputType string, payload map[string]interface{}) []string {
	var errors []string

	requireKey := func(key string) {
		if _, ok := payload[key]; !ok {
			errors = append(errors, fmt.Sprintf("payload missing required key %q for input_type %q", key, inputType))
		}
	}

	requireStringKey := func(key string) {
		v, ok := payload[key]
		if !ok {
			errors = append(errors, fmt.Sprintf("payload missing required key %q for input_type %q", key, inputType))
			return
		}
		if _, isStr := v.(string); !isStr {
			errors = append(errors, fmt.Sprintf("payload.%s must be a string for input_type %q", key, inputType))
		}
	}

	switch inputType {
	case "url":
		// Required: method (string), url (string)
		requireStringKey("method")
		requireStringKey("url")

	case "request_body":
		// Required: method (string), url (string), content_type (string), body (string)
		requireStringKey("method")
		requireStringKey("url")
		requireStringKey("content_type")
		requireStringKey("body")

	case "header":
		// Required: method (string), url (string), headers (object)
		requireStringKey("method")
		requireStringKey("url")
		v, ok := payload["headers"]
		if !ok {
			errors = append(errors, fmt.Sprintf("payload missing required key %q for input_type %q", "headers", inputType))
		} else if _, isMap := v.(map[string]interface{}); !isMap {
			errors = append(errors, fmt.Sprintf("payload.headers must be an object for input_type %q", inputType))
		}

	case "response_content":
		// Required: url (string), response_body (string)
		requireStringKey("url")
		requireStringKey("response_body")

	case "mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "mcp_tool_sequence":
		// Required: jsonrpc_messages (array of objects with "jsonrpc" field)
		requireKey("jsonrpc_messages")
		v, ok := payload["jsonrpc_messages"]
		if ok {
			arr, isArr := v.([]interface{})
			if !isArr {
				errors = append(errors, fmt.Sprintf("payload.jsonrpc_messages must be an array for input_type %q", inputType))
			} else if len(arr) == 0 {
				errors = append(errors, fmt.Sprintf("payload.jsonrpc_messages must not be empty for input_type %q", inputType))
			} else {
				for i, elem := range arr {
					obj, isObj := elem.(map[string]interface{})
					if !isObj {
						errors = append(errors, fmt.Sprintf("payload.jsonrpc_messages[%d] must be an object for input_type %q", i, inputType))
						continue
					}
					if _, hasVersion := obj["jsonrpc"]; !hasVersion {
						errors = append(errors, fmt.Sprintf("payload.jsonrpc_messages[%d] missing required field \"jsonrpc\" for input_type %q", i, inputType))
					}
				}
			}
		}
	}

	return errors
}

func categoryToDir(category string) string {
	switch category {
	case "url":
		return "url"
	case "request_body":
		return "request-body"
	case "headers":
		return "headers"
	case "response_fetch":
		return "response-fetch"
	case "response_mitm":
		return "response-mitm"
	case "mcp_input":
		return "mcp-input"
	case "mcp_tool":
		return "mcp-tool"
	case "mcp_chain":
		return "mcp-chain"
	default:
		return ""
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

// ResultLine represents a single line in a runner results JSONL file.
type ResultLine struct {
	CaseID          string                 `json:"case_id"`
	Tool            string                 `json:"tool"`
	ToolVersion     string                 `json:"tool_version"`
	ExpectedVerdict string                 `json:"expected_verdict"`
	ActualVerdict   string                 `json:"actual_verdict"`
	Score           string                 `json:"score"`
	Evidence        map[string]interface{} `json:"evidence"`
	Notes           *string                `json:"notes"`
}

func validateResultLine(lineNum int, r ResultLine) []string {
	var errors []string
	addErr := func(msg string) {
		errors = append(errors, fmt.Sprintf("line %d: %s", lineNum, msg))
	}

	if r.CaseID == "" {
		addErr("missing case_id")
	}
	if r.Tool == "" {
		addErr("missing tool")
	}
	if r.ToolVersion == "" {
		addErr("missing tool_version")
	}
	if !validVerdicts[r.ExpectedVerdict] {
		addErr(fmt.Sprintf("invalid expected_verdict: %q (must be block or allow)", r.ExpectedVerdict))
	}
	if !validActualVerdicts[r.ActualVerdict] {
		addErr(fmt.Sprintf("invalid actual_verdict: %q", r.ActualVerdict))
	}
	if !validScores[r.Score] {
		addErr(fmt.Sprintf("invalid score: %q", r.Score))
	}
	if r.Evidence == nil {
		addErr("missing evidence (must be an object)")
	}
	if r.Notes == nil {
		addErr("missing notes (must be a string, use empty string if no context)")
	}

	// Score consistency checks.
	if validActualVerdicts[r.ActualVerdict] && validVerdicts[r.ExpectedVerdict] && validScores[r.Score] {
		switch {
		case r.ActualVerdict == r.ExpectedVerdict && r.Score != "pass":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict matches expected_verdict (%q) but score is %q (should be pass)",
				r.ActualVerdict, r.Score))
		case r.ActualVerdict == "not_applicable" && r.Score != "not_applicable":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict is not_applicable but score is %q (should be not_applicable)", r.Score))
		case r.ActualVerdict == "error" && r.Score != "error":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict is error but score is %q (should be error)", r.Score))
		}
	}

	return errors
}

func validateResultsFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}
	defer func() { _ = f.Close() }()

	var allErrors []string
	seenIDs := make(map[string]int)
	lineNum := 0
	resultCount := 0

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lineNum++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		resultCount++

		var r ResultLine
		dec := json.NewDecoder(strings.NewReader(text))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&r); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("line %d: JSON parse error: %v", lineNum, err))
			continue
		}

		lineErrors := validateResultLine(lineNum, r)
		allErrors = append(allErrors, lineErrors...)

		if r.CaseID != "" {
			if prevLine, exists := seenIDs[r.CaseID]; exists {
				allErrors = append(allErrors, fmt.Sprintf("line %d: duplicate case_id %q (first seen on line %d)", lineNum, r.CaseID, prevLine))
			} else {
				seenIDs[r.CaseID] = lineNum
			}
		}
	}

	if err := scanner.Err(); err != nil {
		allErrors = append(allErrors, fmt.Sprintf("%s: read error: %v", path, err))
	}
	if resultCount == 0 {
		allErrors = append(allErrors, fmt.Sprintf("%s: file contains no result lines", path))
	}

	return allErrors
}

// Profile represents a tool profile JSON file.
type Profile struct {
	SchemaVersion int                    `json:"schema_version"`
	Tool          string                 `json:"tool"`
	ToolVersion   string                 `json:"tool_version"`
	RunnerVersion string                 `json:"runner_version"`
	Claims        []string               `json:"claims"`
	Supports      map[string]interface{} `json:"supports"`
}

func validateProfile(p Profile) []string {
	var errors []string

	if p.SchemaVersion != 1 {
		errors = append(errors, fmt.Sprintf("schema_version must be 1, got %d", p.SchemaVersion))
	}
	if p.Tool == "" {
		errors = append(errors, "missing tool")
	}
	if p.ToolVersion == "" {
		errors = append(errors, "missing tool_version")
	}
	if p.RunnerVersion == "" {
		errors = append(errors, "missing runner_version")
	}
	if p.Claims == nil {
		errors = append(errors, "missing claims (must be an array)")
	}
	for _, claim := range p.Claims {
		if !validCapabilityTags[claim] {
			errors = append(errors, fmt.Sprintf("invalid claim: %q", claim))
		}
	}
	if p.Supports == nil {
		errors = append(errors, "missing supports (must be an object)")
	} else {
		// Validate present keys.
		for key, val := range p.Supports {
			if !validSupportsKeys[key] {
				errors = append(errors, fmt.Sprintf("invalid supports key: %q", key))
			}
			if _, isBool := val.(bool); !isBool {
				errors = append(errors, fmt.Sprintf("supports.%s must be a boolean", key))
			}
		}
		// Require all supports keys per schema.
		for key := range validSupportsKeys {
			if _, exists := p.Supports[key]; !exists {
				errors = append(errors, fmt.Sprintf("missing required supports key: %q", key))
			}
		}
	}

	return errors
}

func validateProfileFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}

	var p Profile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return []string{fmt.Sprintf("%s: JSON parse error: %v", path, err)}
	}

	return validateProfile(p)
}
