// validate checks benchmark artifacts against the agent-egress-bench contracts.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

// activeCaseSchemaVersion is the case schema version this validator enforces.
// Both case shapes read it, so the single-file and multi-file paths cannot
// drift apart on the version boundary the way they previously did on the
// requires vocabulary. It mirrors activeSchemaVersion in the runner; the two
// move together whenever the coordinated artifact set is bumped.
const activeCaseSchemaVersion = 4

// Valid enum values for v1 schema.
var (
	validCategories = map[string]bool{
		"url": true, "request_body": true, "headers": true,
		"response_fetch": true, "response_mitm": true,
		"mcp_input": true, "mcp_tool": true, "mcp_chain": true,
		"a2a_message": true, "a2a_agent_card": true, "websocket_dlp": true,
		"ssrf_bypass": true, "encoding_evasion": true, "shell_obfuscation": true,
		"crypto_financial": true, "false_positive": true,
		"hostname_exfiltration": true,
	}

	// New categories added by the Gauntlet expansion.
	gauntletCategories = map[string]bool{
		"a2a_message": true, "a2a_agent_card": true, "websocket_dlp": true,
		"ssrf_bypass": true, "encoding_evasion": true, "shell_obfuscation": true,
		"crypto_financial": true, "false_positive": true,
		"hostname_exfiltration": true,
	}

	validInputTypes = map[string]bool{
		"url": true, "request_body": true, "header": true,
		"response_content": true, "mcp_tool_call": true, "mcp_tool_result": true,
		"mcp_tool_definition": true, "mcp_tool_sequence": true,
		"a2a_message": true, "a2a_agent_card": true, "websocket_frame": true,
	}

	validTransports = map[string]bool{
		"fetch_proxy": true, "http_proxy": true,
		"mcp_stdio": true, "mcp_http": true, "websocket": true,
		"a2a": true,
	}

	validMeasuredVerdicts = map[string]bool{"block": true, "allow": true}

	validCaseExpectedVerdicts = map[string]bool{"block": true, "allow": true, "warn": true}

	validSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true,
	}

	validFPRisk = map[string]bool{
		"low": true, "medium": true, "high": true,
	}

	validRequires = map[string]bool{
		"tls_interception": true,
		"url_dlp_scanning": true, "request_body_dlp_scanning": true,
		"header_dlp_scanning": true, "response_prompt_injection_scanning": true,
		"mcp_input_dlp_scanning": true, "mcp_input_prompt_injection_scanning": true,
		"mcp_tool_policy": true, "mcp_tool_result_prompt_injection_scanning": true,
		"mcp_tool_poison_scanning": true, "mcp_tool_baseline": true,
		"mcp_chain_memory": true,
		// Cross-server chain memory: detector must correlate tool calls
		// across distinct MCP server sessions to catch toxic compositions
		// where the attack lives in the composition, not the individual
		// servers. Strict superset of mcp_chain_memory (which covers a
		// single session).
		"mcp_cross_server_chain_memory": true,
		// Data-class labels on tool outputs: detector tags outputs of
		// read-style tools (read_file, list_secrets, etc.) with a
		// sensitivity class (filesystem_secret, credential, internal_doc)
		// so chain-composition rules can distinguish "read public file
		// then write" from "read SSH key then write". Without labels a
		// detector cannot tell which read-then-write chains are safe.
		"mcp_data_class_labels": true,
		"a2a_dlp_scanning":      true, "a2a_prompt_injection_scanning": true,
		"a2a_card_prompt_injection_scanning": true, "a2a_card_drift_scanning": true,
		"a2a_ssrf_scanning":      true,
		"websocket_dlp_scanning": true, "websocket_prompt_injection_scanning": true,
		"ssrf_scanning":    true,
		"domain_blocklist": true, "entropy_scanning": true,
		"shell_analysis":      true,
		"crypto_dlp_scanning": true, "hostname_exfil_scanning": true,
		"dns_rebinding_fixture": true, "budget_enforcement": true,
	}

	validActualVerdicts = map[string]bool{
		"block": true, "allow": true, "unreachable": true, "error": true,
	}

	validScores = map[string]bool{
		"pass": true, "fail": true, "error": true,
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
		// Gauntlet categories:
		"a2a_message":           {"a2a_message"},
		"a2a_agent_card":        {"a2a_agent_card"},
		"websocket_dlp":         {"websocket_frame"},
		"ssrf_bypass":           {"url"},
		"encoding_evasion":      {"url", "request_body", "mcp_tool_call"},
		"shell_obfuscation":     {"mcp_tool_call"},
		"crypto_financial":      {"url", "request_body", "header", "mcp_tool_call"},
		"false_positive":        {"url", "request_body", "header", "response_content", "mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "websocket_frame", "a2a_message"},
		"hostname_exfiltration": {"url"},
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
		// Gauntlet categories:
		"a2a_message":           {"a2a"},
		"a2a_agent_card":        {"a2a"},
		"websocket_dlp":         {"websocket"},
		"ssrf_bypass":           {"fetch_proxy", "http_proxy"},
		"encoding_evasion":      {"fetch_proxy", "mcp_stdio"},
		"shell_obfuscation":     {"mcp_stdio", "mcp_http"},
		"crypto_financial":      {"fetch_proxy", "http_proxy", "mcp_stdio"},
		"false_positive":        {"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"},
		"hostname_exfiltration": {"fetch_proxy", "http_proxy"},
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
	Supersedes      string                 `json:"supersedes,omitempty"`
}

const usageText = `usage: validate <command> <target>

commands:
  cases   <dir>    validate case JSON files in a directory
  results <file> [cases-dir]   validate runner JSONL; cases-dir enables case-bound checks
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
		if len(os.Args) < 3 || len(os.Args) > 4 {
			fmt.Fprintf(os.Stderr, "usage: validate results <results-file> [cases-directory]\n")
			os.Exit(1)
		}
		casesDir := ""
		if len(os.Args) > 3 {
			casesDir = os.Args[3]
		}
		os.Exit(runResults(os.Args[2], casesDir))
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
		// Multi-file families own a directory contract rather than the
		// single-file JSON shape. Validate each logical case once, then skip
		// its JSON components so they cannot be mistaken for standalone cases.
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			entries, readErr := os.ReadDir(path)
			if readErr != nil {
				errors = append(errors, fmt.Sprintf("%s: cannot read multi-file case directory: %v", path, readErr))
				return filepath.SkipDir
			}
			// Every immediate subdirectory is one logical case. Globbing for
			// */case.yaml silently ignored a subdirectory that had none, so a
			// corpus the runner hard-refuses to load validated clean here.
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				caseDir := filepath.Join(path, entry.Name())
				caseYAML := filepath.Join(caseDir, "case.yaml")
				fileCount++
				if _, statErr := os.Stat(caseYAML); statErr != nil {
					errors = append(errors, fmt.Sprintf("%s: cannot read required case.yaml: %v; restore case.yaml or remove the directory", caseDir, statErr))
					continue
				}
				errors = append(errors, validateMultiFileCase(caseYAML, ids)...)
			}
			return filepath.SkipDir
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
	// Supersession is a relationship between two cases, so it can only be
	// checked once every case ID is known. JSON Schema cannot express "the
	// referenced case exists", which left the field accepting an empty string, a
	// nonexistent target, a self-reference, or a cycle. A relationship that
	// points nowhere is not relationship metadata.
	errors = append(errors, validateSupersessionGraph(ids)...)
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

func runResults(path, casesDir string) int {
	errors := validateResultsFileAgainstCases(path, casesDir)
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

func registryRootForArtifact(path string) (string, error) {
	if root := os.Getenv("AEB_CAPABILITY_REGISTRY"); root != "" {
		return root, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "capability-registry")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", fmt.Errorf("capability registry not found for %s", path)
}

// validateSupersessionGraph checks the supersedes relationships across the whole
// corpus. ids maps every known case ID to the file that declares it, which is
// what makes an existence check possible; a per-file validator cannot do this
// because it cannot see the other cases.
//
// The corpus currently declares zero supersessions, so this guards the first one
// rather than an existing defect. That is the point: the field's only stated
// meaning is a replacement relationship, so the moment someone uses it, a
// self-reference or a dangling target must be refused instead of recorded.
func validateSupersessionGraph(ids map[string]string) []string {
	var errors []string
	targets := make(map[string]string, len(ids))

	sortedIDs := make([]string, 0, len(ids))
	for id := range ids {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	for _, id := range sortedIDs {
		path := ids[id]
		data, err := os.ReadFile(path)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: reading for supersession check: %v", path, err))
			continue
		}
		var c Case
		if err := json.Unmarshal(data, &c); err != nil {
			// The per-file validator already reports a parse failure; do not
			// duplicate it here.
			continue
		}
		raw, declared := rawSupersedes(data)
		if !declared {
			continue
		}
		if strings.TrimSpace(raw) == "" {
			errors = append(errors, fmt.Sprintf("%s: supersedes is present but empty; omit the field instead", path))
			continue
		}
		if raw == id {
			errors = append(errors, fmt.Sprintf("%s: case %q supersedes itself", path, id))
			continue
		}
		if _, exists := ids[raw]; !exists {
			errors = append(errors, fmt.Sprintf("%s: case %q supersedes %q, which is not a case in this corpus", path, id, raw))
			continue
		}
		targets[id] = raw
	}

	// A cycle means no case in the chain is the current one, so the chain cannot
	// answer which semantics are live.
	for _, id := range sortedIDs {
		if _, ok := targets[id]; !ok {
			continue
		}
		seen := map[string]bool{id: true}
		for cur := targets[id]; cur != ""; cur = targets[cur] {
			if seen[cur] {
				errors = append(errors, fmt.Sprintf("%s: supersession chain starting at %q is cyclic", ids[id], id))
				break
			}
			seen[cur] = true
		}
	}

	return errors
}

// rawSupersedes reports the declared supersedes value and whether the key was
// present at all. An absent field and a field set to an empty string are
// different mistakes, and the Go zero value cannot tell them apart.
func rawSupersedes(data []byte) (string, bool) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", false
	}
	raw, present := probe["supersedes"]
	if !present {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", true
	}
	return value, true
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
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		addErr(fmt.Sprintf("JSON field inventory error: %v", err))
		return errors
	}
	for _, field := range []string{"schema_version", "id", "category", "title", "description", "input_type", "transport", "payload", "expected_verdict", "severity", "capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source"} {
		if _, present := fields[field]; !present {
			addErr(fmt.Sprintf("missing required field %q", field))
		}
	}
	if c.SchemaVersion != activeCaseSchemaVersion {
		addErr(fmt.Sprintf("schema_version must be %d, got %d", activeCaseSchemaVersion, c.SchemaVersion))
	}

	// Required fields
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
	if !validCaseExpectedVerdicts[c.ExpectedVerdict] {
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
	seenTags := make(map[string]bool, len(c.CapabilityTags))
	for _, tag := range c.CapabilityTags {
		if strings.TrimSpace(tag) == "" {
			addErr("capability_tag must be non-empty")
		}
		if seenTags[tag] {
			addErr(fmt.Sprintf("duplicate capability_tag: %q", tag))
		}
		seenTags[tag] = true
	}

	// Requires
	for _, req := range c.Requires {
		if problem := requiresTokenProblem(req); problem != "" {
			addErr(problem)
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
	if c.Category == "crypto_financial" && c.Transport == "http_proxy" &&
		c.InputType != "request_body" && c.InputType != "header" {
		addErr("category \"crypto_financial\" allows http_proxy only for request_body or header input_type")
	}

	// Payload shape validation per input_type
	if c.Payload != nil && validInputTypes[c.InputType] {
		payloadErrors := validatePayload(c.InputType, c.Payload)
		for _, pe := range payloadErrors {
			addErr(pe)
		}
		for _, pe := range validateBudgetPayload(c) {
			addErr(pe)
		}
	}

	// Gauntlet categories require a non-empty source field.
	if gauntletCategories[c.Category] && c.Source == "" {
		addErr(fmt.Sprintf("category %q requires a non-empty source field (see provenance conventions)", c.Category))
	}

	return errors
}

func validateBudgetPayload(c Case) []string {
	if !contains(c.Requires, "budget_enforcement") && !contains(c.CapabilityTags, "denial_of_wallet") {
		return nil
	}
	var errors []string
	payload := c.Payload

	if _, hasOldUnits := payload["budget_limit_units"]; hasOldUnits {
		errors = append(errors, "payload.budget_limit_units is not scoreable; use budget_limit_calls")
	}
	if containsCostUnits(payload["jsonrpc_messages"]) {
		errors = append(errors, "payload jsonrpc_messages must not use weighted cost_units for budget_enforcement cases")
	}
	if c.InputType != "mcp_tool_sequence" {
		errors = append(errors, "budget_enforcement cases must use input_type mcp_tool_sequence")
	}
	if scope, ok := payload["budget_scope"].(string); !ok || scope != "per_subject" {
		errors = append(errors, "payload.budget_scope must be \"per_subject\" for budget_enforcement cases")
	}
	subjectID, ok := payload["subject_id"].(string)
	if !ok || subjectID == "" {
		errors = append(errors, "payload.subject_id must be a non-empty string for budget_enforcement cases")
	}
	limit, ok := positiveInt(payload["budget_limit_calls"])
	if !ok {
		errors = append(errors, "payload.budget_limit_calls must be a positive integer for budget_enforcement cases")
	}

	msgs, _ := payload["jsonrpc_messages"].([]interface{})
	if len(msgs) == 0 || !ok || subjectID == "" {
		return errors
	}

	subjectCalls := 0
	overBudgetIndex := -1
	overBudgetID, hasOverBudgetID := positiveInt(payload["over_budget_call_id"])
	for _, raw := range msgs {
		msg, isObj := raw.(map[string]interface{})
		if !isObj {
			continue
		}
		params, _ := msg["params"].(map[string]interface{})
		args, _ := params["arguments"].(map[string]interface{})
		if argsSubject, _ := args["subject_id"].(string); argsSubject == subjectID {
			subjectCalls++
			if hasOverBudgetID && jsonValueIDString(msg["id"]) == fmt.Sprint(overBudgetID) {
				overBudgetIndex = subjectCalls
			}
		}
	}

	switch c.ExpectedVerdict {
	case "block":
		if !hasOverBudgetID {
			errors = append(errors, "block budget_enforcement cases must set payload.over_budget_call_id")
		} else if overBudgetIndex == -1 {
			errors = append(errors, "payload.over_budget_call_id must identify a call by payload.subject_id")
		} else if overBudgetIndex != limit+1 {
			errors = append(errors, fmt.Sprintf("payload.over_budget_call_id must identify subject call %d for budget_limit_calls=%d", limit+1, limit))
		}
		if subjectCalls <= limit {
			errors = append(errors, fmt.Sprintf("block budget_enforcement cases must include more than %d calls by payload.subject_id", limit))
		}
	case "allow":
		if _, hasOver := payload["over_budget_call_id"]; hasOver {
			errors = append(errors, "allow budget_enforcement cases must not set payload.over_budget_call_id")
		}
		if subjectCalls > limit {
			errors = append(errors, fmt.Sprintf("allow budget_enforcement cases must not exceed budget_limit_calls=%d for payload.subject_id", limit))
		}
	}

	return errors
}

func containsCostUnits(v interface{}) bool {
	switch x := v.(type) {
	case []interface{}:
		for _, elem := range x {
			if containsCostUnits(elem) {
				return true
			}
		}
	case map[string]interface{}:
		if _, ok := x["cost_units"]; ok {
			return true
		}
		for _, elem := range x {
			if containsCostUnits(elem) {
				return true
			}
		}
	}
	return false
}

func positiveInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n > 0
	case int64:
		return int(n), n > 0
	case float64:
		i := int(n)
		return i, n > 0 && float64(i) == n
	default:
		return 0, false
	}
}

func jsonValueIDString(v interface{}) string {
	switch id := v.(type) {
	case string:
		return id
	case float64:
		i := int(id)
		if float64(i) == id {
			return fmt.Sprint(i)
		}
		return fmt.Sprint(id)
	case int:
		return fmt.Sprint(id)
	case int64:
		return fmt.Sprint(id)
	default:
		return ""
	}
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

	case "mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "mcp_tool_sequence",
		"a2a_message":
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

	case "a2a_agent_card":
		// Required: agent_card (object with "name" and "skills" fields)
		v, ok := payload["agent_card"]
		if !ok {
			errors = append(errors, fmt.Sprintf("payload missing required key %q for input_type %q", "agent_card", inputType))
		} else if card, isObj := v.(map[string]interface{}); !isObj {
			errors = append(errors, fmt.Sprintf("payload.agent_card must be an object for input_type %q", inputType))
		} else {
			if _, hasName := card["name"]; !hasName {
				errors = append(errors, fmt.Sprintf("payload.agent_card missing required field \"name\" for input_type %q", inputType))
			}
			if _, hasSkills := card["skills"]; !hasSkills {
				errors = append(errors, fmt.Sprintf("payload.agent_card missing required field \"skills\" for input_type %q", inputType))
			}
		}

	case "websocket_frame":
		// Required: url (string), frames (non-empty array of objects with "opcode" and "payload")
		requireStringKey("url")
		v, ok := payload["frames"]
		if !ok {
			errors = append(errors, fmt.Sprintf("payload missing required key %q for input_type %q", "frames", inputType))
		} else if arr, isArr := v.([]interface{}); !isArr {
			errors = append(errors, fmt.Sprintf("payload.frames must be an array for input_type %q", inputType))
		} else if len(arr) == 0 {
			errors = append(errors, fmt.Sprintf("payload.frames must not be empty for input_type %q", inputType))
		} else {
			for i, elem := range arr {
				frame, isObj := elem.(map[string]interface{})
				if !isObj {
					errors = append(errors, fmt.Sprintf("payload.frames[%d] must be an object for input_type %q", i, inputType))
					continue
				}
				if _, hasOpcode := frame["opcode"]; !hasOpcode {
					errors = append(errors, fmt.Sprintf("payload.frames[%d] missing required field \"opcode\" for input_type %q", i, inputType))
				}
				if _, hasPayload := frame["payload"]; !hasPayload {
					errors = append(errors, fmt.Sprintf("payload.frames[%d] missing required field \"payload\" for input_type %q", i, inputType))
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
	case "a2a_message":
		return "a2a-message"
	case "a2a_agent_card":
		return "a2a-agent-card"
	case "websocket_dlp":
		return "websocket-dlp"
	case "ssrf_bypass":
		return "ssrf-bypass"
	case "encoding_evasion":
		return "encoding-evasion"
	case "shell_obfuscation":
		return "shell-obfuscation"
	case "crypto_financial":
		return "crypto-financial"
	case "false_positive":
		return "false-positive"
	case "hostname_exfiltration":
		return "hostname-exfiltration"
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

// multiFileCaseCategories lists case-directory names that use the multi-file
// case format (per-case directory containing case.yaml, before.json,
// after.json, expected.json, notes.md). The single-JSON validator skips
// these — they have their own per-directory schema documented in the
// directory's README.md. v0 ships with mcp-drift; future categories that
// need temporal before/after pairs join this list.
var multiFileCaseCategories = map[string]bool{
	"mcp-drift": true,
}

// isMultiFileCaseDir reports whether name (a directory base name immediately
// under cases/) uses the multi-file case format.
func isMultiFileCaseDir(name string) bool {
	return multiFileCaseCategories[name]
}

// validateMultiFileRequires enforces the requires vocabulary on a multi-file
// case.yaml so the applicability rules cannot be bypassed through the multi-file
// case shape. It extracts the requires list (block or inline) with a minimal
// stdlib parser rather than a full YAML dependency, then applies the same
// difficulty-flag ban and vocabulary check as single-file cases.
// requiresTokenProblem returns the reason a token may not appear in a case's
// requires, or "" when it is allowed. Both the single-file JSON shape and the
// multi-file case.yaml shape route through here: when each carried its own copy
// of these rules, the multi-file shape silently kept accepting tokens the
// single-file shape had already banned.
func requiresTokenProblem(token string) string {
	switch {
	// Attack-difficulty and evasion-technique flags describe how hard an input
	// is on a surface the tool already inspects. Gating on one lets a tool dodge
	// the hard variant by declining the claim. See docs/gauntlet.md.
	case token == "encoding_evasion_scanning", token == "ssrf_bypass_scanning":
		return fmt.Sprintf("%q is an attack-difficulty flag and cannot appear in requires; move it to capability_tags", token)
	// Enforcement claims name the feature the case exists to test. Gating on one
	// lets a tool delete the case, and the benign control that measures its
	// over-blocking, by declining the claim. They remain reporting-label terms.
	case token == "budget_enforcement":
		return fmt.Sprintf("%q is an enforcement claim and cannot appear in requires; gate on the observation surface and keep the claim in capability_tags", token)
	case !validRequires[token]:
		return fmt.Sprintf("invalid requires value: %q", token)
	}
	return ""
}

// ResultLine represents a single line in a runner results JSONL file.
type ResultLine struct {
	SchemaVersion      int                          `json:"schema_version"`
	CaseID             string                       `json:"case_id"`
	Tool               string                       `json:"tool"`
	ToolVersion        string                       `json:"tool_version"`
	CapabilityRegistry capabilityregistry.Reference `json:"capability_registry"`
	ExpectedVerdict    string                       `json:"expected_verdict"`
	ActualVerdict      string                       `json:"actual_verdict"`
	Score              string                       `json:"score"`
	Evidence           map[string]interface{}       `json:"evidence"`
	Notes              *string                      `json:"notes"`
}

type resultCaseMetadata struct {
	ExpectedVerdict      string
	BudgetTimingRequired bool
}

func validateResultLine(lineNum int, r ResultLine) []string {
	return validateResultLineAgainstCase(lineNum, r, nil)
}

func validateResultLineAgainstCase(lineNum int, r ResultLine, caseMetadata *resultCaseMetadata) []string {
	var errors []string
	addErr := func(msg string) {
		errors = append(errors, fmt.Sprintf("line %d: %s", lineNum, msg))
	}

	if r.CaseID == "" {
		addErr("missing case_id")
	}
	if r.SchemaVersion != activeCaseSchemaVersion {
		addErr(fmt.Sprintf("schema_version must be %d, got %d", activeCaseSchemaVersion, r.SchemaVersion))
	}
	if r.Tool == "" {
		addErr("missing tool")
	}
	if r.ToolVersion == "" {
		addErr("missing tool_version")
	}
	if !validMeasuredVerdicts[r.ExpectedVerdict] {
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
	if err := validateRegistryReference(r.CapabilityRegistry); err != nil {
		addErr(fmt.Sprintf("invalid capability_registry: %v", err))
	}
	if caseMetadata != nil && r.ExpectedVerdict != caseMetadata.ExpectedVerdict {
		addErr(fmt.Sprintf("expected_verdict %q does not match case metadata %q", r.ExpectedVerdict, caseMetadata.ExpectedVerdict))
	}

	// Score consistency checks. The exhaustive public matrix lives in
	// contracts/result-states-v4.json and contract tests compare every row to
	// this validator.
	if validActualVerdicts[r.ActualVerdict] && validMeasuredVerdicts[r.ExpectedVerdict] && validScores[r.Score] {
		caseSpecificScore, hasCaseSpecificScore, caseSpecificProblem := expectedCaseSpecificScore(r, caseMetadata)
		if caseSpecificProblem != "" {
			addErr(caseSpecificProblem)
		}
		switch {
		case caseSpecificProblem != "":
		case hasCaseSpecificScore && r.Score != caseSpecificScore:
			addErr(fmt.Sprintf("inconsistent score: budget_block_timing requires score %q, got %q",
				caseSpecificScore, r.Score))
		case !hasCaseSpecificScore && r.ActualVerdict == r.ExpectedVerdict && r.Score != "pass":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict matches expected_verdict (%q) but score is %q (should be pass)",
				r.ActualVerdict, r.Score))
		case validMeasuredVerdicts[r.ActualVerdict] && r.ActualVerdict != r.ExpectedVerdict && r.Score != "fail":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict %q does not match expected_verdict %q but score is %q (should be fail)",
				r.ActualVerdict, r.ExpectedVerdict, r.Score))
		case r.ActualVerdict == "unreachable" && r.Score != "error":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict is unreachable but score is %q (should be error)", r.Score))
		case r.ActualVerdict == "error" && r.Score != "error":
			addErr(fmt.Sprintf("inconsistent score: actual_verdict is error but score is %q (should be error)", r.Score))
		}
	}

	return errors
}

func expectedCaseSpecificScore(r ResultLine, caseMetadata *resultCaseMetadata) (string, bool, string) {
	if r.Evidence == nil {
		return "", false, ""
	}
	if caseMetadata != nil && (!caseMetadata.BudgetTimingRequired || r.ExpectedVerdict != "block" || r.ActualVerdict != "block") {
		if _, hasTiming := r.Evidence["budget_block_timing"]; hasTiming {
			return "", false, "budget_block_timing is not valid for this case"
		}
		if !caseMetadata.BudgetTimingRequired {
			if _, hasCallID := r.Evidence["over_budget_call_id"]; hasCallID {
				return "", false, "over_budget_call_id is not valid for this case"
			}
		}
	}
	if r.ExpectedVerdict != "block" || r.ActualVerdict != "block" {
		return "", false, ""
	}
	if caseMetadata != nil && !caseMetadata.BudgetTimingRequired {
		return "", false, ""
	}
	if caseMetadata == nil {
		// Structural-only validation has no corpus metadata. It can check a
		// declared override but cannot require one for a particular case.
		if _, ok := r.Evidence["over_budget_call_id"]; !ok {
			return "", false, ""
		}
	}
	timing, ok := r.Evidence["budget_block_timing"].(string)
	if !ok {
		if caseMetadata != nil && caseMetadata.BudgetTimingRequired {
			return "", false, "budget block result requires budget_block_timing evidence"
		}
		return "", false, ""
	}
	switch timing {
	case "at_over_budget":
		return "pass", true, ""
	case "before_over_budget", "after_over_budget":
		return "fail", true, ""
	default:
		if caseMetadata != nil {
			return "", false, fmt.Sprintf("invalid budget_block_timing: %q", timing)
		}
		return "", false, ""
	}
}

func validateResultsFile(path string) []string {
	return validateResultsFileWithMetadata(path, nil)
}

func validateResultsFileAgainstCases(path, casesDir string) []string {
	if casesDir == "" {
		return validateResultsFile(path)
	}
	metadata, err := loadResultCaseMetadata(casesDir)
	if err != nil {
		return []string{fmt.Sprintf("case metadata: %v", err)}
	}
	return validateResultsFileWithMetadata(path, metadata)
}

func loadResultCaseMetadata(casesDir string) (map[string]resultCaseMetadata, error) {
	metadata := make(map[string]resultCaseMetadata)
	add := func(id, expected string, budget bool) error {
		if id == "" {
			return fmt.Errorf("case has no id")
		}
		if expected == "warn" {
			expected = "allow"
		}
		if _, exists := metadata[id]; exists {
			return fmt.Errorf("duplicate case id %q", id)
		}
		metadata[id] = resultCaseMetadata{ExpectedVerdict: expected, BudgetTimingRequired: budget}
		return nil
	}
	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			entries, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				data, err := os.ReadFile(filepath.Join(path, entry.Name(), "case.yaml"))
				if err != nil {
					return err
				}
				c, err := parseMultiFileCaseYAML(data)
				if err != nil {
					return err
				}
				if err := add(c.ID, c.ExpectedVerdict, false); err != nil {
					return err
				}
			}
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var c Case
		if err := json.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		_, budget := c.Payload["budget_limit_calls"]
		return add(c.ID, c.ExpectedVerdict, budget && c.ExpectedVerdict == "block")
	})
	if err != nil {
		return nil, err
	}
	if len(metadata) == 0 {
		return nil, fmt.Errorf("no cases found in %s", casesDir)
	}
	return metadata, nil
}

func validateResultsFileWithMetadata(path string, caseMetadata map[string]resultCaseMetadata) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}
	defer func() { _ = f.Close() }()

	var allErrors []string
	seenIDs := make(map[string]int)
	lineNum := 0
	resultCount := 0
	var registryReference *capabilityregistry.Reference

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

		var metadata *resultCaseMetadata
		if caseMetadata != nil {
			value, ok := caseMetadata[r.CaseID]
			if !ok {
				allErrors = append(allErrors, fmt.Sprintf("line %d: case_id %q is not in the supplied cases directory", lineNum, r.CaseID))
			} else {
				metadata = &value
			}
		}
		lineErrors := validateResultLineAgainstCase(lineNum, r, metadata)
		allErrors = append(allErrors, lineErrors...)
		if registryReference == nil {
			copy := r.CapabilityRegistry
			registryReference = &copy
		} else if *registryReference != r.CapabilityRegistry {
			allErrors = append(allErrors, fmt.Sprintf("line %d: capability_registry differs from prior result rows", lineNum))
		}

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
	if registryReference != nil {
		root, err := registryRootForArtifact(path)
		if err != nil {
			allErrors = append(allErrors, err.Error())
		} else if _, err := (capabilityregistry.Resolver{Root: root}).Resolve(*registryReference); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("capability_registry: %v", err))
		}
	}

	return allErrors
}

// Profile represents a tool profile JSON file.
type Profile struct {
	SchemaVersion      int                          `json:"schema_version"`
	Tool               string                       `json:"tool"`
	ToolVersion        string                       `json:"tool_version"`
	RunnerVersion      string                       `json:"runner_version"`
	Claims             []string                     `json:"claims"`
	CapabilityRegistry capabilityregistry.Reference `json:"capability_registry"`
}

func validateProfile(p Profile) []string {
	var errors []string

	if p.SchemaVersion != activeCaseSchemaVersion {
		errors = append(errors, fmt.Sprintf("schema_version must be %d, got %d", activeCaseSchemaVersion, p.SchemaVersion))
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
	seen := make(map[string]bool, len(p.Claims))
	for _, claim := range p.Claims {
		if strings.TrimSpace(claim) == "" {
			errors = append(errors, "claim must be non-empty")
		}
		if seen[claim] {
			errors = append(errors, fmt.Sprintf("duplicate claim: %q", claim))
		}
		seen[claim] = true
	}
	if err := validateRegistryReference(p.CapabilityRegistry); err != nil {
		errors = append(errors, fmt.Sprintf("invalid capability_registry: %v", err))
	}

	return errors
}

func validateRegistryReference(ref capabilityregistry.Reference) error {
	if ref.ID == "" || filepath.Base(ref.ID) != ref.ID || strings.Contains(ref.ID, "..") {
		return fmt.Errorf("invalid id")
	}
	if ref.Format != capabilityregistry.SupportedFormat {
		return fmt.Errorf("unsupported format: %d", ref.Format)
	}
	if ref.Revision < 1 {
		return fmt.Errorf("invalid revision: %d", ref.Revision)
	}
	if len(ref.SHA256) != 64 || strings.ToLower(ref.SHA256) != ref.SHA256 {
		return fmt.Errorf("invalid sha256")
	}
	for _, r := range ref.SHA256 {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return fmt.Errorf("invalid sha256")
		}
	}
	return nil
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

	errors := validateProfile(p)
	if len(errors) != 0 {
		return errors
	}
	root, rootErr := registryRootForArtifact(path)
	if rootErr != nil {
		return []string{fmt.Sprintf("%s: %v", path, rootErr)}
	}
	resolved, resolveErr := (capabilityregistry.Resolver{Root: root}).Resolve(p.CapabilityRegistry)
	if resolveErr != nil {
		return []string{fmt.Sprintf("%s: capability_registry: %v", path, resolveErr)}
	}
	if err := resolved.ValidateActiveIDs("claim", p.Claims); err != nil {
		return []string{fmt.Sprintf("%s: %v", path, err)}
	}
	return nil
}
