// validate checks benchmark artifacts against the agent-egress-bench contracts.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

// Active schema version per artifact family, mirroring the runner's constants
// of the same names.
//
// Each constant belongs to one family in contracts/artifacts.json. Keeping the
// values separate prevents a version bump in one family from changing another
// family's reader by accident.
const (
	activeCaseSchemaVersion          = 4
	activeMultiFileCaseSchemaVersion = 4
	activeResultSchemaVersion        = 6
	activeToolProfileSchemaVersion   = 4
	legacyResultSchemaVersionV4      = 4
	legacyResultSchemaVersionV5      = 5
)

// Valid enum values for v1 schema.
var (
	caseIDPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
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

	validPrerequisiteKinds = map[string]bool{
		"blocklist_domain":    true,
		"reserved_sink_route": true,
	}

	// reservedSinkHosts is the closed set of corpus-reserved untrusted sink
	// hostnames. These names are reserved in the runner contract; a case that
	// targets one must declare reserved_sink_route with that exact host. The
	// list is closed on purpose: a new reserved sink is a contract change
	// (SPEC, RUNNER, adapter constants, and this map), not something the
	// validator should infer from hostname shape.
	reservedSinkHosts = map[string]bool{
		"ws-exfil-sink.test":  true,
		"a2a-exfil-sink.test": true,
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
		"dns_rebinding_fixture": true,
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

// Prerequisite is a machine-readable external setup step a runner must satisfy
// before executing a case. It is separate from capability declarations because
// the exact value (a domain, a sink route, etc.) is case-specific.
type Prerequisite struct {
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
}

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
	Prerequisites   []Prerequisite         `json:"prerequisites,omitempty"`
	FPRisk          string                 `json:"false_positive_risk"`
	WhyExpected     string                 `json:"why_expected"`
	SafeExample     *bool                  `json:"safe_example,omitempty"`
	Notes           string                 `json:"notes"`
	Source          string                 `json:"source"`
	Supersedes      string                 `json:"supersedes,omitempty"`
}

var (
	caseRequiredFields = []string{
		"schema_version", "id", "category", "title", "description", "input_type", "transport", "payload",
		"expected_verdict", "severity", "capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source",
	}
	resultRequiredFields = []string{
		"schema_version", "scoring_version", "case_id", "tool", "tool_version", "capability_registry", "expected_verdict", "actual_verdict", "score", "evidence", "notes",
	}
	profileRequiredFields = []string{
		"schema_version", "tool", "tool_version", "runner_version", "claims", "capability_registry",
	}
	// The schema's required list for receipt_evidence. This lived only in the
	// authority test, so the test asserted the schema matched a list the test
	// itself declared while the validator enforced no presence at all: an
	// omitted required field decoded to its zero value and passed.
	receiptEvidenceRequiredFields = []string{
		"evidence_dir", "file_glob", "detail_json_pointer", "detail_encoding", "verify_command", "valid_exit_codes",
	}
)

// releaseVersion and releaseCommit are stamped by the release build so this
// binary can state which release produced it. Source and "go run" builds keep
// the placeholders, which is why the release verifier only compares this output
// for an archive built as a release.
var (
	releaseVersion = "dev"
	releaseCommit  = "unknown"
)

const usageText = `usage: validate <command> <target>

commands:
  cases   <dir>    validate case JSON files in a directory
  results <file> [cases-dir]   validate runner JSONL; cases-dir enables case-bound checks
  profile <file>   validate a tool profile JSON file
  --version        print the release version and commit this binary was built from

for backwards compatibility, 'validate <dir>' works as 'validate cases <dir>'.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(1)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "--version", "-version":
		// A release records this binary's name in its identity. A name is not
		// evidence of a program, so the release verifier runs this and compares
		// the output, the same way it already does for the runner.
		fmt.Fprintf(os.Stdout, "aeb-validate %s %s\n", releaseVersion, releaseCommit)
		os.Exit(0)
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
	for _, field := range caseRequiredFields {
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
	} else if !caseIDPattern.MatchString(c.ID) {
		addErr("id must contain only lower-case letters, digits, hyphens, and underscores")
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
	if supersedes, present := rawSupersedes(data); present && !caseIDPattern.MatchString(supersedes) {
		addErr("supersedes must contain only lower-case letters, digits, hyphens, and underscores")
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
	seenRequires := make(map[string]bool, len(c.Requires))
	for _, req := range c.Requires {
		if seenRequires[req] {
			addErr(fmt.Sprintf("duplicate requires value: %q", req))
		}
		seenRequires[req] = true
		if problem := requiresTokenProblem(req); problem != "" {
			addErr(problem)
		}
	}

	payloadHosts := extractPayloadURLHosts(c.Payload)
	payloadHost := ""
	if len(payloadHosts) > 0 {
		payloadHost = payloadHosts[0]
	}
	matchesPayloadHost := func(value string) bool {
		normalized := strings.ToLower(strings.TrimSpace(value))
		for _, host := range payloadHosts {
			if normalized == host {
				return true
			}
		}
		return false
	}
	seenPrereq := make(map[string]bool, len(c.Prerequisites))
	for i, prereq := range c.Prerequisites {
		key := prereq.Kind + "\x00" + prereq.Value
		if seenPrereq[key] {
			addErr(fmt.Sprintf("duplicate prerequisite at index %d: kind=%q value=%q", i, prereq.Kind, prereq.Value))
			continue
		}
		seenPrereq[key] = true
		if !validPrerequisiteKinds[prereq.Kind] {
			addErr(fmt.Sprintf("invalid prerequisite kind at index %d: %q", i, prereq.Kind))
			continue
		}
		if strings.TrimSpace(prereq.Value) == "" {
			addErr(fmt.Sprintf("prerequisite value at index %d must be non-empty", i))
			continue
		}
		if prereq.Kind == "blocklist_domain" || prereq.Kind == "reserved_sink_route" {
			// Match ANY endpoint the payload names, not just the first. A payload
			// carrying both url and target_url delivers to one of them depending on
			// transport, and binding to the first let a decoy satisfy the check.
			if len(payloadHosts) == 0 {
				addErr(fmt.Sprintf("prerequisite kind %q at index %d requires a payload url or target_url host to bind against", prereq.Kind, i))
			} else if !matchesPayloadHost(prereq.Value) {
				addErr(fmt.Sprintf("prerequisite kind %q value %q does not match any payload host %v", prereq.Kind, prereq.Value, payloadHosts))
			}
		}
		// reservedSinkHosts is declared as a closed contract, so enforce it. Without
		// this a case could name any host as a reserved sink route and turn a
		// scoreable case into an unsatisfied-setup error no runner can clear.
		if prereq.Kind == "reserved_sink_route" && !reservedSinkHosts[strings.ToLower(strings.TrimSpace(prereq.Value))] {
			addErr(fmt.Sprintf("prerequisite reserved_sink_route value %q at index %d is not a corpus-reserved sink host", prereq.Value, i))
		}
	}
	// Coverage has to be COMPLETE, not just consistent. The per-entry check above only asks
	// that a declared value name some endpoint the payload carries; with both url and
	// target_url present, one entry naming either of them satisfies it while the transport may
	// select the other. So once a case covers one endpoint it must cover every endpoint it
	// names, mirrored in runner/prerequisites.go uncoveredEndpoint.
	if len(payloadHosts) > 1 {
		covered := make(map[string]bool, len(payloadHosts))
		for _, prereq := range c.Prerequisites {
			if prereq.Kind != "blocklist_domain" && prereq.Kind != "reserved_sink_route" {
				continue
			}
			covered[strings.ToLower(strings.TrimSpace(prereq.Value))] = true
		}
		for _, req := range c.Requires {
			if req == "domain_blocklist" {
				for _, host := range payloadHosts {
					covered[host] = true
				}
			}
		}
		for _, host := range payloadHosts {
			if reservedSinkHosts[host] {
				covered[host] = true
			}
		}
		if len(covered) > 0 {
			for _, host := range payloadHosts {
				if !covered[host] {
					addErr(fmt.Sprintf("payload names endpoint %q that no prerequisite covers while another endpoint it names is covered: setup must cover every endpoint the payload names, because the transport selects one of them", host))
				}
			}
		}
	}
	// The prerequisite VALUE is derivable, so it is not demanded. A case requiring a blocklist
	// names the action in requires, and the domain to seed is the host in its own payload. A case
	// targeting a reserved sink names a host that is already a fixed documented list in RUNNER.md.
	// Demanding a declared copy of either would be unreachable for cases whose bytes are frozen,
	// which is every case already merged, so the defect this guards would stay open on exactly the
	// cases that have it. Declaring one stays allowed and is bound to the payload host above; that
	// is for a future case whose required domain is NOT its payload host, where derivation breaks.
	for _, req := range c.Requires {
		if req == "domain_blocklist" && payloadHost == "" {
			addErr(`requires contains "domain_blocklist" but the payload has no url or target_url host to derive the domain from`)
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

// extractPayloadURLHosts returns every endpoint host a payload names, lowercased.
// Returning all of them keeps validation and the runner on one rule: a payload
// carrying both url and target_url must not let one satisfy a check the other
// escapes.
func extractPayloadURLHosts(payload map[string]interface{}) []string {
	if payload == nil {
		return nil
	}
	var hosts []string
	seen := make(map[string]struct{}, 2)
	for _, key := range []string{"url", "target_url"} {
		raw, ok := payload[key].(string)
		if !ok {
			continue
		}
		// The runner trims before parsing. Parsing the raw string here meant a
		// leading-space endpoint produced no host for the validator and a real host
		// for the runner, so a case could validate and then fail setup on a host
		// validation never saw.
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
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
	ScoringVersion     string                       `json:"scoring_version,omitempty"`
	CaseID             string                       `json:"case_id"`
	Tool               string                       `json:"tool"`
	ToolVersion        string                       `json:"tool_version"`
	CapabilityRegistry capabilityregistry.Reference `json:"capability_registry"`
	ExpectedVerdict    string                       `json:"expected_verdict"`
	ActualVerdict      string                       `json:"actual_verdict"`
	Score              string                       `json:"score"`
	Evidence           map[string]interface{}       `json:"evidence"`
	Notes              *string                      `json:"notes"`
	scoringVersionSet  bool
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
	} else if r.SchemaVersion == activeResultSchemaVersion && !caseIDPattern.MatchString(r.CaseID) {
		addErr("case_id must contain only lower-case letters, digits, hyphens, and underscores")
	}
	if r.SchemaVersion != legacyResultSchemaVersionV4 && r.SchemaVersion != legacyResultSchemaVersionV5 && r.SchemaVersion != activeResultSchemaVersion {
		addErr(fmt.Sprintf("schema_version must be %d, %d, or %d, got %d", legacyResultSchemaVersionV4, legacyResultSchemaVersionV5, activeResultSchemaVersion, r.SchemaVersion))
	}
	if r.SchemaVersion == activeResultSchemaVersion && strings.TrimSpace(r.ScoringVersion) == "" {
		addErr("missing scoring_version")
	}
	if (r.SchemaVersion == legacyResultSchemaVersionV4 || r.SchemaVersion == legacyResultSchemaVersionV5) && (r.scoringVersionSet || r.ScoringVersion != "") {
		addErr("scoring_version is not allowed for frozen result schemas")
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
	} else if r.SchemaVersion >= legacyResultSchemaVersionV5 {
		for _, issue := range validateResultState(r) {
			addErr(issue)
		}
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
	// contracts/result-states-v6.json and contract tests compare every row to
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

func validateResultState(r ResultLine) []string {
	raw, present := r.Evidence["result_state"]
	if !present {
		return []string{"missing evidence.result_state"}
	}
	state, ok := raw.(string)
	if !ok {
		return []string{"evidence.result_state must be a string"}
	}
	if !validResultStates[state] {
		return []string{fmt.Sprintf("invalid evidence.result_state: %q", state)}
	}

	switch state {
	case "observed":
		if !validMeasuredVerdicts[r.ActualVerdict] || (r.Score != "pass" && r.Score != "fail") {
			return []string{"evidence.result_state observed requires an allow or block verdict and a pass or fail score"}
		}
	case "unreachable":
		if r.ActualVerdict != "unreachable" || r.Score != "error" {
			return []string{"evidence.result_state unreachable requires actual_verdict unreachable and score error"}
		}
	default:
		if r.ActualVerdict != "error" || r.Score != "error" {
			return []string{fmt.Sprintf("evidence.result_state %s requires actual_verdict error and score error", state)}
		}
	}
	return nil
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
	var scoringVersion string
	var frozenRowLines []int
	activeRowsSeen := false

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
		var fields map[string]json.RawMessage
		if err := json.Unmarshal([]byte(text), &fields); err != nil {
			allErrors = append(allErrors, fmt.Sprintf("line %d: JSON parse error: %v", lineNum, err))
			continue
		}
		_, r.scoringVersionSet = fields["scoring_version"]

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
		if r.SchemaVersion == activeResultSchemaVersion {
			activeRowsSeen = true
		} else if r.SchemaVersion == legacyResultSchemaVersionV4 || r.SchemaVersion == legacyResultSchemaVersionV5 {
			frozenRowLines = append(frozenRowLines, lineNum)
		}
		if r.SchemaVersion == activeResultSchemaVersion && r.ScoringVersion != "" {
			if scoringVersion == "" {
				scoringVersion = r.ScoringVersion
			} else if scoringVersion != r.ScoringVersion {
				allErrors = append(allErrors, fmt.Sprintf("line %d: scoring_version differs from prior result rows", lineNum))
			}
		}
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
	if activeRowsSeen {
		for _, frozenLine := range frozenRowLines {
			allErrors = append(allErrors, fmt.Sprintf("line %d: frozen result rows cannot share a file with active schema_version %d rows", frozenLine, activeResultSchemaVersion))
		}
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
	// Kept raw so an omitted declaration stays distinguishable from an explicit
	// null. Decoding straight into a pointer collapses both to nil, which let a
	// schema-invalid null skip validation entirely.
	ReceiptEvidence json.RawMessage `json:"receipt_evidence,omitempty"`
}

// ReceiptEvidence is the optional receipt-evidence declaration in the active
// tool-profile schema. The validator does not execute it, but it must accept
// and structurally validate the same declaration the runner consumes.
type ReceiptEvidence struct {
	EvidenceDir                 string   `json:"evidence_dir"`
	FileGlob                    string   `json:"file_glob"`
	JSONLRecordType             string   `json:"jsonl_record_type"`
	DetailJSONPointer           string   `json:"detail_json_pointer"`
	DetailEncoding              string   `json:"detail_encoding"`
	RecordCaseIDJSONPointer     string   `json:"record_case_id_json_pointer"`
	RecordIdentifierJSONPointer string   `json:"record_identifier_json_pointer"`
	CaseIdentifierJSONPointer   string   `json:"case_identifier_json_pointer"`
	VerifyCommand               []string `json:"verify_command"`
	// Optional in the schema, so absence must stay distinguishable from a
	// supplied zero. Decoding into a plain int made an omitted value look like
	// 0 and rejected profiles the schema accepts.
	VerifyTimeoutSeconds *int  `json:"verify_timeout_seconds"`
	ValidExitCodes       []int `json:"valid_exit_codes"`
	PartialExitCodes     []int `json:"partial_exit_codes"`
}

func validateProfile(p Profile) []string {
	var errors []string

	if p.SchemaVersion != activeToolProfileSchemaVersion {
		errors = append(errors, fmt.Sprintf("schema_version must be %d, got %d", activeToolProfileSchemaVersion, p.SchemaVersion))
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
	if p.ReceiptEvidence != nil {
		for _, issue := range validateReceiptEvidenceRaw(p.ReceiptEvidence) {
			errors = append(errors, "invalid receipt_evidence: "+issue)
		}
	}

	return errors
}

// validateReceiptEvidenceRaw checks the declaration before it is decoded, because
// the schema types every receipt_evidence field as an object, string, or array and
// none of them accept null. Go decodes a null into the zero value, so a null would
// otherwise be indistinguishable from a legitimately empty or omitted field and
// would pass a check the schema fails.
func validateReceiptEvidenceRaw(raw json.RawMessage) []string {
	if strings.TrimSpace(string(raw)) == "null" {
		return []string{"must be an object, not null"}
	}
	var generic interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return []string{fmt.Sprintf("must be an object: %v", err)}
	}
	fields, isObject := generic.(map[string]interface{})
	if !isObject {
		return []string{"must be an object"}
	}

	// Nulls are checked at every depth, not just on the top-level properties.
	// A null inside valid_exit_codes decodes into []int as 0, which is the
	// success exit code, so a schema-invalid declaration would otherwise become
	// a silently different and more permissive verifier contract.
	errors := jsonNullPaths(fields, "")
	var missing []string
	for _, name := range receiptEvidenceRequiredFields {
		if _, present := fields[name]; !present {
			missing = append(missing, name+" is required")
		}
	}
	sort.Strings(missing)
	errors = append(errors, missing...)
	if len(errors) > 0 {
		return errors
	}

	// Strict, matching how this validator decodes every other artifact. A
	// tolerant decode would accept tool-specific keys the runner never reads
	// while the schema forbids them.
	var e ReceiptEvidence
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return []string{fmt.Sprintf("is malformed: %v", err)}
	}
	return validateReceiptEvidence(e)
}

// jsonNullPaths reports every null reachable inside a decoded JSON value, named
// by its dotted path. No receipt_evidence field is nullable in the schema, and
// Go turns each null into a zero value that is indistinguishable from a
// legitimately empty one, so the null has to be caught before decoding.
func jsonNullPaths(value interface{}, path string) []string {
	switch typed := value.(type) {
	case nil:
		if path == "" {
			return []string{"must not be null"}
		}
		return []string{path + " must not be null"}
	case map[string]interface{}:
		names := make([]string, 0, len(typed))
		for name := range typed {
			names = append(names, name)
		}
		sort.Strings(names)
		var found []string
		for _, name := range names {
			child := name
			if path != "" {
				child = path + "." + name
			}
			found = append(found, jsonNullPaths(typed[name], child)...)
		}
		return found
	case []interface{}:
		var found []string
		for index, item := range typed {
			found = append(found, jsonNullPaths(item, fmt.Sprintf("%s[%d]", path, index))...)
		}
		return found
	}
	return nil
}

func validateReceiptEvidence(e ReceiptEvidence) []string {
	var errors []string
	if strings.TrimSpace(e.EvidenceDir) == "" {
		errors = append(errors, "evidence_dir must be non-empty")
	}
	if strings.TrimSpace(e.FileGlob) == "" {
		errors = append(errors, "file_glob must be non-empty")
	}
	if e.DetailJSONPointer != "" && !strings.HasPrefix(e.DetailJSONPointer, "/") {
		errors = append(errors, "detail_json_pointer must be empty or start with /")
	}
	switch e.DetailEncoding {
	case "object", "json_string", "object_or_json_string":
	default:
		errors = append(errors, "detail_encoding must be object, json_string, or object_or_json_string")
	}
	for _, pointer := range []struct {
		name  string
		value string
	}{
		{"record_case_id_json_pointer", e.RecordCaseIDJSONPointer},
		{"record_identifier_json_pointer", e.RecordIdentifierJSONPointer},
		{"case_identifier_json_pointer", e.CaseIdentifierJSONPointer},
	} {
		if pointer.value != "" && !strings.HasPrefix(pointer.value, "/") {
			errors = append(errors, pointer.name+" must be empty or start with /")
		}
	}
	if len(e.VerifyCommand) == 0 {
		errors = append(errors, "verify_command must not be empty")
	}
	for _, value := range e.VerifyCommand {
		if strings.TrimSpace(value) == "" {
			errors = append(errors, "verify_command entries must be non-empty")
			break
		}
	}
	if e.VerifyTimeoutSeconds != nil && *e.VerifyTimeoutSeconds < 1 {
		errors = append(errors, "verify_timeout_seconds must be positive")
	}
	if len(e.ValidExitCodes) == 0 {
		errors = append(errors, "valid_exit_codes must not be empty")
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
