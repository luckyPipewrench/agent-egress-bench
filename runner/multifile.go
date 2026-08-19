package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var multiFileComponentName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

var validMultiFileRequires = map[string]struct{}{
	"tls_interception": {}, "url_dlp_scanning": {}, "request_body_dlp_scanning": {},
	"header_dlp_scanning": {}, "response_prompt_injection_scanning": {}, "mcp_input_dlp_scanning": {},
	"mcp_input_prompt_injection_scanning": {}, "mcp_tool_policy": {}, "mcp_tool_result_prompt_injection_scanning": {},
	"mcp_tool_poison_scanning": {}, "mcp_tool_baseline": {}, "mcp_chain_memory": {},
	"mcp_cross_server_chain_memory": {}, "mcp_data_class_labels": {}, "a2a_dlp_scanning": {},
	"a2a_prompt_injection_scanning": {}, "a2a_card_prompt_injection_scanning": {}, "a2a_card_drift_scanning": {},
	"a2a_ssrf_scanning": {}, "websocket_dlp_scanning": {}, "websocket_prompt_injection_scanning": {},
	"ssrf_scanning": {}, "domain_blocklist": {}, "entropy_scanning": {}, "shell_analysis": {},
	"crypto_dlp_scanning": {}, "hostname_exfil_scanning": {}, "dns_rebinding_fixture": {},
}

// MultiFileCase represents one temporal MCP-drift case loaded from a
// subdirectory containing case.yaml + before.json + after.json +
// expected.json + notes.md. The single-JSON Case type does not fit this
// shape because the attack is the delta between two snapshots.
//
// The driver replays Before and After through a single MCP session against
// the running tool, observes the verdict on the second tools/list response,
// and emits a CaseResult in the same shape as single-file cases so the
// downstream scoring and receipt-profile code does not need to branch.
type MultiFileCase struct {
	Dir             string         `yaml:"-"`
	SchemaVersion   int            `yaml:"schema_version"`
	ID              string         `yaml:"id"`
	Category        string         `yaml:"category"`
	Title           string         `yaml:"title"`
	Description     string         `yaml:"description"`
	ThreatModel     string         `yaml:"threat_model"`
	InputType       string         `yaml:"input_type"`
	Transport       string         `yaml:"transport"`
	ExpectedVerdict string         `yaml:"expected_verdict"`
	Severity        string         `yaml:"severity"`
	CapabilityTags  []string       `yaml:"capability_tags"`
	Requires        []string       `yaml:"requires"`
	Prerequisites   []Prerequisite `yaml:"prerequisites,omitempty"`
	FPRisk          string         `yaml:"false_positive_risk"`
	WhyExpected     string         `yaml:"why_expected"`
	Files           struct {
		Before   string `yaml:"before"`
		After    string `yaml:"after"`
		Expected string `yaml:"expected"`
	} `yaml:"files"`
	Notes  string `yaml:"notes"`
	Source string `yaml:"source"`

	// BeforeJSON and AfterJSON are the parsed contents of the two snapshot
	// files, cached at load time so the driver does not re-read them per run.
	BeforeJSON   map[string]interface{} `yaml:"-"`
	AfterJSON    map[string]interface{} `yaml:"-"`
	ExpectedJSON map[string]interface{} `yaml:"-"`
}

// loadMultiFileCases walks the multi-file case directory (typically
// cases/mcp-drift/) and returns one MultiFileCase per immediate subdirectory.
// Each subdirectory must contain case.yaml plus the three JSON snapshots
// (before.json, after.json, expected.json) named by the case.yaml files
// block. A subdirectory that has case.yaml but is missing any of the three
// snapshots is a hard error: a partial multi-file case cannot be replayed.
//
// Order of returned cases is sorted by case ID so callers can rely on a
// stable iteration order for byte-reproducible profile emission.
func loadMultiFileCases(dir string) ([]MultiFileCase, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading multi-file case dir %s: %w", dir, err)
	}

	var cases []MultiFileCase
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		caseDir := filepath.Join(dir, entry.Name())
		caseYAMLPath := filepath.Join(caseDir, "case.yaml")
		if _, statErr := os.Stat(caseYAMLPath); statErr != nil {
			if os.IsNotExist(statErr) {
				return nil, fmt.Errorf("multi-file case directory %s is missing required case.yaml; restore case.yaml or remove the directory, then run 'make cases-manifest'", caseDir)
			}
			return nil, fmt.Errorf("stat %s: %w", caseYAMLPath, statErr)
		}

		c, loadErr := loadMultiFileCase(caseDir)
		if loadErr != nil {
			return nil, loadErr
		}
		cases = append(cases, c)
	}

	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, nil
}

// selectedMultiFileSnapshotPaths returns the machine-readable files selected by
// the multi-file loader without touching disk. It is shared by the load-time
// snapshot parser and both digest functions, so notes.md and stray files cannot
// accidentally enter one surface but not the other.
func selectedMultiFileSnapshotPaths(files []corpusFile, directory multiFileCaseDir) ([]string, error) {
	cases, paths, err := multiFileCasesFromSnapshot(files, directory)
	if err != nil {
		return nil, err
	}
	available := make(map[string]struct{}, len(files))
	for _, file := range files {
		if !file.isDir {
			available[file.path] = struct{}{}
		}
	}
	for _, c := range cases {
		notesPath := filepath.Join(c.Dir, c.Notes)
		if _, ok := available[notesPath]; !ok {
			return nil, fmt.Errorf("multi-file case %s is missing required notes file %s", c.ID, notesPath)
		}
		paths = append(paths, notesPath)
	}
	return paths, nil
}

// loadMultiFileCasesFromSnapshot parses only bytes captured before execution.
func loadMultiFileCasesFromSnapshot(files []corpusFile, directories []multiFileCaseDir) ([]MultiFileCase, error) {
	var cases []MultiFileCase
	for _, directory := range directories {
		loaded, _, err := multiFileCasesFromSnapshot(files, directory)
		if err != nil {
			return nil, err
		}
		cases = append(cases, loaded...)
	}
	return cases, nil
}

func multiFileCasesFromSnapshot(files []corpusFile, directory multiFileCaseDir) ([]MultiFileCase, []string, error) {
	byPath := make(map[string]corpusFile)
	caseDirs := make(map[string]struct{})
	for _, file := range files {
		if file.sourceRoot != directory.path {
			continue
		}
		if file.isDir {
			if filepath.Dir(file.path) == directory.path {
				caseDirs[file.path] = struct{}{}
			}
			continue
		}
		byPath[file.path] = file
		relative, err := filepath.Rel(directory.path, file.path)
		if err != nil {
			return nil, nil, fmt.Errorf("finding multi-file case path %s: %w", file.path, err)
		}
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if len(parts) >= 2 {
			caseDirs[filepath.Join(directory.path, parts[0])] = struct{}{}
		}
	}

	directories := make([]string, 0, len(caseDirs))
	for caseDir := range caseDirs {
		directories = append(directories, caseDir)
	}
	sort.Strings(directories)

	cases := make([]MultiFileCase, 0, len(directories))
	paths := make([]string, 0, len(directories)*4)
	for _, caseDir := range directories {
		caseYAMLPath := filepath.Join(caseDir, "case.yaml")
		caseYAML, ok := byPath[caseYAMLPath]
		if !ok {
			return nil, nil, fmt.Errorf("multi-file case directory %s is missing required case.yaml; restore case.yaml or remove the directory, then run 'make cases-manifest'", caseDir)
		}
		loaded, used, err := loadMultiFileCaseFromSnapshot(caseDir, caseYAML.data, byPath)
		if err != nil {
			return nil, nil, err
		}
		cases = append(cases, loaded)
		paths = append(paths, caseYAMLPath)
		paths = append(paths, used...)
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, paths, nil
}

func loadMultiFileCaseFromSnapshot(caseDir string, yamlData []byte, files map[string]corpusFile) (MultiFileCase, []string, error) {
	caseYAMLPath := filepath.Join(caseDir, "case.yaml")
	if err := requireMultiFileYAMLKeys(yamlData, caseYAMLPath); err != nil {
		return MultiFileCase{}, nil, err
	}
	var c MultiFileCase
	dec := yaml.NewDecoder(bytes.NewReader(yamlData))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return MultiFileCase{}, nil, fmt.Errorf("parsing %s: %w", caseYAMLPath, err)
	}
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return MultiFileCase{}, nil, fmt.Errorf("parsing %s: multiple YAML documents", caseYAMLPath)
		}
		return MultiFileCase{}, nil, fmt.Errorf("parsing %s: %w", caseYAMLPath, err)
	}
	c.Dir = caseDir
	if err := validateMultiFileCaseMetadata(c, caseYAMLPath); err != nil {
		return MultiFileCase{}, nil, err
	}

	resolve := func(name, label string) (string, corpusFile, error) {
		path, err := resolveMultiFileCasePath(caseDir, name, label)
		if err != nil {
			return "", corpusFile{}, fmt.Errorf("%s: %w", caseYAMLPath, err)
		}
		file, ok := files[path]
		if !ok {
			return "", corpusFile{}, fmt.Errorf("reading %s: captured corpus snapshot has no such file", path)
		}
		return path, file, nil
	}
	beforePath, beforeFile, err := resolve(c.Files.Before, "before")
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	afterPath, afterFile, err := resolve(c.Files.After, "after")
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	expectedPath, expectedFile, err := resolve(c.Files.Expected, "expected")
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	before, err := readJSONObjectBytes(beforeFile.data, beforePath)
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	after, err := readJSONObjectBytes(afterFile.data, afterPath)
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	expected, err := readJSONObjectBytes(expectedFile.data, expectedPath)
	if err != nil {
		return MultiFileCase{}, nil, err
	}
	if err := validateMultiFileSnapshots(c, before, after, expected, caseYAMLPath); err != nil {
		return MultiFileCase{}, nil, err
	}
	c.BeforeJSON = before
	c.AfterJSON = after
	c.ExpectedJSON = expected
	return c, []string{beforePath, afterPath, expectedPath}, nil
}

// loadMultiFileCase reads case.yaml from the given directory and then loads
// before.json + after.json + expected.json by the relative names declared in
// the case.yaml files block. Missing any of the three is a hard error.
func loadMultiFileCase(caseDir string) (MultiFileCase, error) {
	caseYAMLPath := filepath.Join(caseDir, "case.yaml")
	yamlData, err := os.ReadFile(caseYAMLPath)
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("reading %s: %w", caseYAMLPath, err)
	}
	if err := requireMultiFileYAMLKeys(yamlData, caseYAMLPath); err != nil {
		return MultiFileCase{}, err
	}

	var c MultiFileCase
	dec := yaml.NewDecoder(bytes.NewReader(yamlData))
	dec.KnownFields(true)
	if yamlErr := dec.Decode(&c); yamlErr != nil {
		return MultiFileCase{}, fmt.Errorf("parsing %s: %w", caseYAMLPath, yamlErr)
	}
	var extra interface{}
	if extraErr := dec.Decode(&extra); extraErr != io.EOF {
		if extraErr == nil {
			return MultiFileCase{}, fmt.Errorf("parsing %s: multiple YAML documents", caseYAMLPath)
		}
		return MultiFileCase{}, fmt.Errorf("parsing %s: %w", caseYAMLPath, extraErr)
	}
	c.Dir = caseDir

	if err := validateMultiFileCaseMetadata(c, caseYAMLPath); err != nil {
		return MultiFileCase{}, err
	}

	beforePath, err := resolveMultiFileCasePath(caseDir, c.Files.Before, "before")
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("%s: %w", caseYAMLPath, err)
	}
	afterPath, err := resolveMultiFileCasePath(caseDir, c.Files.After, "after")
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("%s: %w", caseYAMLPath, err)
	}
	expectedPath, err := resolveMultiFileCasePath(caseDir, c.Files.Expected, "expected")
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("%s: %w", caseYAMLPath, err)
	}

	beforeJSON, err := readJSONObject(beforePath)
	if err != nil {
		return MultiFileCase{}, err
	}
	afterJSON, err := readJSONObject(afterPath)
	if err != nil {
		return MultiFileCase{}, err
	}
	// expected.json is the portable decision contract. Validate it at load time
	// against case.yaml even though the generic adapter does not yet expose a
	// field-by-field receipt comparison surface.
	expectedJSON, err := readJSONObject(expectedPath)
	if err != nil {
		return MultiFileCase{}, err
	}
	if err := validateMultiFileSnapshots(c, beforeJSON, afterJSON, expectedJSON, caseYAMLPath); err != nil {
		return MultiFileCase{}, err
	}
	notesPath := filepath.Join(caseDir, c.Notes)
	info, err := os.Stat(notesPath)
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("reading required notes file %s: %w", notesPath, err)
	}
	if info.IsDir() {
		return MultiFileCase{}, fmt.Errorf("required notes file is a directory: %s", notesPath)
	}
	c.BeforeJSON = beforeJSON
	c.AfterJSON = afterJSON
	c.ExpectedJSON = expectedJSON
	return c, nil
}

func requireMultiFileYAMLKeys(data []byte, path string) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("parsing %s: top-level value must be a mapping", path)
	}
	present := make(map[string]*yaml.Node, len(document.Content[0].Content)/2)
	for index := 0; index < len(document.Content[0].Content); index += 2 {
		present[document.Content[0].Content[index].Value] = document.Content[0].Content[index+1]
	}
	for _, key := range []string{
		"schema_version", "id", "category", "title", "description", "threat_model",
		"input_type", "transport", "files", "expected_verdict", "severity",
		"capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source",
	} {
		if _, ok := present[key]; !ok {
			return fmt.Errorf("%s: missing required field %s", path, key)
		}
	}
	for _, key := range []string{"capability_tags", "requires"} {
		if present[key].Kind != yaml.SequenceNode {
			return fmt.Errorf("%s: %s must be a sequence", path, key)
		}
	}
	return nil
}

func validateMultiFileCaseMetadata(c MultiFileCase, caseYAMLPath string) error {
	if c.SchemaVersion != activeMultiFileCaseSchemaVersion {
		return fmt.Errorf("%s: schema_version must be %d, got %d", caseYAMLPath, activeMultiFileCaseSchemaVersion, c.SchemaVersion)
	}
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("%s: id must be non-empty", caseYAMLPath)
	}
	if c.ID != filepath.Base(filepath.Dir(caseYAMLPath)) {
		return fmt.Errorf("%s: id %q must match directory name %q", caseYAMLPath, c.ID, filepath.Base(filepath.Dir(caseYAMLPath)))
	}

	requiredStrings := map[string]string{
		"category":            c.Category,
		"title":               c.Title,
		"description":         c.Description,
		"threat_model":        c.ThreatModel,
		"input_type":          c.InputType,
		"transport":           c.Transport,
		"severity":            c.Severity,
		"false_positive_risk": c.FPRisk,
		"why_expected":        c.WhyExpected,
		"notes":               c.Notes,
		"source":              c.Source,
	}
	for field, value := range requiredStrings {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s: %s must be non-empty", caseYAMLPath, field)
		}
	}

	if c.Category != "mcp_drift" {
		return fmt.Errorf("%s: category must be mcp_drift, got %q", caseYAMLPath, c.Category)
	}
	if c.InputType != "mcp_tool_sequence_temporal" {
		return fmt.Errorf("%s: input_type must be mcp_tool_sequence_temporal, got %q", caseYAMLPath, c.InputType)
	}
	if c.Transport != "mcp_stdio" && c.Transport != "mcp_http" {
		return fmt.Errorf("%s: transport must be mcp_stdio or mcp_http, got %q", caseYAMLPath, c.Transport)
	}
	if c.ExpectedVerdict != "block" && c.ExpectedVerdict != "warn" && c.ExpectedVerdict != "allow" {
		return fmt.Errorf("%s: expected_verdict must be block, warn, or allow, got %q", caseYAMLPath, c.ExpectedVerdict)
	}
	if c.Severity != "critical" && c.Severity != "high" && c.Severity != "medium" && c.Severity != "low" {
		return fmt.Errorf("%s: severity must be critical, high, medium, or low, got %q", caseYAMLPath, c.Severity)
	}
	if c.FPRisk != "low" && c.FPRisk != "medium" && c.FPRisk != "high" {
		return fmt.Errorf("%s: false_positive_risk must be low, medium, or high, got %q", caseYAMLPath, c.FPRisk)
	}
	if len(c.CapabilityTags) == 0 {
		return fmt.Errorf("%s: capability_tags must be non-empty", caseYAMLPath)
	}
	if err := validateUniqueNonEmptyStrings(c.CapabilityTags, "capability_tags"); err != nil {
		return fmt.Errorf("%s: %w", caseYAMLPath, err)
	}
	if err := validateUniqueNonEmptyStrings(c.Requires, "requires"); err != nil {
		return fmt.Errorf("%s: %w", caseYAMLPath, err)
	}
	for _, requirement := range c.Requires {
		if _, ok := validMultiFileRequires[requirement]; !ok {
			return fmt.Errorf("%s: invalid requires value %q", caseYAMLPath, requirement)
		}
	}
	if err := validateMultiFilePrerequisites(c.Prerequisites, c.Requires, caseYAMLPath); err != nil {
		return err
	}
	if c.Files.Before == "" || c.Files.After == "" || c.Files.Expected == "" {
		return fmt.Errorf("%s: files block must name before, after, and expected", caseYAMLPath)
	}
	fileNames := []string{c.Files.Before, c.Files.After, c.Files.Expected}
	if fileNames[0] == fileNames[1] || fileNames[0] == fileNames[2] || fileNames[1] == fileNames[2] {
		return fmt.Errorf("%s: files.before, files.after, and files.expected must name three distinct files", caseYAMLPath)
	}
	for index, name := range fileNames {
		label := []string{"before", "after", "expected"}[index]
		if err := validateMultiFileName(name, ".json", "files."+label); err != nil {
			return fmt.Errorf("%s: %w", caseYAMLPath, err)
		}
	}
	if err := validateMultiFileName(c.Notes, ".md", "notes"); err != nil {
		return fmt.Errorf("%s: %w", caseYAMLPath, err)
	}

	return nil
}

func validateUniqueNonEmptyStrings(values []string, label string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s entries must be non-empty", label)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("%s contains duplicate value %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateMultiFileName(name, suffix, label string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("%s must be non-empty", label)
	}
	if !strings.HasSuffix(name, suffix) {
		return fmt.Errorf("%s must end in %s, got %q", label, suffix, name)
	}
	if !multiFileComponentName.MatchString(name) {
		return fmt.Errorf("%s must match the published safe relative-path pattern, got %q", label, name)
	}
	return nil
}

func resolveMultiFileCasePath(caseDir, name, label string) (string, error) {
	if err := validateMultiFileName(name, ".json", "files."+label); err != nil {
		return "", err
	}
	return filepath.Join(caseDir, name), nil
}

// readJSONObject reads a JSON file and decodes it as a generic JSON object.
// Returns a helpful error including the path on parse failure so corpus
// authors can find broken fixtures.
func readJSONObject(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return readJSONObjectBytes(data, path)
}

func readJSONObjectBytes(data []byte, path string) (map[string]interface{}, error) {
	var obj map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if jsonErr := dec.Decode(&obj); jsonErr != nil {
		return nil, fmt.Errorf("parsing %s as JSON object: %w", path, jsonErr)
	}
	if obj == nil {
		return nil, fmt.Errorf("parsing %s as JSON object: top-level value must be an object", path)
	}
	var extra interface{}
	if extraErr := dec.Decode(&extra); extraErr != io.EOF {
		if extraErr == nil {
			return nil, fmt.Errorf("parsing %s as JSON object: multiple JSON values", path)
		}
		return nil, fmt.Errorf("parsing %s as JSON object: %w", path, extraErr)
	}
	return obj, nil
}

// receiptScoringExpected returns the expected_verdict value the receipt-
// scoring rubric should classify this case under. The rubric only knows
// "block" (malicious case, blocked yes/no, false_positive n/a) and "allow"
// (benign baseline, blocked n/a, false_positive yes/no). A case marked
// "warn" in case.yaml is a drift-detection FP guardrail and should map to
// "allow" for receipt-scoring purposes: a tool that blocks it is over-
// reaching and should be counted as a false positive.
func (c MultiFileCase) receiptScoringExpected() string {
	switch c.ExpectedVerdict {
	case "warn":
		return "allow"
	default:
		return c.ExpectedVerdict
	}
}

// toCase converts a MultiFileCase into a regular Case the existing runner
// pipeline can execute. The Payload contains an ordered JSON-RPC sequence of
// client tools/list requests interleaved with server responses. Single-server
// fixtures become the usual four-message sequence (before request/response,
// after request/response). Multi-server fixtures become one request/response
// pair per server snapshot so stdio proxy adapters can replay each observed
// tools/list response without relying on JSON-RPC batches.
//
// ExpectedVerdict is normalized through receiptScoringExpected so the
// downstream receipt-profile mapping does not need to know about the
// "warn" verdict that mcp-drift benign cases declare.
func (c MultiFileCase) toCase() (Case, error) {
	messages := make([]interface{}, 0, 4)
	nextID := float64(1)
	appendSnapshotMessages := func(label string, snapshot map[string]interface{}) error {
		responses, err := multiFileSnapshotResponses(snapshot)
		if err != nil {
			return fmt.Errorf("%s snapshot: %w", label, err)
		}
		for _, response := range responses {
			messages = append(messages, map[string]interface{}{
				"jsonrpc": "2.0",
				"method":  "tools/list",
				"id":      nextID,
			})
			messages = append(messages, withJSONRPCID(response, nextID))
			nextID++
		}
		return nil
	}
	if err := appendSnapshotMessages("before", c.BeforeJSON); err != nil {
		return Case{}, err
	}
	if err := appendSnapshotMessages("after", c.AfterJSON); err != nil {
		return Case{}, err
	}

	return Case{
		SchemaVersion: c.SchemaVersion,
		ID:            c.ID,
		Category:      c.Category,
		Title:         c.Title,
		Description:   c.Description,
		InputType:     c.InputType,
		Transport:     c.Transport,
		Payload: map[string]interface{}{
			"jsonrpc_messages": messages,
		},
		ExpectedVerdict: c.receiptScoringExpected(),
		Severity:        c.Severity,
		CapabilityTags:  c.CapabilityTags,
		Requires:        c.Requires,
		Prerequisites:   c.Prerequisites,
		FPRisk:          c.FPRisk,
		WhyExpected:     c.WhyExpected,
		Notes:           c.Notes,
		Source:          c.Source,
	}, nil
}

func validateMultiFileSnapshots(c MultiFileCase, before, after, expected map[string]interface{}, caseYAMLPath string) error {
	for label, snapshot := range map[string]map[string]interface{}{"before": before, "after": after} {
		responses, err := multiFileSnapshotResponses(snapshot)
		if err != nil {
			return fmt.Errorf("%s: %s snapshot: %w", caseYAMLPath, label, err)
		}
		for index, response := range responses {
			if err := validateToolsListResponse(response); err != nil {
				return fmt.Errorf("%s: %s snapshot response %d: %w", caseYAMLPath, label, index, err)
			}
		}
	}
	if err := validateExpectedReceiptContract(c, expected); err != nil {
		return fmt.Errorf("%s: expected snapshot: %w", caseYAMLPath, err)
	}
	return nil
}

func validateToolsListResponse(value interface{}) error {
	response, ok := value.(map[string]interface{})
	if !ok {
		return fmt.Errorf("tools/list response must be an object")
	}
	if response["jsonrpc"] != "2.0" {
		return fmt.Errorf("jsonrpc must be %q", "2.0")
	}
	id, ok := response["id"]
	if !ok {
		return fmt.Errorf("missing id")
	}
	if !validJSONRPCID(id) {
		return fmt.Errorf("id must be a string, number, or null")
	}
	if _, exists := response["error"]; exists {
		return fmt.Errorf("tools/list response must not contain both result and error")
	}
	result, ok := response["result"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("result must be an object")
	}
	tools, ok := result["tools"].([]interface{})
	if !ok {
		return fmt.Errorf("result.tools must be an array")
	}
	for index, rawTool := range tools {
		tool, ok := rawTool.(map[string]interface{})
		if !ok {
			return fmt.Errorf("result.tools[%d] must be an object", index)
		}
		name, ok := tool["name"].(string)
		if !ok || strings.TrimSpace(name) == "" {
			return fmt.Errorf("result.tools[%d].name must be a non-empty string", index)
		}
		if _, ok := tool["inputSchema"].(map[string]interface{}); !ok {
			return fmt.Errorf("result.tools[%d].inputSchema must be an object", index)
		}
	}
	return nil
}

func validJSONRPCID(value interface{}) bool {
	switch value.(type) {
	case nil, string, json.Number, float64:
		return true
	default:
		return false
	}
}

func validateExpectedReceiptContract(c MultiFileCase, expected map[string]interface{}) error {
	if !isJSONIntegerOne(expected["version"]) {
		return fmt.Errorf("version must be 1")
	}
	record, ok := expected["action_record"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("action_record must be an object")
	}
	if !isJSONIntegerOne(record["version"]) {
		return fmt.Errorf("action_record.version must be 1")
	}
	for field, want := range map[string]string{
		"verdict":   c.ExpectedVerdict,
		"transport": c.Transport,
		"severity":  c.Severity,
	} {
		got, ok := record[field].(string)
		if !ok || got != want {
			return fmt.Errorf("action_record.%s must equal case.yaml %s %q, got %q", field, field, want, got)
		}
	}
	for _, field := range []string{"layer", "pattern", "intent"} {
		value, ok := record[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("action_record.%s must be a non-empty string", field)
		}
	}
	return nil
}

func isJSONIntegerOne(value interface{}) bool {
	number, ok := value.(json.Number)
	return ok && number.String() == "1"
}

func multiFileSnapshotResponses(snapshot map[string]interface{}) ([]interface{}, error) {
	rawServers, hasServers := snapshot["servers"]
	if !hasServers {
		return []interface{}{snapshot}, nil
	}
	servers, ok := rawServers.([]interface{})
	if !ok {
		return nil, fmt.Errorf("servers must be an array")
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("servers must contain at least one entry")
	}

	responses := make([]interface{}, 0, len(servers))
	seenServerIDs := make(map[string]struct{}, len(servers))
	for i, rawServer := range servers {
		server, ok := rawServer.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("servers[%d] must be an object", i)
		}
		resp, ok := server["tools_list_response"]
		if !ok {
			return nil, fmt.Errorf("servers[%d] missing tools_list_response", i)
		}
		if _, ok := resp.(map[string]interface{}); !ok {
			return nil, fmt.Errorf("servers[%d].tools_list_response must be an object", i)
		}
		serverID, ok := server["server_id"].(string)
		if !ok || strings.TrimSpace(serverID) == "" {
			return nil, fmt.Errorf("servers[%d].server_id must be a non-empty string", i)
		}
		if _, duplicate := seenServerIDs[serverID]; duplicate {
			return nil, fmt.Errorf("servers[%d].server_id duplicates %q", i, serverID)
		}
		seenServerIDs[serverID] = struct{}{}
		responses = append(responses, resp)
	}
	return responses, nil
}

func withJSONRPCID(msg interface{}, id float64) interface{} {
	m, ok := msg.(map[string]interface{})
	if !ok {
		return msg
	}
	cp := make(map[string]interface{}, len(m)+1)
	for k, v := range m {
		cp[k] = v
	}
	cp["id"] = id
	return cp
}

// computeMultiFileSHA256 hashes the multi-file corpus directory contents
// (case.yaml plus the three JSON snapshots per case, sorted by path) so
// the receipt profile's corpus_sha256 covers multi-file cases when the
// driver loads them. notes.md is intentionally excluded: it is documentation
// for human reviewers, not part of the case-machine-readable contract.
func computeMultiFileSHA256Paths(dir string) ([]string, error) {
	if dir == "" {
		return nil, nil
	}
	cases, err := loadMultiFileCases(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, c := range cases {
		paths = append(paths, filepath.Join(c.Dir, "case.yaml"))
		for label, name := range map[string]string{
			"before":   c.Files.Before,
			"after":    c.Files.After,
			"expected": c.Files.Expected,
		} {
			path, pathErr := resolveMultiFileCasePath(c.Dir, name, label)
			if pathErr != nil {
				return nil, pathErr
			}
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}
