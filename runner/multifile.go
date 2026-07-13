package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

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
	Dir             string   `yaml:"-"`
	SchemaVersion   int      `yaml:"schema_version"`
	ID              string   `yaml:"id"`
	Category        string   `yaml:"category"`
	Title           string   `yaml:"title"`
	Description     string   `yaml:"description"`
	ThreatModel     string   `yaml:"threat_model"`
	InputType       string   `yaml:"input_type"`
	Transport       string   `yaml:"transport"`
	ExpectedVerdict string   `yaml:"expected_verdict"`
	Severity        string   `yaml:"severity"`
	CapabilityTags  []string `yaml:"capability_tags"`
	Requires        []string `yaml:"requires"`
	FPRisk          string   `yaml:"false_positive_risk"`
	WhyExpected     string   `yaml:"why_expected"`
	Files           struct {
		Before   string `yaml:"before"`
		After    string `yaml:"after"`
		Expected string `yaml:"expected"`
	} `yaml:"files"`
	Notes  string `yaml:"notes"`
	Source string `yaml:"source"`

	// BeforeJSON and AfterJSON are the parsed contents of the two snapshot
	// files, cached at load time so the driver does not re-read them per run.
	BeforeJSON map[string]interface{} `yaml:"-"`
	AfterJSON  map[string]interface{} `yaml:"-"`
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
				// Subdirectory without case.yaml is ignored, not an error.
				// The mcp-drift directory has a README.md sibling and may
				// gain other non-case subdirectories over time.
				continue
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

// loadMultiFileCase reads case.yaml from the given directory and then loads
// before.json + after.json + expected.json by the relative names declared in
// the case.yaml files block. Missing any of the three is a hard error.
func loadMultiFileCase(caseDir string) (MultiFileCase, error) {
	caseYAMLPath := filepath.Join(caseDir, "case.yaml")
	yamlData, err := os.ReadFile(caseYAMLPath)
	if err != nil {
		return MultiFileCase{}, fmt.Errorf("reading %s: %w", caseYAMLPath, err)
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
	// expected.json is not consumed by the runner yet, but it is part of the
	// machine-readable case contract. Parse it at load time so malformed
	// multi-file fixtures fail before any tool run starts.
	if _, err := readJSONObject(expectedPath); err != nil {
		return MultiFileCase{}, err
	}

	c.BeforeJSON = beforeJSON
	c.AfterJSON = afterJSON
	return c, nil
}

func validateMultiFileCaseMetadata(c MultiFileCase, caseYAMLPath string) error {
	if c.SchemaVersion != 2 {
		return fmt.Errorf("%s: schema_version must be 2, got %d", caseYAMLPath, c.SchemaVersion)
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
	if c.Files.Before == "" || c.Files.After == "" || c.Files.Expected == "" {
		return fmt.Errorf("%s: files block must name before, after, and expected", caseYAMLPath)
	}

	return nil
}

func resolveMultiFileCasePath(caseDir, name, label string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("files.%s must be non-empty", label)
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("files.%s must be relative to the case directory, got %q", label, name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("files.%s must stay inside the case directory, got %q", label, name)
	}
	return filepath.Join(caseDir, clean), nil
}

// readJSONObject reads a JSON file and decodes it as a generic JSON object.
// Returns a helpful error including the path on parse failure so corpus
// authors can find broken fixtures.
func readJSONObject(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
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
		FPRisk:          c.FPRisk,
		WhyExpected:     c.WhyExpected,
		Notes:           c.Notes,
		Source:          c.Source,
	}, nil
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
