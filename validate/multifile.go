package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var multiFileComponentName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

type multiFileCase struct {
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
}

func validateMultiFileCase(path string, ids map[string]string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: cannot read case.yaml: %v", path, err)}
	}
	c, err := parseMultiFileCaseYAML(data)
	if err != nil {
		return []string{fmt.Sprintf("%s: YAML parse error: %v", path, err)}
	}

	var issues []string
	add := func(message string) { issues = append(issues, fmt.Sprintf("%s: %s", path, message)) }
	if c.SchemaVersion != activeCaseSchemaVersion {
		add(fmt.Sprintf("schema_version must be %d, got %d", activeCaseSchemaVersion, c.SchemaVersion))
	}
	if strings.TrimSpace(c.ID) == "" {
		add("id must be non-empty")
	} else {
		if c.ID != filepath.Base(filepath.Dir(path)) {
			add(fmt.Sprintf("id %q must match directory name %q", c.ID, filepath.Base(filepath.Dir(path))))
		}
		if previous, duplicate := ids[c.ID]; duplicate {
			add(fmt.Sprintf("duplicate id %q (also in %s)", c.ID, previous))
		} else {
			ids[c.ID] = path
		}
	}
	for field, value := range map[string]string{
		"title": c.Title, "description": c.Description, "threat_model": c.ThreatModel,
		"why_expected": c.WhyExpected, "source": c.Source,
	} {
		if strings.TrimSpace(value) == "" {
			add(field + " must be non-empty")
		}
	}
	if c.Category != "mcp_drift" {
		add(fmt.Sprintf("category must be mcp_drift, got %q", c.Category))
	}
	if c.InputType != "mcp_tool_sequence_temporal" {
		add(fmt.Sprintf("input_type must be mcp_tool_sequence_temporal, got %q", c.InputType))
	}
	if c.Transport != "mcp_stdio" && c.Transport != "mcp_http" {
		add(fmt.Sprintf("transport must be mcp_stdio or mcp_http, got %q", c.Transport))
	}
	if !validCaseExpectedVerdicts[c.ExpectedVerdict] {
		add(fmt.Sprintf("invalid expected_verdict: %q", c.ExpectedVerdict))
	}
	if !validSeverities[c.Severity] {
		add(fmt.Sprintf("invalid severity: %q", c.Severity))
	}
	if !validFPRisk[c.FPRisk] {
		add(fmt.Sprintf("invalid false_positive_risk: %q", c.FPRisk))
	}
	if len(c.CapabilityTags) == 0 {
		add("capability_tags must not be empty")
	}
	for _, issue := range validateUniqueMultiFileStrings(c.CapabilityTags, "capability_tags") {
		add(issue)
	}
	for _, issue := range validateUniqueMultiFileStrings(c.Requires, "requires") {
		add(issue)
	}
	for _, requirement := range c.Requires {
		if problem := requiresTokenProblem(requirement); problem != "" {
			add(problem)
		}
	}

	fileNames := []struct {
		label string
		name  string
	}{
		{"before", c.Files.Before},
		{"after", c.Files.After},
		{"expected", c.Files.Expected},
	}
	seenFiles := make(map[string]string, len(fileNames))
	loaded := make(map[string]map[string]interface{}, len(fileNames))
	for _, file := range fileNames {
		if err := validateMultiFileName(file.name, ".json", "files."+file.label); err != nil {
			add(err.Error())
			continue
		}
		if prior, duplicate := seenFiles[file.name]; duplicate {
			add(fmt.Sprintf("files.%s duplicates files.%s path %q", file.label, prior, file.name))
			continue
		}
		seenFiles[file.name] = file.label
		value, err := readMultiFileJSONObject(filepath.Join(filepath.Dir(path), file.name))
		if err != nil {
			add(err.Error())
			continue
		}
		loaded[file.label] = value
	}
	if err := validateMultiFileName(c.Notes, ".md", "notes"); err != nil {
		add(err.Error())
	} else {
		notesPath := filepath.Join(filepath.Dir(path), c.Notes)
		info, err := os.Stat(notesPath)
		if err != nil {
			add(fmt.Sprintf("reading required notes file %s: %v", notesPath, err))
		} else if info.IsDir() {
			add(fmt.Sprintf("required notes file is a directory: %s", notesPath))
		}
	}
	if len(issues) == 0 {
		if err := validateMultiFileDocuments(c, loaded["before"], loaded["after"], loaded["expected"]); err != nil {
			add(err.Error())
		}
	}
	return issues
}

// parseMultiFileCaseYAML accepts only the deliberately small case.yaml grammar:
// top-level scalars, literal block scalars, two string lists, and the files
// mapping. Keeping this parser narrow preserves the validator's stdlib-only
// binary while rejecting YAML features whose decoded meaning is ambiguous.
func parseMultiFileCaseYAML(data []byte) (multiFileCase, error) {
	var c multiFileCase
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	known := map[string]bool{
		"schema_version": true, "id": true, "category": true, "title": true,
		"description": true, "threat_model": true, "input_type": true,
		"transport": true, "files": true, "expected_verdict": true,
		"severity": true, "capability_tags": true, "requires": true,
		"false_positive_risk": true, "why_expected": true, "notes": true, "source": true,
	}
	present := make(map[string]bool, len(known))
	values := make(map[string]string, len(known))
	lists := make(map[string][]string, 2)
	files := make(map[string]string, 3)

	for i := 0; i < len(lines); {
		line := lines[i]
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			i++
			continue
		}
		if strings.Contains(line, "\t") {
			return c, fmt.Errorf("line %d: tabs are not allowed", i+1)
		}
		if line == "---" || line == "..." || strings.HasPrefix(line, " ") {
			return c, fmt.Errorf("line %d: expected a top-level key", i+1)
		}
		key, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(key) != key || !known[key] || (rest != "" && rest[0] != ' ') {
			return c, fmt.Errorf("line %d: unknown or malformed field %q", i+1, key)
		}
		if present[key] {
			return c, fmt.Errorf("line %d: duplicate field %s", i+1, key)
		}
		present[key] = true
		rest = strings.TrimSpace(rest)
		if key == "schema_version" && (strings.HasPrefix(rest, "\"") || strings.HasPrefix(rest, "'")) {
			return c, fmt.Errorf("schema_version must be an unquoted integer")
		}
		i++
		switch {
		case key == "files":
			if rest != "" {
				return c, fmt.Errorf("files must be a block mapping")
			}
			for i < len(lines) && (strings.HasPrefix(lines[i], "  ") || strings.TrimSpace(lines[i]) == "") {
				trimmed := strings.TrimSpace(lines[i])
				i++
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if !strings.HasPrefix(lines[i-1], "  ") || strings.HasPrefix(lines[i-1], "   ") {
					return c, fmt.Errorf("files entries must use exactly two spaces")
				}
				name, raw, found := strings.Cut(trimmed, ":")
				if !found || (name != "before" && name != "after" && name != "expected") || files[name] != "" {
					return c, fmt.Errorf("invalid or duplicate files entry %q", name)
				}
				value, parseErr := parseRestrictedYAMLScalar(strings.TrimSpace(raw))
				if parseErr != nil {
					return c, fmt.Errorf("files.%s: %w", name, parseErr)
				}
				files[name] = value
			}
		case key == "capability_tags" || key == "requires":
			if rest != "" {
				list, parseErr := parseRestrictedYAMLStringList(rest)
				if parseErr != nil {
					return c, fmt.Errorf("%s: %w", key, parseErr)
				}
				lists[key] = list
				continue
			}
			for i < len(lines) && (strings.HasPrefix(lines[i], "  ") || strings.TrimSpace(lines[i]) == "") {
				trimmed := strings.TrimSpace(lines[i])
				i++
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				if !strings.HasPrefix(lines[i-1], "  - ") {
					return c, fmt.Errorf("%s entries must use exactly two spaces and '- '", key)
				}
				value, parseErr := parseRestrictedYAMLScalar(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")))
				if parseErr != nil {
					return c, fmt.Errorf("%s: %w", key, parseErr)
				}
				lists[key] = append(lists[key], value)
			}
		case rest == "|" || rest == "|-":
			var block []string
			for i < len(lines) && (strings.HasPrefix(lines[i], "  ") || strings.TrimSpace(lines[i]) == "") {
				if strings.TrimSpace(lines[i]) == "" {
					block = append(block, "")
				} else if !strings.HasPrefix(lines[i], "  ") {
					break
				} else {
					block = append(block, strings.TrimPrefix(lines[i], "  "))
				}
				i++
			}
			values[key] = strings.TrimSpace(strings.Join(block, "\n"))
		case rest == "" || rest == "null" || rest == "~" || rest == ">" || strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "*") || strings.HasPrefix(rest, "!"):
			return c, fmt.Errorf("%s must use a supported non-null scalar", key)
		default:
			value, parseErr := parseRestrictedYAMLScalar(rest)
			if parseErr != nil {
				return c, fmt.Errorf("%s: %w", key, parseErr)
			}
			values[key] = value
		}
	}
	for key := range known {
		if !present[key] {
			return c, fmt.Errorf("missing required field %s", key)
		}
	}
	version, err := strconv.Atoi(values["schema_version"])
	if err != nil {
		return c, fmt.Errorf("schema_version must be an integer")
	}
	c.SchemaVersion = version
	c.ID, c.Category, c.Title = values["id"], values["category"], values["title"]
	c.Description, c.ThreatModel = values["description"], values["threat_model"]
	c.InputType, c.Transport = values["input_type"], values["transport"]
	c.ExpectedVerdict, c.Severity = values["expected_verdict"], values["severity"]
	c.CapabilityTags, c.Requires = lists["capability_tags"], lists["requires"]
	c.FPRisk, c.WhyExpected = values["false_positive_risk"], values["why_expected"]
	c.Files.Before, c.Files.After, c.Files.Expected = files["before"], files["after"], files["expected"]
	c.Notes, c.Source = values["notes"], values["source"]
	return c, nil
}

func parseRestrictedYAMLStringList(raw string) ([]string, error) {
	if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' {
		return nil, fmt.Errorf("must be a block sequence or bracketed string list")
	}
	contents := strings.TrimSpace(raw[1 : len(raw)-1])
	if contents == "" {
		return []string{}, nil
	}
	parts := strings.Split(contents, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value, err := parseRestrictedYAMLScalar(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		if strings.ContainsAny(value, "[]{}") {
			return nil, fmt.Errorf("nested collections are not supported")
		}
		values = append(values, value)
	}
	return values, nil
}

func parseRestrictedYAMLScalar(raw string) (string, error) {
	if raw == "" || raw == "null" || raw == "~" {
		return "", fmt.Errorf("value must be non-empty and non-null")
	}
	if strings.HasPrefix(raw, "\"") {
		value, err := strconv.Unquote(raw)
		if err != nil {
			return "", fmt.Errorf("invalid quoted scalar: %w", err)
		}
		return value, nil
	}
	if strings.HasPrefix(raw, "'") {
		if len(raw) < 2 || !strings.HasSuffix(raw, "'") {
			return "", fmt.Errorf("unterminated quoted scalar")
		}
		return strings.ReplaceAll(raw[1:len(raw)-1], "''", "'"), nil
	}
	if strings.Contains(raw, " #") {
		return "", fmt.Errorf("inline comments are not supported")
	}
	return raw, nil
}

func validateUniqueMultiFileStrings(values []string, label string) []string {
	var issues []string
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			issues = append(issues, label+" entries must be non-empty")
		}
		if _, duplicate := seen[value]; duplicate {
			issues = append(issues, fmt.Sprintf("%s contains duplicate value %q", label, value))
		}
		seen[value] = struct{}{}
	}
	return issues
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

func readMultiFileJSONObject(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var object map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil {
		return nil, fmt.Errorf("parsing %s as JSON object: %w", path, err)
	}
	if object == nil {
		return nil, fmt.Errorf("parsing %s as JSON object: top-level value must be an object", path)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parsing %s as JSON object: multiple JSON values", path)
		}
		return nil, fmt.Errorf("parsing %s as JSON object: %w", path, err)
	}
	return object, nil
}

func validateMultiFileDocuments(c multiFileCase, before, after, expected map[string]interface{}) error {
	for label, snapshot := range map[string]map[string]interface{}{"before": before, "after": after} {
		responses, err := multiFileResponses(snapshot)
		if err != nil {
			return fmt.Errorf("%s snapshot: %w", label, err)
		}
		for index, response := range responses {
			if err := validateMultiFileToolsList(response); err != nil {
				return fmt.Errorf("%s snapshot response %d: %w", label, index, err)
			}
		}
	}
	record, ok := expected["action_record"].(map[string]interface{})
	if !isMultiFileJSONIntegerOne(expected["version"]) || !ok {
		return fmt.Errorf("expected.json must carry version 1 and an action_record object")
	}
	if !isMultiFileJSONIntegerOne(record["version"]) {
		return fmt.Errorf("expected.json action_record.version must be 1")
	}
	for field, want := range map[string]string{"verdict": c.ExpectedVerdict, "transport": c.Transport, "severity": c.Severity} {
		got, ok := record[field].(string)
		if !ok || got != want {
			return fmt.Errorf("expected.json action_record.%s must equal case.yaml value %q, got %q", field, want, got)
		}
	}
	for _, field := range []string{"layer", "pattern", "intent"} {
		value, ok := record[field].(string)
		if !ok || strings.TrimSpace(value) == "" {
			return fmt.Errorf("expected.json action_record.%s must be a non-empty string", field)
		}
	}
	return nil
}

func multiFileResponses(snapshot map[string]interface{}) ([]interface{}, error) {
	rawServers, hasServers := snapshot["servers"]
	if !hasServers {
		return []interface{}{snapshot}, nil
	}
	servers, ok := rawServers.([]interface{})
	if !ok || len(servers) == 0 {
		return nil, fmt.Errorf("servers must be a non-empty array")
	}
	responses := make([]interface{}, 0, len(servers))
	seen := make(map[string]struct{}, len(servers))
	for index, raw := range servers {
		server, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("servers[%d] must be an object", index)
		}
		response, ok := server["tools_list_response"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("servers[%d].tools_list_response must be an object", index)
		}
		serverID, ok := server["server_id"].(string)
		if !ok || strings.TrimSpace(serverID) == "" {
			return nil, fmt.Errorf("servers[%d].server_id must be a non-empty string", index)
		}
		if _, duplicate := seen[serverID]; duplicate {
			return nil, fmt.Errorf("servers[%d].server_id duplicates %q", index, serverID)
		}
		seen[serverID] = struct{}{}
		responses = append(responses, response)
	}
	return responses, nil
}

func validateMultiFileToolsList(raw interface{}) error {
	response, ok := raw.(map[string]interface{})
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
	if !validMultiFileJSONRPCID(id) {
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

func validMultiFileJSONRPCID(value interface{}) bool {
	switch value.(type) {
	case nil, string, json.Number, float64:
		return true
	default:
		return false
	}
}

func isMultiFileJSONIntegerOne(value interface{}) bool {
	number, ok := value.(json.Number)
	return ok && number.String() == "1"
}
