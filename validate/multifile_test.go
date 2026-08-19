package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestMultiFileContractMatchesOfficialValidator(t *testing.T) {
	source := filepath.Join("..", "cases", "mcp-drift", "mcp-drift-http-rugpull-desc-005")
	raw, err := os.ReadFile(filepath.Join(source, "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMultiFileCaseYAML(raw)
	if err != nil {
		t.Fatal(err)
	}
	baseline := multiFileCaseDocument(parsed)
	assertMultiFileValidatorAccept(t, baseline, source)

	for _, required := range []string{
		"schema_version", "id", "category", "title", "description", "threat_model",
		"input_type", "transport", "files", "expected_verdict", "severity",
		"capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source",
	} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneMultiFileDocument(t, baseline)
			delete(mutated, required)
			assertMultiFileValidatorReject(t, mutated, source)
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"schema_version": func(v map[string]any) { v["schema_version"] = 99 },
		"category":       func(v map[string]any) { v["category"] = "mcp_tool" },
		"transport":      func(v map[string]any) { v["transport"] = "websocket" },
		"verdict":        func(v map[string]any) { v["expected_verdict"] = "error" },
		"whitespace_id":  func(v map[string]any) { v["id"] = " " },
		"uppercase_id":   func(v map[string]any) { v["id"] = "Invalid-ID" },
		"oversized_id":   func(v map[string]any) { v["id"] = strings.Repeat("a", 129) },
		"null_source":    func(v map[string]any) { v["source"] = nil },
		"null_requires":  func(v map[string]any) { v["requires"] = nil },
		"unknown_field":  func(v map[string]any) { v["unexpected"] = true },
		"unknown_requires": func(v map[string]any) {
			v["requires"] = []any{"not_a_runtime_prerequisite"}
		},
		"duplicate_requires": func(v map[string]any) {
			v["requires"] = []any{"mcp_tool_baseline", "mcp_tool_baseline"}
		},
		"unsafe_before_path": func(v map[string]any) {
			v["files"].(map[string]any)["before"] = "../before.json"
		},
		"space_in_before_name": func(v map[string]any) {
			v["files"].(map[string]any)["before"] = "before file.json"
		},
		"leading_punctuation_in_before_name": func(v map[string]any) {
			v["files"].(map[string]any)["before"] = ".before.json"
		},
		"non_ascii_notes_name": func(v map[string]any) { v["notes"] = "nøtes.md" },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneMultiFileDocument(t, baseline)
			mutate(mutated)
			assertMultiFileValidatorReject(t, mutated, source)
		})
	}
}

func TestRestrictedYAMLParserMatchesRunnerScalarBoundaries(t *testing.T) {
	for name, tc := range map[string]struct {
		source string
		want   string
	}{
		"compact mapping": {
			source: "id:mcp-drift-001\n",
			want:   `unknown or malformed field "id"`,
		},
		"quoted schema version": {
			source: "schema_version: \"4\"\n",
			want:   "schema_version must be an unquoted integer",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseMultiFileCaseYAML([]byte(tc.source)); err == nil ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parser error = %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func cloneMultiFileDocument(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func assertMultiFileValidatorAccept(t *testing.T, document map[string]any, source string) {
	t.Helper()
	if issues := validateMultiFileDocument(t, document, source); len(issues) != 0 {
		t.Fatalf("validator rejected valid fixture: %v", issues)
	}
}

func assertMultiFileValidatorReject(t *testing.T, document map[string]any, source string) {
	t.Helper()
	if issues := validateMultiFileDocument(t, document, source); len(issues) == 0 {
		t.Fatalf("validator accepted invalid mutation: %#v", document)
	}
}

func validateMultiFileDocument(t *testing.T, document map[string]any, source string) []string {
	t.Helper()
	id, _ := document["id"].(string)
	if id == "" {
		id = "invalid-case"
	}
	root := t.TempDir()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	raw := encodeMultiFileYAMLForTest(t, document)
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	files, _ := document["files"].(map[string]any)
	targets := map[string]string{
		"before.json":   stringValue(files["before"]),
		"after.json":    stringValue(files["after"]),
		"expected.json": stringValue(files["expected"]),
		"notes.md":      stringValue(document["notes"]),
	}
	for sourceName, targetName := range targets {
		if targetName == "" {
			continue
		}
		content, readErr := os.ReadFile(filepath.Join(source, sourceName))
		if readErr != nil {
			t.Fatal(readErr)
		}
		targetPath := filepath.Join(dir, targetName)
		if mkdirErr := os.MkdirAll(filepath.Dir(targetPath), 0o750); mkdirErr != nil {
			t.Fatal(mkdirErr)
		}
		if writeErr := os.WriteFile(targetPath, content, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	return validateMultiFileCase(filepath.Join(dir, "case.yaml"), make(map[string]string))
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func multiFileCaseDocument(c multiFileCase) map[string]any {
	return map[string]any{
		"schema_version": c.SchemaVersion, "id": c.ID, "category": c.Category,
		"title": c.Title, "description": c.Description, "threat_model": c.ThreatModel,
		"input_type": c.InputType, "transport": c.Transport,
		"files":            map[string]any{"before": c.Files.Before, "after": c.Files.After, "expected": c.Files.Expected},
		"expected_verdict": c.ExpectedVerdict, "severity": c.Severity,
		"capability_tags": stringsToAny(c.CapabilityTags), "requires": stringsToAny(c.Requires),
		"false_positive_risk": c.FPRisk, "why_expected": c.WhyExpected,
		"notes": c.Notes, "source": c.Source,
	}
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for i, value := range values {
		result[i] = value
	}
	return result
}

func encodeMultiFileYAMLForTest(t *testing.T, document map[string]any) []byte {
	t.Helper()
	var output bytes.Buffer
	keys := make([]string, 0, len(document))
	for key := range document {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := document[key]
		switch typed := value.(type) {
		case map[string]any:
			fmt.Fprintf(&output, "%s:\n", key)
			nested := make([]string, 0, len(typed))
			for nestedKey := range typed {
				nested = append(nested, nestedKey)
			}
			sort.Strings(nested)
			for _, nestedKey := range nested {
				fmt.Fprintf(&output, "  %s: %s\n", nestedKey, yamlTestScalar(typed[nestedKey]))
			}
		case []any:
			fmt.Fprintf(&output, "%s:\n", key)
			for _, item := range typed {
				fmt.Fprintf(&output, "  - %s\n", yamlTestScalar(item))
			}
		default:
			fmt.Fprintf(&output, "%s: %s\n", key, yamlTestScalar(value))
		}
	}
	return output.Bytes()
}

func yamlTestScalar(value any) string {
	switch typed := value.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(typed)
	case bool:
		return strconv.FormatBool(typed)
	case int:
		return strconv.Itoa(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

func TestMultiFileValidatorAcceptsEveryPublishedFixture(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	ids := make(map[string]string)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		count++
		path := filepath.Join("..", "cases", "mcp-drift", entry.Name(), "case.yaml")
		if issues := validateMultiFileCase(path, ids); len(issues) != 0 {
			t.Errorf("%s: %v", entry.Name(), issues)
		}
	}
	if count == 0 {
		t.Fatal("no published multi-file fixtures were validated")
	}
}

func TestOfficialValidatorRejectsMalformedComponentShapes(t *testing.T) {
	validResponse := func() map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": json.Number("1"),
			"result": map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "read_file", "inputSchema": map[string]interface{}{"type": "object"}},
			}},
		}
	}
	objectID := validResponse()
	objectID["id"] = []interface{}{1}
	if err := validateMultiFileToolsList(objectID); err == nil {
		t.Fatal("accepted array-valued JSON-RPC id")
	}
	missingSchema := validResponse()
	delete(missingSchema["result"].(map[string]interface{})["tools"].([]interface{})[0].(map[string]interface{}), "inputSchema")
	if err := validateMultiFileToolsList(missingSchema); err == nil {
		t.Fatal("accepted tool without inputSchema")
	}
	bothResultAndError := validResponse()
	bothResultAndError["error"] = map[string]interface{}{"code": json.Number("-32000"), "message": "denied"}
	if err := validateMultiFileToolsList(bothResultAndError); err == nil || !strings.Contains(err.Error(), "both result and error") {
		t.Fatalf("result-and-error response error = %v, want exclusive response-shape refusal", err)
	}

	c := multiFileCase{ExpectedVerdict: "block", Transport: "mcp_http", Severity: "critical"}
	record := map[string]interface{}{
		"version": json.Number("1"), "verdict": "block", "transport": "mcp_http",
		"severity": "critical", "layer": "mcp_tool_baseline", "pattern": "drift", "intent": "deny",
	}
	if err := validateMultiFileDocuments(c, validResponse(), validResponse(), map[string]interface{}{"version": "1", "action_record": record}); err == nil {
		t.Fatal("accepted string top-level receipt version")
	}
	record["version"] = "1"
	if err := validateMultiFileDocuments(c, validResponse(), validResponse(), map[string]interface{}{"version": json.Number("1"), "action_record": record}); err == nil {
		t.Fatal("accepted string action-record version")
	}
}

func TestMultiFileValidatorRejectsWholeContractMutations(t *testing.T) {
	source := filepath.Join("..", "cases", "mcp-drift", "mcp-drift-http-rugpull-desc-005")
	baseline, err := os.ReadFile(filepath.Join(source, "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"null_required_field": func(value []byte) []byte {
			return []byte(replaceOnce(t, string(value), "source: ", "source: null # "))
		},
		"unknown_field": func(value []byte) []byte {
			return append(value, []byte("unexpected: true\n")...)
		},
		"unknown_version": func(value []byte) []byte {
			return []byte(replaceOnce(t, string(value), "schema_version: 4", "schema_version: 99"))
		},
		"unsafe_component_path": func(value []byte) []byte {
			return []byte(replaceOnce(t, string(value), "before: before.json", "before: ../before.json"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "mcp-drift-http-rugpull-desc-005")
			if err := os.MkdirAll(dir, 0o750); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"before.json", "after.json", "expected.json", "notes.md"} {
				content, readErr := os.ReadFile(filepath.Join(source, file))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if writeErr := os.WriteFile(filepath.Join(dir, file), content, 0o600); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "case.yaml"), mutate(baseline), 0o600); err != nil {
				t.Fatal(err)
			}
			if issues := validateMultiFileCase(filepath.Join(dir, "case.yaml"), make(map[string]string)); len(issues) == 0 {
				t.Fatal("validator accepted malformed multi-file contract")
			}
		})
	}
}

func replaceOnce(t *testing.T, value, old, replacement string) string {
	t.Helper()
	updated := []byte(value)
	index := -1
	for i := 0; i+len(old) <= len(updated); i++ {
		if string(updated[i:i+len(old)]) == old {
			index = i
			break
		}
	}
	if index < 0 {
		t.Fatalf("fixture does not contain %q", old)
	}
	return value[:index] + replacement + value[index+len(old):]
}

// The prerequisites key was in neither the known-field map nor any optional set,
// so the parser rejected it as an unknown field before the branch that reads it
// could run. Every multi-file case declaring setup failed, and the parse branch
// below that rejection was unreachable code no test could reach either.
func TestMultiFileCaseParsesPrerequisites(t *testing.T) {
	raw := multiFileFixtureYAML(t)
	if strings.Contains(string(raw), "prerequisites:") {
		t.Fatal("fixture already declares prerequisites; pick a case that does not")
	}

	// Both spellings a YAML emitter produces for one object. The inline mapping is
	// what the runner's own YAML library reads, so the validator refusing it meant
	// the two disagreed about the same bytes.
	forms := map[string]string{
		"block_object":   "prerequisites:\n  -\n    kind: reserved_sink_route\n    value: a2a-exfil-sink.test\n",
		"inline_mapping": "prerequisites:\n  - kind: reserved_sink_route\n    value: a2a-exfil-sink.test\n",
	}
	for name, block := range forms {
		t.Run(name, func(t *testing.T) {
			parsed, err := parseMultiFileCaseYAML(append(append([]byte{}, raw...), []byte(block)...))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(parsed.Prerequisites) != 1 {
				t.Fatalf("prerequisites = %d, want 1", len(parsed.Prerequisites))
			}
			if parsed.Prerequisites[0].Kind != "reserved_sink_route" {
				t.Fatalf("kind = %q", parsed.Prerequisites[0].Kind)
			}
			if parsed.Prerequisites[0].Value != "a2a-exfil-sink.test" {
				t.Fatalf("value = %q", parsed.Prerequisites[0].Value)
			}
		})
	}

	// Optional means optional. Adding the key to the required set would have made
	// every existing multi-file case invalid instead.
	if _, err := parseMultiFileCaseYAML(raw); err != nil {
		t.Fatalf("case without prerequisites must still parse: %v", err)
	}
}

// The single-file validator enforces the closed reserved-sink set and this one
// did not, so a multi-file case could pass validation and then produce a runner
// setup error no operator flag can clear.
func TestMultiFileValidationEnforcesClosedReservedSinkSet(t *testing.T) {
	for name, tc := range map[string]struct {
		value    string
		rejected bool
	}{
		"arbitrary_host":   {value: "attacker.example.net", rejected: true},
		"reserved_sink":    {value: "a2a-exfil-sink.test", rejected: false},
		"letter_case_only": {value: "A2A-Exfil-Sink.TEST", rejected: false},
	} {
		t.Run(name, func(t *testing.T) {
			block := "prerequisites:\n  - kind: reserved_sink_route\n    value: " + tc.value + "\n"
			path := multiFileFixtureCopy(t, block)
			problems := validateMultiFileCase(path, make(map[string]string))
			found := false
			for _, problem := range problems {
				if strings.Contains(problem, "is not a corpus-reserved sink host") {
					found = true
				}
			}
			if found != tc.rejected {
				t.Fatalf("rejected = %v, want %v; problems: %v", found, tc.rejected, problems)
			}
		})
	}
}

func multiFileFixtureDir() string {
	return filepath.Join("..", "cases", "mcp-drift", "mcp-drift-http-rugpull-desc-005")
}

func multiFileFixtureYAML(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(multiFileFixtureDir(), "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// multiFileFixtureCopy reproduces the fixture case directory under a temporary
// root, keeping its directory name because the validator binds the case id to it,
// and appends the given case.yaml block.
func multiFileFixtureCopy(t *testing.T, appended string) string {
	t.Helper()
	source := multiFileFixtureDir()
	target := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name() == "case.yaml" {
			data = append(append([]byte{}, data...), []byte(appended)...)
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(target, "case.yaml")
}
