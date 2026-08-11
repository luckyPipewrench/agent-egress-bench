package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestMultiFileSchemaMatchesOfficialValidator(t *testing.T) {
	schema := compileConformanceSchema(t, filepath.Join("..", "schemas", "multi-file-case-v4.schema.json"))
	source := filepath.Join("..", "cases", "mcp-drift", "mcp-drift-http-rugpull-desc-005")
	raw, err := os.ReadFile(filepath.Join(source, "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var baseline map[string]any
	if err := yaml.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	assertMultiFileSchemaAndValidatorAccept(t, schema, baseline, source)

	for _, required := range []string{
		"schema_version", "id", "category", "title", "description", "threat_model",
		"input_type", "transport", "files", "expected_verdict", "severity",
		"capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source",
	} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneMultiFileDocument(t, baseline)
			delete(mutated, required)
			assertMultiFileSchemaAndValidatorReject(t, schema, mutated, source)
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"schema_version": func(v map[string]any) { v["schema_version"] = 99 },
		"category":       func(v map[string]any) { v["category"] = "mcp_tool" },
		"transport":      func(v map[string]any) { v["transport"] = "websocket" },
		"verdict":        func(v map[string]any) { v["expected_verdict"] = "error" },
		"whitespace_id":  func(v map[string]any) { v["id"] = " " },
		"null_source":    func(v map[string]any) { v["source"] = nil },
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
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneMultiFileDocument(t, baseline)
			mutate(mutated)
			assertMultiFileSchemaAndValidatorReject(t, schema, mutated, source)
		})
	}
}

func cloneMultiFileDocument(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]any
	if err := yaml.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func assertMultiFileSchemaAndValidatorAccept(t *testing.T, schema *jsonschema.Schema, document map[string]any, source string) {
	t.Helper()
	if err := schema.Validate(document); err != nil {
		t.Fatalf("schema rejected fixture: %v", err)
	}
	if issues := validateMultiFileDocument(t, document, source); len(issues) != 0 {
		t.Fatalf("validator rejected schema-valid fixture: %v", issues)
	}
}

func assertMultiFileSchemaAndValidatorReject(t *testing.T, schema *jsonschema.Schema, document map[string]any, source string) {
	t.Helper()
	if err := schema.Validate(document); err == nil {
		t.Fatalf("schema accepted mutation: %#v", document)
	}
	if issues := validateMultiFileDocument(t, document, source); len(issues) == 0 {
		t.Fatalf("validator accepted schema-rejected mutation: %#v", document)
	}
}

func validateMultiFileDocument(t *testing.T, document map[string]any, source string) []string {
	t.Helper()
	id, _ := document["id"].(string)
	if id == "" {
		id = "invalid-case"
	}
	dir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "case.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before.json", "after.json", "expected.json", "notes.md"} {
		content, readErr := os.ReadFile(filepath.Join(source, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(dir, name), content, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	return validateMultiFileCase(filepath.Join(dir, "case.yaml"), make(map[string]string))
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
