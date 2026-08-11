package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

func TestMultiFileCaseSchemaConformance(t *testing.T) {
	schema := compileMultiFileCaseSchema(t)
	sourceDir := filepath.Join("..", "cases", "mcp-drift", "mcp-drift-http-rugpull-desc-005")
	baseline := readMultiFileCaseYAMLObject(t, filepath.Join(sourceDir, "case.yaml"))
	assertMultiFileSchemaAndGoAccept(t, schema, baseline, sourceDir)

	for _, required := range []string{
		"schema_version", "id", "category", "title", "description", "threat_model",
		"input_type", "transport", "files", "expected_verdict", "severity",
		"capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source",
	} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneMultiFileYAMLObject(t, baseline)
			delete(mutated, required)
			assertMultiFileSchemaAndGoReject(t, schema, mutated, sourceDir)
		})
	}

	for name, mutate := range map[string]func(map[string]interface{}){
		"schema_version_const": func(v map[string]interface{}) { v["schema_version"] = 99 },
		"category_const":       func(v map[string]interface{}) { v["category"] = "mcp_tool" },
		"input_type_const":     func(v map[string]interface{}) { v["input_type"] = "mcp_tool_sequence" },
		"transport_enum":       func(v map[string]interface{}) { v["transport"] = "websocket" },
		"verdict_enum":         func(v map[string]interface{}) { v["expected_verdict"] = "error" },
		"severity_enum":        func(v map[string]interface{}) { v["severity"] = "unknown" },
		"false_positive_enum":  func(v map[string]interface{}) { v["false_positive_risk"] = "none" },
		"empty_title":          func(v map[string]interface{}) { v["title"] = " " },
		"empty_id":             func(v map[string]interface{}) { v["id"] = " " },
		"duplicate_tag": func(v map[string]interface{}) {
			v["capability_tags"] = []interface{}{"mcp_tool_poison", "mcp_tool_poison"}
		},
		"duplicate_requires": func(v map[string]interface{}) {
			v["requires"] = []interface{}{"mcp_tool_baseline", "mcp_tool_baseline"}
		},
		"unknown_requires": func(v map[string]interface{}) {
			v["requires"] = []interface{}{"not_a_runtime_prerequisite"}
		},
		"unknown_property":    func(v map[string]interface{}) { v["unexpected"] = true },
		"null_required_value": func(v map[string]interface{}) { v["source"] = nil },
		"unsafe_before_path": func(v map[string]interface{}) {
			v["files"].(map[string]interface{})["before"] = "../before.json"
		},
		"extra_files_key": func(v map[string]interface{}) {
			v["files"].(map[string]interface{})["other"] = "other.json"
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneMultiFileYAMLObject(t, baseline)
			mutate(mutated)
			assertMultiFileSchemaAndGoReject(t, schema, mutated, sourceDir)
		})
	}

	t.Run("go_only_distinct_snapshot_paths", func(t *testing.T) {
		mutated := cloneMultiFileYAMLObject(t, baseline)
		files := mutated["files"].(map[string]interface{})
		files["after"] = files["before"]
		if err := schema.Validate(mutated); err != nil {
			t.Fatalf("schema cannot express cross-property path uniqueness and should accept this fixture: %v", err)
		}
		if err := multiFileGoAccepts(t, mutated, sourceDir); err == nil {
			t.Fatal("Go loader accepted aliased before and after snapshots")
		}
	})
}

func TestMultiFileCaseSchemaAcceptsEveryPublishedFixture(t *testing.T) {
	schema := compileMultiFileCaseSchema(t)
	entries, err := os.ReadDir(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		count++
		caseDir := filepath.Join("..", "cases", "mcp-drift", entry.Name())
		document := readMultiFileCaseYAMLObject(t, filepath.Join(caseDir, "case.yaml"))
		assertMultiFileSchemaAndGoAccept(t, schema, document, caseDir)
	}
	if count == 0 {
		t.Fatal("no published multi-file fixtures were validated")
	}
}

func compileMultiFileCaseSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "schemas", "multi-file-case-v4.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(path, document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func readMultiFileCaseYAMLObject(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	return document
}

func cloneMultiFileYAMLObject(t *testing.T, value map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := yaml.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone map[string]interface{}
	if err := yaml.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func assertMultiFileSchemaAndGoAccept(t *testing.T, schema *jsonschema.Schema, document map[string]interface{}, sourceDir string) {
	t.Helper()
	if err := schema.Validate(document); err != nil {
		t.Fatalf("schema rejected fixture: %v", err)
	}
	if err := multiFileGoAccepts(t, document, sourceDir); err != nil {
		t.Fatalf("Go loader rejected schema-valid fixture: %v", err)
	}
}

func assertMultiFileSchemaAndGoReject(t *testing.T, schema *jsonschema.Schema, document map[string]interface{}, sourceDir string) {
	t.Helper()
	if err := schema.Validate(document); err == nil {
		t.Fatalf("schema accepted mutation: %#v", document)
	}
	if err := multiFileGoAccepts(t, document, sourceDir); err == nil {
		t.Fatalf("Go loader accepted schema-rejected mutation: %#v", document)
	}
}

func multiFileGoAccepts(t *testing.T, document map[string]interface{}, sourceDir string) error {
	t.Helper()
	id, _ := document["id"].(string)
	if id == "" {
		id = "invalid-case"
	}
	caseDir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(caseDir, 0o750); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before.json", "after.json", "expected.json", "notes.md"} {
		content, readErr := os.ReadFile(filepath.Join(sourceDir, name))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if writeErr := os.WriteFile(filepath.Join(caseDir, name), content, 0o600); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	return func() error {
		_, loadErr := loadMultiFileCase(caseDir)
		return loadErr
	}()
}
