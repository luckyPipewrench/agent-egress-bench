package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// These vectors pin the structural boundary shared by the public root schemas
// and the stdlib validator. Repository-wide graph and registry checks are
// called out below as Go-only because one JSON document cannot express them.
func TestCaseSchemaConformance(t *testing.T) {
	schema := compileConformanceSchema(t, filepath.Join("..", "schemas", "case-v4.schema.json"))
	raw := readConformanceFixture(t, filepath.Join("..", "cases", "a2a-agent-card", "a2a-card-benign-normal-006.json"))
	assertSchemaAndGoAccept(t, schema, raw, caseValidatorAccepts(t))

	baseline := decodeConformanceObject(t, raw)
	for _, required := range []string{"schema_version", "id", "category", "title", "description", "input_type", "transport", "payload", "expected_verdict", "severity", "capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			delete(mutated, required)
			assertSchemaAndGoReject(t, schema, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema_version_const":  func(v map[string]any) { v["schema_version"] = 99 },
		"category_enum":         func(v map[string]any) { v["category"] = "not-a-category" },
		"input_type_enum":       func(v map[string]any) { v["input_type"] = "not-an-input" },
		"transport_enum":        func(v map[string]any) { v["transport"] = "not-a-transport" },
		"expected_verdict_enum": func(v map[string]any) { v["expected_verdict"] = "not-a-verdict" },
		"severity_enum":         func(v map[string]any) { v["severity"] = "not-a-severity" },
		"requires_item_enum":    func(v map[string]any) { v["requires"] = []any{"not-a-requirement"} },
		"false_positive_enum":   func(v map[string]any) { v["false_positive_risk"] = "not-a-risk" },
		"unknown_property":      func(v map[string]any) { v["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertSchemaAndGoReject(t, schema, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"allow_requires_safe_example": func(v map[string]any) { delete(v, "safe_example") },
		"allow_requires_safe_true":    func(v map[string]any) { v["safe_example"] = false },
	} {
		t.Run("conditional_"+name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertSchemaAndGoReject(t, schema, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
		})
	}

	t.Run("go_only_supersession_graph", func(t *testing.T) {
		mutated := cloneConformanceObject(t, baseline)
		mutated["supersedes"] = mutated["id"]
		data := marshalConformanceJSON(t, mutated)
		schemaAcceptsConformance(t, schema, data)
		path := filepath.Join(t.TempDir(), "case.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if issues := validateSupersessionGraph(map[string]string{mutated["id"].(string): path}); len(issues) == 0 {
			t.Fatal("Go-only supersession graph check accepted a self-cycle")
		}
	})
}

func TestResultSchemaConformance(t *testing.T) {
	schema := compileConformanceSchema(t, filepath.Join("..", "schemas", "result-v4.schema.json"))
	profile := decodeConformanceObject(t, readConformanceFixture(t, filepath.Join("..", "examples", "pipelock", "tool-profile.json")))
	caseDoc := decodeConformanceObject(t, readConformanceFixture(t, filepath.Join("..", "cases", "a2a-agent-card", "a2a-card-benign-normal-006.json")))
	baseline := map[string]any{
		"schema_version":      4,
		"case_id":             caseDoc["id"],
		"tool":                profile["tool"],
		"tool_version":        profile["tool_version"],
		"capability_registry": profile["capability_registry"],
		"expected_verdict":    "allow",
		"actual_verdict":      "allow",
		"score":               "pass",
		"evidence":            map[string]any{},
		"notes":               "",
	}
	raw := marshalConformanceJSON(t, baseline)
	accepts := resultValidatorAccepts(t)
	assertSchemaAndGoAccept(t, schema, raw, accepts)

	for _, required := range []string{"schema_version", "case_id", "tool", "tool_version", "capability_registry", "expected_verdict", "actual_verdict", "score", "evidence", "notes"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			delete(mutated, required)
			assertSchemaAndGoReject(t, schema, marshalConformanceJSON(t, mutated), accepts)
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema_version_const":  func(v map[string]any) { v["schema_version"] = 99 },
		"expected_verdict_enum": func(v map[string]any) { v["expected_verdict"] = "warn" },
		"actual_verdict_enum":   func(v map[string]any) { v["actual_verdict"] = "warn" },
		"score_enum":            func(v map[string]any) { v["score"] = "not-a-score" },
		"unknown_property":      func(v map[string]any) { v["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertSchemaAndGoReject(t, schema, marshalConformanceJSON(t, mutated), accepts)
		})
	}

	t.Run("go_only_score_consistency", func(t *testing.T) {
		mutated := cloneConformanceObject(t, baseline)
		mutated["score"] = "fail"
		raw := marshalConformanceJSON(t, mutated)
		schemaAcceptsConformance(t, schema, raw)
		if accepts(raw) {
			t.Fatal("Go-only score consistency accepted matching verdict with fail score")
		}
	})
	t.Run("go_only_cross_line_duplicate", func(t *testing.T) {
		schemaAcceptsConformance(t, schema, raw)
		path := filepath.Join(t.TempDir(), "results.jsonl")
		if err := os.WriteFile(path, append(append(raw, '\n'), raw...), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
		if issues := validateResultsFile(path); len(issues) == 0 {
			t.Fatal("Go-only result-set duplicate check accepted duplicate case_id")
		}
	})
}

func caseValidatorAccepts(t *testing.T) func([]byte) bool {
	t.Helper()
	return func(raw []byte) bool {
		doc := decodeConformanceObject(t, raw)
		id, _ := doc["id"].(string)
		category, _ := doc["category"].(string)
		path := filepath.Join(t.TempDir(), categoryToDir(category), id+".json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		issues := validateFile(path, map[string]string{})
		if len(issues) != 0 {
			t.Logf("case validator issues: %v", issues)
		}
		return len(issues) == 0
	}
}

func resultValidatorAccepts(t *testing.T) func([]byte) bool {
	t.Helper()
	t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
	return func(raw []byte) bool {
		path := filepath.Join(t.TempDir(), "results.jsonl")
		if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		issues := validateResultsFile(path)
		if len(issues) != 0 {
			t.Logf("result validator issues: %v", issues)
		}
		return len(issues) == 0
	}
}

func compileConformanceSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	raw := readConformanceFixture(t, path)
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource(path, doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertSchemaAndGoAccept(t *testing.T, schema *jsonschema.Schema, raw []byte, goAccepts func([]byte) bool) {
	t.Helper()
	schemaAcceptsConformance(t, schema, raw)
	if !goAccepts(raw) {
		t.Fatalf("Go validator rejected schema-valid vector: %s", raw)
	}
}

func assertSchemaAndGoReject(t *testing.T, schema *jsonschema.Schema, raw []byte, goAccepts func([]byte) bool) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err == nil {
		t.Fatalf("schema accepted mutation: %s", raw)
	}
	if goAccepts(raw) {
		t.Fatalf("Go validator accepted schema-rejected mutation: %s", raw)
	}
}

func schemaAcceptsConformance(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected vector: %v\n%s", err, raw)
	}
}

func readConformanceFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeConformanceObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func cloneConformanceObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	return decodeConformanceObject(t, marshalConformanceJSON(t, value))
}

func marshalConformanceJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
