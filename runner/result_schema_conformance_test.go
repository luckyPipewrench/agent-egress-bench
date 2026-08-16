package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type resultSchemaConformanceVector struct {
	Name          string          `json:"name"`
	SchemaRejects bool            `json:"schema_rejects"`
	Row           json.RawMessage `json:"row"`
}

type resultSchemaConformanceCorpus struct {
	Accepted []resultSchemaConformanceVector `json:"accepted"`
	Rejected []resultSchemaConformanceVector `json:"rejected"`
}

func TestResultV5SchemaConformanceVectors(t *testing.T) {
	schema := compileJSONSchema(t, filepath.Join("..", "schemas", "result-v5.schema.json"))
	raw, err := os.ReadFile(filepath.Join("..", "validate", "testdata", "result-v5-conformance.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus resultSchemaConformanceCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, vector := range corpus.Accepted {
		t.Run("accepted/"+vector.Name, func(t *testing.T) {
			var row interface{}
			if err := json.Unmarshal(vector.Row, &row); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(row); err != nil {
				t.Fatalf("schema rejected accepted vector: %v", err)
			}
		})
	}
	for _, vector := range corpus.Rejected {
		t.Run("rejected/"+vector.Name, func(t *testing.T) {
			var row interface{}
			if err := json.Unmarshal(vector.Row, &row); err != nil {
				t.Fatal(err)
			}
			err := schema.Validate(row)
			if vector.SchemaRejects && err == nil {
				t.Fatal("schema accepted structurally rejected vector")
			}
			if !vector.SchemaRejects && err != nil {
				t.Fatalf("schema rejected Go-only cross-field vector: %v", err)
			}
		})
	}
}

func TestResultV4SchemaStillAcceptsMissingResultState(t *testing.T) {
	schema := compileJSONSchema(t, filepath.Join("..", "schemas", "result-v4.schema.json"))
	row := map[string]interface{}{
		"schema_version": float64(4), "case_id": "legacy", "tool": "fixture-tool", "tool_version": "1.0.0",
		"capability_registry": map[string]interface{}{"id": "registry", "format": float64(1), "revision": float64(1), "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"expected_verdict":    "allow", "actual_verdict": "allow", "score": "pass", "evidence": map[string]interface{}{}, "notes": "",
	}
	if err := schema.Validate(row); err != nil {
		t.Fatalf("result-v4 rejected a historical row without evidence.result_state: %v", err)
	}
}
