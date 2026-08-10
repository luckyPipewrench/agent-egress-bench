package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestToolProfileSchemaConformance uses the shipped Pipelock profile as the
// positive vector. Registry snapshot resolution is deliberately tested as a
// Go-only boundary because JSON Schema can validate a reference's shape but
// cannot open the immutable registry snapshot it names.
func TestToolProfileSchemaConformance(t *testing.T) {
	schema := compileToolProfileSchema(t)
	raw := mustReadToolProfileVector(t, filepath.Join("..", "examples", "pipelock", "tool-profile.json"))
	assertToolProfileSchemaAndGoAccept(t, schema, raw)

	baseline := decodeToolProfileObject(t, raw)
	for _, required := range []string{"schema_version", "tool", "tool_version", "runner_version", "claims", "capability_registry"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneToolProfileObject(t, baseline)
			delete(mutated, required)
			assertToolProfileSchemaAndGoReject(t, schema, marshalToolProfileJSON(t, mutated))
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema_version_const": func(v map[string]any) { v["schema_version"] = 99 },
		"detail_encoding_enum": func(v map[string]any) {
			v["receipt_evidence"].(map[string]any)["detail_encoding"] = "not-an-encoding"
		},
		"unknown_property": func(v map[string]any) { v["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneToolProfileObject(t, baseline)
			mutate(mutated)
			assertToolProfileSchemaAndGoReject(t, schema, marshalToolProfileJSON(t, mutated))
		})
	}

	t.Run("go_only_registry_resolution", func(t *testing.T) {
		mutated := cloneToolProfileObject(t, baseline)
		mutated["capability_registry"].(map[string]any)["sha256"] = string(bytes.Repeat([]byte("0"), 64))
		raw := marshalToolProfileJSON(t, mutated)
		assertToolProfileSchemaAccepts(t, schema, raw)
		profile, err := loadToolProfileVector(t, raw)
		if err != nil {
			t.Fatal(err)
		}
		cases, err := loadCases(filepath.Join("..", "cases"))
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
		if _, err := preflightRegistry(profile, cases[:1], filepath.Join("..", "cases")); err == nil {
			t.Fatal("Go-only immutable registry resolution accepted a substituted digest")
		}
	})
}

func compileToolProfileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw := mustReadToolProfileVector(t, filepath.Join("..", "schemas", "tool-profile-v4.schema.json"))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("tool-profile.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("tool-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertToolProfileSchemaAndGoAccept(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	assertToolProfileSchemaAccepts(t, schema, raw)
	if _, err := loadToolProfileVector(t, raw); err != nil {
		t.Fatalf("Go loader rejected schema-valid profile: %v", err)
	}
}

func assertToolProfileSchemaAndGoReject(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err == nil {
		t.Fatalf("schema accepted mutation: %s", raw)
	}
	if _, err := loadToolProfileVector(t, raw); err == nil {
		t.Fatalf("Go loader accepted schema-rejected mutation: %s", raw)
	}
}

func assertToolProfileSchemaAccepts(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected vector: %v\n%s", err, raw)
	}
}

func loadToolProfileVector(t *testing.T, raw []byte) (Profile, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool-profile.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := loadProfile(path)
	if err != nil {
		return Profile{}, err
	}
	if profile.ReceiptEvidence != nil {
		if reason := validateReceiptEvidenceDeclaration(*profile.ReceiptEvidence); reason != "" {
			return Profile{}, &toolProfileConformanceError{reason}
		}
	}
	return profile, nil
}

type toolProfileConformanceError struct{ reason string }

func (e *toolProfileConformanceError) Error() string { return e.reason }

func mustReadToolProfileVector(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeToolProfileObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func cloneToolProfileObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	return decodeToolProfileObject(t, marshalToolProfileJSON(t, value))
}

func marshalToolProfileJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
