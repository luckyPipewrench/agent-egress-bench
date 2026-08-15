package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// These tests bind the active public schemas directly to the stdlib validator.
// The runner also compiles the schemas in its conformance tests. Keeping this
// validator-level comparison matters because it owns the vocabulary maps that
// reject invalid case, result, and profile inputs before a runner sees them.
type authoritySchema struct {
	Required             []string                        `json:"required"`
	AdditionalProperties bool                            `json:"additionalProperties"`
	Properties           map[string]authoritySchemaField `json:"properties"`
}

type authoritySchemaField struct {
	Const      any                             `json:"const"`
	Enum       []string                        `json:"enum"`
	Required   []string                        `json:"required"`
	Properties map[string]authoritySchemaField `json:"properties"`
	Items      struct {
		Enum []string `json:"enum"`
	} `json:"items"`
}

func readAuthoritySchema(t *testing.T, name string) authoritySchema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "schemas", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema authoritySchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Properties) == 0 {
		t.Fatalf("%s has no properties", name)
	}
	return schema
}

func sortedSchemaStrings(values []string) []string {
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	return copyOfValues
}

func sortedSchemaKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return sortedSchemaStrings(keys)
}

func assertSchemaStrings(t *testing.T, schema authoritySchema, property string, want []string) {
	t.Helper()
	field, ok := schema.Properties[property]
	if !ok {
		t.Fatalf("schema has no %q property", property)
	}
	if got := sortedSchemaStrings(field.Enum); !reflect.DeepEqual(got, sortedSchemaStrings(want)) {
		t.Errorf("schema %s enum = %v, validator accepts %v", property, got, sortedSchemaStrings(want))
	}
}

func assertSchemaVersion(t *testing.T, schema authoritySchema, want int) {
	t.Helper()
	field, ok := schema.Properties["schema_version"]
	if !ok || field.Const == nil {
		t.Fatal("schema_version const is missing")
	}
	got, ok := field.Const.(float64)
	if !ok || int(got) != want {
		t.Errorf("schema_version const = %#v, validator requires %d", field.Const, want)
	}
}

func TestCaseSchemaMatchesValidator(t *testing.T) {
	schema := readAuthoritySchema(t, "case-v4.schema.json")
	assertSchemaVersion(t, schema, activeCaseSchemaVersion)
	if schema.AdditionalProperties {
		t.Error("case schema permits unknown fields but the validator rejects them")
	}
	if got := sortedSchemaStrings(schema.Required); !reflect.DeepEqual(got, sortedSchemaStrings(caseRequiredFields)) {
		t.Errorf("case schema required fields = %v, validator requires %v", got, sortedSchemaStrings(caseRequiredFields))
	}
	assertSchemaStrings(t, schema, "category", sortedSchemaKeys(validCategories))
	assertSchemaStrings(t, schema, "input_type", sortedSchemaKeys(validInputTypes))
	assertSchemaStrings(t, schema, "transport", sortedSchemaKeys(validTransports))
	assertSchemaStrings(t, schema, "expected_verdict", sortedSchemaKeys(validCaseExpectedVerdicts))
	assertSchemaStrings(t, schema, "severity", sortedSchemaKeys(validSeverities))
	assertSchemaStrings(t, schema, "false_positive_risk", sortedSchemaKeys(validFPRisk))
	requires := schema.Properties["requires"]
	if got := sortedSchemaStrings(requires.Items.Enum); !reflect.DeepEqual(got, sortedSchemaKeys(validRequires)) {
		t.Errorf("schema requires enum = %v, validator accepts %v", got, sortedSchemaKeys(validRequires))
	}
}

func TestResultSchemaMatchesValidator(t *testing.T) {
	schema := readAuthoritySchema(t, "result-v4.schema.json")
	assertSchemaVersion(t, schema, activeResultSchemaVersion)
	if schema.AdditionalProperties {
		t.Error("result schema permits unknown fields but the validator rejects them")
	}
	if got := sortedSchemaStrings(schema.Required); !reflect.DeepEqual(got, sortedSchemaStrings(resultRequiredFields)) {
		t.Errorf("result schema required fields = %v, validator requires %v", got, sortedSchemaStrings(resultRequiredFields))
	}
	assertSchemaStrings(t, schema, "expected_verdict", sortedSchemaKeys(validMeasuredVerdicts))
	assertSchemaStrings(t, schema, "actual_verdict", sortedSchemaKeys(validActualVerdicts))
	assertSchemaStrings(t, schema, "score", sortedSchemaKeys(validScores))
}

func TestToolProfileSchemaMatchesValidator(t *testing.T) {
	schema := readAuthoritySchema(t, "tool-profile-v4.schema.json")
	assertSchemaVersion(t, schema, activeToolProfileSchemaVersion)
	if schema.AdditionalProperties {
		t.Error("tool-profile schema permits unknown fields but the validator rejects them")
	}
	if got := sortedSchemaStrings(schema.Required); !reflect.DeepEqual(got, sortedSchemaStrings(profileRequiredFields)) {
		t.Errorf("tool-profile schema required fields = %v, validator requires %v", got, sortedSchemaStrings(profileRequiredFields))
	}
	if _, ok := schema.Properties["receipt_evidence"]; !ok {
		t.Fatal("tool-profile schema no longer declares receipt_evidence")
	}
	receipt := schema.Properties["receipt_evidence"]
	wantReceiptFields := []string{
		"evidence_dir", "file_glob", "jsonl_record_type", "detail_json_pointer", "detail_encoding",
		"record_case_id_json_pointer", "record_identifier_json_pointer", "case_identifier_json_pointer",
		"verify_command", "verify_timeout_seconds", "valid_exit_codes", "partial_exit_codes",
	}
	gotReceiptFields := make([]string, 0, len(receipt.Properties))
	for name := range receipt.Properties {
		gotReceiptFields = append(gotReceiptFields, name)
	}
	if got := sortedSchemaStrings(gotReceiptFields); !reflect.DeepEqual(got, sortedSchemaStrings(wantReceiptFields)) {
		t.Errorf("receipt_evidence fields = %v, validator accepts %v", got, sortedSchemaStrings(wantReceiptFields))
	}
	wantReceiptRequired := []string{"evidence_dir", "file_glob", "detail_json_pointer", "detail_encoding", "verify_command", "valid_exit_codes"}
	if got := sortedSchemaStrings(receipt.Required); !reflect.DeepEqual(got, sortedSchemaStrings(wantReceiptRequired)) {
		t.Errorf("receipt_evidence required fields = %v, validator requires %v", got, sortedSchemaStrings(wantReceiptRequired))
	}
	if issues := validateProfileFile(filepath.Join("..", "examples", "pipelock", "tool-profile.json")); len(issues) != 0 {
		t.Fatalf("validator rejected the shipped schema-valid profile: %v", issues)
	}
}
