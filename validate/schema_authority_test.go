package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// These tests bind the active public schemas directly to the stdlib validator.
// The runner also compiles the schemas in its conformance tests. Keeping this
// validator-level comparison matters because it owns the vocabulary maps that
// reject invalid case, result, and profile inputs before a runner sees them.
type authoritySchema struct {
	Required []string `json:"required"`
	// A pointer because an omitted additionalProperties and an explicit false
	// both decode to false, and in JSON Schema an omitted one PERMITS unknown
	// properties. Decoding into a plain bool made this assertion vacuous:
	// deleting the keyword left the schema permissive while the validator kept
	// rejecting unknown fields, and the drift test still passed.
	AdditionalProperties *bool                           `json:"additionalProperties"`
	Properties           map[string]authoritySchemaField `json:"properties"`
}

type authoritySchemaField struct {
	Const                any                             `json:"const"`
	Enum                 []string                        `json:"enum"`
	Required             []string                        `json:"required"`
	AdditionalProperties *bool                           `json:"additionalProperties"`
	Properties           map[string]authoritySchemaField `json:"properties"`
	Items                struct {
		Enum []string `json:"enum"`
	} `json:"items"`
}

// jsonFieldNames returns the JSON property names a struct decodes, which is the
// exact surface DisallowUnknownFields accepts.
func jsonFieldNames(structType reflect.Type) []string {
	names := make([]string, 0, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		tag := structType.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// requireClosedObject fails unless the scope explicitly forbids unknown
// properties, which is what the validator's strict decoding enforces.
func requireClosedObject(t *testing.T, additionalProperties *bool, scope string) {
	t.Helper()
	if additionalProperties == nil {
		t.Errorf("%s omits additionalProperties, so the schema permits unknown fields the validator rejects", scope)
		return
	}
	if *additionalProperties {
		t.Errorf("%s permits unknown fields but the validator rejects them", scope)
	}
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
	requireClosedObject(t, schema.AdditionalProperties, "case schema")
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
	requireClosedObject(t, schema.AdditionalProperties, "result schema")
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
	requireClosedObject(t, schema.AdditionalProperties, "tool-profile schema")
	if got := sortedSchemaStrings(schema.Required); !reflect.DeepEqual(got, sortedSchemaStrings(profileRequiredFields)) {
		t.Errorf("tool-profile schema required fields = %v, validator requires %v", got, sortedSchemaStrings(profileRequiredFields))
	}
	if _, ok := schema.Properties["receipt_evidence"]; !ok {
		t.Fatal("tool-profile schema no longer declares receipt_evidence")
	}
	receipt := schema.Properties["receipt_evidence"]
	// The nested object is closed too, because validateReceiptEvidenceRaw
	// decodes it strictly. This scope was never asserted at all.
	requireClosedObject(t, receipt.AdditionalProperties, "receipt_evidence schema")
	// Derived from the struct the validator strictly decodes into, not from a
	// hand-written copy. A copy only catches a schema-side change: adding a
	// field to the struct alone would make the validator accept a property the
	// schema forbids, while a copy that still matched the schema passed.
	wantReceiptFields := jsonFieldNames(reflect.TypeOf(ReceiptEvidence{}))
	gotReceiptFields := make([]string, 0, len(receipt.Properties))
	for name := range receipt.Properties {
		gotReceiptFields = append(gotReceiptFields, name)
	}
	if got := sortedSchemaStrings(gotReceiptFields); !reflect.DeepEqual(got, sortedSchemaStrings(wantReceiptFields)) {
		t.Errorf("receipt_evidence fields = %v, validator accepts %v", got, sortedSchemaStrings(wantReceiptFields))
	}
	// Compared against the list the validator actually enforces, not a copy
	// declared here. A local copy made this assertion self-satisfying: it agreed
	// with the schema while the validator enforced no presence at all.
	if got := sortedSchemaStrings(receipt.Required); !reflect.DeepEqual(got, sortedSchemaStrings(receiptEvidenceRequiredFields)) {
		t.Errorf("receipt_evidence required fields = %v, validator requires %v", got, sortedSchemaStrings(receiptEvidenceRequiredFields))
	}
	if issues := validateProfileFile(filepath.Join("..", "examples", "pipelock", "tool-profile.json")); len(issues) != 0 {
		t.Fatalf("validator rejected the shipped schema-valid profile: %v", issues)
	}
}

// The schema types every receipt_evidence field as an object, string, array, or
// integer, and none of them accept null. Go decodes a null into the zero value,
// so without an explicit presence check a schema-invalid null is
// indistinguishable from an omitted or empty field and passes a validator the
// schema would fail. verify_timeout_seconds runs the same risk in the opposite
// direction: it is optional, so decoding an absent value as 0 rejected profiles
// the schema accepts.
func TestReceiptEvidenceNullAndOptionalHandling(t *testing.T) {
	valid := `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":"/detail","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0]}`
	nullPointer := `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":null,"detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0]}`
	nullTimeout := `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":"/detail","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0],"verify_timeout_seconds":null}`
	zeroTimeout := `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":"/detail","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0],"verify_timeout_seconds":0}`

	for _, tc := range []struct {
		name    string
		raw     string
		wantErr string
	}{
		{"explicit null declaration is rejected", "null", "must be an object, not null"},
		{"omitted required field is rejected", `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0]}`, "detail_json_pointer is required"},
		// A null here decodes into []int as 0, which is the success exit code, so
		// the invalid declaration would otherwise become a more permissive one.
		{"null inside an exit-code array is rejected", `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":"/detail","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[null]}`, "valid_exit_codes[0] must not be null"},
		{"unknown field is rejected", `{"evidence_dir":"receipts","file_glob":"*.jsonl","detail_json_pointer":"/detail","detail_encoding":"object","verify_command":["true"],"valid_exit_codes":[0],"made_up":"x"}`, `is malformed: json: unknown field "made_up"`},
		{"null in a required string is rejected", nullPointer, "detail_json_pointer must not be null"},
		{"null in an optional integer is rejected", nullTimeout, "verify_timeout_seconds must not be null"},
		{"supplied non-positive timeout is still rejected", zeroTimeout, "verify_timeout_seconds must be positive"},
		{"omitted optional timeout is accepted", valid, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issues := validateReceiptEvidenceRaw([]byte(tc.raw))
			if tc.wantErr == "" {
				if len(issues) != 0 {
					t.Fatalf("schema-valid declaration rejected: %v", issues)
				}
				return
			}
			for _, issue := range issues {
				if issue == tc.wantErr {
					return
				}
			}
			t.Fatalf("issues = %v, want one equal to %q", issues, tc.wantErr)
		})
	}
}
