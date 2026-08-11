package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func compileSummarySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaRaw, err := os.ReadFile(filepath.Join("..", "schemas", "summary-v5.schema.json"))
	if err != nil {
		t.Fatalf("read summary schema: %v", err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatalf("decode summary schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("summary-v5.schema.json", document); err != nil {
		t.Fatalf("add summary schema: %v", err)
	}
	schema, err := compiler.Compile("summary-v5.schema.json")
	if err != nil {
		t.Fatalf("compile summary schema: %v", err)
	}
	return schema
}

func summaryRequiredFields(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "schemas", "summary-v5.schema.json"))
	if err != nil {
		t.Fatalf("read summary schema: %v", err)
	}
	var document struct {
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode summary required fields: %v", err)
	}
	if len(document.Required) == 0 {
		t.Fatal("summary schema has no required fields")
	}
	return document.Required
}

func validSummaryDocument(t *testing.T) map[string]any {
	t.Helper()
	return validSummaryDocumentForProfile(t, testProfile())
}

func validSummaryDocumentForProfile(t *testing.T, profile Profile) map[string]any {
	t.Helper()
	dir, profilePath := provenanceTestDirs(t)
	caseValue := Case{
		ID:              "a",
		Category:        "url",
		Transport:       "fetch_proxy",
		ExpectedVerdict: "allow",
		CapabilityTags:  []string{"url_dlp"},
	}
	result := CaseResult{CaseID: "a", ExpectedVerdict: "allow", ActualVerdict: "allow", Score: "pass"}
	summary, err := buildSummary(
		profile,
		[]Case{caseValue},
		[]CaseResult{result},
		map[string]struct{}{},
		map[NAKind]int{},
		summarySnapshot(t, dir),
		map[string]Case{"a": caseValue},
		profilePath,
		RunProvenance{},
	)
	if err != nil {
		t.Fatalf("build valid summary: %v", err)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshal valid summary: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode valid summary: %v", err)
	}
	return document
}

func validateSummaryDocument(t *testing.T, schema *jsonschema.Schema, document map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("marshal summary document: %v", err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode summary document: %v", err)
	}
	return schema.Validate(value)
}

func TestSummaryV5SchemaAcceptsRunnerDocument(t *testing.T) {
	if err := validateSummaryDocument(t, compileSummarySchema(t), validSummaryDocument(t)); err != nil {
		t.Fatalf("active summary schema rejected runner document: %v", err)
	}
}

func TestSummaryV5SchemaAcceptsEmptyReportedClaims(t *testing.T) {
	profile := testProfile()
	profile.Claims = []string{}
	document := validSummaryDocumentForProfile(t, profile)
	if claims, ok := document["reported_claims"].([]any); !ok || len(claims) != 0 {
		t.Fatalf("reported_claims = %#v, want an empty JSON array", document["reported_claims"])
	}
	if err := validateSummaryDocument(t, compileSummarySchema(t), document); err != nil {
		t.Fatalf("active summary schema rejected empty reported claims: %v", err)
	}
}

func TestSummaryV5SchemaAcceptsDocumentedExample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "gauntlet.md"))
	if err != nil {
		t.Fatalf("read gauntlet documentation: %v", err)
	}
	const heading = "### Gauntlet summary (JSON file)"
	section := strings.SplitN(string(raw), heading, 2)
	if len(section) != 2 {
		t.Fatalf("documentation does not contain %q", heading)
	}
	code := strings.SplitN(section[1], "```json\n", 2)
	if len(code) != 2 {
		t.Fatal("gauntlet summary section has no JSON example")
	}
	jsonBlock := strings.SplitN(code[1], "\n```", 2)
	if len(jsonBlock) != 2 {
		t.Fatal("gauntlet summary JSON example has no closing fence")
	}
	var document map[string]any
	if err := json.Unmarshal([]byte(jsonBlock[0]), &document); err != nil {
		t.Fatalf("decode documented summary: %v", err)
	}
	if err := validateSummaryDocument(t, compileSummarySchema(t), document); err != nil {
		t.Fatalf("active summary schema rejected documented example: %v", err)
	}
}

func TestSummaryV5SchemaRejectsUnknownTopLevelFields(t *testing.T) {
	document := validSummaryDocument(t)
	document["detection"] = 1
	if err := validateSummaryDocument(t, compileSummarySchema(t), document); err == nil {
		t.Fatal("summary schema accepted retired or unknown top-level field")
	}
}

func TestSummaryV5SchemaRejectsMissingAndNullRequiredFields(t *testing.T) {
	schema := compileSummarySchema(t)
	for _, field := range summaryRequiredFields(t) {
		t.Run(field+"/missing", func(t *testing.T) {
			document := validSummaryDocument(t)
			delete(document, field)
			if err := validateSummaryDocument(t, schema, document); err == nil {
				t.Fatalf("summary schema accepted missing required field %q", field)
			}
		})
		t.Run(field+"/null", func(t *testing.T) {
			document := validSummaryDocument(t)
			document[field] = nil
			if err := validateSummaryDocument(t, schema, document); err == nil {
				t.Fatalf("summary schema accepted null required field %q", field)
			}
		})
	}
}

func TestSummaryV5SchemaRejectsWrongTypesForNewlyTypedFields(t *testing.T) {
	schema := compileSummarySchema(t)
	wrongValues := map[string]any{
		"gauntlet_version": 1,
		"scoring_version":  []any{},
		"runner_version":   false,
		"tool":             map[string]any{},
		"tool_version":     1,
		"corpus_version":   true,
		"case_count":       []any{},
		"exercised":        "fetch_proxy",
	}
	for field, wrong := range wrongValues {
		t.Run(field, func(t *testing.T) {
			document := validSummaryDocument(t)
			document[field] = wrong
			if err := validateSummaryDocument(t, schema, document); err == nil {
				t.Fatalf("summary schema accepted wrong type for %q", field)
			}
		})
	}
}

func TestSummaryV5SchemaRejectsMalformedDigests(t *testing.T) {
	schema := compileSummarySchema(t)
	for _, field := range []string{
		"corpus_sha256", "benchmark_manifest_sha256", "tool_profile_sha256",
	} {
		t.Run(field, func(t *testing.T) {
			document := validSummaryDocument(t)
			document[field] = "not-a-sha256"
			if err := validateSummaryDocument(t, schema, document); err == nil {
				t.Fatalf("summary schema accepted malformed digest in %q", field)
			}
		})
	}
}
