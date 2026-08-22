package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type resultV5ConformanceVector struct {
	Name          string          `json:"name"`
	FailureMode   string          `json:"failure_mode"`
	SchemaRejects bool            `json:"schema_rejects"`
	Row           json.RawMessage `json:"row"`
}

type resultV5ConformanceCorpus struct {
	Accepted []resultV5ConformanceVector `json:"accepted"`
	Rejected []resultV5ConformanceVector `json:"rejected"`
}

// These vectors pin the structural boundary shared by the public root schemas
// and the stdlib validator. Repository-wide graph and registry checks are
// called out below as Go-only because one JSON document cannot express them.
func TestCaseSchemaConformance(t *testing.T) {
	raw := readConformanceFixture(t, filepath.Join("..", "cases", "a2a-agent-card", "a2a-card-benign-normal-006.json"))
	assertGoAccept(t, raw, caseValidatorAccepts(t))

	baseline := decodeConformanceObject(t, raw)
	for _, required := range []string{"schema_version", "id", "category", "title", "description", "input_type", "transport", "payload", "expected_verdict", "severity", "capability_tags", "requires", "false_positive_risk", "why_expected", "notes", "source"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			delete(mutated, required)
			assertGoReject(t, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
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
		"malformed_id":          func(v map[string]any) { v["id"] = "Bad ID" },
		"malformed_supersedes":  func(v map[string]any) { v["supersedes"] = "../case" },
		"duplicate_capability": func(v map[string]any) {
			tags := v["capability_tags"].([]any)
			v["capability_tags"] = append(tags, tags[0])
		},
		"duplicate_requires": func(v map[string]any) { v["requires"] = []any{"mcp_tool_policy", "mcp_tool_policy"} },
		"unknown_property":   func(v map[string]any) { v["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertGoReject(t, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"allow_requires_safe_example": func(v map[string]any) { delete(v, "safe_example") },
		"allow_requires_safe_true":    func(v map[string]any) { v["safe_example"] = false },
	} {
		t.Run("conditional_"+name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertGoReject(t, marshalConformanceJSON(t, mutated), caseValidatorAccepts(t))
		})
	}

	t.Run("go_only_supersession_graph", func(t *testing.T) {
		mutated := cloneConformanceObject(t, baseline)
		mutated["supersedes"] = mutated["id"]
		data := marshalConformanceJSON(t, mutated)
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
	profile := decodeConformanceObject(t, readConformanceFixture(t, filepath.Join("..", "examples", "pipelock", "tool-profile.json")))
	caseDoc := decodeConformanceObject(t, readConformanceFixture(t, filepath.Join("..", "cases", "a2a-agent-card", "a2a-card-benign-normal-006.json")))
	baseline := map[string]any{
		"schema_version":      6,
		"scoring_version":     "2.8",
		"case_id":             caseDoc["id"],
		"tool":                profile["tool"],
		"tool_version":        profile["tool_version"],
		"capability_registry": profile["capability_registry"],
		"expected_verdict":    "allow",
		"actual_verdict":      "allow",
		"score":               "pass",
		"evidence":            map[string]any{"result_state": "observed"},
		"notes":               "",
	}
	raw := marshalConformanceJSON(t, baseline)
	accepts := resultValidatorAccepts(t)
	assertGoAccept(t, raw, accepts)

	for _, required := range []string{"schema_version", "scoring_version", "case_id", "tool", "tool_version", "capability_registry", "expected_verdict", "actual_verdict", "score", "evidence", "notes"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			delete(mutated, required)
			assertGoReject(t, marshalConformanceJSON(t, mutated), accepts)
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema_version_const":  func(v map[string]any) { v["schema_version"] = 99 },
		"expected_verdict_enum": func(v map[string]any) { v["expected_verdict"] = "warn" },
		"actual_verdict_enum":   func(v map[string]any) { v["actual_verdict"] = "warn" },
		"score_enum":            func(v map[string]any) { v["score"] = "not-a-score" },
		"malformed_case_id":     func(v map[string]any) { v["case_id"] = "../case" },
		"empty_tool":            func(v map[string]any) { v["tool"] = "" },
		"empty_tool_version":    func(v map[string]any) { v["tool_version"] = "" },
		"unknown_property":      func(v map[string]any) { v["unexpected"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneConformanceObject(t, baseline)
			mutate(mutated)
			assertGoReject(t, marshalConformanceJSON(t, mutated), accepts)
		})
	}

	t.Run("go_only_score_consistency", func(t *testing.T) {
		mutated := cloneConformanceObject(t, baseline)
		mutated["score"] = "fail"
		raw := marshalConformanceJSON(t, mutated)
		if accepts(raw) {
			t.Fatal("Go-only score consistency accepted matching verdict with fail score")
		}
	})
	t.Run("go_only_cross_line_duplicate", func(t *testing.T) {
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

func TestResultV6ConformanceVectors(t *testing.T) {
	raw := readConformanceFixture(t, filepath.Join("testdata", "result-v6-conformance.json"))
	var corpus resultV5ConformanceCorpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Accepted) == 0 || len(corpus.Rejected) == 0 {
		t.Fatal("result-v6 conformance corpus must contain accepted and rejected vectors")
	}

	acceptedStates := make(map[string]bool)
	for _, vector := range corpus.Accepted {
		t.Run("accepted/"+vector.Name, func(t *testing.T) {
			var row ResultLine
			if err := json.Unmarshal(vector.Row, &row); err != nil {
				t.Fatal(err)
			}
			state, _ := row.Evidence["result_state"].(string)
			acceptedStates[state] = true
			if issues := validateResultLine(1, row); len(issues) != 0 {
				t.Fatalf("validator rejected accepted vector: %v", issues)
			}
		})
	}
	if len(acceptedStates) != len(validResultStates) {
		t.Fatalf("accepted vectors cover %v, validator accepts %v", acceptedStates, validResultStates)
	}
	for state := range validResultStates {
		if !acceptedStates[state] {
			t.Errorf("accepted vectors omit result_state %q", state)
		}
	}

	failureModes := make(map[string]bool)
	for _, vector := range corpus.Rejected {
		t.Run("rejected/"+vector.Name, func(t *testing.T) {
			if vector.FailureMode == "" || failureModes[vector.FailureMode] {
				t.Fatalf("rejected vector has missing or duplicate failure mode %q", vector.FailureMode)
			}
			failureModes[vector.FailureMode] = true
			var row ResultLine
			if err := json.Unmarshal(vector.Row, &row); err != nil {
				return
			}
			if issues := validateResultLine(1, row); len(issues) == 0 {
				t.Fatal("validator accepted rejected vector")
			}
		})
	}
}

func TestResultV4WithoutResultStateRemainsReadable(t *testing.T) {
	row := ResultLine{
		SchemaVersion: legacyResultSchemaVersionV4, CaseID: "legacy-result", Tool: "fixture-tool", ToolVersion: "1.0.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "allow", ActualVerdict: "allow", Score: "pass", Evidence: map[string]interface{}{}, Notes: strPtr(""),
	}
	if issues := validateResultLine(1, row); len(issues) != 0 {
		t.Fatalf("v4 row without evidence.result_state was rejected: %v", issues)
	}
}

func TestResultV5WithoutScoringVersionRemainsReadable(t *testing.T) {
	row := ResultLine{
		SchemaVersion: legacyResultSchemaVersionV5, CaseID: "legacy-result-v5", Tool: "fixture-tool", ToolVersion: "1.0.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "allow", ActualVerdict: "allow", Score: "pass",
		Evidence: map[string]interface{}{"result_state": "observed"}, Notes: strPtr(""),
	}
	if issues := validateResultLine(1, row); len(issues) != 0 {
		t.Fatalf("validator rejected frozen result-v5 row without scoring_version: %v", issues)
	}
}

func TestResultV6RetainsOlderScoringIdentity(t *testing.T) {
	row := ResultLine{
		SchemaVersion: activeResultSchemaVersion, ScoringVersion: "2.7", CaseID: "retained-v6-result", Tool: "fixture-tool", ToolVersion: "1.0.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "allow", ActualVerdict: "allow", Score: "pass",
		Evidence: map[string]interface{}{"result_state": "observed"}, Notes: strPtr(""),
	}
	if issues := validateResultLine(1, row); len(issues) != 0 {
		t.Fatalf("validator rejected a well-formed retained v6 scoring identity: %v", issues)
	}
}

func TestResultV4AndV5RowsCanShareFile(t *testing.T) {
	v4 := ResultLine{
		SchemaVersion: legacyResultSchemaVersionV4, CaseID: "legacy-result", Tool: "fixture-tool", ToolVersion: "1.0.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "allow", ActualVerdict: "allow", Score: "pass", Evidence: map[string]interface{}{}, Notes: strPtr(""),
	}
	v5 := ResultLine{
		SchemaVersion: legacyResultSchemaVersionV5, CaseID: "legacy-result-v5-mixed", Tool: "fixture-tool", ToolVersion: "1.0.0",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "block", ActualVerdict: "block", Score: "pass", Evidence: map[string]interface{}{"result_state": "observed"}, Notes: strPtr(""),
	}
	var rows bytes.Buffer
	for _, row := range []ResultLine{v4, v5} {
		if err := json.NewEncoder(&rows).Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "mixed-results.jsonl")
	if err := os.WriteFile(path, rows.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
	if issues := validateResultsFile(path); len(issues) != 0 {
		t.Fatalf("mixed v4/v5 result file was rejected: %v", issues)
	}
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

func assertGoAccept(t *testing.T, raw []byte, goAccepts func([]byte) bool) {
	t.Helper()
	if !goAccepts(raw) {
		t.Fatalf("Go validator rejected valid vector: %s", raw)
	}
}

func assertGoReject(t *testing.T, raw []byte, goAccepts func([]byte) bool) {
	t.Helper()
	if goAccepts(raw) {
		t.Fatalf("Go validator accepted invalid mutation: %s", raw)
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
