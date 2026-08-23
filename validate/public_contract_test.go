package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

type caseShape struct {
	InputTypes []string `json:"input_types"`
	Transports []string `json:"transports"`
}

type caseShapesContract struct {
	Contract          string               `json:"contract"`
	Format            int                  `json:"format"`
	CaseSchemaVersion int                  `json:"case_schema_version"`
	SingleFile        map[string]caseShape `json:"single_file"`
	MultiFile         map[string]caseShape `json:"multi_file"`
}

type resultMatrixRow struct {
	ExpectedVerdict string `json:"expected_verdict"`
	ActualVerdict   string `json:"actual_verdict"`
	Score           string `json:"score"`
}

type resultStateOverride struct {
	Name string `json:"name"`
	When struct {
		ExpectedVerdict        string   `json:"expected_verdict"`
		ActualVerdict          string   `json:"actual_verdict"`
		CasePayloadFields      []string `json:"case_payload_fields"`
		RequiredEvidenceFields []string `json:"required_evidence_fields"`
	} `json:"when"`
	ScoresByBudgetBlockTiming map[string]string `json:"scores_by_budget_block_timing"`
}

type resultStatesContract struct {
	Contract              string                `json:"contract"`
	Format                int                   `json:"format"`
	ResultSchemaVersion   int                   `json:"result_schema_version"`
	ScoringVersion        string                `json:"scoring_version"`
	ExpectedVerdicts      []string              `json:"expected_verdicts"`
	ActualVerdicts        []string              `json:"actual_verdicts"`
	Scores                []string              `json:"scores"`
	Matrix                []resultMatrixRow     `json:"matrix"`
	CaseSpecificOverrides []resultStateOverride `json:"case_specific_overrides"`
	AdapterOnlyStates     map[string]struct {
		ActiveResult resultMatrixRow `json:"active_result"`
	} `json:"adapter_only_states"`
	HistoricalOnlyStates map[string]string `json:"historical_only_states"`
}

func readPublicContract[T any](t *testing.T, name string) T {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", name))
	if err != nil {
		t.Fatalf("read public contract %s: %v", name, err)
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode public contract %s: %v", name, err)
	}
	return value
}

func sortedCopy(values []string) []string {
	copyOfValues := append([]string(nil), values...)
	sort.Strings(copyOfValues)
	return copyOfValues
}

func mapKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return sortedCopy(keys)
}

func resultStateForContractRow(row resultMatrixRow) string {
	if row.ActualVerdict == "unreachable" {
		return "unreachable"
	}
	if row.ActualVerdict == "error" {
		return "delivery_unavailable"
	}
	return "observed"
}

func TestPublicCaseShapesMatchValidator(t *testing.T) {
	contract := readPublicContract[caseShapesContract](t, "case-shapes-v4.json")
	if contract.Contract != "aeb.case-shapes" || contract.Format != 1 || contract.CaseSchemaVersion != activeCaseSchemaVersion {
		t.Fatalf("case-shapes identity/version = %q/%d/%d", contract.Contract, contract.Format, contract.CaseSchemaVersion)
	}
	if len(contract.SingleFile) != len(validCategoryInputType) || len(contract.SingleFile) != len(validCategoryTransport) {
		t.Fatalf("single-file category count = %d, validator input/transport counts = %d/%d", len(contract.SingleFile), len(validCategoryInputType), len(validCategoryTransport))
	}
	for category, shape := range contract.SingleFile {
		if got := sortedCopy(validCategoryInputType[category]); !reflect.DeepEqual(got, sortedCopy(shape.InputTypes)) {
			t.Errorf("%s input_types = %v, public contract wants %v", category, got, sortedCopy(shape.InputTypes))
		}
		if got := sortedCopy(validCategoryTransport[category]); !reflect.DeepEqual(got, sortedCopy(shape.Transports)) {
			t.Errorf("%s transports = %v, public contract wants %v", category, got, sortedCopy(shape.Transports))
		}
	}
	multi, ok := contract.MultiFile["mcp_drift"]
	if !ok || len(contract.MultiFile) != 1 {
		t.Fatalf("multi-file shapes = %v, want exactly mcp_drift", contract.MultiFile)
	}
	if !reflect.DeepEqual(multi.InputTypes, []string{"mcp_tool_sequence_temporal"}) ||
		!reflect.DeepEqual(sortedCopy(multi.Transports), []string{"mcp_http", "mcp_stdio"}) {
		t.Fatalf("mcp_drift shape = %+v", multi)
	}
	if got, want := sortedCopy(mapKeys(validCategories)), sortedCopy(mapKeys(validCategoryInputType)); !reflect.DeepEqual(got, want) {
		t.Fatalf("category enum = %v, shape categories = %v", got, want)
	}
}

func TestPublicResultStateMatrixMatchesValidator(t *testing.T) {
	contract := readPublicContract[resultStatesContract](t, "result-states-v6.json")
	if contract.Contract != "aeb.result-states" || contract.Format != 1 || contract.ResultSchemaVersion != activeResultSchemaVersion {
		t.Fatalf("result-states identity/version = %q/%d/%d", contract.Contract, contract.Format, contract.ResultSchemaVersion)
	}
	if contract.ScoringVersion == "" {
		t.Fatal("result-states scoring_version is empty")
	}
	if len(contract.Matrix) != len(contract.ExpectedVerdicts)*len(contract.ActualVerdicts) {
		t.Fatalf("matrix has %d rows, want %d", len(contract.Matrix), len(contract.ExpectedVerdicts)*len(contract.ActualVerdicts))
	}
	for _, row := range contract.Matrix {
		t.Run(row.ExpectedVerdict+"/"+row.ActualVerdict, func(t *testing.T) {
			result := ResultLine{
				SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "contract-case", Tool: "contract-tool", ToolVersion: "1",
				CapabilityRegistry: testRegistryReference,
				ExpectedVerdict:    row.ExpectedVerdict, ActualVerdict: row.ActualVerdict, Score: row.Score,
				Evidence: map[string]interface{}{"result_state": resultStateForContractRow(row)}, Notes: strPtr(""),
			}
			if errs := validateResultLine(1, result); len(errs) != 0 {
				t.Fatalf("public matrix row rejected: %v", errs)
			}
			for _, wrongScore := range contract.Scores {
				if wrongScore == row.Score {
					continue
				}
				result.Score = wrongScore
				if errs := validateResultLine(1, result); len(errs) == 0 {
					t.Errorf("validator accepted wrong score %q", wrongScore)
				}
			}
		})
	}
	if len(contract.CaseSpecificOverrides) != 1 || contract.CaseSpecificOverrides[0].Name != "budget_block_timing" {
		t.Fatalf("case-specific overrides = %+v", contract.CaseSpecificOverrides)
	}
	override := contract.CaseSpecificOverrides[0]
	if override.When.ExpectedVerdict != "block" || override.When.ActualVerdict != "block" ||
		!reflect.DeepEqual(override.When.CasePayloadFields, []string{"budget_limit_calls"}) ||
		!reflect.DeepEqual(override.When.RequiredEvidenceFields, []string{"budget_block_timing"}) {
		t.Fatalf("budget timing override condition = %+v", override.When)
	}
	budgetCase := &resultCaseMetadata{ExpectedVerdict: "block", BudgetTimingRequired: true}
	for timing, score := range override.ScoresByBudgetBlockTiming {
		result := ResultLine{
			SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "budget-case", Tool: "contract-tool", ToolVersion: "1",
			CapabilityRegistry: testRegistryReference,
			ExpectedVerdict:    "block", ActualVerdict: "block", Score: score,
			Evidence: map[string]interface{}{"result_state": "observed", "over_budget_call_id": float64(4), "budget_block_timing": timing}, Notes: strPtr(""),
		}
		if errs := validateResultLineAgainstCase(1, result, budgetCase); len(errs) != 0 {
			t.Errorf("budget timing %q with score %q rejected: %v", timing, score, errs)
		}
		for _, wrongScore := range contract.Scores {
			if wrongScore == score {
				continue
			}
			result.Score = wrongScore
			if errs := validateResultLineAgainstCase(1, result, budgetCase); len(errs) == 0 {
				t.Errorf("budget timing %q accepted wrong score %q", timing, wrongScore)
			}
		}
	}
	for name, evidence := range map[string]map[string]interface{}{
		"missing": {"result_state": "observed"},
		"unknown": {"result_state": "observed", "budget_block_timing": "unknown"},
	} {
		result := ResultLine{
			SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "budget-case", Tool: "contract-tool", ToolVersion: "1",
			CapabilityRegistry: testRegistryReference,
			ExpectedVerdict:    "block", ActualVerdict: "block", Score: "pass",
			Evidence: evidence, Notes: strPtr(""),
		}
		if errs := validateResultLineAgainstCase(1, result, budgetCase); len(errs) == 0 {
			t.Errorf("budget timing %s evidence accepted", name)
		}
	}
	nonBudgetCase := &resultCaseMetadata{ExpectedVerdict: "block"}
	nonBudgetResult := ResultLine{
		SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "ordinary-case", Tool: "contract-tool", ToolVersion: "1",
		CapabilityRegistry: testRegistryReference,
		ExpectedVerdict:    "block", ActualVerdict: "block", Score: "fail",
		Evidence: map[string]interface{}{"result_state": "observed", "over_budget_call_id": float64(4), "budget_block_timing": "before_over_budget"}, Notes: strPtr(""),
	}
	if errs := validateResultLineAgainstCase(1, nonBudgetResult, nonBudgetCase); len(errs) == 0 {
		t.Error("non-budget case accepted budget timing override")
	}
	for name, tc := range map[string]struct {
		result   ResultLine
		metadata *resultCaseMetadata
	}{
		"allow case": {
			result: ResultLine{
				SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "allow-case", Tool: "contract-tool", ToolVersion: "1",
				CapabilityRegistry: testRegistryReference,
				ExpectedVerdict:    "allow", ActualVerdict: "allow", Score: "pass",
				Evidence: map[string]interface{}{"result_state": "observed", "budget_block_timing": "at_over_budget"}, Notes: strPtr(""),
			},
			metadata: &resultCaseMetadata{ExpectedVerdict: "allow"},
		},
		"budget case without block verdict": {
			result: ResultLine{
				SchemaVersion: activeResultSchemaVersion, ScoringVersion: contract.ScoringVersion, CaseID: "budget-case", Tool: "contract-tool", ToolVersion: "1",
				CapabilityRegistry: testRegistryReference,
				ExpectedVerdict:    "block", ActualVerdict: "allow", Score: "fail",
				Evidence: map[string]interface{}{"result_state": "observed", "budget_block_timing": "at_over_budget"}, Notes: strPtr(""),
			},
			metadata: budgetCase,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if errs := validateResultLineAgainstCase(1, tc.result, tc.metadata); len(errs) == 0 {
				t.Error("result accepted stray budget timing evidence")
			}
		})
	}
	skip, ok := contract.AdapterOnlyStates["skip"]
	if !ok || len(contract.AdapterOnlyStates) != 1 || skip.ActiveResult.ActualVerdict != "error" || skip.ActiveResult.Score != "error" {
		t.Fatalf("adapter-only states = %+v, want skip -> error/error", contract.AdapterOnlyStates)
	}
	if got, ok := contract.HistoricalOnlyStates["not_applicable"]; !ok || len(contract.HistoricalOnlyStates) != 1 || got == "" {
		t.Fatalf("historical-only states = %+v, want a non-empty not_applicable entry", contract.HistoricalOnlyStates)
	}
}

func TestPublicResultValidationLoadsCanonicalCaseMetadata(t *testing.T) {
	metadata, err := loadResultCaseMetadata(filepath.Join("..", "cases"))
	if err != nil {
		t.Fatalf("load case metadata: %v", err)
	}
	budget := metadata["mcp-chain-dow-budget-exceeded-010"]
	if budget.ExpectedVerdict != "block" || !budget.BudgetTimingRequired {
		t.Fatalf("budget case metadata = %+v", budget)
	}
	warn := metadata["mcp-drift-benign-001"]
	if warn.ExpectedVerdict != "allow" || warn.BudgetTimingRequired {
		t.Fatalf("warn-normalized case metadata = %+v", warn)
	}
	ordinary := metadata["url-dlp-aws-key-001"]
	if ordinary.ExpectedVerdict != "block" || ordinary.BudgetTimingRequired {
		t.Fatalf("ordinary case metadata = %+v", ordinary)
	}
}
