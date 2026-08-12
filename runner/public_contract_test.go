package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type publicResultMatrixRow struct {
	ExpectedVerdict string `json:"expected_verdict"`
	ActualVerdict   string `json:"actual_verdict"`
	Score           string `json:"score"`
}

type publicResultStateOverride struct {
	Name                      string            `json:"name"`
	ScoresByBudgetBlockTiming map[string]string `json:"scores_by_budget_block_timing"`
}

type publicResultStatesContract struct {
	Contract              string                      `json:"contract"`
	Format                int                         `json:"format"`
	ResultSchemaVersion   int                         `json:"result_schema_version"`
	Matrix                []publicResultMatrixRow     `json:"matrix"`
	CaseSpecificOverrides []publicResultStateOverride `json:"case_specific_overrides"`
}

func loadPublicResultStates(t *testing.T) publicResultStatesContract {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "result-states-v4.json"))
	if err != nil {
		t.Fatalf("read public result-state contract: %v", err)
	}
	var contract publicResultStatesContract
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatalf("decode public result-state contract: %v", err)
	}
	return contract
}

func TestPublicResultStateMatrixMatchesScorer(t *testing.T) {
	contract := loadPublicResultStates(t)
	if contract.Contract != "aeb.result-states" || contract.Format != 1 || contract.ResultSchemaVersion != activeSchemaVersion {
		t.Fatalf("result-states identity/version = %q/%d/%d", contract.Contract, contract.Format, contract.ResultSchemaVersion)
	}
	for _, row := range contract.Matrix {
		if got := scoreCase(row.ExpectedVerdict, row.ActualVerdict); got != row.Score {
			t.Errorf("scoreCase(%q, %q) = %q, public contract wants %q", row.ExpectedVerdict, row.ActualVerdict, got, row.Score)
		}
	}
}

func TestPublicBudgetTimingOverrideMatchesScorer(t *testing.T) {
	contract := loadPublicResultStates(t)
	if len(contract.CaseSpecificOverrides) != 1 || contract.CaseSpecificOverrides[0].Name != "budget_block_timing" {
		t.Fatalf("case-specific overrides = %+v", contract.CaseSpecificOverrides)
	}
	budgetCase := Case{ExpectedVerdict: "block", Payload: map[string]interface{}{"budget_limit_calls": float64(3)}}
	for timing, want := range contract.CaseSpecificOverrides[0].ScoresByBudgetBlockTiming {
		evidence := map[string]interface{}{"over_budget_call_id": float64(4), "budget_block_timing": timing}
		if got := scoreCaseWithEvidence(budgetCase, "block", evidence); got != want {
			t.Errorf("budget timing %q score = %q, public contract wants %q", timing, got, want)
		}
	}
}
