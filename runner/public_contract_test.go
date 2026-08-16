package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type publicResultMatrixRow struct {
	ExpectedVerdict string `json:"expected_verdict"`
	ActualVerdict   string `json:"actual_verdict"`
	Score           string `json:"score"`
}

type publicResultStateOverride struct {
	Name string `json:"name"`
	When struct {
		ExpectedVerdict        string   `json:"expected_verdict"`
		ActualVerdict          string   `json:"actual_verdict"`
		CasePayloadFields      []string `json:"case_payload_fields"`
		RequiredEvidenceFields []string `json:"required_evidence_fields"`
	} `json:"when"`
	ScoresByBudgetBlockTiming map[string]string `json:"scores_by_budget_block_timing"`
}

type publicResultStatesContract struct {
	Contract              string                      `json:"contract"`
	Format                int                         `json:"format"`
	ResultSchemaVersion   int                         `json:"result_schema_version"`
	EvidenceResultStates  map[string]string           `json:"evidence_result_states"`
	Matrix                []publicResultMatrixRow     `json:"matrix"`
	CaseSpecificOverrides []publicResultStateOverride `json:"case_specific_overrides"`
}

func loadPublicResultStates(t *testing.T) publicResultStatesContract {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "contracts", "result-states-v5.json"))
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
	if contract.Contract != "aeb.result-states" || contract.Format != 1 || contract.ResultSchemaVersion != activeResultSchemaVersion {
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
	override := contract.CaseSpecificOverrides[0]
	if override.When.ExpectedVerdict != "block" || override.When.ActualVerdict != "block" ||
		len(override.When.CasePayloadFields) != 1 || override.When.CasePayloadFields[0] != "budget_limit_calls" ||
		len(override.When.RequiredEvidenceFields) != 1 || override.When.RequiredEvidenceFields[0] != "budget_block_timing" {
		t.Fatalf("budget timing override condition = %+v", override.When)
	}
	budgetCase := Case{ExpectedVerdict: "block", Payload: map[string]interface{}{override.When.CasePayloadFields[0]: float64(3)}}
	for timing, want := range override.ScoresByBudgetBlockTiming {
		evidence := map[string]interface{}{override.When.RequiredEvidenceFields[0]: timing}
		if got := scoreCaseWithEvidence(budgetCase, "block", evidence); got != want {
			t.Errorf("budget timing %q score = %q, public contract wants %q", timing, got, want)
		}
	}
}

// TestPublicResultStatesMatchEmitter binds the published state vocabulary to
// the states this runner actually writes.
//
// Every row carries evidence.result_state, added by evidenceWithResultState.
// Keep the published vocabulary tied to the emitter so an outside runner can
// implement the closed v5 result-state contract without guessing.
func TestPublicResultStatesMatchEmitter(t *testing.T) {
	contract := loadPublicResultStates(t)

	emitted := map[string]bool{
		string(ResultStateObserved):            true,
		string(ResultStateUnreachable):         true,
		string(ResultStateAdapterError):        true,
		string(ResultStateDeliveryUnavailable): true,
		string(ResultStateVerdictUnobservable): true,
		string(ResultStateInvalidVerdict):      true,
	}

	if len(contract.EvidenceResultStates) == 0 {
		t.Fatal("public contract publishes no evidence_result_states")
	}
	for name, meaning := range contract.EvidenceResultStates {
		if !emitted[name] {
			t.Errorf("public contract publishes result state %q that this runner never emits", name)
		}
		if strings.TrimSpace(meaning) == "" {
			t.Errorf("public contract publishes result state %q with no stated meaning", name)
		}
	}
	for name := range emitted {
		if _, ok := contract.EvidenceResultStates[name]; !ok {
			t.Errorf("this runner emits result state %q that the public contract does not publish", name)
		}
	}
}
