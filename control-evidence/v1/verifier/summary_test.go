package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// v1SummaryState builds the state verifySummary needs, using a summary shaped the
// way the runner actually emits one. Nothing exercised verifySummary before this
// file, which is how a requirement for a field the runner had stopped producing
// survived: the only other v1 test covers registry binding, and the conformance
// vector that should have caught it carries no payload.
func v1SummaryState(t *testing.T) *verificationState {
	t.Helper()
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatalf("loadSchemas() error = %v", err)
	}

	// The real shipped profile, so this test tracks the active tool-profile schema
	// rather than a hand-built shape that could drift away from it.
	profileBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "pipelock", "tool-profile.json"))
	if err != nil {
		t.Fatalf("read example tool profile: %v", err)
	}
	if !validToolProfileSchema(profileBytes, schemas) {
		t.Fatal("the shipped example tool profile does not satisfy the active tool-profile schema")
	}
	var profile map[string]any
	if _, err := strictJSON(profileBytes, &profile); err != nil {
		t.Fatalf("parse example tool profile: %v", err)
	}

	var claims []string
	for _, claim := range profile["claims"].([]any) {
		claims = append(claims, claim.(string))
	}

	req := requirement{
		RequiredCaseIDs: []string{"case-block", "case-allow"},
		RequiredCaseExpectations: []caseExpectation{
			{CaseID: "case-block", ExpectedVerdict: "block"},
			{CaseID: "case-allow", ExpectedVerdict: "allow"},
		},
		ApprovedToolProfile: digestRef{SHA256: digestBytes(profileBytes)},
	}

	env := runEnvelope{}
	env.Tool.Product = textField(profile, "tool")
	env.Tool.Version = textField(profile, "tool_version")
	env.Runner.Version = textField(profile, "runner_version")
	env.Corpus.Version = "v2.0.0"
	env.Corpus.CorpusSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	env.Corpus.ScoringVersion = "1.0"

	rows := []outcomeRow{
		{CaseID: "case-block", TrialIndex: 1, ExpectedVerdict: "block", ActualVerdict: "block", Outcome: "pass"},
		{CaseID: "case-allow", TrialIndex: 1, ExpectedVerdict: "allow", ActualVerdict: "allow", Outcome: "pass"},
	}

	state := &verificationState{
		schemas:       schemas,
		files:         map[string][]byte{"profile.json": profileBytes},
		entriesByRole: map[string][]manifestEntry{"tool-profile": {{Path: "profile.json"}}},
		req:           &verifiedDSSE[requirement]{Payload: req},
		env:           &verifiedDSSE[runEnvelope]{Payload: env},
		outcomes:      outcomes{Rows: rows},
		summary: map[string]any{
			"tool_profile_sha256": digestBytes(profileBytes),
			"reported_claims":     toAny(claims),
			"case_count": map[string]any{
				"total":                  json.Number("2"),
				"applicable":             json.Number("2"),
				"not_applicable":         json.Number("0"),
				"errors":                 json.Number("0"),
				"not_applicable_reasons": map[string]any{},
			},
			"per_category":     map[string]any{"mcp_input": map[string]any{"applicable": json.Number("2")}},
			"tool":             env.Tool.Product,
			"tool_version":     env.Tool.Version,
			"runner_version":   env.Runner.Version,
			"corpus_version":   env.Corpus.Version,
			"corpus_sha256":    env.Corpus.CorpusSHA256,
			"scoring_version":  env.Corpus.ScoringVersion,
			"gauntlet_version": "1.0",
		},
	}
	return state
}

func toAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

// A summary carrying no "sufficient" field is the only kind the runner produces.
// Before the projection was removed this returned summary_score_projection_mismatch,
// so every real package failed verification.
func TestV1SummaryAcceptsARunnerShapedSummary(t *testing.T) {
	if result := v1SummaryState(t).verifySummary(); result != nil {
		t.Fatalf("verifySummary() = %+v, want success", result)
	}
}

// Sufficiency belongs to the buyer's signed requirement, so the verifier must not
// reintroduce an opinion about it. A summary that volunteers the field either way
// is still just a summary, and neither answer may change the verdict.
func TestV1SummaryIgnoresAVolunteeredSufficiencyClaim(t *testing.T) {
	for _, claimed := range []bool{true, false} {
		state := v1SummaryState(t)
		state.summary["sufficient"] = claimed
		if result := state.verifySummary(); result != nil {
			t.Fatalf("verifySummary() with sufficient=%v = %+v, want success", claimed, result)
		}
	}
}

// The count projections are what catch a tool publishing a summary its own outcome
// rows do not support. Removing the sufficiency grade must not have weakened them.
func TestV1SummaryStillRejectsCountProjectionLies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(state *verificationState)
		reason string
	}{
		{"inflated total", func(s *verificationState) { mapField(s.summary, "case_count")["total"] = json.Number("3") }, "summary_score_projection_mismatch"},
		{"understated applicable", func(s *verificationState) { mapField(s.summary, "case_count")["applicable"] = json.Number("1") }, "summary_score_projection_mismatch"},
		{"hidden errors", func(s *verificationState) { mapField(s.summary, "case_count")["errors"] = json.Number("1") }, "summary_error_count_mismatch"},
		{"invented not_applicable", func(s *verificationState) { mapField(s.summary, "case_count")["not_applicable"] = json.Number("1") }, "summary_not_applicable_count_mismatch"},
		{"invented not_applicable reason", func(s *verificationState) {
			mapField(s.summary, "case_count")["not_applicable_reasons"] = map[string]any{"unsupported": json.Number("1")}
		}, "summary_not_applicable_count_mismatch"},
		{"incorrect category applicable", func(s *verificationState) {
			mapField(mapField(s.summary, "per_category"), "mcp_input")["applicable"] = json.Number("1")
		}, "summary_score_projection_mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := v1SummaryState(t)
			tc.mutate(state)
			result := state.verifySummary()
			if result == nil || result.Reason != tc.reason {
				t.Fatalf("verifySummary() = %+v, want reason %q", result, tc.reason)
			}
		})
	}
}
