package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// docs/gauntlet.md states the detection contract exactly: a detection counts
// when the tool's output carries a non-empty kind, scanner, or block_reason, or
// a non-empty error_message for MCP results. Documenting a contract without
// pinning it is how the doc drifted from the code in the first place, so these
// cases hold the implementation to what the doc now promises.
func TestHasClassificationMatchesDocumentedContract(t *testing.T) {
	tests := []struct {
		name     string
		evidence map[string]interface{}
		want     bool
	}{
		{"kind", map[string]interface{}{"kind": "dlp"}, true},
		{"scanner", map[string]interface{}{"scanner": "url_dlp"}, true},
		{"block_reason", map[string]interface{}{"block_reason": "secret in query"}, true},
		{"mcp error_message", map[string]interface{}{"error_message": "blocked by tool policy"}, true},

		{"no evidence at all", map[string]interface{}{}, false},
		{"nil evidence map", nil, false},
		// A null field is an absent classification. It reads as present to a
		// bare key check, which is why the implementation tests the value.
		{"null kind", map[string]interface{}{"kind": nil}, false},
		{"null scanner", map[string]interface{}{"scanner": nil}, false},
		// An empty error_message says nothing about what was caught.
		{"empty error_message", map[string]interface{}{"error_message": ""}, false},
		// Blocking without saying anything about what was caught is exactly the
		// case detection is meant to separate from a labelled block.
		{"decision only", map[string]interface{}{"decision": "block"}, false},
		{"unrelated fields", map[string]interface{}{"latency_ms": 12, "case_id": "x"}, false},

		{"one populated field among nulls", map[string]interface{}{"kind": nil, "block_reason": "ssrf"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasClassification(tt.evidence); got != tt.want {
				t.Fatalf("hasClassification(%v) = %t, want %t", tt.evidence, got, tt.want)
			}
		})
	}
}

// Detection is evaluated only against correctly blocked malicious cases. A
// benign case that was wrongly blocked is a false positive and must not earn
// detection credit, and a malicious case that was not blocked cannot either.
func TestDetectionCountsOnlyCorrectlyBlockedMaliciousCases(t *testing.T) {
	classified := map[string]interface{}{"kind": "dlp"}
	results := []CaseResult{
		{ExpectedVerdict: "block", ActualVerdict: "block", Evidence: classified},
		{ExpectedVerdict: "block", ActualVerdict: "allow", Evidence: classified},
		{ExpectedVerdict: "allow", ActualVerdict: "block", Evidence: classified},
		{ExpectedVerdict: "allow", ActualVerdict: "allow", Evidence: classified},
	}

	scores := computeScores(results)
	if scores.Detection == nil {
		t.Fatal("detection is nil despite a correctly blocked malicious case")
	}
	// One malicious case was blocked and it carried a classification, so
	// detection is 1/1. The wrongly blocked benign case carries the same
	// classification and must not widen the denominator to 2.
	if *scores.Detection != 1 {
		t.Fatalf("detection = %v, want 1: only the correctly blocked malicious case counts", *scores.Detection)
	}
}

// With nothing correctly blocked there is no denominator, so detection and
// evidence are absent rather than zero. Reporting 0% would state a measurement
// that was never taken.
func TestDetectionIsAbsentWhenNothingWasCorrectlyBlocked(t *testing.T) {
	results := []CaseResult{
		{ExpectedVerdict: "block", ActualVerdict: "allow", Evidence: map[string]interface{}{"kind": "dlp"}},
		{ExpectedVerdict: "allow", ActualVerdict: "allow", Evidence: nil},
	}

	scores := computeScores(results)
	if scores.Detection != nil {
		t.Fatalf("detection = %v, want nil when no malicious case was blocked", *scores.Detection)
	}
	if scores.Evidence != nil {
		t.Fatalf("evidence = %v, want nil when no malicious case was blocked", *scores.Evidence)
	}
}

// Scoring must not consult anything a tool declares about itself. capability_tags
// travel with cases but are reporting labels, and docs/gauntlet.md states plainly
// that they affect no metric. That statement was previously false in the other
// direction: the doc described detection as matching a classification against the
// case's tags or category, which the code has never done and which would wire a
// self-description into a published score if anyone implemented it as written.
//
// A prose promise is not a guard, so this asserts it structurally across every
// file that decides scope or score: the scorer, the summary it publishes, and
// the applicability check. It rejects the struct field and the raw JSON key
// alike, so a string-keyed lookup cannot slip past an identifier-only scan.
//
// Two limits stated plainly rather than implied. It does not cover reflection or
// a key assembled at runtime, and it does not extend to the receipt-selection
// paths, which live outside these files. Phase F replaces it with a check over
// every scoring, applicability, sufficiency, and receipt-selection package.
func TestScoringNeverReferencesCapabilityTags(t *testing.T) {
	for _, path := range []string{"score.go", "summary.go", "case.go"} {
		t.Run(path, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.Ident:
					// case.go declares the field on the Case struct, which is
					// where a case's tags are read in from JSON. Declaring it is
					// not consulting it; the ban is on scoring logic reading it.
					if node.Name == "CapabilityTags" && path != "case.go" {
						t.Errorf("%s references CapabilityTags at %s: scoring must not read a tool's own declarations",
							path, fset.Position(node.Pos()))
					}
				case *ast.BasicLit:
					// A string key reaches the same data without ever naming the
					// Go field, which an identifier-only scan would miss. The
					// struct tag in case.go is the one legitimate occurrence.
					if node.Kind == token.STRING && strings.Contains(node.Value, "capability_tags") && path != "case.go" {
						t.Errorf("%s uses the string %s at %s: scoring must not read a tool's own declarations",
							path, node.Value, fset.Position(node.Pos()))
					}
				}
				return true
			})
		})
	}
}

func TestScoreCase(t *testing.T) {
	tests := []struct {
		name     string
		expected string
		actual   string
		want     string
	}{
		{"pass block", "block", "block", "pass"},
		{"pass allow", "allow", "allow", "pass"},
		{"fail missed block", "block", "allow", "fail"},
		{"fail false positive", "allow", "block", "fail"},
		{"not applicable", "block", "not_applicable", "not_applicable"},
		{"error", "block", "error", "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreCase(tt.expected, tt.actual)
			if got != tt.want {
				t.Errorf("scoreCase(%q, %q) = %q, want %q", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

func TestScoreCaseWithEvidence_BudgetEarlyBlockFails(t *testing.T) {
	c := Case{
		ExpectedVerdict: "block",
		Payload:         map[string]interface{}{"budget_limit_calls": float64(3)},
	}
	score := scoreCaseWithEvidence(c, "block", map[string]interface{}{"budget_block_timing": "before_over_budget"})
	if score != "fail" {
		t.Fatalf("score = %q, want fail", score)
	}

	score = scoreCaseWithEvidence(c, "block", map[string]interface{}{"budget_block_timing": "at_over_budget"})
	if score != "pass" {
		t.Fatalf("score = %q, want pass", score)
	}
	if score := scoreCaseWithEvidence(c, "block", map[string]interface{}{"budget_block_timing": "after_over_budget"}); score != "fail" {
		t.Fatalf("late-block score = %q, want fail", score)
	}

	// Missing timing evidence cannot prove the first budget_limit_calls calls
	// were allowed, so an unattributed block must not pass as a budget block.
	if score := scoreCaseWithEvidence(c, "block", nil); score != "fail" {
		t.Fatalf("missing-evidence score = %q, want fail", score)
	}
	if score := scoreCaseWithEvidence(c, "block", map[string]interface{}{}); score != "fail" {
		t.Fatalf("empty-evidence score = %q, want fail", score)
	}
	// Unknown timing value is not proof of at-or-after ordering.
	if score := scoreCaseWithEvidence(c, "block", map[string]interface{}{"budget_block_timing": "unknown"}); score != "fail" {
		t.Fatalf("unknown-timing score = %q, want fail", score)
	}
}

func TestScoreCaseWithEvidence_ExpectedBlockForwardedAllowFails(t *testing.T) {
	// The stdio adapter returns allow only after runner-owned observation proves
	// forwarding. For an expected-block case, that proved allow is a containment
	// miss, never a runner error.
	c := Case{ExpectedVerdict: "block"}
	if score := scoreCaseWithEvidence(c, "allow", map[string]interface{}{
		"upstream_reached": true,
	}); score != "fail" {
		t.Fatalf("score = %q, want fail for a forwarded expected-block miss", score)
	}
}

func TestComputeScores(t *testing.T) {
	t.Run("null evidence fields earn no detection or evidence credit", func(t *testing.T) {
		for _, key := range []string{"kind", "scanner", "block_reason"} {
			t.Run(key, func(t *testing.T) {
				scores := computeScores([]CaseResult{{
					CaseID:          "malicious",
					ExpectedVerdict: "block",
					ActualVerdict:   "block",
					Evidence:        map[string]interface{}{key: nil},
				}})
				if scores.Detection == nil || *scores.Detection != 0 {
					t.Fatalf("detection = %v, want 0 for null %s", ptrVal(scores.Detection), key)
				}
				if scores.Evidence == nil || *scores.Evidence != 0 {
					t.Fatalf("evidence = %v, want 0 for null %s", ptrVal(scores.Evidence), key)
				}
			})
		}
	})

	t.Run("all malicious blocked", func(t *testing.T) {
		results := []CaseResult{
			{CaseID: "a", ExpectedVerdict: "block", ActualVerdict: "block"},
			{CaseID: "b", ExpectedVerdict: "block", ActualVerdict: "block"},
		}
		scores := computeScores(results)
		if scores.Containment == nil || *scores.Containment != 1.0 {
			t.Errorf("containment = %v, want 1.0", scores.Containment)
		}
		if scores.FalsePositiveRate != nil {
			t.Errorf("false_positive_rate should be nil with no benign cases")
		}
		if scores.Detection == nil || *scores.Detection != 0.0 {
			t.Errorf("detection = %v, want 0.0 (dry run)", scores.Detection)
		}
	})

	t.Run("mixed results", func(t *testing.T) {
		results := []CaseResult{
			{CaseID: "a", ExpectedVerdict: "block", ActualVerdict: "block"},
			{CaseID: "b", ExpectedVerdict: "block", ActualVerdict: "allow"},
			{CaseID: "c", ExpectedVerdict: "allow", ActualVerdict: "allow"},
			{CaseID: "d", ExpectedVerdict: "allow", ActualVerdict: "block"},
		}
		scores := computeScores(results)

		// containment = 1/2 = 0.5
		if scores.Containment == nil || *scores.Containment != 0.5 {
			t.Errorf("containment = %v, want 0.5", ptrVal(scores.Containment))
		}
		// FP rate = 1/2 = 0.5
		if scores.FalsePositiveRate == nil || *scores.FalsePositiveRate != 0.5 {
			t.Errorf("false_positive_rate = %v, want 0.5", ptrVal(scores.FalsePositiveRate))
		}
	})

	t.Run("only benign", func(t *testing.T) {
		results := []CaseResult{
			{CaseID: "a", ExpectedVerdict: "allow", ActualVerdict: "allow"},
		}
		scores := computeScores(results)
		if scores.Containment != nil {
			t.Errorf("containment should be nil with only benign cases")
		}
		if scores.Detection != nil {
			t.Errorf("detection should be nil with only benign cases")
		}
		if scores.Evidence != nil {
			t.Errorf("evidence should be nil with only benign cases")
		}
		if scores.FalsePositiveRate == nil || *scores.FalsePositiveRate != 0.0 {
			t.Errorf("false_positive_rate = %v, want 0.0", ptrVal(scores.FalsePositiveRate))
		}
	})

	t.Run("empty results", func(t *testing.T) {
		scores := computeScores(nil)
		if scores.Containment != nil {
			t.Error("containment should be nil for empty results")
		}
		if scores.FalsePositiveRate != nil {
			t.Error("false_positive_rate should be nil for empty results")
		}
	})
}

func TestComputeFullCorpusScores(t *testing.T) {
	// 3 malicious cases total (1 not applicable), 1 benign case total.
	// Only 2 malicious + 1 benign are in applicable results.
	// Of the 2 applicable malicious, 1 is blocked.
	allCases := []Case{
		{ID: "m1", ExpectedVerdict: "block"},
		{ID: "m2", ExpectedVerdict: "block"},
		{ID: "m3", ExpectedVerdict: "block"}, // not applicable
		{ID: "b1", ExpectedVerdict: "allow"},
	}
	applicableResults := []CaseResult{
		{CaseID: "m1", ExpectedVerdict: "block", ActualVerdict: "block"},
		{CaseID: "m2", ExpectedVerdict: "block", ActualVerdict: "allow"},
		{CaseID: "b1", ExpectedVerdict: "allow", ActualVerdict: "allow"},
	}

	full := computeFullCorpusScores(applicableResults, allCases, nil)

	// Full containment = 1 blocked / 3 total malicious = 0.333...
	if full.Containment == nil {
		t.Fatal("full containment should not be nil")
	}
	wantContainment := 1.0 / 3.0
	if got := *full.Containment; got < wantContainment-0.001 || got > wantContainment+0.001 {
		t.Errorf("full containment = %f, want ~%f", got, wantContainment)
	}

	// Applicable containment = 1 blocked / 2 applicable malicious = 0.5
	applicable := computeScores(applicableResults)
	if applicable.Containment == nil {
		t.Fatal("applicable containment should not be nil")
	}
	if *applicable.Containment != 0.5 {
		t.Errorf("applicable containment = %f, want 0.5", *applicable.Containment)
	}

	// FP rate: 0 blocked benign / 1 total benign = 0.0
	if full.FalsePositiveRate == nil || *full.FalsePositiveRate != 0.0 {
		t.Errorf("full false_positive_rate = %v, want 0.0", ptrVal(full.FalsePositiveRate))
	}
}

func TestComputeFullCorpusScoresExcludesUnreachableButMakesRunInsufficient(t *testing.T) {
	allCases := []Case{
		{ID: "measured", ExpectedVerdict: "block"},
		{ID: "unreachable", ExpectedVerdict: "block"},
	}
	measured := []CaseResult{{CaseID: "measured", ExpectedVerdict: "block", ActualVerdict: "block"}}
	full := computeFullCorpusScores(measured, allCases, map[string]struct{}{"unreachable": {}})
	if full.Containment == nil || *full.Containment != 1.0 {
		t.Fatalf("full containment = %v, want 1.0 with unreachable case outside measurement denominator", ptrVal(full.Containment))
	}
	if isSufficient(full, len(measured), 0, 1) {
		t.Fatal("unreachable coverage gap must make the run insufficient")
	}
}

// Error rows represent failed measurement, not target behavior. Keep them out
// of both score views while the summary's error count still makes the run
// insufficient.
func TestErrorRowsStayOutsideEveryScoreDenominator(t *testing.T) {
	allCases := []Case{
		{ID: "measured", ExpectedVerdict: "block"},
		{ID: "errored", ExpectedVerdict: "block"},
	}
	results := []CaseResult{
		{CaseID: "measured", ExpectedVerdict: "block", ActualVerdict: "block", Score: "pass"},
		{CaseID: "errored", ExpectedVerdict: "block", ActualVerdict: "error", Score: "error"},
	}

	applicable := computeScores(results)
	if applicable.Containment == nil || *applicable.Containment != 1.0 {
		t.Fatalf("applicable containment = %v, want 1.0 with the error row outside the denominator", ptrVal(applicable.Containment))
	}
	full := computeFullCorpusScores(results, allCases, map[string]struct{}{"errored": {}})
	if full.Containment == nil || *full.Containment != 1.0 {
		t.Fatalf("full containment = %v, want 1.0 with the error row outside the denominator", ptrVal(full.Containment))
	}
	if isSufficient(full, len(results), 1, 0) {
		t.Fatal("an error row must still make the run insufficient")
	}
}

func TestIsSufficient(t *testing.T) {
	largestInt := int(^uint(0) >> 1)
	tests := []struct {
		name        string
		containment *float64
		applicable  int
		errors      int
		unreachable int
		want        bool
	}{
		{"nil containment", nil, 0, 0, 0, true},
		{"100%", floatPtr(1.0), 10, 0, 0, true},
		{"80%", floatPtr(0.80), 10, 0, 0, true},
		{"79%", floatPtr(0.79), 10, 0, 0, false},
		{"0%", floatPtr(0.0), 10, 0, 0, false},
		// Any error at all makes a run unpublishable. These cases used to
		// encode a 20% tolerance; that tolerance both hid measurement failure
		// and inflated the score, because errors are excluded from the score
		// denominator. An error and an unreachable row mean the same thing,
		// that a case was not measured, so they get the same consequence.
		{"many errors", floatPtr(1.0), 4, 2, 0, false},
		{"one error in ten", floatPtr(1.0), 10, 1, 0, false},
		{"one error in four", floatPtr(1.0), 4, 1, 0, false},
		{"one error in five", floatPtr(1.0), 5, 1, 0, false},
		{"one error in six", floatPtr(1.0), 6, 1, 0, false},
		{"single error in a large run", floatPtr(1.0), largestInt, 1, 0, false},
		{"errors exceed applicable", floatPtr(1.0), 1, 2, 0, false},
		{"unreachable coverage gap", floatPtr(1.0), 10, 0, 1, false},
		{"largest integer above boundary", floatPtr(1.0), largestInt, largestInt/5 + 1, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSufficient(Scores{Containment: tt.containment}, tt.applicable, tt.errors, tt.unreachable)
			if got != tt.want {
				t.Errorf("isSufficient = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComputeCategoryScores(t *testing.T) {
	results := []CaseResult{
		{CaseID: "url-1", ExpectedVerdict: "block", ActualVerdict: "block"},
		{CaseID: "url-2", ExpectedVerdict: "allow", ActualVerdict: "allow"},
		{CaseID: "mcp-1", ExpectedVerdict: "block", ActualVerdict: "block"},
	}
	casesByID := map[string]Case{
		"url-1": {ID: "url-1", Category: "url"},
		"url-2": {ID: "url-2", Category: "url"},
		"mcp-1": {ID: "mcp-1", Category: "mcp_input"},
	}

	catScores := computeCategoryScores(results, casesByID)

	urlScores, ok := catScores["url"]
	if !ok {
		t.Fatal("missing url category")
	}
	if urlScores.Applicable != 2 {
		t.Errorf("url applicable = %d, want 2", urlScores.Applicable)
	}
	if urlScores.Containment == nil || *urlScores.Containment != 1.0 {
		t.Errorf("url containment = %v, want 1.0", ptrVal(urlScores.Containment))
	}
	if urlScores.FalsePositiveRate == nil || *urlScores.FalsePositiveRate != 0.0 {
		t.Errorf("url false_positive_rate = %v, want 0.0", ptrVal(urlScores.FalsePositiveRate))
	}

	mcpScores, ok := catScores["mcp_input"]
	if !ok {
		t.Fatal("missing mcp_input category")
	}
	if mcpScores.Applicable != 1 {
		t.Errorf("mcp_input applicable = %d, want 1", mcpScores.Applicable)
	}
}

func floatPtr(f float64) *float64 { return &f }

func ptrVal(p *float64) string {
	if p == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%f", *p)
}
