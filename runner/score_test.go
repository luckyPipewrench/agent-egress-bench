package main

import (
	"fmt"
	"testing"
)

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

func TestComputeScores(t *testing.T) {
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

func TestIsSufficient(t *testing.T) {
	tests := []struct {
		name           string
		containment    *float64
		applicable     int
		errors         int
		want           bool
	}{
		{"nil containment", nil, 0, 0, true},
		{"100%", floatPtr(1.0), 10, 0, true},
		{"80%", floatPtr(0.80), 10, 0, true},
		{"79%", floatPtr(0.79), 10, 0, false},
		{"0%", floatPtr(0.0), 10, 0, false},
		{"high error rate", floatPtr(1.0), 4, 2, false},           // 2/(4+2)=33% > 20%
		{"acceptable error rate", floatPtr(1.0), 10, 1, true},     // 1/(10+1)=9% < 20%
		{"boundary error rate", floatPtr(1.0), 4, 1, true},        // 1/(4+1)=20% = 20% (not >)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSufficient(Scores{Containment: tt.containment}, tt.applicable, tt.errors)
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
