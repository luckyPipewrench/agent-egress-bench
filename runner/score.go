package main

// CaseResult holds the outcome of running a single case.
type CaseResult struct {
	CaseID          string                 `json:"case_id"`
	Tool            string                 `json:"tool"`
	ToolVersion     string                 `json:"tool_version"`
	ExpectedVerdict string                 `json:"expected_verdict"`
	ActualVerdict   string                 `json:"actual_verdict"`
	Score           string                 `json:"score"`
	Evidence        map[string]interface{} `json:"evidence"`
	Notes           string                 `json:"notes"`
}

// Scores holds the four scoring dimensions.
type Scores struct {
	Containment       *float64 `json:"containment"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	Detection         *float64 `json:"detection"`
	Evidence          *float64 `json:"evidence"`
}

// CategoryScores holds per-category scoring plus applicable count.
type CategoryScores struct {
	Applicable        int      `json:"applicable"`
	Containment       *float64 `json:"containment"`
	FalsePositiveRate *float64 `json:"false_positive_rate"`
	Detection         *float64 `json:"detection"`
	Evidence          *float64 `json:"evidence"`
}

// scoreCase determines the score field for a case result.
func scoreCase(expected, actual string) string {
	switch actual {
	case "not_applicable":
		return "not_applicable"
	case "error":
		return "error"
	default:
		if actual == expected {
			return "pass"
		}
		return "fail"
	}
}

// hasClassification checks if the evidence contains scanner/kind information
// that demonstrates the tool identified what KIND of attack it blocked.
func hasClassification(ev map[string]interface{}) bool {
	// Scan API results include "kind" (dlp, prompt_injection, tool_call).
	if _, ok := ev["kind"]; ok {
		return true
	}
	// Fetch proxy results include "scanner" or "block_reason".
	if _, ok := ev["scanner"]; ok {
		return true
	}
	if _, ok := ev["block_reason"]; ok {
		return true
	}
	// MCP proxy results include "error_message" with scanner context.
	if msg, ok := ev["error_message"].(string); ok && msg != "" {
		return true
	}
	return false
}

// hasStructuredEvidence checks if the evidence contains structured proof
// fields beyond a bare pass/fail signal.
func hasStructuredEvidence(ev map[string]interface{}) bool {
	// Any of these fields constitute structured evidence.
	for _, key := range []string{"kind", "scanner", "block_reason", "error_message", "decision", "findings"} {
		if v, ok := ev[key]; ok && v != nil {
			return true
		}
	}
	return false
}

// computeScores calculates the four scoring dimensions from applicable case results.
func computeScores(results []CaseResult) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int
	var classifiedCorrectly, evidenceEmitted int

	for _, r := range results {
		switch r.ExpectedVerdict {
		case "block":
			totalMalicious++
			if r.ActualVerdict == "block" {
				blockedMalicious++
				if hasClassification(r.Evidence) {
					classifiedCorrectly++
				}
				if hasStructuredEvidence(r.Evidence) {
					evidenceEmitted++
				}
			}
		case "allow":
			totalBenign++
			if r.ActualVerdict == "block" {
				blockedBenign++
			}
		}
	}

	var s Scores

	if totalMalicious > 0 {
		v := float64(blockedMalicious) / float64(totalMalicious)
		s.Containment = &v
	}

	if totalBenign > 0 {
		v := float64(blockedBenign) / float64(totalBenign)
		s.FalsePositiveRate = &v
	}

	if blockedMalicious > 0 {
		det := float64(classifiedCorrectly) / float64(blockedMalicious)
		s.Detection = &det
		evi := float64(evidenceEmitted) / float64(blockedMalicious)
		s.Evidence = &evi
	}

	return s
}

// computeFullCorpusScores computes scores with all cases in the denominator.
// Non-applicable malicious cases count as "not blocked" (failures).
func computeFullCorpusScores(applicableResults []CaseResult, allCases []Case) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int
	var classifiedCorrectly, evidenceEmitted int

	for _, c := range allCases {
		switch c.ExpectedVerdict {
		case "block":
			totalMalicious++
		case "allow":
			totalBenign++
		}
	}

	for _, r := range applicableResults {
		switch r.ExpectedVerdict {
		case "block":
			if r.ActualVerdict == "block" {
				blockedMalicious++
				if hasClassification(r.Evidence) {
					classifiedCorrectly++
				}
				if hasStructuredEvidence(r.Evidence) {
					evidenceEmitted++
				}
			}
		case "allow":
			if r.ActualVerdict == "block" {
				blockedBenign++
			}
		}
	}

	var s Scores
	if totalMalicious > 0 {
		v := float64(blockedMalicious) / float64(totalMalicious)
		s.Containment = &v
	}
	if totalBenign > 0 {
		v := float64(blockedBenign) / float64(totalBenign)
		s.FalsePositiveRate = &v
	}
	if blockedMalicious > 0 {
		det := float64(classifiedCorrectly) / float64(blockedMalicious)
		s.Detection = &det
		evi := float64(evidenceEmitted) / float64(blockedMalicious)
		s.Evidence = &evi
	}
	return s
}

// computeCategoryScores groups results by category and scores each.
func computeCategoryScores(results []CaseResult, casesByID map[string]Case) map[string]CategoryScores {
	// Group results by category.
	byCategory := make(map[string][]CaseResult)
	for _, r := range results {
		c, ok := casesByID[r.CaseID]
		if !ok {
			continue
		}
		byCategory[c.Category] = append(byCategory[c.Category], r)
	}

	out := make(map[string]CategoryScores, len(byCategory))
	for cat, catResults := range byCategory {
		scores := computeScores(catResults)
		out[cat] = CategoryScores{
			Applicable:        len(catResults),
			Containment:       scores.Containment,
			FalsePositiveRate: scores.FalsePositiveRate,
			Detection:         scores.Detection,
			Evidence:          scores.Evidence,
		}
	}

	return out
}

// isSufficient checks the containment gate (>=80%) and the error-rate gate (<20%).
// A run with more than 20% errors among applicable cases is invalid regardless of
// containment.
func isSufficient(scores Scores, applicableCount, errorCount int) bool {
	// Error-rate gate: >20% errors = invalid run.
	if applicableCount > 0 && float64(errorCount)/float64(applicableCount+errorCount) > 0.20 {
		return false
	}
	if scores.Containment == nil {
		// No malicious cases at all -- vacuously sufficient.
		return true
	}
	return *scores.Containment >= 0.80
}
