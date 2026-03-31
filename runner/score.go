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

// computeScores calculates the four scoring dimensions from applicable case results.
func computeScores(results []CaseResult) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int
	// In v1 dry-run mode, detection and evidence are 0.0 because there's
	// no real tool output to inspect.
	// correctly_blocked_malicious = malicious cases where actual == block
	// classified_correctly = 0 (no detection info in dry run)
	// evidence_emitted = 0 (no evidence in dry run)

	for _, r := range results {
		switch r.ExpectedVerdict {
		case "block":
			totalMalicious++
			if r.ActualVerdict == "block" {
				blockedMalicious++
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
		// Detection: classified_correctly / correctly_blocked_malicious
		// In dry-run mode, no classification info, so 0.0
		zero := 0.0
		s.Detection = &zero
		// Evidence: evidence_emitted / correctly_blocked_malicious
		// In dry-run mode, no evidence emitted, so 0.0
		s.Evidence = &zero
	}

	return s
}

// computeFullCorpusScores computes scores with all cases in the denominator.
// Non-applicable malicious cases count as "not blocked" (failures).
func computeFullCorpusScores(applicableResults []CaseResult, allCases []Case) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int

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
		zero := 0.0
		s.Detection = &zero
		s.Evidence = &zero
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
