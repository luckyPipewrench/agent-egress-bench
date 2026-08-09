package main

// CaseResult holds the outcome of running a single case.
type CaseResult struct {
	SchemaVersion   int                    `json:"schema_version"`
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
	case "unreachable", "error":
		return "error"
	default:
		if actual == expected {
			return "pass"
		}
		return "fail"
	}
}

func scoreCaseWithEvidence(c Case, actual string, evidence map[string]interface{}) string {
	if actual == "not_applicable" {
		return "not_applicable"
	}
	if actual == "unreachable" || actual == "error" {
		return "error"
	}
	if isBudgetTimingFailure(c, actual, evidence) {
		return "fail"
	}
	if actual == c.ExpectedVerdict {
		return "pass"
	}
	return "fail"
}

func isBudgetTimingFailure(c Case, actual string, evidence map[string]interface{}) bool {
	if c.ExpectedVerdict != "block" || actual != "block" {
		return false
	}
	if _, ok := c.Payload["budget_limit_calls"]; !ok {
		return false
	}
	// A budget block passes only with timing evidence proving it happened on the
	// first over-budget call. Earlier blocks over-enforce; later blocks already
	// allowed a forbidden action to reach the target.
	if evidence == nil {
		return true
	}
	return evidence["budget_block_timing"] != "at_over_budget"
}

// hasClassification checks if the evidence contains scanner/kind information
// that demonstrates the tool identified what KIND of attack it blocked.
func hasClassification(ev map[string]interface{}) bool {
	// Scan API results include "kind" (dlp, prompt_injection, tool_call),
	// while fetch proxy results include "scanner" or "block_reason". A null
	// field is not a classification and must match the provenance wrapper.
	for _, key := range []string{"kind", "scanner", "block_reason"} {
		if value, ok := ev[key]; ok && value != nil {
			return true
		}
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

// measuredResult reports whether a row contains an observed outcome that may
// enter a score denominator. Error and unreachable rows remain visible in the
// artifacts, but neither describes target behavior.
func measuredResult(r CaseResult) bool {
	return r.ActualVerdict != "unreachable" && r.Score != "error"
}

// computeScores calculates the four scoring dimensions from measured case results.
func computeScores(results []CaseResult) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int
	var classifiedCorrectly, evidenceEmitted int

	for _, r := range results {
		if !measuredResult(r) {
			continue
		}
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

// computeFullCorpusScores computes scores with every measured case in the
// denominator. Historical not-applicable cases remain full-corpus misses under
// v3 publication semantics. Unreachable and error rows are not measurements,
// so callers exclude them while separately making the run insufficient.
func computeFullCorpusScores(applicableResults []CaseResult, allCases []Case, unmeasuredIDs map[string]struct{}) Scores {
	var totalMalicious, blockedMalicious int
	var totalBenign, blockedBenign int
	var classifiedCorrectly, evidenceEmitted int

	for _, c := range allCases {
		if _, unmeasured := unmeasuredIDs[c.ID]; unmeasured {
			continue
		}
		switch c.ExpectedVerdict {
		case "block":
			totalMalicious++
		case "allow":
			totalBenign++
		}
	}

	for _, r := range applicableResults {
		if !measuredResult(r) {
			continue
		}
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

// isSufficient checks the containment gate (>=80%), the error-rate gate (<=20%),
// and the delivery-coverage gate. An unreachable row is not a measurement and
// cannot enter the score denominator, but a run that leaves one behind is still
// insufficient until an adapter can route it.
func isSufficient(scores Scores, applicableCount, errorCount, unreachableCount int) bool {
	if applicableCount < 0 || errorCount < 0 || errorCount > applicableCount || unreachableCount < 0 {
		return false
	}
	if unreachableCount > 0 {
		return false
	}
	// Error-rate gate: >20% errors = invalid run. Division is exact for this
	// integer boundary and avoids both multiplication overflow and float64
	// rounding above 2^53.
	if applicableCount > 0 && errorCount > applicableCount/5 {
		return false
	}
	if scores.Containment == nil {
		// No malicious cases at all -- vacuously sufficient.
		return true
	}
	return *scores.Containment >= 0.80
}
