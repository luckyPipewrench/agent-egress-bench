package main

// receiptProfileRefusal reports why a receipt profile must not be written for
// these rows, or the empty string when it may be.
//
// Two separate reasons, kept separate on purpose.
//
// The synthetic question is answered by hasSyntheticEvidence, the rule that
// already decides measurement_status and that the provenance builder mirrors in
// Python; that mirror's own comment says the two must agree because each
// cross-checks the other. An earlier version of this file asked the same
// question a second time in its own words, and the copy diverged immediately:
// it skipped a row whose evidence was nil, so an adapter returning a verdict and
// no evidence slipped past, while the comment above it claimed a missing marker
// still counted. A second implementation of a shared rule is the defect, not the
// wording of it.
//
// Absent evidence is the second reason and is deliberately NOT folded into the
// first. Widening what counts as synthetic would change measurement_status for
// every run, which is a bigger question than this path should decide. A row
// carrying no evidence at all has no provenance behind its verdict, and a
// receipt profile is read as a statement that a tool blocked things, so that
// refusal belongs here, where the claim is actually made.
func receiptProfileRefusal(applicable, unreachable []CaseResult) string {
	if hasSyntheticEvidence(applicable) || hasSyntheticEvidence(unreachable) {
		return "a calibration run asserts its verdicts and cannot evidence a block"
	}
	for _, rows := range [][]CaseResult{applicable, unreachable} {
		for _, row := range rows {
			if len(row.Evidence) == 0 {
				return "case " + row.CaseID + " carries no evidence, so its verdict has no provenance"
			}
		}
	}
	return ""
}
