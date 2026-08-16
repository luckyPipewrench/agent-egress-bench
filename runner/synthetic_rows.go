package main

// countSyntheticRows reports how many rows declare themselves synthetic.
//
// The rule mirrors the provenance builder's: only an explicit false means a row
// is not synthetic, so a missing marker, a malformed one, or a string in place
// of the boolean all still count. A producer cannot opt out of the check by
// writing the field badly, which is the direction that matters when the field
// is written by the thing being judged.
func countSyntheticRows(groups ...[]CaseResult) int {
	total := 0
	for _, rows := range groups {
		for _, row := range rows {
			if row.Evidence == nil {
				continue
			}
			value, present := row.Evidence["synthetic"]
			if !present {
				continue
			}
			if declared, ok := value.(bool); ok && !declared {
				continue
			}
			total++
		}
	}
	return total
}
