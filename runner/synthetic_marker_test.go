package main

import "testing"

// A synthetic marker that is present but not the boolean true must still make a
// run incomplete. Requiring the boolean would let a malformed marker be the
// reason a run reads as measured and publishes, inverting the gate. An explicit
// boolean false stays an honest negative.
func TestHasSyntheticEvidenceFailsClosedOnMalformedMarkers(t *testing.T) {
	tests := []struct {
		name   string
		marker interface{}
		want   bool
	}{
		{"boolean true", true, true},
		{"boolean false is an honest negative", false, false},
		{"string marker", "calibration", true},
		{"string true", "true", true},
		{"string false is not a boolean negative", "false", true},
		{"numeric marker", 1, true},
		{"zero is still a present claim", 0, true},
		{"null marker", nil, true},
		{"object marker", map[string]interface{}{"adapter": "dryrun"}, true},
		{"array marker", []interface{}{"dryrun"}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			results := []CaseResult{{
				CaseID:   "case",
				Evidence: map[string]interface{}{"synthetic": tc.marker},
			}}
			if got := hasSyntheticEvidence(results); got != tc.want {
				t.Fatalf("marker %#v: got %v, want %v", tc.marker, got, tc.want)
			}
		})
	}
}

func TestHasSyntheticEvidenceIgnoresAbsentMarker(t *testing.T) {
	results := []CaseResult{
		{CaseID: "a", Evidence: map[string]interface{}{"scanner": "dlp"}},
		{CaseID: "b", Evidence: nil},
	}
	if hasSyntheticEvidence(results) {
		t.Fatal("absent marker was treated as a synthetic claim")
	}
}

// A malformed marker on any row is enough, so it cannot be hidden behind
// well-formed rows.
func TestHasSyntheticEvidenceScansEveryRow(t *testing.T) {
	results := []CaseResult{
		{CaseID: "a", Evidence: map[string]interface{}{"scanner": "dlp"}},
		{CaseID: "b", Evidence: map[string]interface{}{"synthetic": false}},
		{CaseID: "c", Evidence: map[string]interface{}{"synthetic": "calibration"}},
	}
	if !hasSyntheticEvidence(results) {
		t.Fatal("a malformed marker on a later row was missed")
	}
}
