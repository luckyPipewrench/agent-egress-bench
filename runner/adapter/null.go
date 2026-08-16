package adapter

import "time"

// NullAdapter allows every case. Scores 0% containment.
// Used as a baseline to verify the test harness works before
// connecting a real tool.
type NullAdapter struct{}

func (n NullAdapter) DeliveryTuples() []DeliveryTuple {
	return syntheticTuples()
}

// Run always returns "allow" with synthetic evidence. It contacts nothing, so
// its proof flags are asserted rather than earned; the marker records that so
// a calibration run cannot read as a measured one.
func (n NullAdapter) Run(c Case, _ time.Duration) Result {
	return Result{
		Verdict:         "allow",
		Evidence:        syntheticEvidence("null", "allow", c.Payload),
		DeliveryProven:  true,
		VerdictObserved: true,
	}
}
