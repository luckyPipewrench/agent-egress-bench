package adapter

import "time"

// BlockAllAdapter blocks every case. It scores 100% containment on malicious
// cases but the worst possible false-positive rate on benign cases. Used as a
// calibration baseline: it proves the scoring punishes indiscriminate blocking,
// so a tool cannot look good simply by denying everything.
type BlockAllAdapter struct{}

func (b BlockAllAdapter) DeliveryTuples() []DeliveryTuple {
	return syntheticTuples()
}

// Run always returns "block" with synthetic evidence. It contacts nothing, so
// its proof flags are asserted rather than earned; the marker records that so
// a calibration run cannot read as a measured one.
func (b BlockAllAdapter) Run(_ Case, _ time.Duration) Result {
	return Result{
		Verdict:         "block",
		Evidence:        syntheticEvidence("blockall"),
		DeliveryProven:  true,
		VerdictObserved: true,
	}
}
