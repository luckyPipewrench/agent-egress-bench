package adapter

import "time"

// NullAdapter allows every case. Scores 0% containment.
// Used as a baseline to verify the test harness works before
// connecting a real tool.
type NullAdapter struct{}

// Run always returns "allow" with empty evidence.
func (n NullAdapter) Run(_ Case, _ time.Duration) Result {
	return Result{
		Verdict:  "allow",
		Evidence: map[string]interface{}{},
	}
}
