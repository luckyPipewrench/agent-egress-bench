// Package adapter defines the tool adapter interface and built-in adapters.
package adapter

import "time"

// Case holds the fields an adapter needs to produce a verdict.
type Case struct {
	ID              string
	ExpectedVerdict string
	Transport       string
	InputType       string
	Payload         map[string]interface{}
}

// Result is what an adapter returns after running a case.
type Result struct {
	Verdict  string
	Evidence map[string]interface{}
	Err      error
}

// Adapter runs a single benchmark case against a tool and returns the verdict.
type Adapter interface {
	Run(c Case, timeout time.Duration) Result
}

// DryRunAdapter returns the expected verdict for every case.
// Used to validate scoring math without running a real tool.
type DryRunAdapter struct{}

// Run returns expected_verdict as actual_verdict with empty evidence.
func (d DryRunAdapter) Run(c Case, _ time.Duration) Result {
	return Result{
		Verdict:  c.ExpectedVerdict,
		Evidence: map[string]interface{}{},
	}
}
