// Package adapter defines the tool adapter interface and built-in adapters.
package adapter

import "time"

// Case holds the fields an adapter needs to produce a verdict.
type Case struct {
	ID              string
	ExpectedVerdict string
	Transport       string
	InputType       string
	Requires        []string
	Payload         map[string]interface{}
}

// DeliveryTuple records a transport and semantic surface an adapter can drive.
// It is declarative only until the result-state implementation consumes it.
// The declaration must never change a case's score by itself.
type DeliveryTuple struct {
	WireTransport   string
	SemanticSurface string
	Lifecycle       string
}

// Result is what an adapter returns after running a case.
type Result struct {
	Verdict  string
	Evidence map[string]interface{}
	Err      error
}

// Adapter runs a single benchmark case against a tool and returns the verdict.
//
// DeliveryPlanner is deliberately NOT embedded here. Embedding it would break
// every external adapter that implements only Run, at no version boundary, so
// the runner type-asserts for the optional capability instead.
type Adapter interface {
	Run(c Case, timeout time.Duration) Result
}

// TupleForCase derives the tuple vocabulary shared by the built-in adapters.
func TupleForCase(c Case) DeliveryTuple {
	lifecycle := "single_request"
	if c.Transport == "mcp_stdio" || c.Transport == "mcp_http" {
		lifecycle = "mcp_session"
	}
	return DeliveryTuple{WireTransport: c.Transport, SemanticSurface: c.InputType, Lifecycle: lifecycle}
}

// DeliveryPlanner is the optional capability of declaring which exact routes an
// adapter can drive. It is a query surface only: an adapter states what it can
// deliver, and callers ask. Nothing here decides a score.
//
// That separation is the point. Letting a declaration drive scoring meant an
// adapter that simply omitted a hard route shrank its own denominator, and a
// route it could not drive charged the target for a gap in the benchmark's own
// integration. The result-state implementation owns that transition, where an
// absent route becomes an explicit state that marks the run non-scoreable
// rather than quietly improving it.
type DeliveryPlanner interface {
	DeliveryTuples() []DeliveryTuple
}

// SupportsTuple reports whether the adapter declares an exact route for the
// case. It answers a question and changes nothing.
func SupportsTuple(a interface{}, c Case) (DeliveryTuple, bool) {
	planner, ok := a.(DeliveryPlanner)
	if !ok {
		return DeliveryTuple{}, false
	}
	want := TupleForCase(c)
	for _, declared := range planner.DeliveryTuples() {
		if declared == want {
			return declared, true
		}
	}
	return DeliveryTuple{}, false
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
