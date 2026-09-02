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

// DeliveryTuple records a transport and semantic surface an adapter can attempt.
// It authorizes only an attempt: the declaration alone never creates a verdict,
// not-applicable row, or score.
type DeliveryTuple struct {
	WireTransport   string
	SemanticSurface string
	Lifecycle       string
}

// Result is what an adapter returns after running a case.
type Result struct {
	Verdict  string
	Evidence map[string]interface{}
	// ReturnedContent is kept out of Evidence so raw bytes can only be retained
	// by an explicit runner-side opt-in. It must never be serialized directly.
	ReturnedContent []ReturnedContent `json:"-"`
	Err             error
	DeliveryProven  bool
	VerdictObserved bool
}

// ReturnedContent describes bytes received from a content-bearing response.
// Path is a closed protocol-path label; Metadata contains only bounded shape
// facts and never payload strings.
type ReturnedContent struct {
	Bytes     []byte
	MediaType string
	Path      string
	Metadata  map[string]interface{}
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

func (d DryRunAdapter) DeliveryTuples() []DeliveryTuple {
	return syntheticTuples()
}

// Run returns expected_verdict as actual_verdict with synthetic evidence.
//
// This adapter contacts nothing, so its proof flags are asserted rather than
// earned. They are set because the calibration adapters exist to exercise the
// scoring math end to end, which requires scoreable rows. The evidence marker
// is what keeps that honest: every row it produces says so, so a synthetic run
// can never be mistaken for a measured one by a reader or a downstream
// consumer.
func (d DryRunAdapter) Run(c Case, _ time.Duration) Result {
	return Result{
		Verdict:         c.ExpectedVerdict,
		Evidence:        syntheticEvidence("dryrun", c.ExpectedVerdict, c.Payload),
		DeliveryProven:  true,
		VerdictObserved: true,
	}
}

// syntheticEvidence marks a result produced without contacting any tool. A
// calibration adapter asserts delivery and observation it did not perform, so
// the row must carry that fact rather than presenting as a measurement.
// syntheticEvidence takes the verdict actually being claimed rather than the
// case's expected one, because the evidence a contract demands follows the
// claim. blockall claims a block on every case including the ones it was never
// going to match, so keying on the expectation would have left it emitting the
// same unsupported claim dryrun did.
func syntheticEvidence(adapterName string, verdict string, payload map[string]interface{}) map[string]interface{} {
	evidence := map[string]interface{}{
		"synthetic":         true,
		"synthetic_adapter": adapterName,
		"proof":             "asserted_by_calibration_adapter_not_observed",
	}
	// A denial-of-wallet case requires a target to say WHEN it blocked, because
	// blocking before the budget is spent disrupts legitimate work and blocking
	// after the over-budget call has already gone out is not containment. A
	// calibration row claiming the block without that field was rejected by the
	// contract, which was the contract working.
	//
	// The field is asserted, exactly like the delivery and observation above it,
	// and carries the same synthetic marker that keeps every row honest and
	// keeps the run unpublishable. Claiming the block while withholding one of
	// the three assertions it rests on was the arbitrary position, not the
	// principled one.
	if verdict == "block" {
		if _, overBudget := payload["over_budget_call_id"]; overBudget {
			evidence["budget_block_timing"] = "at_over_budget"
		}
	}
	return evidence
}

func syntheticTuples() []DeliveryTuple {
	transports := []string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}
	surfaces := []string{
		"url", "request_body", "header", "response_content",
		"mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "mcp_initialize_response", "mcp_tool_sequence", "mcp_tool_sequence_temporal",
		"a2a_message", "a2a_agent_card", "websocket_frame",
	}
	routes := make([]DeliveryTuple, 0, len(transports)*len(surfaces))
	for _, transport := range transports {
		for _, surface := range surfaces {
			lifecycle := "single_request"
			if transport == "mcp_stdio" || transport == "mcp_http" {
				lifecycle = "mcp_session"
			}
			routes = append(routes, DeliveryTuple{
				WireTransport: transport, SemanticSurface: surface, Lifecycle: lifecycle,
			})
		}
	}
	return routes
}
