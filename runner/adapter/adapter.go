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

// DeliveryTuple is the exact input a runner adapter can exercise. WireTransport
// is the physical corpus transport; SemanticSurface is the event shape the
// target sees; Lifecycle names the interaction lifetime required to drive it.
// DeliveryProof and VerdictProof name the runner-owned evidence the adapter
// records for that route. They are an execution contract, not a product claim.
type DeliveryTuple struct {
	WireTransport   string
	SemanticSurface string
	Lifecycle       string
	DeliveryProof   string
	VerdictProof    string
}

// TupleForCase derives the tuple vocabulary used by every built-in adapter.
func TupleForCase(c Case) DeliveryTuple {
	lifecycle := "single_request"
	if c.Transport == "mcp_stdio" || c.Transport == "mcp_http" {
		lifecycle = "mcp_session"
	}
	return DeliveryTuple{WireTransport: c.Transport, SemanticSurface: c.InputType, Lifecycle: lifecycle}
}

// DeliveryPlanner exposes every exact route an adapter can drive.
type DeliveryPlanner interface {
	DeliveryTuples() []DeliveryTuple
}

// SupportsTuple returns the declared route including its proof contract.
func SupportsTuple(a DeliveryPlanner, c Case) (DeliveryTuple, bool) {
	want := TupleForCase(c)
	for _, route := range a.DeliveryTuples() {
		if route.WireTransport == want.WireTransport && route.SemanticSurface == want.SemanticSurface && route.Lifecycle == want.Lifecycle {
			return route, true
		}
	}
	return DeliveryTuple{}, false
}

// Result is what an adapter returns after running a case.
type Result struct {
	Verdict  string
	Evidence map[string]interface{}
	Err      error
}

// Adapter runs a single benchmark case against a tool and returns the verdict.
type Adapter interface {
	DeliveryPlanner
	Run(c Case, timeout time.Duration) Result
}

// DryRunAdapter returns the expected verdict for every case.
// Used to validate scoring math without running a real tool.
type DryRunAdapter struct{}

func (d DryRunAdapter) DeliveryTuples() []DeliveryTuple {
	return syntheticTuples("synthetic expected-verdict baseline")
}

// Run returns expected_verdict as actual_verdict with empty evidence.
func (d DryRunAdapter) Run(c Case, _ time.Duration) Result {
	return Result{
		Verdict:  c.ExpectedVerdict,
		Evidence: map[string]interface{}{},
	}
}

func syntheticTuples(proof string) []DeliveryTuple {
	transports := []string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}
	surfaces := []string{"url", "request_body", "header", "response_content", "mcp_tool_call", "mcp_tool_result", "mcp_tool_definition", "mcp_tool_sequence", "mcp_tool_sequence_temporal", "a2a_message", "a2a_agent_card", "websocket_frame"}
	routes := make([]DeliveryTuple, 0, len(transports)*len(surfaces))
	for _, transport := range transports {
		for _, surface := range surfaces {
			lifecycle := "single_request"
			if transport == "mcp_stdio" || transport == "mcp_http" {
				lifecycle = "mcp_session"
			}
			routes = append(routes, DeliveryTuple{transport, surface, lifecycle, proof, proof})
		}
	}
	return routes
}
