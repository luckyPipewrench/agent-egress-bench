package main

import (
	"fmt"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

// ResultState records whether a case became a measurement before scoring. It
// is intentionally separate from an adapter's declared DeliveryTuple: a tuple
// authorizes an attempt, while delivery proof plus verdict observation authorizes
// scoring.
type ResultState string

const (
	ResultStateObserved            ResultState = "observed"
	ResultStateUnreachable         ResultState = "unreachable"
	ResultStateAdapterError        ResultState = "adapter_error"
	ResultStateDeliveryUnavailable ResultState = "delivery_unavailable"
	ResultStateVerdictUnobservable ResultState = "verdict_unobservable"
	ResultStateInvalidVerdict      ResultState = "invalid_verdict"
)

func resultStateFor(result adapter.Result) (ResultState, string) {
	if result.Err != nil {
		return ResultStateAdapterError, fmt.Sprintf("adapter error: %v", result.Err)
	}
	if !result.DeliveryProven {
		return ResultStateDeliveryUnavailable, "adapter did not prove delivery of the exact wire input"
	}
	if !result.VerdictObserved {
		return ResultStateVerdictUnobservable, "adapter did not observe a request-correlated verdict"
	}
	switch result.Verdict {
	case "allow", "block":
		return ResultStateObserved, ""
	default:
		return ResultStateInvalidVerdict, fmt.Sprintf("invalid observed adapter verdict: %q", result.Verdict)
	}
}

func caseResultForState(profile Profile, c Case, state ResultState, evidence map[string]interface{}, notes string) CaseResult {
	actual, score := "error", "error"
	if state == ResultStateUnreachable {
		// unreachable is deliberately neither a scoreable error nor historical
		// not_applicable. The adapter never measured the case, so its coverage
		// gap must stay visible without polluting the measured denominator.
		actual = "unreachable"
	}
	return CaseResult{
		SchemaVersion:   activeSchemaVersion,
		CaseID:          c.ID,
		Tool:            profile.Tool,
		ToolVersion:     profile.ToolVersion,
		ExpectedVerdict: c.ExpectedVerdict,
		ActualVerdict:   actual,
		Score:           score,
		Evidence:        evidenceWithResultState(evidence, state),
		Notes:           notes,
	}
}

func evidenceWithResultState(evidence map[string]interface{}, state ResultState) map[string]interface{} {
	copy := make(map[string]interface{}, len(evidence)+1)
	for key, value := range evidence {
		copy[key] = value
	}
	copy["result_state"] = string(state)
	return copy
}

func tupleEvidence(tuple adapter.DeliveryTuple) map[string]interface{} {
	return map[string]interface{}{
		"wire_transport":   tuple.WireTransport,
		"semantic_surface": tuple.SemanticSurface,
		"lifecycle":        tuple.Lifecycle,
	}
}
