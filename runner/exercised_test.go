package main

import (
	"reflect"
	"testing"
)

// The summary must report the capability surface a run actually exercised, so a
// published result states what was tested rather than only what the profile
// declared. Transports, categories, and capability tags are reported as the
// sorted, de-duplicated union across the applicable results.
func TestComputeExercisedReportsDistinctSortedCapabilities(t *testing.T) {
	casesByID := map[string]Case{
		"a": {ID: "a", Transport: "mcp_http", Category: "mcp_input", CapabilityTags: []string{"mcp_input_scan", "encoding_evasion"}},
		"b": {ID: "b", Transport: "fetch_proxy", Category: "url", CapabilityTags: []string{"url_dlp"}},
		"c": {ID: "c", Transport: "mcp_http", Category: "mcp_input", CapabilityTags: []string{"mcp_input_scan"}},
	}
	observed := map[string]interface{}{"result_state": string(ResultStateObserved)}
	results := []CaseResult{
		{CaseID: "a", ActualVerdict: "block", Score: "pass", Evidence: observed},
		{CaseID: "b", ActualVerdict: "allow", Score: "pass", Evidence: observed},
		{CaseID: "c", ActualVerdict: "block", Score: "fail", Evidence: observed},
	}

	got := computeExercised(results, casesByID)

	if want := []string{"fetch_proxy", "mcp_http"}; !reflect.DeepEqual(got.Transports, want) {
		t.Errorf("transports = %v, want %v", got.Transports, want)
	}
	if want := []string{"mcp_input", "url"}; !reflect.DeepEqual(got.Categories, want) {
		t.Errorf("categories = %v, want %v", got.Categories, want)
	}
	if want := []string{"encoding_evasion", "mcp_input_scan", "url_dlp"}; !reflect.DeepEqual(got.CapabilityTags, want) {
		t.Errorf("capability_tags = %v, want %v", got.CapabilityTags, want)
	}
}

// A result whose case is missing from the lookup is skipped rather than
// panicking or inventing a capability.
func TestComputeExercisedIgnoresUnknownCase(t *testing.T) {
	casesByID := map[string]Case{"a": {ID: "a", Transport: "mcp_http", Category: "mcp_input"}}
	observed := map[string]interface{}{"result_state": string(ResultStateObserved)}
	results := []CaseResult{
		{CaseID: "a", ActualVerdict: "allow", Score: "pass", Evidence: observed},
		{CaseID: "missing", ActualVerdict: "allow", Score: "pass", Evidence: observed},
	}

	got := computeExercised(results, casesByID)

	if want := []string{"mcp_http"}; !reflect.DeepEqual(got.Transports, want) {
		t.Errorf("transports = %v, want %v", got.Transports, want)
	}
}

func TestComputeExercisedExcludesRoutedRowsWithoutObservedVerdict(t *testing.T) {
	casesByID := map[string]Case{
		"observed": {ID: "observed", Transport: "fetch_proxy", Category: "url", CapabilityTags: []string{"url_dlp"}},
		"error":    {ID: "error", Transport: "mcp_http", Category: "mcp_input", CapabilityTags: []string{"mcp_input_scan"}},
		// A verdict-shaped row whose state says it was never a request-correlated
		// observation. The error row above is already excluded by its score, so
		// without this row the result_state test would pass with the state check
		// deleted and prove nothing about it.
		"unobserved": {ID: "unobserved", Transport: "mcp_stdio", Category: "mcp_tool_result", CapabilityTags: []string{"mcp_result_scan"}},
	}
	results := []CaseResult{
		{CaseID: "observed", ActualVerdict: "block", Score: "pass", Evidence: map[string]interface{}{"result_state": string(ResultStateObserved)}},
		{CaseID: "error", ActualVerdict: "error", Score: "error", Evidence: map[string]interface{}{"result_state": string(ResultStateDeliveryUnavailable)}},
		{CaseID: "unobserved", ActualVerdict: "block", Score: "pass", Evidence: map[string]interface{}{"result_state": string(ResultStateVerdictUnobservable)}},
	}

	got := computeExercised(results, casesByID)
	if want := []string{"fetch_proxy"}; !reflect.DeepEqual(got.Transports, want) {
		t.Errorf("transports = %v, want observed-only %v", got.Transports, want)
	}
	if want := []string{"url"}; !reflect.DeepEqual(got.Categories, want) {
		t.Errorf("categories = %v, want observed-only %v", got.Categories, want)
	}
	if want := []string{"url_dlp"}; !reflect.DeepEqual(got.CapabilityTags, want) {
		t.Errorf("capability_tags = %v, want observed-only %v", got.CapabilityTags, want)
	}
}
