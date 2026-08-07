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
	results := []CaseResult{{CaseID: "a"}, {CaseID: "b"}, {CaseID: "c"}}

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
	results := []CaseResult{{CaseID: "a"}, {CaseID: "missing"}}

	got := computeExercised(results, casesByID)

	if want := []string{"mcp_http"}; !reflect.DeepEqual(got.Transports, want) {
		t.Errorf("transports = %v, want %v", got.Transports, want)
	}
}
