package verifier

import (
	"testing"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

func v1RegistryState(t *testing.T) *verificationState {
	t.Helper()
	raw := []byte(`{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label only"}]}`)
	ref := capabilityregistry.Reference{ID: "aeb.core-capabilities", Format: 1, Revision: 1, SHA256: capabilityregistry.SHA256(raw)}
	profile := []byte(`{"capability_registry":{"id":"aeb.core-capabilities","format":1,"revision":1,"sha256":"` + ref.SHA256 + `"},"claims":["url_dlp"]}`)
	return &verificationState{
		files: map[string][]byte{"registry.json": raw, "profile.json": profile},
		entriesByRole: map[string][]manifestEntry{
			"capability-registry": {{Path: "registry.json"}},
			"tool-profile":        {{Path: "profile.json"}},
		},
		req:      &verifiedDSSE[requirement]{Payload: requirement{CapabilityRegistry: ref}},
		env:      &verifiedDSSE[runEnvelope]{Payload: runEnvelope{CapabilityRegistry: ref}},
		outcomes: outcomes{CapabilityRegistry: ref},
		summary: map[string]any{
			"capability_registry": map[string]any{"id": ref.ID, "format": ref.Format, "revision": ref.Revision, "sha256": ref.SHA256},
			"reported_claims":     []any{"url_dlp"},
			"exercised":           map[string]any{"capability_tags": []any{"url_dlp"}},
		},
	}
}

func TestV1RegistryBindingAcceptsOneExactRawSnapshot(t *testing.T) {
	if result := v1RegistryState(t).verifyRegistryBinding(); result != nil {
		t.Fatalf("verifyRegistryBinding() = %+v, want success", result)
	}
}

func TestV1RegistryBindingRejectsSummaryTripleMismatchBeforeRows(t *testing.T) {
	state := v1RegistryState(t)
	state.summary["capability_registry"].(map[string]any)["revision"] = 2
	result := state.verifyRegistryBinding()
	if result == nil || result.Reason != "capability_registry_summary_mismatch" {
		t.Fatalf("verifyRegistryBinding() = %+v, want summary mismatch", result)
	}
}

func TestV1RegistryBindingRejectsUnknownReportedLabel(t *testing.T) {
	state := v1RegistryState(t)
	state.summary["reported_claims"] = []any{"invented_label"}
	result := state.verifyRegistryBinding()
	if result == nil || result.Reason != "capability_registry_label_mismatch" {
		t.Fatalf("verifyRegistryBinding() = %+v, want label mismatch", result)
	}
}
