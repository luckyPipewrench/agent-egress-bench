package verifier

import (
	"encoding/json"
	"reflect"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

// verifyRegistryBinding runs before outcome-row evaluation. A signed package
// without the exact raw snapshot is not merely incomplete: it is
// uninterpretable and therefore cannot contribute a score.
func (s *verificationState) verifyRegistryBinding() *Result {
	entries := s.entriesByRole["capability-registry"]
	if len(entries) != 1 {
		return failure(outcomeInsufficientEvidence, "capability_registry_snapshot_missing")
	}
	ref := s.req.Payload.CapabilityRegistry
	if !reflect.DeepEqual(ref, s.env.Payload.CapabilityRegistry) || !reflect.DeepEqual(ref, s.outcomes.CapabilityRegistry) {
		return failure(outcomeScopeMismatch, "capability_registry_envelope_mismatch")
	}
	if _, err := capabilityregistry.ResolveRaw(ref, s.files[entries[0].Path]); err != nil {
		return failure(outcomeScopeMismatch, "capability_registry_snapshot_mismatch")
	}
	profileEntries := s.entriesByRole["tool-profile"]
	if len(profileEntries) != 1 {
		return failure(outcomeInsufficientEvidence, "tool_profile_missing")
	}
	var profile map[string]any
	if _, err := strictJSON(s.files[profileEntries[0].Path], &profile); err != nil {
		return failure(outcomeInvalid, "tool_profile_invalid")
	}
	profileRef, ok := registryReferenceFromMap(profile)
	if !ok || !reflect.DeepEqual(ref, profileRef) {
		return failure(outcomeScopeMismatch, "capability_registry_profile_mismatch")
	}
	summaryRef, ok := registryReferenceFromMap(s.summary)
	if !ok || !reflect.DeepEqual(ref, summaryRef) {
		return failure(outcomeScopeMismatch, "capability_registry_summary_mismatch")
	}
	return nil
}

func registryReferenceFromMap(value map[string]any) (capabilityregistry.Reference, bool) {
	raw, err := json.Marshal(value["capability_registry"])
	if err != nil {
		return capabilityregistry.Reference{}, false
	}
	var ref capabilityregistry.Reference
	if err := json.Unmarshal(raw, &ref); err != nil {
		return capabilityregistry.Reference{}, false
	}
	if ref.ID == "" || ref.Format == 0 || ref.Revision == 0 || ref.SHA256 == "" {
		return capabilityregistry.Reference{}, false
	}
	return ref, true
}
