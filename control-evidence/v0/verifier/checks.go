package verifier

import (
	"bytes"
	"encoding/json"
	"time"
)

func (s *verificationState) verifyBindingsAndManifest() *Result {
	requirementSHA := digestBytes(s.req.PayloadBytes)
	if s.env.Payload.RequirementSHA256 != requirementSHA {
		return failure(outcomeInvalid, "requirement_payload_hash_mismatch")
	}
	if s.env.Payload.ChallengeNonce != s.req.Payload.ChallengeNonce {
		return failure(outcomeInvalid, "challenge_nonce_mismatch")
	}
	if s.outcomes.RequirementSHA256 != requirementSHA || s.outcomes.RunID != s.env.Payload.RunID {
		return failure(outcomeInvalid, "outcomes_binding_mismatch")
	}
	if s.env.Payload.Observations.SHA256 != digestBytes(s.files["outcomes.json"]) {
		return failure(outcomeInvalid, "observations_digest_mismatch")
	}
	if s.env.Payload.Observations.RowCount != len(s.outcomes.Rows) {
		return failure(outcomeInvalid, "observations_row_count_mismatch")
	}
	if s.env.Payload.Artifacts.ManifestSHA256 != digestBytes(s.files["manifest.json"]) {
		return failure(outcomeInvalid, "manifest_digest_mismatch")
	}
	if s.env.Payload.Artifacts.Count != len(s.manifest.Entries) {
		return failure(outcomeInvalid, "manifest_count_mismatch")
	}

	seenPaths := map[string]bool{}
	var total int64
	for _, entry := range s.manifest.Entries {
		if seenPaths[entry.Path] || !normalizedPath(entry.Path) {
			return failure(outcomeInvalid, "manifest_path_ambiguous")
		}
		seenPaths[entry.Path] = true
		data, ok := s.files[entry.Path]
		if !ok || int64(len(data)) != entry.ByteLength || digestBytes(data) != entry.SHA256 {
			return failure(outcomeInvalid, "manifest_member_mismatch")
		}
		total += entry.ByteLength
	}
	if total != s.manifest.TotalUncompressedBytes {
		return failure(outcomeInvalid, "manifest_total_mismatch")
	}
	for path := range s.files {
		if path == "manifest.json" || path == "envelope.dsse.json" {
			continue
		}
		if !seenPaths[path] {
			return failure(outcomeInvalid, "manifest_member_uncommitted")
		}
	}
	for role, path := range map[string]string{
		"requirement": "requirement.dsse.json",
		"outcomes":    "outcomes.json",
		"summary":     "summary.json",
	} {
		entries := s.entriesByRole[role]
		if len(entries) != 1 || entries[0].Path != path {
			return failure(outcomeInvalid, "manifest_core_role_mismatch")
		}
	}
	if entries := s.entriesByRole["policy"]; len(entries) == 1 && entries[0].SHA256 != s.req.Payload.ApprovedPolicy.SHA256 {
		return failure(outcomeScopeMismatch, "policy_artifact_digest_mismatch")
	}
	if entries := s.entriesByRole["adapter"]; len(entries) == 1 && entries[0].SHA256 != s.req.Payload.ApprovedAdapter.SHA256 {
		return failure(outcomeScopeMismatch, "adapter_artifact_digest_mismatch")
	}
	for _, role := range s.req.Payload.RequiredArtifacts {
		dedicated := role == "tool-profile" ||
			(role == "token-material" && s.req.Payload.TokenMaterial.Mode == "packaged-encrypted") ||
			(role == "health-control-material" && s.req.Payload.HealthMaterial.Mode == "packaged-encrypted") ||
			(role == "clock-evidence" && s.env.Payload.FreshnessBasis == "customer-observed-clock")
		if dedicated {
			// Dedicated verifiers below preserve the more precise outcome class.
			continue
		}
		entries := s.entriesByRole[role]
		if len(entries) == 0 {
			return failure(outcomeInsufficientEvidence, "required_artifact_missing")
		}
		if role != "observer-evidence" && len(entries) != 1 {
			return failure(outcomeInvalid, "required_artifact_ambiguous")
		}
	}
	return nil
}

func (s *verificationState) verifyScopeAndTime() *Result {
	req := s.req.Payload
	env := s.env.Payload
	if env.Signer.KeyID != s.env.SignerKeyID || s.req.SignerKeyID == s.env.SignerKeyID || duplicateSignerRole(req.AuthorizedRunSigners) ||
		!sameIdentity(env.Signer, req.RequiredSignerPolicy) || !authorizedSigner(env.Signer, req.AuthorizedRunSigners) {
		return failure(outcomeScopeMismatch, "run_signer_mismatch")
	}
	if env.Runner.Version != req.ApprovedRunner.Version || env.Runner.BinarySHA256 != req.ApprovedRunner.SHA256 {
		return failure(outcomeScopeMismatch, "runner_identity_mismatch")
	}
	if env.Adapter.Protocol != req.ApprovedAdapter.Protocol || env.Adapter.Version != req.ApprovedAdapter.Version || env.Adapter.SHA256 != req.ApprovedAdapter.SHA256 {
		return failure(outcomeScopeMismatch, "adapter_identity_mismatch")
	}
	if env.Policy.SHA256 != req.ApprovedPolicy.SHA256 {
		return failure(outcomeScopeMismatch, "policy_identity_mismatch")
	}
	if env.Tool.Identity.Kind != req.ApprovedToolIdentity.Kind || env.Tool.Identity.Value != req.ApprovedToolIdentity.Expected {
		return failure(outcomeScopeMismatch, "tool_identity_mismatch")
	}
	if env.Scope.DeploymentArchetype != req.DeploymentArchetype || env.Scope.EnforcementPoint != req.EnforcementPoint.Kind ||
		!sameStringSet(env.Scope.Transports, req.RequiredTransports) || env.Scope.CaseIDsSHA256 != digestJSON(req.RequiredCaseIDs) {
		return failure(outcomeScopeMismatch, "run_scope_mismatch")
	}
	if env.Observations.ObserverProtocol != req.ApprovedObserver.Protocol || env.Observations.ObserverVersion != req.ApprovedObserver.Version {
		return failure(outcomeScopeMismatch, "observer_identity_mismatch")
	}
	if req.ApprovedObserver.KeyID != s.context.TrustedKeys.Observer || signerKeyAuthorized(req.ApprovedObserver.KeyID, req.AuthorizedRunSigners) {
		return failure(outcomeScopeMismatch, "observer_identity_mismatch")
	}

	now, ok := parseTime(s.context.ReferenceNow)
	if !ok {
		return failure(outcomeInvalid, "context_invalid")
	}
	finished, ok := parseTime(env.FinishedAt)
	if !ok {
		return failure(outcomeInvalid, "envelope_time_invalid")
	}
	expires, ok := parseTime(env.ExpiresAt)
	if !ok {
		return failure(outcomeInvalid, "envelope_time_invalid")
	}
	started, startedOK := parseTime(env.StartedAt)
	requirementIssued, issuedOK := parseTime(req.IssuedAt)
	requirementNotBefore, notBeforeOK := parseTime(req.NotBefore)
	requirementExpires, requirementExpiresOK := parseTime(req.ExpiresAt)
	if !startedOK || !issuedOK || !notBeforeOK || !requirementExpiresOK || requirementNotBefore.Before(requirementIssued) ||
		finished.Before(started) || expires.Before(finished) {
		return failure(outcomeInvalid, "envelope_time_invalid")
	}
	if started.Before(requirementNotBefore) {
		return failure(outcomeStale, "requirement_not_yet_valid")
	}
	if finished.After(requirementExpires) {
		return failure(outcomeStale, "run_after_requirement_expiry")
	}
	if expires.After(requirementExpires) {
		return failure(outcomeStale, "envelope_expiry_after_requirement")
	}
	if now.After(requirementExpires) {
		return failure(outcomeStale, "requirement_expired")
	}
	if now.After(expires) {
		return failure(outcomeStale, "envelope_expired")
	}
	if finished.After(now.Add(time.Duration(req.AllowedFutureSkewSeconds) * time.Second)) {
		return failure(outcomeStale, "finished_at_future")
	}
	if now.Sub(finished) > time.Duration(req.MaximumAgeSeconds)*time.Second {
		return failure(outcomeStale, "envelope_too_old")
	}
	if env.FreshnessBasis == "customer-observed-clock" || env.FreshnessBasis == "independent-witness-clock" {
		return s.verifyClock(finished, now, env.FreshnessBasis)
	}
	if env.FreshnessBasis != "vendor-asserted-clock" {
		return failure(outcomeUnverifiable, "freshness_basis_unsupported")
	}
	return nil
}

func (s *verificationState) verifyClock(finished, referenceNow time.Time, basis string) *Result {
	approved := s.req.Payload.ApprovedClockEvidence
	trustedKey := s.context.TrustedKeys.CustomerClock
	expectedRole := "customer-clock-attestor"
	if basis == "independent-witness-clock" {
		trustedKey = s.context.TrustedKeys.IndependentWitnessClock
		expectedRole = "independent-witness-clock-attestor"
	}
	if approved == nil || approved.KeyID != trustedKey || approved.Role != expectedRole ||
		signerKeyAuthorized(approved.KeyID, s.req.Payload.AuthorizedRunSigners) || signerAuthorityAuthorized(approved.AuthorityID, s.req.Payload.AuthorizedRunSigners) {
		return failure(outcomeScopeMismatch, "clock_role_mismatch")
	}
	entry, ok := s.entriesByDigest[s.env.Payload.ClockEvidenceRef]
	if !ok || entry.Role != "clock-evidence" {
		return failure(outcomeInvalid, "clock_evidence_missing")
	}
	clock, reason, err := verifyDSSE[clockEvidence](s.files[entry.Path], typeClock, trustedKey, s.schemas, nil)
	if err != nil {
		return failure(outcomeInvalid, reason)
	}
	value := clock.Payload
	if value.Attestor.KeyID != clock.SignerKeyID || value.Attestor.KeyID != approved.KeyID ||
		value.Attestor.AuthorityID != approved.AuthorityID || value.Attestor.Role != approved.Role ||
		value.Attestor.Profile != approved.Profile || value.Attestor.VerifierSHA256 != approved.VerifierSHA256 || value.Attestor.PolicySHA256 != approved.PolicySHA256 {
		return failure(outcomeScopeMismatch, "clock_role_mismatch")
	}
	if value.ObservationKind != "run-completion-observed" {
		return failure(outcomeInvalid, "clock_observation_kind_invalid")
	}
	clockValue, parseErr := strictJSON(clock.PayloadBytes, nil)
	if parseErr != nil || validateSchema(s.schemas.clock, clockValue) != nil {
		return failure(outcomeInvalid, "clock_evidence_invalid")
	}
	if value.RequirementSHA256 != s.env.Payload.RequirementSHA256 || value.RunID != s.env.Payload.RunID ||
		value.ObservationsSHA256 != s.env.Payload.Observations.SHA256 || value.FinishedAt != s.env.Payload.FinishedAt || value.StartedAt != s.env.Payload.StartedAt {
		return failure(outcomeInvalid, "clock_binding_mismatch")
	}
	observed, ok := parseTime(value.ObservedAt)
	if !ok {
		return failure(outcomeInvalid, "clock_time_invalid")
	}
	if observed.Add(time.Duration(approved.PermittedSkewSeconds) * time.Second).Before(finished) {
		return failure(outcomeStale, "clock_observed_before_completion")
	}
	if observed.After(referenceNow.Add(time.Duration(s.req.Payload.AllowedFutureSkewSeconds) * time.Second)) {
		return failure(outcomeStale, "clock_observed_in_future")
	}
	envelopeExpires, _ := parseTime(s.env.Payload.ExpiresAt)
	if observed.After(envelopeExpires) {
		return failure(outcomeStale, "clock_observed_after_envelope_expiry")
	}
	return nil
}

func (s *verificationState) seedReplayStatus() (string, *Result) {
	tuple := s.req.SignerKeyID + "\x00" + s.req.Payload.RequirementID + "\x00" + s.req.Payload.ChallengeNonce
	envelopeSHA := digestBytes(s.env.PayloadBytes)
	for _, entry := range s.context.NonceLedger {
		candidate := entry.RequirementSignerKeyID + "\x00" + entry.RequirementID + "\x00" + entry.ChallengeNonce
		if candidate != tuple {
			continue
		}
		if entry.EnvelopePayloadSHA256 == envelopeSHA {
			return "reverified_same_envelope", nil
		}
		result := failure(outcomeInvalid, "different_envelope_replay")
		result.NonceStatus = "different_envelope_replay"
		return "", result
	}
	return "first_verification", nil
}

func sameIdentity(a, b signerIdentity) bool {
	return a.KeyID == b.KeyID && a.AuthorityID == b.AuthorityID && a.Role == b.Role
}

func authorizedSigner(value signerIdentity, allowed []signerIdentity) bool {
	for _, candidate := range allowed {
		if sameIdentity(value, candidate) {
			return true
		}
	}
	return false
}

func signerKeyAuthorized(keyID string, allowed []signerIdentity) bool {
	for _, identity := range allowed {
		if identity.KeyID == keyID {
			return true
		}
	}
	return false
}

func signerAuthorityAuthorized(authorityID string, allowed []signerIdentity) bool {
	for _, identity := range allowed {
		if identity.AuthorityID == authorityID {
			return true
		}
	}
	return false
}

func duplicateSignerRole(allowed []signerIdentity) bool {
	seen := map[string]bool{}
	for _, identity := range allowed {
		if seen[identity.KeyID] {
			return true
		}
		seen[identity.KeyID] = true
	}
	return false
}

func digestJSON(value any) string {
	data, _ := json.Marshal(value)
	return digestBytes(data)
}

func parseTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, value)
	return parsed, err == nil
}

func equalJSON(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}
