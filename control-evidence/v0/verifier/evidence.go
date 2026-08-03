package verifier

import (
	"sort"
	"time"
)

func (s *verificationState) verifyOutcomesAndEvidence(materials materialInputs) *Result {
	req := s.req.Payload
	requirementSHA := digestBytes(s.req.PayloadBytes)
	wantedRows := map[string]bool{}
	for _, caseID := range req.RequiredCaseIDs {
		wantedRows[rowKey(caseID, 1)] = true
	}
	seenRows := map[string]bool{}
	usedControls := map[string]bool{}
	errorsSeen := 0
	for _, row := range s.outcomes.Rows {
		key := rowKey(row.CaseID, row.TrialIndex)
		if seenRows[key] {
			return failure(outcomeInvalid, "outcomes_row_duplicate")
		}
		seenRows[key] = true
		if !wantedRows[key] {
			return failure(outcomeInvalid, "outcomes_row_unexpected")
		}
		if !contains(req.RequiredTransports, row.Transport) {
			return failure(outcomeScopeMismatch, "outcomes_transport_mismatch")
		}
		if row.Outcome == "not_applicable" {
			if !authorizedNA(row.CaseID, row.NotApplicableReason, req.AllowedNotApplicable) {
				return failure(outcomeScopeMismatch, "not_applicable_reason_unauthorized")
			}
			continue
		}
		if row.Outcome == "error" {
			errorsSeen++
			continue
		}
		if result := s.verifyRowCanaries(row, materials, requirementSHA, usedControls); result != nil {
			return result
		}
	}
	for key := range wantedRows {
		if !seenRows[key] {
			return failure(outcomeInvalid, "outcomes_row_missing")
		}
	}
	if errorsSeen > req.MaximumErrors {
		return failure(outcomeInvalid, "maximum_errors_exceeded")
	}
	if req.HealthMaterial.Mode == "packaged-encrypted" && !sameStringSet(boolKeys(usedControls), keys(materials.controls)) {
		return failure(outcomeInvalid, "health_control_material_control_id_set_mismatch")
	}
	return nil
}

func (s *verificationState) verifyRowCanaries(row outcomeRow, materials materialInputs, requirementSHA string, usedControls map[string]bool) *Result {
	wanted := append(append([]string{}, s.req.Payload.RequiredPositiveCanaries...), s.req.Payload.RequiredNegativeCanaries...)
	seen := map[string]bool{}
	for _, canary := range row.Canaries {
		if seen[canary.CanaryID] {
			return failure(outcomeInvalid, "canary_duplicate")
		}
		seen[canary.CanaryID] = true
		input, ok := materials.tokens[canary.CanaryID]
		if !ok || tokenCommitment(requirementSHA, s.env.Payload.RunID, row.CaseID, row.TrialIndex, canary, input) != canary.CanaryCommitmentSHA256 {
			return failure(outcomeInvalid, "canary_token_mismatch")
		}
		if canary.ObserverProtocol != s.req.Payload.ApprovedObserver.Protocol || canary.ObserverVersion != s.req.Payload.ApprovedObserver.Version ||
			canary.TargetIdentity != s.req.Payload.ApprovedObserver.TargetIdentity {
			return failure(outcomeScopeMismatch, "observer_identity_mismatch")
		}
		switch canary.Polarity {
		case "positive":
			if canary.State != "observed" || canary.ExpectedPredicate != "allow-observed" {
				return failure(outcomeInvalid, "positive_canary_state_invalid")
			}
			if result := s.verifyPositive(row, canary); result != nil {
				return result
			}
		case "negative":
			if canary.State != "not_observed" && canary.State != "observer_unavailable" {
				return failure(outcomeInvalid, "negative_canary_state_invalid")
			}
			if canary.ExpectedPredicate != "block-not-observed" {
				return failure(outcomeInvalid, "negative_canary_state_invalid")
			}
			if result := s.verifyNegative(row, canary, materials, usedControls); result != nil {
				return result
			}
		default:
			return failure(outcomeInvalid, "canary_polarity_invalid")
		}
	}
	if !sameStringSet(boolKeys(seen), wanted) {
		return failure(outcomeInvalid, "canary_set_mismatch")
	}
	return nil
}

func (s *verificationState) verifyPositive(row outcomeRow, canary canary) *Result {
	if canary.ObservationRef == "" {
		return failure(outcomeInsufficientEvidence, "positive_canary_observation_missing")
	}
	evidence, result := s.observerByRef(canary.ObservationRef)
	if result != nil {
		return result
	}
	if evidence.Kind != "target-observation" || evidence.ObservationState != "observed" || !observerBinds(evidence, s, row, canary) {
		return failure(outcomeInvalid, "positive_canary_observation_invalid")
	}
	observed, observedOK := parseTime(evidence.ObservedAt)
	started, startedOK := parseTime(s.env.Payload.StartedAt)
	finished, finishedOK := parseTime(s.env.Payload.FinishedAt)
	if !observedOK || !startedOK || !finishedOK || observed.Before(started) || observed.After(finished) {
		return failure(outcomeInvalid, "positive_canary_observation_time_invalid")
	}
	return nil
}

func (s *verificationState) verifyNegative(row outcomeRow, canary canary, materials materialInputs, usedControls map[string]bool) *Result {
	if canary.State == "observer_unavailable" {
		return failure(outcomeInsufficientEvidence, "negative_canary_observer_unavailable")
	}
	if canary.ObserverKeyID != s.req.Payload.ApprovedObserver.KeyID {
		return failure(outcomeScopeMismatch, "observer_identity_mismatch")
	}
	if canary.LivenessRecordRef != "" {
		return s.verifyLiveness(row, canary)
	}
	if canary.PrecedingHealthRef == "" || canary.FollowingHealthRef == "" {
		return failure(outcomeInvalid, "negative_canary_health_incomplete")
	}
	if canary.PrecedingHealthRef == canary.FollowingHealthRef {
		return failure(outcomeInvalid, "negative_canary_health_incomplete")
	}
	windowStart, okStart := parseTime(canary.WindowStart)
	windowEnd, okEnd := parseTime(canary.WindowEnd)
	if !okStart || !okEnd || windowEnd.Before(windowStart) {
		return failure(outcomeInvalid, "negative_canary_window_invalid")
	}
	if !s.observationWindowWithinRun(windowStart, windowEnd) {
		return failure(outcomeInvalid, "negative_canary_window_outside_run")
	}
	pre, result := s.observerByRef(canary.PrecedingHealthRef)
	if result != nil {
		return result
	}
	post, result := s.observerByRef(canary.FollowingHealthRef)
	if result != nil {
		return result
	}
	for _, item := range []*observerEvidence{pre, post} {
		if item.Kind != "health-control" || item.HealthState != "allow-observed" || !observerBinds(item, s, row, canary) {
			return failure(outcomeInvalid, "negative_canary_health_invalid")
		}
		usedControls[item.ControlID] = true
		input, found := materials.healthInput(s.req.Payload, s.context, item.ControlID)
		if !found {
			return failure(outcomeInvalid, "health_control_material_control_id_set_mismatch")
		}
		expected := healthCommitment(digestBytes(s.req.PayloadBytes), s.env.Payload.RunID, row, canary, item.ControlID, input)
		if item.HealthControlCommitmentSHA256 != expected {
			return failure(outcomeInvalid, "health_control_commitment_mismatch")
		}
	}
	preTime, preOK := parseTime(pre.ObservedAt)
	postTime, postOK := parseTime(post.ObservedAt)
	maximum := time.Duration(s.req.Payload.ApprovedObserver.MaximumHealthControlIntervalSeconds) * time.Second
	if !preOK || !postOK || preTime.After(windowStart) || postTime.Before(windowEnd) || windowStart.Sub(preTime) > maximum || postTime.Sub(windowEnd) > maximum {
		return failure(outcomeInvalid, "negative_canary_health_window_invalid")
	}
	return nil
}

func (s *verificationState) verifyLiveness(row outcomeRow, canary canary) *Result {
	evidence, result := s.observerByRef(canary.LivenessRecordRef)
	if result != nil {
		return result
	}
	if evidence.Kind != "liveness-record" || evidence.RequirementSHA256 != digestBytes(s.req.PayloadBytes) ||
		evidence.RunID != s.env.Payload.RunID || evidence.TargetIdentity != canary.TargetIdentity || evidence.Transport != row.Transport {
		return failure(outcomeInvalid, "negative_canary_liveness_invalid")
	}
	windowStart, okStart := parseTime(canary.WindowStart)
	windowEnd, okEnd := parseTime(canary.WindowEnd)
	if !okStart || !okEnd || windowEnd.Before(windowStart) {
		return failure(outcomeInvalid, "negative_canary_window_invalid")
	}
	if len(evidence.Liveness) == 0 {
		return failure(outcomeInsufficientEvidence, "negative_canary_liveness_gap")
	}
	if !s.observationWindowWithinRun(windowStart, windowEnd) {
		return failure(outcomeInvalid, "negative_canary_window_outside_run")
	}
	maximum := time.Duration(s.req.Payload.ApprovedObserver.MaximumLivenessGapSeconds) * time.Second
	var previous time.Time
	for i, point := range evidence.Liveness {
		current, ok := parseTime(point.ObservedAt)
		if !ok || point.HealthState != "alive" || (i > 0 && (point.Sequence <= evidence.Liveness[i-1].Sequence || !current.After(previous) || current.Sub(previous) > maximum)) {
			return failure(outcomeInsufficientEvidence, "negative_canary_liveness_gap")
		}
		previous = current
	}
	first, _ := parseTime(evidence.Liveness[0].ObservedAt)
	last, _ := parseTime(evidence.Liveness[len(evidence.Liveness)-1].ObservedAt)
	if first.After(windowStart) || last.Before(windowEnd) {
		return failure(outcomeInsufficientEvidence, "negative_canary_liveness_gap")
	}
	return nil
}

func (s *verificationState) observationWindowWithinRun(start, end time.Time) bool {
	runStart, startOK := parseTime(s.env.Payload.StartedAt)
	runEnd, endOK := parseTime(s.env.Payload.FinishedAt)
	return startOK && endOK && !start.Before(runStart) && !end.After(runEnd)
}

func (s *verificationState) observerByRef(ref string) (*observerEvidence, *Result) {
	entry, ok := s.entriesByDigest[ref]
	if !ok || entry.Role != "observer-evidence" {
		return nil, failure(outcomeInsufficientEvidence, "observer_evidence_missing")
	}
	verified, reason, err := verifyDSSE[observerEvidence](s.files[entry.Path], typeObserver, s.context.TrustedKeys.Observer, s.schemas, s.schemas.observer)
	if err != nil {
		return nil, failure(outcomeInvalid, reason)
	}
	value := &verified.Payload
	if value.Observer.KeyID != verified.SignerKeyID || value.Observer.KeyID != s.req.Payload.ApprovedObserver.KeyID ||
		value.Observer.Protocol != s.req.Payload.ApprovedObserver.Protocol || value.Observer.Version != s.req.Payload.ApprovedObserver.Version {
		return nil, failure(outcomeScopeMismatch, "observer_identity_mismatch")
	}
	return value, nil
}

func observerBinds(value *observerEvidence, s *verificationState, row outcomeRow, canary canary) bool {
	return value.RequirementSHA256 == digestBytes(s.req.PayloadBytes) && value.RunID == s.env.Payload.RunID &&
		value.CaseID == row.CaseID && value.TrialIndex == row.TrialIndex && value.CanaryID == canary.CanaryID &&
		value.CanaryCommitmentSHA256 == canary.CanaryCommitmentSHA256 && value.Transport == row.Transport &&
		value.TargetIdentity == canary.TargetIdentity
}

func rowKey(caseID string, trial int) string { return caseID + "\x00" + string(rune(trial)) }

func authorizedNA(caseID, reason string, allowed []allowedNA) bool {
	for _, item := range allowed {
		if item.CaseID == caseID && item.Reason == reason {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func boolKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
