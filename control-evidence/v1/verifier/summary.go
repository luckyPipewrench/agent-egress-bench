package verifier

func (s *verificationState) verifySummary() *Result {
	if _, ok := requiredCaseExpectations(s.req.Payload); !ok {
		return failure(outcomeInvalid, "required_case_expectations_invalid")
	}
	entries := s.entriesByRole["tool-profile"]
	if len(entries) == 0 {
		return failure(outcomeInsufficientEvidence, "tool_profile_missing")
	}
	if len(entries) != 1 {
		return failure(outcomeInvalid, "tool_profile_ambiguous")
	}
	profileBytes := s.files[entries[0].Path]
	_, err := strictJSON(profileBytes, &s.toolProfile)
	if err != nil || !validToolProfileSchema(profileBytes, s.schemas) {
		return failure(outcomeInvalid, "tool_profile_invalid")
	}
	profileSHA := digestBytes(profileBytes)
	if profileSHA != s.req.Payload.ApprovedToolProfile.SHA256 {
		return failure(outcomeScopeMismatch, "tool_profile_digest_mismatch")
	}
	if textField(s.summary, "tool_profile_sha256") != profileSHA {
		return failure(outcomeInvalid, "summary_tool_profile_digest_mismatch")
	}
	if textField(s.toolProfile, "tool") != s.env.Payload.Tool.Product || textField(s.toolProfile, "tool_version") != s.env.Payload.Tool.Version ||
		textField(s.toolProfile, "runner_version") != s.env.Payload.Runner.Version {
		return failure(outcomeScopeMismatch, "tool_profile_identity_mismatch")
	}
	if !equalJSON(s.summary["reported_claims"], s.toolProfile["claims"]) {
		return failure(outcomeInvalid, "summary_reported_claims_mismatch")
	}

	counts := mapField(s.summary, "case_count")
	applicable, notApplicable, errorsSeen := 0, 0, 0
	reasons := map[string]int{}
	for _, row := range s.outcomes.Rows {
		switch row.Outcome {
		case "not_applicable":
			notApplicable++
			reasons[row.NotApplicableReason]++
		default:
			applicable++
			if row.Outcome == "error" {
				errorsSeen++
			}
		}
	}
	if integerField(counts, "not_applicable") != notApplicable || !integerMapEqual(mapField(counts, "not_applicable_reasons"), reasons) {
		return failure(outcomeInvalid, "summary_not_applicable_count_mismatch")
	}
	if integerField(counts, "errors") != errorsSeen {
		return failure(outcomeInvalid, "summary_error_count_mismatch")
	}
	if integerField(counts, "total") != len(s.outcomes.Rows) || integerField(counts, "applicable") != applicable {
		return failure(outcomeInvalid, "summary_score_projection_mismatch")
	}
	category := mapField(mapField(s.summary, "per_category"), "mcp_input")
	if integerField(category, "applicable") != applicable {
		return failure(outcomeInvalid, "summary_score_projection_mismatch")
	}
	// There is deliberately no sufficiency projection here. Sufficiency is the
	// buyer's question and the buyer already answers it in the signed requirement:
	// required_case_ids, required_case_expectations, allowed_not_applicable and
	// maximum_errors. verifyOutcomesAndEvidence enforces every one of those per row
	// and runs BEFORE this function, so a run that misses the buyer's bar has
	// already failed with a reason naming the specific row or limit.
	//
	// The projection that used to sit here recomputed sufficiency from constants:
	// four fifths of malicious cases blocked, and errors within one fifth of
	// applicable. Those numbers are the bench grading the tool, which is what the
	// v4 schema work removed when capability claims became reporting labels. Worse,
	// they could CONTRADICT the buyer: a buyer signing maximum_errors 50 on a
	// hundred applicable cases passes the enforced limit and fails the hardcoded
	// fifth, so a bench constant would override a signed requirement.
	//
	// It also required summary["sufficient"], which the runner stopped emitting and
	// the active summary schema does not define, so every real package failed
	// summary_score_projection_mismatch. The count consistency checks above are
	// what catch a tool publishing a summary its own outcome rows do not support,
	// and those stay.
	if textField(s.summary, "tool") != s.env.Payload.Tool.Product || textField(s.summary, "tool_version") != s.env.Payload.Tool.Version ||
		textField(s.summary, "runner_version") != s.env.Payload.Runner.Version || textField(s.summary, "corpus_version") != s.env.Payload.Corpus.Version ||
		textField(s.summary, "corpus_sha256") != s.env.Payload.Corpus.CorpusSHA256 || textField(s.summary, "scoring_version") != s.env.Payload.Corpus.ScoringVersion {
		return failure(outcomeInvalid, "summary_binding_mismatch")
	}
	if textField(s.summary, "gauntlet_version") != "1.0" {
		return failure(outcomeInvalid, "summary_binding_mismatch")
	}
	return nil
}

func mapField(value map[string]any, key string) map[string]any {
	result, _ := value[key].(map[string]any)
	return result
}

func textField(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func integerField(value map[string]any, key string) int {
	return numberField(value, key)
}

func integerMapEqual(value map[string]any, expected map[string]int) bool {
	if len(value) != len(expected) {
		return false
	}
	for key, wanted := range expected {
		if integerField(value, key) != wanted {
			return false
		}
	}
	return true
}
