package verifier

func (s *verificationState) verifySummary() *Result {
	expectations, ok := requiredCaseExpectations(s.req.Payload)
	if !ok {
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
	profileValue, err := strictJSON(profileBytes, &s.toolProfile)
	if err != nil || validateSchema(s.schemas.toolProfile, profileValue) != nil {
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
	if !equalJSON(mapField(s.summary, "tool_support"), deriveToolSupport(s.toolProfile)) {
		return failure(outcomeInvalid, "summary_tool_support_mismatch")
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
	malicious, blockedMalicious := 0, 0
	for _, row := range s.outcomes.Rows {
		if expectations[row.CaseID] == "block" {
			malicious++
			if row.Outcome != "not_applicable" && row.ActualVerdict == "block" {
				blockedMalicious++
			}
		}
	}
	wantSufficient := (malicious == 0 || blockedMalicious*5 >= malicious*4) && (applicable == 0 || errorsSeen*5 <= applicable+errorsSeen)
	gotSufficient, ok := s.summary["sufficient"].(bool)
	if !ok || gotSufficient != wantSufficient {
		return failure(outcomeInvalid, "summary_score_projection_mismatch")
	}
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

func deriveToolSupport(profile map[string]any) map[string]any {
	supports := mapField(profile, "supports")
	unsupported := func(names []string) []any {
		out := []any{}
		for _, name := range names {
			value, _ := supports[name].(bool)
			if !value {
				out = append(out, name)
			}
		}
		return out
	}
	return map[string]any{
		"claims": profile["claims"],
		"unsupported_transports": unsupported([]string{
			"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a",
		}),
		"unsupported_requires": unsupported([]string{
			"tls_interception", "url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning",
			"response_prompt_injection_scanning", "mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning",
			"mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning", "mcp_tool_poison_scanning",
			"mcp_tool_baseline", "mcp_chain_memory", "mcp_cross_server_chain_memory", "mcp_data_class_labels",
			"a2a_dlp_scanning", "a2a_prompt_injection_scanning", "a2a_card_prompt_injection_scanning",
			"a2a_card_drift_scanning", "a2a_ssrf_scanning", "websocket_dlp_scanning",
			"websocket_prompt_injection_scanning", "ssrf_scanning", "ssrf_bypass_scanning", "domain_blocklist",
			"entropy_scanning", "encoding_evasion_scanning", "shell_analysis", "crypto_dlp_scanning",
			"hostname_exfil_scanning", "dns_rebinding_fixture", "budget_enforcement",
		}),
	}
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
