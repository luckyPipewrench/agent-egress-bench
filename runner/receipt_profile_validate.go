package main

import (
	"fmt"
	"regexp"
	"strings"
)

// sha256HexPattern matches the schema's corpus_sha256 / tool_profile_sha256
// pattern: 64 lower-case hex characters.
var sha256HexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validBlockedValues lists the values the schema accepts for the blocked
// dimension.
var validBlockedValues = map[string]bool{"yes": true, "no": true, "n/a": true}

// validBooleanDimension lists the values the schema accepts for the
// explained and receipt_produced dimensions.
var validBooleanDimension = map[string]bool{"yes": true, "no": true}

// validVerifiableValues lists the values the schema accepts for the
// receipt_independently_verifiable dimension.
var validVerifiableValues = map[string]bool{"yes": true, "partial": true, "no": true}

// validFalsePositiveValues lists the values the schema accepts for the
// false_positive dimension.
var validFalsePositiveValues = map[string]bool{"yes": true, "no": true, "n/a": true}

// ValidateReceiptProfile checks a ReceiptProfile against the structural
// rules in schemas/receipt-scoring-profile.schema.json, including the
// cross-field invariants the schema encodes via allOf and if/then. It
// also re-derives summary counts from per_case and confirms they match
// (the kickoff's done-state item 2).
//
// Validation is intentionally stdlib-only so callers can re-verify a
// profile without pulling a JSON Schema dependency into this module.
// The returned slice is empty when the profile is valid.
func ValidateReceiptProfile(rp ReceiptProfile) []string {
	var issues []string

	if rp.SchemaVersion != activeSchemaVersion {
		issues = append(issues, fmt.Sprintf("schema_version must be %d, got %d", activeSchemaVersion, rp.SchemaVersion))
	}
	if strings.TrimSpace(rp.Tool) == "" {
		issues = append(issues, "tool must be a non-empty string")
	}
	if strings.TrimSpace(rp.ToolVersion) == "" {
		issues = append(issues, "tool_version must be a non-empty string")
	}
	if strings.TrimSpace(rp.CorpusVersion) == "" {
		issues = append(issues, "corpus_version must be a non-empty string")
	}
	if !sha256HexPattern.MatchString(rp.CorpusSHA256) {
		issues = append(issues, "corpus_sha256 must be 64 lower-case hex characters")
	}
	if !sha256HexPattern.MatchString(rp.ToolProfileSHA256) {
		issues = append(issues, "tool_profile_sha256 must be 64 lower-case hex characters")
	}

	// Per-row validation, plus accumulators for the summary cross-check.
	var derived ReceiptSummary
	seen := make(map[string]bool, len(rp.PerCase))
	for i, row := range rp.PerCase {
		prefix := fmt.Sprintf("per_case[%d] (case_id=%q)", i, row.CaseID)

		if strings.TrimSpace(row.CaseID) == "" {
			issues = append(issues, prefix+": case_id must be a non-empty string")
		} else if seen[row.CaseID] {
			issues = append(issues, prefix+": duplicate case_id")
		} else {
			seen[row.CaseID] = true
		}

		if !validBlockedValues[row.Blocked] {
			issues = append(issues, fmt.Sprintf("%s: blocked must be yes|no|n/a, got %q", prefix, row.Blocked))
		}
		if !validBooleanDimension[row.Explained] {
			issues = append(issues, fmt.Sprintf("%s: explained must be yes|no, got %q", prefix, row.Explained))
		}
		if !validBooleanDimension[row.ReceiptProduced] {
			issues = append(issues, fmt.Sprintf("%s: receipt_produced must be yes|no, got %q", prefix, row.ReceiptProduced))
		}
		if !validVerifiableValues[row.ReceiptIndependentlyVerifiable] {
			issues = append(issues, fmt.Sprintf("%s: receipt_independently_verifiable must be yes|partial|no, got %q", prefix, row.ReceiptIndependentlyVerifiable))
		}
		if !validFalsePositiveValues[row.FalsePositive] {
			issues = append(issues, fmt.Sprintf("%s: false_positive must be yes|no|n/a, got %q", prefix, row.FalsePositive))
		}

		// Cross-field invariant: malicious vs benign split.
		// Malicious: blocked in {yes, no} and false_positive == n/a.
		// Benign:    blocked == n/a       and false_positive in {yes, no}.
		blockedIsResult := row.Blocked == "yes" || row.Blocked == "no"
		blockedIsNA := row.Blocked == "n/a"
		fpIsResult := row.FalsePositive == "yes" || row.FalsePositive == "no"
		fpIsNA := row.FalsePositive == "n/a"
		malicious := blockedIsResult && fpIsNA
		benign := blockedIsNA && fpIsResult
		if !malicious && !benign {
			issues = append(issues, fmt.Sprintf(
				"%s: blocked/false_positive must split malicious(blocked=yes|no, false_positive=n/a) or benign(blocked=n/a, false_positive=yes|no); got blocked=%q false_positive=%q",
				prefix, row.Blocked, row.FalsePositive))
		}

		// Cross-field invariant: receipt_produced=no implies
		// receipt_independently_verifiable=no.
		if row.ReceiptProduced == "no" && row.ReceiptIndependentlyVerifiable != "no" {
			issues = append(issues, fmt.Sprintf(
				"%s: receipt_independently_verifiable must be \"no\" when receipt_produced=\"no\", got %q",
				prefix, row.ReceiptIndependentlyVerifiable))
		}

		// Accumulate derived summary counts for the cross-check below.
		if row.Blocked == "yes" {
			derived.BlockedYesCount++
		}
		if row.Blocked == "no" {
			derived.BlockedNoCount++
		}
		if row.Explained == "yes" {
			derived.ExplainedYesCount++
		}
		if row.ReceiptProduced == "yes" {
			derived.ReceiptProducedYesCount++
		}
		if row.ReceiptIndependentlyVerifiable == "yes" {
			derived.ReceiptIndependentlyVerifiableYesCount++
		}
		if row.FalsePositive == "yes" {
			derived.FalsePositiveYesCount++
		}
	}

	// Summary counts must agree with per_case. Done-state item 2.
	if rp.Summary.BlockedYesCount != derived.BlockedYesCount {
		issues = append(issues, fmt.Sprintf("summary.blocked_yes_count=%d, per_case sum=%d", rp.Summary.BlockedYesCount, derived.BlockedYesCount))
	}
	if rp.Summary.BlockedNoCount != derived.BlockedNoCount {
		issues = append(issues, fmt.Sprintf("summary.blocked_no_count=%d, per_case sum=%d", rp.Summary.BlockedNoCount, derived.BlockedNoCount))
	}
	if rp.Summary.ExplainedYesCount != derived.ExplainedYesCount {
		issues = append(issues, fmt.Sprintf("summary.explained_yes_count=%d, per_case sum=%d", rp.Summary.ExplainedYesCount, derived.ExplainedYesCount))
	}
	if rp.Summary.ReceiptProducedYesCount != derived.ReceiptProducedYesCount {
		issues = append(issues, fmt.Sprintf("summary.receipt_produced_yes_count=%d, per_case sum=%d", rp.Summary.ReceiptProducedYesCount, derived.ReceiptProducedYesCount))
	}
	if rp.Summary.ReceiptIndependentlyVerifiableYesCount != derived.ReceiptIndependentlyVerifiableYesCount {
		issues = append(issues, fmt.Sprintf("summary.receipt_independently_verifiable_yes_count=%d, per_case sum=%d", rp.Summary.ReceiptIndependentlyVerifiableYesCount, derived.ReceiptIndependentlyVerifiableYesCount))
	}
	if rp.Summary.FalsePositiveYesCount != derived.FalsePositiveYesCount {
		issues = append(issues, fmt.Sprintf("summary.false_positive_yes_count=%d, per_case sum=%d", rp.Summary.FalsePositiveYesCount, derived.FalsePositiveYesCount))
	}

	// Verifier block: structural-only checks. The schema does not require
	// a non-empty URL/license/contract because tools can legitimately set
	// shipped=false. If shipped=true but the verifier_url is missing, the
	// relying party still has license + contract; this is a soft check.

	return issues
}
