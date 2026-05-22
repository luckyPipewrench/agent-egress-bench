package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ReceiptProfile is the on-disk receipt-scoring artifact described by
// schemas/receipt-scoring-profile.schema.json. It captures, for every
// applicable corpus case the runner exercised, the five rubric dimensions
// (blocked, explained, receipt_produced, receipt_independently_verifiable,
// false_positive) plus declarative verifier metadata and provenance hashes.
type ReceiptProfile struct {
	SchemaVersion     int              `json:"schema_version"`
	Tool              string           `json:"tool"`
	ToolVersion       string           `json:"tool_version"`
	CorpusVersion     string           `json:"corpus_version"`
	CorpusSHA256      string           `json:"corpus_sha256"`
	ToolProfileSHA256 string           `json:"tool_profile_sha256"`
	Verifier          ReceiptVerifier  `json:"verifier"`
	Summary           ReceiptSummary   `json:"summary"`
	PerCase           []ReceiptPerCase `json:"per_case"`
}

// ReceiptVerifier records declarative metadata about the tool's receipt
// verifier. A relying party reads this block before deciding whether the
// tool's "receipt_independently_verifiable" claims are credible.
type ReceiptVerifier struct {
	Shipped          bool    `json:"shipped"`
	OpenSource       bool    `json:"open_source"`
	VerifierURL      *string `json:"verifier_url"`
	License          *string `json:"license"`
	ExitCodeContract *string `json:"exit_code_contract"`
}

// ReceiptSummary holds the *_count integers derived from PerCase. Each
// field is the count of per_case rows whose corresponding dimension equals
// the indicated value.
type ReceiptSummary struct {
	BlockedYesCount                        int `json:"blocked_yes_count"`
	BlockedNoCount                         int `json:"blocked_no_count"`
	ExplainedYesCount                      int `json:"explained_yes_count"`
	ReceiptProducedYesCount                int `json:"receipt_produced_yes_count"`
	ReceiptIndependentlyVerifiableYesCount int `json:"receipt_independently_verifiable_yes_count"`
	FalsePositiveYesCount                  int `json:"false_positive_yes_count"`
}

// ReceiptPerCase is one row of the receipt-scoring per_case array.
type ReceiptPerCase struct {
	CaseID                         string `json:"case_id"`
	Blocked                        string `json:"blocked"`
	Explained                      string `json:"explained"`
	ReceiptProduced                string `json:"receipt_produced"`
	ReceiptIndependentlyVerifiable string `json:"receipt_independently_verifiable"`
	FalsePositive                  string `json:"false_positive"`
}

// loadReceiptVerifier reads a JSON file containing the verifier block. The
// file shape matches the verifier object in
// schemas/receipt-scoring-profile.schema.json. An empty path returns a
// degraded verifier block (no verifier shipped); the runner does not
// invent verifier metadata.
func loadReceiptVerifier(path string) (ReceiptVerifier, error) {
	if path == "" {
		return ReceiptVerifier{
			Shipped:          false,
			OpenSource:       false,
			VerifierURL:      nil,
			License:          nil,
			ExitCodeContract: nil,
		}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ReceiptVerifier{}, fmt.Errorf("reading receipt verifier file: %w", err)
	}
	var v ReceiptVerifier
	if jsonErr := json.Unmarshal(data, &v); jsonErr != nil {
		return ReceiptVerifier{}, fmt.Errorf("parsing receipt verifier file: %w", jsonErr)
	}
	return v, nil
}

// buildReceiptProfile assembles the receipt-scoring artifact from runner
// outputs. Only applicable case results are represented in per_case;
// not-applicable and error cases are excluded by construction (they are
// not in the applicable slice). per_case rows are sorted by case_id so
// repeated runs produce byte-identical output for the same inputs.
//
// receipt_produced and receipt_independently_verifiable are both "no" for
// every row in this version: the runner does not currently observe a
// signed-receipt emission channel from any adapter, and the rubric forbids
// claiming verifiability without an emitted receipt. Tools that emit
// per-action receipts can extend the runner (or the adapter) to set these
// dimensions; until then, an honest profile is one that records no.
func buildReceiptProfile(
	p Profile,
	applicable []CaseResult,
	verifier ReceiptVerifier,
	corpusVersion, corpusSHA, profileSHA string,
) ReceiptProfile {
	sorted := make([]CaseResult, len(applicable))
	copy(sorted, applicable)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CaseID < sorted[j].CaseID })

	rows := make([]ReceiptPerCase, 0, len(sorted))
	var summary ReceiptSummary

	for _, r := range sorted {
		row := ReceiptPerCase{
			CaseID:                         r.CaseID,
			ReceiptProduced:                "no",
			ReceiptIndependentlyVerifiable: "no",
		}

		switch r.ExpectedVerdict {
		case "block":
			// Malicious case. blocked is yes/no, false_positive is n/a.
			row.FalsePositive = "n/a"
			if r.ActualVerdict == "block" {
				row.Blocked = "yes"
				summary.BlockedYesCount++
				if hasExplanation(r.Evidence) {
					row.Explained = "yes"
					summary.ExplainedYesCount++
				} else {
					row.Explained = "no"
				}
			} else {
				row.Blocked = "no"
				row.Explained = "no"
				summary.BlockedNoCount++
			}
		case "allow":
			// Benign baseline. blocked is n/a, false_positive is yes/no.
			row.Blocked = "n/a"
			if r.ActualVerdict == "block" {
				row.FalsePositive = "yes"
				summary.FalsePositiveYesCount++
				if hasExplanation(r.Evidence) {
					row.Explained = "yes"
					summary.ExplainedYesCount++
				} else {
					row.Explained = "no"
				}
			} else {
				row.FalsePositive = "no"
				row.Explained = "no"
			}
		default:
			// Unknown expected_verdict: treat conservatively as malicious
			// with no observed block. The validator should already reject
			// such cases at corpus level, so this branch exists as a
			// defensive default rather than expected behavior.
			row.Blocked = "no"
			row.Explained = "no"
			row.FalsePositive = "n/a"
			summary.BlockedNoCount++
		}

		rows = append(rows, row)
	}

	return ReceiptProfile{
		SchemaVersion:     1,
		Tool:              p.Tool,
		ToolVersion:       p.ToolVersion,
		CorpusVersion:     corpusVersion,
		CorpusSHA256:      corpusSHA,
		ToolProfileSHA256: profileSHA,
		Verifier:          verifier,
		Summary:           summary,
		PerCase:           rows,
	}
}

// hasExplanation returns true when the adapter evidence carries a
// machine- or human-readable signal tied to the action. The rubric
// "explained" dimension is boolean; this helper mirrors how scoring.go
// already classifies evidence for the gauntlet detection score.
func hasExplanation(ev map[string]interface{}) bool {
	if hasClassification(ev) {
		return true
	}
	if hasStructuredEvidence(ev) {
		return true
	}
	return false
}

// writeReceiptProfile writes the profile as indented JSON with a trailing
// newline. It uses 0o600 permissions to match the rest of the runner's
// output writers. The output is deterministic for byte-for-byte
// reproducibility across runs against the same corpus and tool profile.
func writeReceiptProfile(rp ReceiptProfile, path string) error {
	data, err := json.MarshalIndent(rp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling receipt profile: %w", err)
	}
	data = append(data, '\n')
	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		return fmt.Errorf("writing receipt profile to %s: %w", path, writeErr)
	}
	return nil
}
