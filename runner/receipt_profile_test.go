package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stringPtr returns a pointer to s. Used in tests that build a fully-valid
// verifier block, where the three nullable string fields must be addresses
// (or nil) per the on-disk encoding.
func stringPtr(s string) *string { return &s }

// validProfile returns a minimal valid ReceiptProfile that tests can mutate
// to exercise specific failure modes. The malicious-blocked row plus the
// benign-allowed row cover both sides of the blocked/false_positive split.
func validProfile() ReceiptProfile {
	zeros := strings.Repeat("0", 64)
	return ReceiptProfile{
		SchemaVersion:     1,
		Tool:              "example-tool",
		ToolVersion:       "0.0.0-example",
		CorpusVersion:     "v2.0.0",
		CorpusSHA256:      zeros,
		ToolProfileSHA256: zeros,
		Verifier: ReceiptVerifier{
			Shipped:          true,
			OpenSource:       true,
			VerifierURL:      stringPtr("https://example.invalid/verifier"),
			License:          stringPtr("Apache-2.0"),
			ExitCodeContract: stringPtr("0 valid, 1 invalid, 2 error, 64 usage"),
		},
		Summary: ReceiptSummary{
			BlockedYesCount:   1,
			BlockedNoCount:    0,
			ExplainedYesCount: 1,
			// Receipts and false-positive counts left at zero so the
			// derived counts agree with per_case below.
		},
		PerCase: []ReceiptPerCase{
			{
				CaseID:                         "malicious-case-001",
				Blocked:                        "yes",
				Explained:                      "yes",
				ReceiptProduced:                "no",
				ReceiptIndependentlyVerifiable: "no",
				FalsePositive:                  "n/a",
			},
			{
				CaseID:                         "benign-case-001",
				Blocked:                        "n/a",
				Explained:                      "no",
				ReceiptProduced:                "no",
				ReceiptIndependentlyVerifiable: "no",
				FalsePositive:                  "no",
			},
		},
	}
}

func TestValidateReceiptProfile_BaseHappyPath(t *testing.T) {
	rp := validProfile()
	if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
		t.Fatalf("expected no issues, got:\n%s", strings.Join(issues, "\n"))
	}
}

// TestValidateReceiptProfile_CommittedExample exercises the committed
// profiles/EXAMPLE.json. If a maintainer ever edits the file by hand, the
// schema invariants encoded here catch invalid combinations before review.
func TestValidateReceiptProfile_CommittedExample(t *testing.T) {
	path := filepath.Join("..", "profiles", "EXAMPLE.json")
	rp := mustLoadReceiptProfile(t, path)
	if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
		t.Fatalf("profiles/EXAMPLE.json has issues:\n%s", strings.Join(issues, "\n"))
	}
}

// TestValidateReceiptProfile_CommittedPipelock exercises the committed
// profiles/pipelock.json. The done-state requires this artifact be a
// fresh runner emission, but the structural validator catches drift if
// someone hand-edits it later.
func TestValidateReceiptProfile_CommittedPipelock(t *testing.T) {
	path := filepath.Join("..", "profiles", "pipelock.json")
	rp := mustLoadReceiptProfile(t, path)
	if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
		t.Fatalf("profiles/pipelock.json has issues:\n%s", strings.Join(issues, "\n"))
	}
}

func TestValidateReceiptProfile_RejectsBadSchemaVersion(t *testing.T) {
	rp := validProfile()
	rp.SchemaVersion = 2
	expectIssueMatch(t, rp, "schema_version must be 1")
}

func TestValidateReceiptProfile_RejectsBadCorpusSHA(t *testing.T) {
	rp := validProfile()
	rp.CorpusSHA256 = "not-a-sha"
	expectIssueMatch(t, rp, "corpus_sha256")
}

func TestValidateReceiptProfile_RejectsUppercaseSHA(t *testing.T) {
	rp := validProfile()
	rp.CorpusSHA256 = strings.Repeat("A", 64) // valid hex but uppercase
	expectIssueMatch(t, rp, "corpus_sha256")
}

func TestValidateReceiptProfile_RejectsInvalidBlockedValue(t *testing.T) {
	rp := validProfile()
	rp.PerCase[0].Blocked = "maybe"
	expectIssueMatch(t, rp, `blocked must be yes|no|n/a`)
}

func TestValidateReceiptProfile_RejectsInvalidExplainedValue(t *testing.T) {
	rp := validProfile()
	rp.PerCase[0].Explained = "n/a"
	expectIssueMatch(t, rp, "explained must be yes|no")
}

func TestValidateReceiptProfile_RejectsBlockedAndFalsePositiveBoth(t *testing.T) {
	// Forbidden: blocked=yes AND false_positive=yes (a case cannot be both
	// a malicious block and a benign baseline FP).
	rp := validProfile()
	rp.PerCase[0].Blocked = "yes"
	rp.PerCase[0].FalsePositive = "yes"
	rp.Summary.FalsePositiveYesCount = 1
	expectIssueMatch(t, rp, "blocked/false_positive must split")
}

func TestValidateReceiptProfile_RejectsBenignWithBlockedResult(t *testing.T) {
	// Forbidden: blocked=yes/no on a benign case (the rubric forces n/a).
	rp := validProfile()
	rp.PerCase[1].Blocked = "yes"
	rp.PerCase[1].FalsePositive = "no"
	rp.Summary.BlockedYesCount = 2
	expectIssueMatch(t, rp, "blocked/false_positive must split")
}

func TestValidateReceiptProfile_RejectsVerifiableWithoutReceipt(t *testing.T) {
	// Forbidden: receipt_independently_verifiable=yes when
	// receipt_produced=no.
	rp := validProfile()
	rp.PerCase[0].ReceiptIndependentlyVerifiable = "yes"
	expectIssueMatch(t, rp, "receipt_independently_verifiable must be \"no\" when receipt_produced=\"no\"")
}

func TestValidateReceiptProfile_RejectsPartialWithoutReceipt(t *testing.T) {
	// Same invariant: partial verifiability also requires a receipt to exist.
	rp := validProfile()
	rp.PerCase[0].ReceiptIndependentlyVerifiable = "partial"
	expectIssueMatch(t, rp, "receipt_independently_verifiable must be \"no\" when receipt_produced=\"no\"")
}

func TestValidateReceiptProfile_RejectsSummaryMismatch(t *testing.T) {
	rp := validProfile()
	rp.Summary.BlockedYesCount = 99
	expectIssueMatch(t, rp, "summary.blocked_yes_count=99, per_case sum=1")
}

func TestValidateReceiptProfile_RejectsDuplicateCaseID(t *testing.T) {
	rp := validProfile()
	rp.PerCase[1].CaseID = rp.PerCase[0].CaseID
	expectIssueMatch(t, rp, "duplicate case_id")
}

// TestReceiptProfile_RoundTrip confirms the on-disk encoding matches the
// in-memory struct and the validator accepts the round-tripped form.
func TestReceiptProfile_RoundTrip(t *testing.T) {
	rp := validProfile()
	path := filepath.Join(t.TempDir(), "rp.json")
	if err := writeReceiptProfile(rp, path); err != nil {
		t.Fatalf("writeReceiptProfile: %v", err)
	}
	loaded := mustLoadReceiptProfile(t, path)
	if issues := ValidateReceiptProfile(loaded); len(issues) != 0 {
		t.Fatalf("round-trip validation failed:\n%s", strings.Join(issues, "\n"))
	}
	if loaded.Summary != rp.Summary {
		t.Fatalf("summary changed across round-trip: got %+v want %+v", loaded.Summary, rp.Summary)
	}
	if len(loaded.PerCase) != len(rp.PerCase) {
		t.Fatalf("per_case length changed: got %d want %d", len(loaded.PerCase), len(rp.PerCase))
	}
}

// TestReceiptProfile_WriteIsByteDeterministic confirms the encoder produces
// identical bytes for the same input across two writes. The runner relies
// on this to satisfy the kickoff's byte-reproducibility requirement.
func TestReceiptProfile_WriteIsByteDeterministic(t *testing.T) {
	rp := validProfile()
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := writeReceiptProfile(rp, a); err != nil {
		t.Fatalf("writeReceiptProfile a: %v", err)
	}
	if err := writeReceiptProfile(rp, b); err != nil {
		t.Fatalf("writeReceiptProfile b: %v", err)
	}
	aData, err := os.ReadFile(a)
	if err != nil {
		t.Fatalf("read a: %v", err)
	}
	bData, err := os.ReadFile(b)
	if err != nil {
		t.Fatalf("read b: %v", err)
	}
	if string(aData) != string(bData) {
		t.Fatalf("two writes of the same profile produced different bytes")
	}
}

func TestLoadReceiptVerifier_EmptyPathYieldsDegraded(t *testing.T) {
	v, err := loadReceiptVerifier("")
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if v.Shipped || v.OpenSource {
		t.Fatalf("empty path should produce shipped=false open_source=false, got %+v", v)
	}
	if v.VerifierURL != nil || v.License != nil || v.ExitCodeContract != nil {
		t.Fatalf("empty path should null all string fields, got %+v", v)
	}
}

func TestLoadReceiptVerifier_CommittedPipelock(t *testing.T) {
	path := filepath.Join("..", "examples", "pipelock", "receipt-verifier.json")
	v, err := loadReceiptVerifier(path)
	if err != nil {
		t.Fatalf("loadReceiptVerifier: %v", err)
	}
	if !v.Shipped || !v.OpenSource {
		t.Fatalf("expected shipped=true open_source=true, got %+v", v)
	}
	if v.VerifierURL == nil || *v.VerifierURL == "" {
		t.Fatal("expected non-empty verifier_url")
	}
	if v.License == nil || *v.License != "Apache-2.0" {
		t.Fatalf("expected license=Apache-2.0, got %v", v.License)
	}
	if v.ExitCodeContract == nil || *v.ExitCodeContract == "" {
		t.Fatal("expected non-empty exit_code_contract")
	}
}

func TestLoadReceiptVerifier_MalformedFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReceiptVerifier(path); err == nil {
		t.Fatal("expected error for malformed verifier file")
	}
}

func TestLoadReceiptVerifier_RejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verifier.json")
	data := `{"shipped":true,"open_source":true,"verifier_url":"https://example.invalid","license":"Apache-2.0","exit_code_contract":"0 valid, 1 invalid","extra":true}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadReceiptVerifier(path); err == nil {
		t.Fatal("expected error for unknown verifier field")
	}
}

// TestBuildReceiptProfile_PerCaseShape walks the build function with a
// synthetic set of results covering all five rubric branches so changes to
// the mapping logic (blocked / explained / false_positive) break here
// instead of leaking into the runner output silently.
func TestBuildReceiptProfile_PerCaseShape(t *testing.T) {
	profile := Profile{Tool: "example-tool", ToolVersion: "0.0.0"}
	verifier := ReceiptVerifier{}
	zeros := strings.Repeat("0", 64)
	applicable := []CaseResult{
		{CaseID: "mal-blocked-explained", ExpectedVerdict: "block", ActualVerdict: "block", Evidence: map[string]interface{}{"scanner": "dlp"}},
		{CaseID: "mal-blocked-silent", ExpectedVerdict: "block", ActualVerdict: "block", Evidence: map[string]interface{}{}},
		{CaseID: "mal-missed", ExpectedVerdict: "block", ActualVerdict: "allow", Evidence: map[string]interface{}{}},
		{CaseID: "benign-allowed", ExpectedVerdict: "allow", ActualVerdict: "allow", Evidence: map[string]interface{}{}},
		{CaseID: "benign-fp", ExpectedVerdict: "allow", ActualVerdict: "block", Evidence: map[string]interface{}{"block_reason": "fp"}},
	}
	rp := buildReceiptProfile(profile, applicable, verifier, "v2.0.0", zeros, zeros)

	if got, want := len(rp.PerCase), len(applicable); got != want {
		t.Fatalf("per_case length: got %d want %d", got, want)
	}
	// Sorted by case_id (lexicographically): benign-allowed, benign-fp, mal-blocked-explained, mal-blocked-silent, mal-missed.
	wantOrder := []string{"benign-allowed", "benign-fp", "mal-blocked-explained", "mal-blocked-silent", "mal-missed"}
	for i, id := range wantOrder {
		if rp.PerCase[i].CaseID != id {
			t.Errorf("per_case[%d].case_id = %q, want %q", i, rp.PerCase[i].CaseID, id)
		}
	}

	if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
		t.Fatalf("buildReceiptProfile output failed validation:\n%s", strings.Join(issues, "\n"))
	}

	// Summary cross-check: 1 blocked_yes (with evidence), 1 blocked_no
	// (silent), 1 mal-missed (blocked_no), 1 false_positive_yes.
	if rp.Summary.BlockedYesCount != 2 {
		t.Errorf("blocked_yes_count = %d, want 2", rp.Summary.BlockedYesCount)
	}
	if rp.Summary.BlockedNoCount != 1 {
		t.Errorf("blocked_no_count = %d, want 1", rp.Summary.BlockedNoCount)
	}
	if rp.Summary.ExplainedYesCount != 2 {
		// The silent-block has explained=no; the explained-block and the
		// fp (which has block_reason) both have explained=yes.
		t.Errorf("explained_yes_count = %d, want 2", rp.Summary.ExplainedYesCount)
	}
	if rp.Summary.FalsePositiveYesCount != 1 {
		t.Errorf("false_positive_yes_count = %d, want 1", rp.Summary.FalsePositiveYesCount)
	}
}

func mustLoadReceiptProfile(t *testing.T, path string) ReceiptProfile {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var rp ReceiptProfile
	if err := decodeStrictJSON(data, &rp); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return rp
}

func expectIssueMatch(t *testing.T, rp ReceiptProfile, substr string) {
	t.Helper()
	issues := ValidateReceiptProfile(rp)
	if len(issues) == 0 {
		t.Fatalf("expected issue containing %q, got none", substr)
	}
	for _, issue := range issues {
		if strings.Contains(issue, substr) {
			return
		}
	}
	t.Fatalf("expected issue containing %q, got:\n%s", substr, strings.Join(issues, "\n"))
}
