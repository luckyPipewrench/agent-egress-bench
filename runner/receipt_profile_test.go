package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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
		SchemaVersion:     3,
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
	expectIssueMatch(t, rp, "schema_version must be 3")
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
	expectIssueMatch(t, rp, "blocked/false_positive must be")
}

func TestValidateReceiptProfile_RejectsBenignWithBlockedResult(t *testing.T) {
	// Forbidden: blocked=yes/no on a benign case (the rubric forces n/a).
	rp := validProfile()
	rp.PerCase[1].Blocked = "yes"
	rp.PerCase[1].FalsePositive = "no"
	rp.Summary.BlockedYesCount = 2
	expectIssueMatch(t, rp, "blocked/false_positive must be")
}

func TestReceiptProfileSchemaAllowsUnmeasuredRow(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "schemas", "receipt-scoring-profile.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	properties, ok := schema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("schema properties missing")
	}
	perCase, ok := properties["per_case"].(map[string]interface{})
	if !ok {
		t.Fatal("per_case schema missing")
	}
	items, ok := perCase["items"].(map[string]interface{})
	if !ok {
		t.Fatal("per_case item schema missing")
	}
	allOf, ok := items["allOf"].([]interface{})
	if !ok || len(allOf) == 0 {
		t.Fatal("per_case allOf missing")
	}
	axis, ok := allOf[0].(map[string]interface{})
	if !ok {
		t.Fatal("per_case axis invariant missing")
	}
	shapes, ok := axis["oneOf"].([]interface{})
	if !ok {
		t.Fatal("per_case axis shapes missing")
	}
	for _, rawShape := range shapes {
		shape, ok := rawShape.(map[string]interface{})
		if !ok {
			continue
		}
		shapeProperties, ok := shape["properties"].(map[string]interface{})
		if !ok {
			continue
		}
		blocked, blockedOK := shapeProperties["blocked"].(map[string]interface{})
		falsePositive, fpOK := shapeProperties["false_positive"].(map[string]interface{})
		if blockedOK && fpOK && blocked["const"] == "n/a" && falsePositive["const"] == "n/a" {
			return
		}
	}
	t.Fatal("receipt schema does not allow the unmeasured blocked=false_positive=n/a row")
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
	rp := buildReceiptProfile(profile, applicable, nil, verifier, "v2.0.0", zeros, zeros)

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

func TestBuildReceiptProfile_ReceiptObservation(t *testing.T) {
	helper := receiptVerifierHelper(t)

	tests := []struct {
		name           string
		configure      func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration)
		wantProduced   string
		wantVerifiable string
		wantReason     string
	}{
		{
			name:           "no declaration preserves existing no/no",
			configure:      nil,
			wantProduced:   "no",
			wantVerifiable: "no",
		},
		{
			name: "receipt present and verify passes",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "yes",
			wantVerifiable: "yes",
		},
		{
			name: "no matching receipt fails closed",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/other?token=[sample-value]")
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "no",
			wantVerifiable: "no",
			wantReason:     "no matching receipt found",
		},
		{
			name: "receipt present and verify fails",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				decl.VerifyCommand = []string{helper, "1"}
			},
			wantProduced:   "yes",
			wantVerifiable: "no",
			wantReason:     "verifier exit code 1",
		},
		{
			name: "verifier missing records reason",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				decl.VerifyCommand = []string{filepath.Join(dir, "missing-verifier")}
			},
			wantProduced:   "yes",
			wantVerifiable: "no",
			wantReason:     "verifier could not run",
		},
		{
			name: "verifier timeout records reason",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				sleeper := filepath.Join(dir, "sleep-verifier.sh")
				if err := os.WriteFile(sleeper, []byte("#!/bin/sh\nsleep 3\nexit 0\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				decl.VerifyCommand = []string{sleeper}
				decl.VerifyTimeoutSeconds = 1
			},
			wantProduced:   "yes",
			wantVerifiable: "no",
			wantReason:     "verifier timed out",
		},
		{
			name: "correlation ambiguous fails closed",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "a.jsonl"), "https://example.test/collect?token=[redacted-value]")
				writeReceiptEvidence(t, filepath.Join(dir, "b.jsonl"), "https://example.test/collect?token=[redacted-value]")
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "no",
			wantVerifiable: "no",
			wantReason:     "ambiguous receipt correlation",
		},
		{
			name: "redacted target correlates",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[redacted-value]")
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "yes",
			wantVerifiable: "yes",
		},
		{
			// A declared partial exit code is the only route to
			// receipt_independently_verifiable=partial. The shared assertion
			// block runs ValidateReceiptProfile on every case, so this also
			// covers the schema rule that partial requires receipt_produced=yes.
			name: "declared partial exit code yields partial",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				decl.VerifyCommand = []string{helper, "2"}
				decl.PartialExitCodes = []int{2}
			},
			wantProduced:   "yes",
			wantVerifiable: "partial",
		},
		{
			// A profile that references environment variables declares a setup
			// contract the runner cannot enforce. An unset variable must name
			// itself rather than expanding to an empty argument and failing as
			// though the receipt were bad.
			name: "unset verifier environment variable names itself",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidence(t, filepath.Join(dir, "evidence.jsonl"), "https://example.test/collect?token=[sample-value]")
				decl.VerifyCommand = []string{helper, "--key", "$AEB_TEST_PUBKEY_UNSET"}
			},
			wantProduced:   "yes",
			wantVerifiable: "no",
			wantReason:     "verifier environment not set: AEB_TEST_PUBKEY_UNSET",
		},
		{
			// Documented correlation order puts the case-ID pointer first. The
			// receipt's target deliberately does NOT match the case URL, so a
			// pass here can only come from the case-ID path and not from
			// identifier matching falling through.
			name: "case id pointer correlates without a matching identifier",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidenceCaseID(t, filepath.Join(dir, "evidence.jsonl"),
					"url-dlp-token-001", "https://example.test/unrelated")
				decl.RecordCaseIDJSONPointer = "/action_record/case_id"
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "yes",
			wantVerifiable: "yes",
		},
		{
			// A receipt carrying a redacted body easily exceeds bufio.Scanner's
			// 64 KiB default. Without an enlarged buffer the scan stops with
			// bufio.ErrTooLong and the row reports unreadable evidence.
			name: "record larger than the default scanner buffer is read",
			configure: func(t *testing.T, dir string, decl *ReceiptEvidenceDeclaration) {
				writeReceiptEvidencePadded(t, filepath.Join(dir, "evidence.jsonl"),
					"https://example.test/collect?token=[sample-value]", 256*1024)
				decl.VerifyCommand = []string{helper, "0"}
			},
			wantProduced:   "yes",
			wantVerifiable: "yes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			profile := Profile{Tool: "example-tool", ToolVersion: "0.0.0"}
			if tt.configure != nil {
				decl := baseReceiptEvidenceDeclaration(dir, helper)
				tt.configure(t, dir, &decl)
				profile.ReceiptEvidence = &decl
			}
			rp := buildReceiptProfile(
				profile,
				[]CaseResult{receiptObservationCaseResult()},
				map[string]Case{"url-dlp-token-001": receiptObservationCase()},
				ReceiptVerifier{},
				"v2.0.0",
				strings.Repeat("0", 64),
				strings.Repeat("0", 64),
			)
			if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
				t.Fatalf("profile validation failed:\n%s", strings.Join(issues, "\n"))
			}
			row := rp.PerCase[0]
			if row.ReceiptProduced != tt.wantProduced {
				t.Fatalf("receipt_produced = %q, want %q (row=%+v)", row.ReceiptProduced, tt.wantProduced, row)
			}
			if row.ReceiptIndependentlyVerifiable != tt.wantVerifiable {
				t.Fatalf("receipt_independently_verifiable = %q, want %q (row=%+v)", row.ReceiptIndependentlyVerifiable, tt.wantVerifiable, row)
			}
			if tt.wantReason != "" && !strings.Contains(row.ReceiptObservationReason, tt.wantReason) {
				t.Fatalf("receipt_observation_reason = %q, want substring %q", row.ReceiptObservationReason, tt.wantReason)
			}
			if tt.wantProduced == "yes" && rp.Summary.ReceiptProducedYesCount != 1 {
				t.Fatalf("receipt_produced_yes_count = %d, want 1", rp.Summary.ReceiptProducedYesCount)
			}
			if tt.wantVerifiable == "yes" && rp.Summary.ReceiptIndependentlyVerifiableYesCount != 1 {
				t.Fatalf("receipt_independently_verifiable_yes_count = %d, want 1", rp.Summary.ReceiptIndependentlyVerifiableYesCount)
			}
		})
	}
}

func TestBuildReceiptProfile_EvidenceDirUnreadableFailsClosed(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read chmod 000 directories")
	}
	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidenceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(evidenceDir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(evidenceDir, 0o700) })

	decl := baseReceiptEvidenceDeclaration(evidenceDir, receiptVerifierHelper(t))
	profile := Profile{Tool: "example-tool", ToolVersion: "0.0.0", ReceiptEvidence: &decl}
	rp := buildReceiptProfile(
		profile,
		[]CaseResult{receiptObservationCaseResult()},
		map[string]Case{"url-dlp-token-001": receiptObservationCase()},
		ReceiptVerifier{},
		"v2.0.0",
		strings.Repeat("0", 64),
		strings.Repeat("0", 64),
	)
	row := rp.PerCase[0]
	if row.ReceiptProduced != "no" || row.ReceiptIndependentlyVerifiable != "no" {
		t.Fatalf("unreadable evidence dir should fail closed, got row=%+v", row)
	}
	if !strings.Contains(row.ReceiptObservationReason, "receipt evidence unavailable") {
		t.Fatalf("receipt_observation_reason = %q, want unavailable reason", row.ReceiptObservationReason)
	}
}

func TestRunReceiptVerifierTimeoutKillsOrphanHoldingOutputPipe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("verifier teardown relies on a POSIX shell and process groups")
	}
	script := filepath.Join(t.TempDir(), "orphan-verifier.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n( while :; do :; done ) &\nwhile :; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	result := runReceiptVerifier("unused-evidence.jsonl", ReceiptEvidenceDeclaration{
		VerifyCommand:        []string{script},
		VerifyTimeoutSeconds: 1,
	})
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("receipt verifier returned after %v; group kill should finish before WaitDelay", elapsed)
	}
	if !strings.Contains(result.reason, "verifier timed out") {
		t.Fatalf("reason = %q, want verifier timeout", result.reason)
	}
}

func baseReceiptEvidenceDeclaration(dir, helper string) ReceiptEvidenceDeclaration {
	return ReceiptEvidenceDeclaration{
		EvidenceDir:                 dir,
		FileGlob:                    "*.jsonl",
		JSONLRecordType:             "action_receipt",
		DetailJSONPointer:           "/detail",
		DetailEncoding:              "object_or_json_string",
		RecordIdentifierJSONPointer: "/action_record/target",
		CaseIdentifierJSONPointer:   "/payload/url",
		VerifyCommand:               []string{helper, "0"},
		VerifyTimeoutSeconds:        2,
		ValidExitCodes:              []int{0},
	}
}

func receiptObservationCase() Case {
	return Case{
		ID:              "url-dlp-token-001",
		ExpectedVerdict: "block",
		Payload: map[string]interface{}{
			"url": "https://example.test/collect?token=[sample-value]",
		},
	}
}

func receiptObservationCaseResult() CaseResult {
	return CaseResult{
		CaseID:          "url-dlp-token-001",
		ExpectedVerdict: "block",
		ActualVerdict:   "block",
		Evidence:        map[string]interface{}{"scanner": "dlp"},
	}
}

func writeReceiptEvidence(t *testing.T, path, target string) {
	t.Helper()
	detail := map[string]interface{}{
		"action_record": map[string]interface{}{
			"target":  target,
			"verdict": "block",
		},
		"signature": "ed25519:synthetic",
	}
	entry := map[string]interface{}{
		"type":   "action_receipt",
		"detail": detail,
	}
	data, err := jsonMarshalLine(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeReceiptEvidenceCaseID writes one receipt that carries an explicit case ID
// alongside a target. Callers pass a target that does not match the case URL so
// that correlation can only succeed through the case-ID pointer.
func writeReceiptEvidenceCaseID(t *testing.T, path, caseID, target string) {
	t.Helper()
	detail := map[string]interface{}{
		"action_record": map[string]interface{}{
			"case_id": caseID,
			"target":  target,
			"verdict": "block",
		},
		"signature": "ed25519:synthetic",
	}
	entry := map[string]interface{}{
		"type":   "action_receipt",
		"detail": detail,
	}
	data, err := jsonMarshalLine(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeReceiptEvidencePadded writes one receipt whose serialized line exceeds
// padBytes, so the record is larger than bufio.Scanner's default buffer.
func writeReceiptEvidencePadded(t *testing.T, path, target string, padBytes int) {
	t.Helper()
	detail := map[string]interface{}{
		"action_record": map[string]interface{}{
			"target":  target,
			"verdict": "block",
		},
		"signature":     "ed25519:synthetic",
		"redacted_body": strings.Repeat("x", padBytes),
	}
	entry := map[string]interface{}{
		"type":   "action_receipt",
		"detail": detail,
	}
	data, err := jsonMarshalLine(entry)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= padBytes {
		t.Fatalf("padded record is %d bytes, want more than %d", len(data), padBytes)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func jsonMarshalLine(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func receiptVerifierHelper(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipt-verifier-helper.sh")
	script := "#!/bin/sh\nif [ \"$1\" = \"0\" ]; then exit 0; fi\necho verifier failed\nexit \"$1\"\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
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

// A runner-layer error is not a measurement, so it must not be scored as an
// outcome on either axis. Before this guard, a malicious error row recorded
// blocked="no" (reading as an observed failure to block) and a benign error
// row recorded false_positive="no" (silently crediting the tool for a correct
// allow nobody observed). Both directions are asserted here.
func TestBuildReceiptProfile_ErrorRowsAreNotScoredAsOutcomes(t *testing.T) {
	profile := Profile{Tool: "example-tool", ToolVersion: "0.0.0"}
	verifier := ReceiptVerifier{}
	zeros := strings.Repeat("0", 64)
	applicable := []CaseResult{
		{CaseID: "mal-errored", ExpectedVerdict: "block", ActualVerdict: "error", Evidence: map[string]interface{}{}},
		{CaseID: "benign-errored", ExpectedVerdict: "allow", ActualVerdict: "error", Evidence: map[string]interface{}{}},
	}
	rp := buildReceiptProfile(profile, applicable, nil, verifier, "v2.0.0", zeros, zeros)

	if got := len(rp.PerCase); got != 2 {
		t.Fatalf("per_case length: got %d want 2 (error rows stay visible)", got)
	}
	for _, row := range rp.PerCase {
		if row.Blocked != "n/a" {
			t.Errorf("%s: blocked = %q, want \"n/a\"; an unmeasured case must not assert a containment outcome", row.CaseID, row.Blocked)
		}
		if row.FalsePositive != "n/a" {
			t.Errorf("%s: false_positive = %q, want \"n/a\"; an unmeasured case must not assert a false-positive outcome", row.CaseID, row.FalsePositive)
		}
	}

	if rp.Summary.BlockedNoCount != 0 {
		t.Errorf("blocked_no_count = %d, want 0; an error is not an observed failure to block", rp.Summary.BlockedNoCount)
	}
	if rp.Summary.BlockedYesCount != 0 {
		t.Errorf("blocked_yes_count = %d, want 0", rp.Summary.BlockedYesCount)
	}
	if rp.Summary.FalsePositiveYesCount != 0 {
		t.Errorf("false_positive_yes_count = %d, want 0", rp.Summary.FalsePositiveYesCount)
	}
	if rp.Summary.ExplainedYesCount != 0 {
		t.Errorf("explained_yes_count = %d, want 0", rp.Summary.ExplainedYesCount)
	}

	if issues := ValidateReceiptProfile(rp); len(issues) != 0 {
		t.Fatalf("error-row output failed schema validation:\n%s", strings.Join(issues, "\n"))
	}
}
