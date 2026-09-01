package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateReportGoldens = flag.Bool("update-report-goldens", false, "update buyer-report golden files")

func TestBuyerReportGoldens(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*reportFixture)
	}{
		{name: "healthy"},
		{name: "not-applicable", mutate: func(f *reportFixture) {
			f.summary["case_count"] = map[string]interface{}{
				"total": 3, "applicable": 2, "not_applicable": 1,
				"not_applicable_reasons": map[string]interface{}{"missing_requires": 1}, "errors": 0,
			}
			f.results = append(f.results, map[string]interface{}{
				"schema_version": 4, "case_id": "mcp-chain-budget-003", "tool": "example-tool", "tool_version": "1.2.3",
				"expected_verdict": "block", "actual_verdict": "not_applicable",
				"score": "not_applicable", "evidence": map[string]interface{}{},
				"notes": "not applicable: missing_requires",
			})
		}},
		{name: "unknown-verdict", mutate: func(f *reportFixture) {
			// An unrecognized verdict is malformed input. Counting it as an
			// applicable case would let it inflate the denominator of every
			// rate while the declared arithmetic still reconciled.
			f.results[1]["actual_verdict"] = "banana"
		}},
		{name: "count-mismatch", mutate: func(f *reportFixture) {
			// The summary claims more cases than results.jsonl can account for.
			// Every rate in the report is computed from these declarations, so
			// a reader has to be told the evidence does not support them.
			f.summary["case_count"] = map[string]interface{}{
				"total": 99, "applicable": 97, "not_applicable": 2,
				"not_applicable_reasons": map[string]interface{}{"missing_requires": 2}, "errors": 5,
			}
		}},
		{name: "errors", mutate: func(f *reportFixture) {
			f.summary["case_count"].(map[string]interface{})["errors"] = 1
			f.results[1]["actual_verdict"] = "error"
			f.results[1]["score"] = "error"
			f.results[1]["notes"] = "adapter error: fixture unavailable"
			f.bundle["bundle_status"] = "partial"
			f.bundle["publication_eligible"] = false
			f.decision["blocked"] = true
			f.decision["execution_status"] = "blocked"
			f.decision["publication_eligible"] = false
			f.decision["failures"] = []interface{}{"runner produced an error result"}
		}},
		{name: "not-publication-eligible", mutate: func(f *reportFixture) {
			f.bundle["publication_eligible"] = false
			f.bundle["noncanonical_reasons"] = []interface{}{"development execution"}
			f.decision["blocked"] = false
			f.decision["execution_status"] = "complete"
			f.decision["publication_eligible"] = false
			f.decision["review_notes"] = []interface{}{"development execution"}
		}},
		{name: "missing-optional", mutate: func(f *reportFixture) {
			delete(f.summary, "date")
		}},
		{name: "missing-required", mutate: func(f *reportFixture) {
			delete(f.summary, "scoring_version")
		}},
		{name: "malformed-summary", mutate: func(f *reportFixture) {
			f.malformedSummary = true
		}},
		{name: "exercised-capabilities", mutate: func(f *reportFixture) {
			// A run that actually drove several surfaces reports them, so the
			// exercised profile is distinct from the declared claims.
			f.summary["exercised"] = map[string]interface{}{
				"transports":      []interface{}{"fetch_proxy", "mcp_http"},
				"categories":      []interface{}{"mcp_input", "url"},
				"capability_tags": []interface{}{"mcp_input_scan", "url_dlp"},
			}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newReportFixture()
			if tt.mutate != nil {
				tt.mutate(fixture)
			}
			dir := t.TempDir()
			fixture.write(t, dir)
			report, err := loadBuyerReport(dir)
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			report.renderMarkdown(&got)
			golden := filepath.Join("testdata", "buyer-report", tt.name+".golden.md")
			if *updateReportGoldens {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, got.Bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("report differs from %s\n--- got ---\n%s\n--- want ---\n%s", golden, got.String(), string(want))
			}
		})
	}
}

func TestBuyerReportBlocksRestrictedClaimLanguageFromArtifacts(t *testing.T) {
	fixture := newReportFixture()
	var terms []string
	for _, pattern := range reportRestrictedClaims {
		sample := sampleForRestrictedPattern(pattern.String())
		// Without this the test proves nothing: a sample that does not match
		// its own pattern would be filtered by no rule, and the assertions
		// below would pass on language the gate never actually blocks.
		if !pattern.MatchString(sample) {
			t.Fatalf("sample %q does not match its restricted pattern %s", sample, pattern.String())
		}
		terms = append(terms, sample)
	}
	fixture.summary["tool"] = strings.Join(terms, " ")
	fixture.summary["reported_claims"] = []interface{}{strings.Join(terms, " ")}
	fixture.command = strings.Join(terms, " ")
	fixture.entrypoint = strings.Join(terms, " ")
	dir := t.TempDir()
	fixture.write(t, dir)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	for _, pattern := range reportRestrictedClaims {
		if pattern.Match(output.Bytes()) {
			t.Errorf("restricted claim pattern %q reached report output", pattern)
		}
	}
}

func TestBuyerReportRequiresV5ManifestDigestInCandidateScope(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["schema_version"] = 5
	fixture.summary["benchmark_manifest_sha256"] = strings.Repeat("c", 64)
	fixture.summary["diagnostics"] = map[string]interface{}{
		"full":       map[string]interface{}{},
		"applicable": map[string]interface{}{},
	}
	dir := t.TempDir()
	fixture.write(t, dir)

	delete(fixture.bundle["candidate_scope"].(map[string]interface{}), "benchmark_manifest_sha256")
	writeFixtureJSON(t, filepath.Join(dir, "run-bundle.json"), fixture.bundle)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.bundleValidation(); !strings.Contains(got, "candidate_scope.benchmark_manifest_sha256 does not match raw-summary.json") {
		t.Fatalf("bundleValidation() = %q, want v5 manifest identity failure", got)
	}
}

func TestBuyerReportRefusesUnboundV4Registry(t *testing.T) {
	fixture := newReportFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "capability-registry.json"), []byte(`{"id":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	if !strings.Contains(output.String(), "## Result unavailable") || strings.Contains(output.String(), "## Method identity") {
		t.Fatalf("v4 report rendered despite an unbound registry:\n%s", output.String())
	}
}

func TestBuyerReportRefusesReceiptProfileWithMismatchedRegistryReference(t *testing.T) {
	fixture := newReportFixture()
	dir := t.TempDir()
	fixture.write(t, dir)

	// The receipt profile is valid on its own and its retained digest is updated
	// in both provenance records. Its registry reference alone belongs to a
	// different run, so only an explicit cross-artifact binding can reject it.
	receipt := validProfile()
	receipt.SchemaVersion = v4SchemaVersion
	receipt.Tool = fixture.summary["tool"].(string)
	receipt.ToolVersion = fixture.summary["tool_version"].(string)
	receipt.CorpusVersion = fixture.summary["corpus_version"].(string)
	receipt.CorpusSHA256 = fixture.summary["corpus_sha256"].(string)
	receipt.ToolProfileSHA256 = fixture.summary["tool_profile_sha256"].(string)
	receipt.CapabilityRegistry.ID = "aeb.other-capabilities"
	receipt.CapabilityRegistry.Format = 1
	receipt.CapabilityRegistry.Revision = 1
	receipt.CapabilityRegistry.SHA256 = strings.Repeat("f", 64)
	if issues := ValidateReceiptProfile(receipt); len(issues) != 0 {
		t.Fatalf("test receipt profile is invalid: %v", issues)
	}
	writeFixtureJSON(t, filepath.Join(dir, "receipt-profile.json"), receiptProfileFixtureValue(receipt))

	receiptBytes, err := os.ReadFile(filepath.Join(dir, "receipt-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	receiptDigest := sha256.Sum256(receiptBytes)
	hashes := fixture.bundle["evidence_sha256"].(map[string]interface{})
	hashes["receipt_profile"] = hex.EncodeToString(receiptDigest[:])
	writeFixtureJSON(t, filepath.Join(dir, "run-bundle.json"), fixture.bundle)
	writeFixtureJSON(t, filepath.Join(dir, "execution-decision.json"), fixture.decision)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	if !strings.Contains(output.String(), "## Result unavailable") {
		t.Fatalf("report accepted a receipt profile bound to a different registry:\n%s", output.String())
	}
}

func TestBuyerReportRefusesV5ReceiptProfileWithMismatchedManifestDigest(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)

	receiptPath := filepath.Join(dir, "receipt-profile.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.BenchmarkManifestSHA256 = strings.Repeat("0", 64)
	writeFixtureJSON(t, receiptPath, receipt)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem := report.receiptProfileBindingError(receipt.CapabilityRegistry); problem != "receipt profile benchmark manifest digest does not match the result" {
		t.Fatalf("receipt profile manifest binding = %q", problem)
	}
}

func TestBuyerReportRefusesSyntheticV5SummaryWithV4Receipt(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	receiptPath := filepath.Join(dir, "receipt-profile.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.SchemaVersion = v4SchemaVersion
	writeFixtureJSON(t, receiptPath, receiptProfileFixtureValue(receipt))
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem := report.receiptProfileBindingError(receipt.CapabilityRegistry); problem != "v5 result requires a v5 receipt profile" {
		t.Fatalf("mixed-version binding = %q", problem)
	}
}

func TestBuyerReportRefusesCleanCorpusCommitContradiction(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	receiptPath := filepath.Join(dir, "receipt-profile.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.CorpusGitSHA = strings.Repeat("d", 40)
	writeFixtureJSON(t, receiptPath, receipt)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem := report.receiptProfileBindingError(receipt.CapabilityRegistry); problem != "receipt profile corpus Git commit does not match the result method commit" {
		t.Fatalf("corpus Git binding = %q", problem)
	}
}

func TestBuyerReportRefusesNonCleanCorpusForPublication(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	receiptPath := filepath.Join(dir, "receipt-profile.json")
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt ReceiptProfile
	if err := decodeStrictJSON(data, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.CorpusGitStatus = corpusGitStatusUnavailable
	receipt.CorpusGitSHA = ""
	writeFixtureJSON(t, receiptPath, receipt)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem := report.receiptProfileBindingError(receipt.CapabilityRegistry); problem != "v5 receipt profile requires clean corpus Git provenance for publication" {
		t.Fatalf("corpus Git binding = %q", problem)
	}
}

func TestV4ReceiptProfileBindingStaysReadableAfterActiveSchemaAdvances(t *testing.T) {
	fixture := newReportFixture()
	dir := t.TempDir()
	fixture.write(t, dir)

	// This is intentionally a literal v4 receipt beside a literal v4 result.
	// When activeReceiptProfileSchemaVersion advances, this historical pair must remain
	// readable rather than being compared to the schema used for new output.
	receipt := validProfile()
	receipt.SchemaVersion = 4
	receipt.Tool = fixture.summary["tool"].(string)
	receipt.ToolVersion = fixture.summary["tool_version"].(string)
	receipt.CorpusVersion = fixture.summary["corpus_version"].(string)
	receipt.CorpusSHA256 = fixture.summary["corpus_sha256"].(string)
	receipt.ToolProfileSHA256 = fixture.summary["tool_profile_sha256"].(string)
	receipt.CapabilityRegistry.ID = fixture.summary["capability_registry"].(map[string]interface{})["id"].(string)
	receipt.CapabilityRegistry.Format = fixture.summary["capability_registry"].(map[string]interface{})["format"].(int)
	receipt.CapabilityRegistry.Revision = fixture.summary["capability_registry"].(map[string]interface{})["revision"].(int)
	receipt.CapabilityRegistry.SHA256 = fixture.summary["capability_registry"].(map[string]interface{})["sha256"].(string)
	if issues := ValidateReceiptProfile(receipt); len(issues) != 0 {
		t.Fatalf("test receipt profile is invalid: %v", issues)
	}
	writeFixtureJSON(t, filepath.Join(dir, "receipt-profile.json"), receiptProfileFixtureValue(receipt))

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if problem := report.receiptProfileBindingError(receipt.CapabilityRegistry); problem != "" {
		t.Fatalf("v4 receipt profile was rejected after an active-schema advance: %s", problem)
	}
}

func TestBuyerReportMarksNotApplicableRowCountMismatchInvalid(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["case_count"].(map[string]interface{})["not_applicable"] = 1
	fixture.summary["case_count"].(map[string]interface{})["applicable"] = 1
	fixture.summary["case_count"].(map[string]interface{})["not_applicable_reasons"] = map[string]interface{}{"missing_requires": 1}
	dir := t.TempDir()
	fixture.write(t, dir)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	if !strings.Contains(output.String(), "summary declares 1 not-applicable cases but results.jsonl contains 0") {
		t.Fatalf("report did not expose N/A row mismatch:\n%s", output.String())
	}
}

func TestBuyerReportTracksUnreachableRowsWithoutReclassifyingThem(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 3, "applicable": 2, "unreachable": 1, "not_applicable": 0,
		"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
	}
	fixture.results = append(fixture.results, map[string]interface{}{
		"schema_version": 4, "case_id": "mcp-stdio-definition-001", "tool": "example-tool", "tool_version": "1.2.3",
		"expected_verdict": "block", "actual_verdict": "unreachable", "score": "error",
		"evidence": map[string]interface{}{"result_state": "unreachable"},
		"notes":    "unreachable: adapter has no exact delivery route for this case",
	})
	dir := t.TempDir()
	fixture.write(t, dir)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if failures := report.summaryScopeFailures(); len(failures) != 0 {
		t.Fatalf("summary scope failures = %v", failures)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	if !strings.Contains(output.String(), "- Unreachable cases: 1") {
		t.Fatalf("report did not surface unreachable count:\n%s", output.String())
	}
}

func TestBuyerReportCallsErrorInclusiveApplicableCountRouted(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["case_count"].(map[string]interface{})["errors"] = 1
	fixture.results[1]["actual_verdict"] = "error"
	fixture.results[1]["score"] = "error"
	fixture.results[1]["notes"] = "adapter error: fixture unavailable"
	fixture.bundle["bundle_status"] = "partial"
	fixture.bundle["publication_eligible"] = false
	fixture.decision["blocked"] = true
	fixture.decision["execution_status"] = "blocked"
	fixture.decision["publication_eligible"] = false
	dir := t.TempDir()
	fixture.write(t, dir)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	if !strings.Contains(output.String(), "- Routed cases: 2") {
		t.Fatalf("report presented an error-inclusive routed count as observed applicability:\n%s", output.String())
	}
}

func sampleForRestrictedPattern(pattern string) string {
	samples := map[string]string{
		`(?i)leaderboards?`:                        "leaderboard",
		`(?i)certif(?:ied|ication|ications|ies|y)`: "certified",
		`(?i)proofstamp`:                           "proofstamp",
		`(?i)neutral benchmark`:                    "neutral benchmark",
		`(?i)proven secure`:                        "proven secure",
		`(?i)no bypass(?:es)?\b`:                   "no bypass",
		`(?i)unbypassable`:                         "unbypassable",
		`(?i)insurance discount`:                   "insurance discount",
		`(?i)\bFIPS\b`:                             "FIPS",
		`(?i)all prox(?:y|ies)[- ]based`:           "all proxy-based",
	}
	if value, ok := samples[pattern]; ok {
		return value
	}
	return "restricted-claim"
}

type reportFixture struct {
	summary          map[string]interface{}
	metadata         map[string]interface{}
	bundle           map[string]interface{}
	decision         map[string]interface{}
	results          []map[string]interface{}
	command          string
	entrypoint       string
	malformedSummary bool
}

func publicationFixture() *reportFixture {
	fixture := newReportFixture()
	fixture.summary["schema_version"] = 5
	fixture.summary["scoring_version"] = scoringVersion
	fixture.summary["method_repository"] = "example/agent-egress-bench"
	fixture.summary["method_commit"] = strings.Repeat("c", 40)
	fixture.summary["benchmark_manifest_sha256"] = strings.Repeat("f", 64)
	fixture.summary["measurement_status"] = measurementStatusMeasured
	fixture.summary["case_count"].(map[string]interface{})["unreachable"] = 0
	fixture.summary["diagnostics"] = map[string]interface{}{
		"full": map[string]interface{}{}, "applicable": map[string]interface{}{},
	}
	fixture.summary["scores"].(map[string]interface{})["full"] = map[string]interface{}{
		"containment": 1.0, "false_positive_rate": 0.0,
	}
	fixture.summary["exercised"] = map[string]interface{}{
		"transports": []interface{}{"http_proxy"}, "categories": []interface{}{"url"},
		"capability_tags": []interface{}{"url_dlp"},
	}
	for _, row := range fixture.results {
		row["schema_version"] = activeResultSchemaVersion
		row["scoring_version"] = scoringVersion
	}
	return fixture
}

func TestPublicationLockupCarriesMethodScopeAndScores(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	if err := generatePublicationLockup(dir, output, []string{"self-run"}, "https://lab.example/results/run-1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range []string{
		"**example-tool 1.2.3 — Agent Egress Bench result**",
		"Publisher-declared assurance: **self run**",
		"example/agent-egress-bench@cccccccccccccccccccccccccccccccccccccccc",
		"2 total · 2 applicable · 2 passed · 0 failed · 0 unreachable · 0 not applicable · 0 errors",
		"containment 100.00% (1/1 malicious cases; case-equal weighting from corpus composition) · false-positive rate 0.00% (0/1 benign cases; case-equal weighting from corpus composition)",
		"Corpus Git observation: `clean` · tool version observation: `observed`",
		"Exercised transports: http\\_proxy",
		"internal consistency only",
		"not a certification, accreditation, audit, endorsement",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("lockup missing %q:\n%s", want, got)
		}
	}
}

func categoryProfileFixture() *reportFixture {
	fixture := publicationFixture()
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 5, "applicable": 4, "unreachable": 1, "not_applicable": 0,
		"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
	}
	fixture.summary["scores"] = map[string]interface{}{
		"full":       map[string]interface{}{"containment": 0.5, "false_positive_rate": 0.5},
		"applicable": map[string]interface{}{"containment": 0.5, "false_positive_rate": 0.5},
	}
	fixture.results = []map[string]interface{}{
		{"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion, "case_id": "url-attack-001", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "block", "score": "pass", "evidence": map[string]interface{}{"result_state": "observed"}, "notes": ""},
		{"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion, "case_id": "url-benign-002", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "allow", "score": "pass", "evidence": map[string]interface{}{"result_state": "observed"}, "notes": ""},
		{"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion, "case_id": "mcp-drift-attack-003", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "allow", "score": "fail", "evidence": map[string]interface{}{"result_state": "observed"}, "notes": ""},
		{"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion, "case_id": "headers-benign-004", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "block", "score": "fail", "evidence": map[string]interface{}{"result_state": "observed"}, "notes": ""},
		{"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion, "case_id": "mcp-tool-attack-005", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "unreachable", "score": "error", "evidence": map[string]interface{}{"result_state": "unreachable"}, "notes": ""},
	}
	return fixture
}

func categoryProfileIndex() map[string]interface{} {
	return map[string]interface{}{
		"schema_version": 3,
		"cases": map[string]interface{}{
			"url-attack-001":       map[string]interface{}{"category": "url", "expected_verdict": "block", "transport": "http_proxy", "capability_tags": []interface{}{"url_dlp"}},
			"url-benign-002":       map[string]interface{}{"category": "url", "expected_verdict": "allow", "transport": "http_proxy", "capability_tags": []interface{}{"url_dlp"}},
			"mcp-drift-attack-003": map[string]interface{}{"category": "mcp_drift", "expected_verdict": "block", "transport": "mcp_http", "capability_tags": []interface{}{"mcp_input_scan"}},
			"headers-benign-004":   map[string]interface{}{"category": "headers", "expected_verdict": "allow", "transport": "http_proxy", "capability_tags": []interface{}{"header_dlp"}},
			"mcp-tool-attack-005":  map[string]interface{}{"category": "mcp_tool", "expected_verdict": "block", "transport": "mcp_stdio", "capability_tags": []interface{}{"mcp_input_scan"}},
		},
	}
}

func writeBoundReportEvidence(t *testing.T, fixture *reportFixture, dir, key, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	for _, document := range []map[string]interface{}{fixture.bundle, fixture.decision} {
		document["evidence_sha256"].(map[string]interface{})[key] = hex.EncodeToString(digest[:])
	}
	writeFixtureJSON(t, filepath.Join(dir, "run-bundle.json"), fixture.bundle)
	writeFixtureJSON(t, filepath.Join(dir, "execution-decision.json"), fixture.decision)
}

func writeCategoryProfileIndex(t *testing.T, fixture *reportFixture, dir string, index map[string]interface{}) {
	t.Helper()
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writeBoundReportEvidence(t, fixture, dir, "case_index", "case-index.json", data)
}

func TestBuyerReportRendersBoundCategoryProfile(t *testing.T) {
	fixture := categoryProfileFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	writeCategoryProfileIndex(t, fixture, dir, categoryProfileIndex())

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	for _, want := range []string{
		"### Applicable-only malicious category profile",
		"### Applicable-only benign category profile",
		"evidence of category coverage and concentration, not a score or ranking",
		"| headers | 0 / 0 | N/A | 0.00% |",
		"| mcp\\_drift | 0 / 1 | 0.00% | 50.00% |",
		"| mcp\\_tool | 0 / 0 | N/A | 0.00% |",
		"| url | 1 / 1 | 100.00% | 50.00% |",
		"| headers | 1 / 1 | 100.00% | 50.00% |",
		"| mcp\\_drift | 0 / 0 | N/A | 0.00% |",
		"| mcp\\_tool | 0 / 0 | N/A | 0.00% |",
		"| url | 0 / 1 | 0.00% | 50.00% |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("category profile missing %q:\n%s", want, got)
		}
	}
}

// A run that observed no malicious case at all still gets a profile. The
// zero-denominator branch of matchesApplicableContainment requires that
// scores.applicable.containment be present and null, because a run with nothing
// to measure must publish an absent rate rather than a zero one.
func TestBuyerReportRendersProfileWhenNoMaliciousCaseWasObserved(t *testing.T) {
	fixture := categoryProfileFixture()
	for _, row := range fixture.results {
		if row["expected_verdict"] != "block" {
			continue
		}
		row["actual_verdict"] = "unreachable"
		row["score"] = "error"
		row["evidence"] = map[string]interface{}{"result_state": "unreachable"}
	}
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 5, "applicable": 2, "unreachable": 3, "not_applicable": 0,
		"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
	}
	fixture.summary["scores"] = map[string]interface{}{
		"full":       map[string]interface{}{"containment": nil, "false_positive_rate": 0.5},
		"applicable": map[string]interface{}{"containment": nil, "false_positive_rate": 0.5},
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	writeCategoryProfileIndex(t, fixture, dir, categoryProfileIndex())

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	if !strings.Contains(got, "### Applicable-only malicious category profile") {
		t.Fatalf("profile section missing:\n%s", got)
	}
	if strings.Contains(got, "Unavailable:") {
		t.Errorf("a run with no observed malicious case must still render a profile:\n%s", got)
	}
	// Every malicious category has a zero denominator, so each must read N/A
	// rather than 0%, which would assert a containment the run never measured.
	for _, want := range []string{
		"| mcp\\_drift | 0 / 0 | N/A | N/A |",
		"| url | 0 / 0 | N/A | N/A |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in:\n%s", want, got)
		}
	}
}

// A run that observed no benign case at all still gets a profile. The
// zero-denominator branch of matchesApplicableFalsePositiveRate requires that
// scores.applicable.false_positive_rate be present and null, because a run
// with nothing to measure must publish an absent rate rather than a zero one.
func TestBuyerReportRendersProfileWhenNoBenignCaseWasObserved(t *testing.T) {
	fixture := categoryProfileFixture()
	for _, row := range fixture.results {
		if row["expected_verdict"] != "allow" {
			continue
		}
		row["actual_verdict"] = "unreachable"
		row["score"] = "error"
		row["evidence"] = map[string]interface{}{"result_state": "unreachable"}
	}
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 5, "applicable": 2, "unreachable": 3, "not_applicable": 0,
		"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
	}
	fixture.summary["scores"] = map[string]interface{}{
		"full":       map[string]interface{}{"containment": 0.5, "false_positive_rate": nil},
		"applicable": map[string]interface{}{"containment": 0.5, "false_positive_rate": nil},
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	writeCategoryProfileIndex(t, fixture, dir, categoryProfileIndex())

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	if !strings.Contains(got, "### Applicable-only benign category profile") {
		t.Fatalf("profile section missing:\n%s", got)
	}
	if strings.Contains(got, "Unavailable:") {
		t.Errorf("a run with no observed benign case must still render a profile:\n%s", got)
	}
	// Every benign category has a zero denominator, so each must read N/A
	// rather than 0%, which would assert a false-positive rate the run never
	// measured.
	for _, want := range []string{
		"| headers | 0 / 0 | N/A | N/A |",
		"| url | 0 / 0 | N/A | N/A |",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in:\n%s", want, got)
		}
	}
}

// Category names come from case-index.json, which is untrusted run input, so
// they must pass the claim-language gate like every other artifact-derived
// string in this renderer. Without that, a category named for a certification
// would render verbatim in a buyer report.
func TestBuyerReportWithholdsRestrictedCategoryClaim(t *testing.T) {
	fixture := categoryProfileFixture()
	index := categoryProfileIndex()
	index["cases"].(map[string]interface{})["url-attack-001"].(map[string]interface{})["category"] = "fips-certified"
	index["cases"].(map[string]interface{})["url-benign-002"].(map[string]interface{})["category"] = "fips-certified"
	dir := t.TempDir()
	fixture.write(t, dir)
	writeCategoryProfileIndex(t, fixture, dir, index)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	if strings.Contains(got, "fips-certified") {
		t.Errorf("a restricted claim in a category name reached the report:\n%s", got)
	}
	if !strings.Contains(got, "Artifact value withheld by claim-language gate") {
		t.Errorf("expected the claim-language gate to withhold the category:\n%s", got)
	}
}

func TestBuyerReportMarksInvalidCategoryProfileUnavailable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, fixture *reportFixture, dir string)
		want   string
	}{
		{name: "missing index", mutate: func(t *testing.T, _ *reportFixture, dir string) {
			if err := os.Remove(filepath.Join(dir, "case-index.json")); err != nil {
				t.Fatal(err)
			}
		}, want: "Unavailable: case-index.json is absent or unreadable."},
		{name: "missing results", mutate: func(t *testing.T, _ *reportFixture, dir string) {
			if err := os.Remove(filepath.Join(dir, "results.jsonl")); err != nil {
				t.Fatal(err)
			}
		}, want: "Unavailable: results.jsonl is absent or unreadable."},
		{name: "malformed index", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			writeBoundReportEvidence(t, fixture, dir, "case_index", "case-index.json", []byte("{"))
		}, want: "Unavailable: case-index.json is malformed."},
		// Named for what it proves. Unparseable rows fail loadReportResults
		// first, so summaryScopeFailures answers and the profile parser is
		// never reached. The case below reaches that parser.
		{name: "unparseable results fail the scope check first", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			writeBoundReportEvidence(t, fixture, dir, "results", "results.jsonl", []byte("{"))
		}, want: "Unavailable: the summary scope does not match the retained result rows."},
		// Rows that loadReportResults accepts but the profile parser rejects:
		// an observed malicious row whose evidence carries no result_state.
		// Both the v5 and v6 result schemas require that field, so a row
		// without it is invalid for its own schema rather than merely old.
		{name: "observed row without a result state", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			rows := make([]map[string]interface{}, len(fixture.results))
			copy(rows, fixture.results)
			stripped := map[string]interface{}{}
			for k, v := range rows[0] {
				stripped[k] = v
			}
			stripped["evidence"] = map[string]interface{}{}
			rows[0] = stripped
			var encoded []byte
			for _, row := range rows {
				line, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				encoded = append(encoded, line...)
				encoded = append(encoded, '\n')
			}
			writeBoundReportEvidence(t, fixture, dir, "results", "results.jsonl", encoded)
		}, want: "Unavailable: results.jsonl has an invalid row."},
		{name: "results digest mismatch", mutate: func(t *testing.T, _ *reportFixture, dir string) {
			data, err := os.ReadFile(filepath.Join(dir, "results.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), append(data, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "Unavailable: results.jsonl does not match its retained digest."},
		{name: "summary scope mismatch", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			fixture.summary["case_count"].(map[string]interface{})["total"] = 6
			writeFixtureJSON(t, filepath.Join(dir, "raw-summary.json"), fixture.summary)
		}, want: "Unavailable: the summary scope does not match the retained result rows."},
		{name: "scope mismatch", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			index := categoryProfileIndex()
			index["cases"].(map[string]interface{})["url-attack-001"].(map[string]interface{})["expected_verdict"] = "allow"
			writeCategoryProfileIndex(t, fixture, dir, index)
		}, want: "Unavailable: the case index and result rows have different case IDs or expected verdicts."},
		{name: "applicable containment mismatch", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			fixture.summary["scores"].(map[string]interface{})["applicable"].(map[string]interface{})["containment"] = 0.75
			writeFixtureJSON(t, filepath.Join(dir, "raw-summary.json"), fixture.summary)
		}, want: "Unavailable: the applicable containment does not match the bound result rows."},
		{name: "applicable false-positive rate mismatch", mutate: func(t *testing.T, fixture *reportFixture, dir string) {
			fixture.summary["scores"].(map[string]interface{})["applicable"].(map[string]interface{})["false_positive_rate"] = 0.25
			writeFixtureJSON(t, filepath.Join(dir, "raw-summary.json"), fixture.summary)
		}, want: "Unavailable: the applicable false-positive rate does not match the bound result rows."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := categoryProfileFixture()
			dir := t.TempDir()
			fixture.write(t, dir)
			writeCategoryProfileIndex(t, fixture, dir, categoryProfileIndex())
			tt.mutate(t, fixture, dir)
			report, err := loadBuyerReport(dir)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			report.renderMarkdown(&output)
			got := output.String()
			if !strings.Contains(got, tt.want) {
				t.Fatalf("report did not mark profile unavailable as expected:\n%s", got)
			}
			if !strings.Contains(got, "- Containment: 50.00%") {
				t.Fatalf("profile failure hid the primary score:\n%s", got)
			}
			if !strings.Contains(got, "- False-positive rate:") {
				t.Fatalf("profile failure hid the primary false-positive rate:\n%s", got)
			}
		})
	}
}

func TestBuyerReportHeadlinesCarryApplicableProfileDenominators(t *testing.T) {
	fixture := categoryProfileFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	writeCategoryProfileIndex(t, fixture, dir, categoryProfileIndex())

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	for _, want := range []string{
		"- Containment: 50.00% (1/2 malicious cases; case-equal weighting from corpus composition)",
		"- False-positive rate: 50.00% (1/2 benign cases; case-equal weighting from corpus composition)",
	} {
		if strings.Count(got, want) != 2 {
			t.Fatalf("headline denominator %q did not appear in both metric scopes:\n%s", want, got)
		}
	}
}

func TestBuyerReportHeadlinesDoNotBorrowFullCorpusDenominators(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 3, "applicable": 2, "not_applicable": 1,
		"not_applicable_reasons": map[string]interface{}{"missing_requires": 1}, "errors": 0,
	}
	fixture.summary["scores"] = map[string]interface{}{
		"full":       map[string]interface{}{"containment": 0.5, "detection": 0.5, "evidence": 0.25, "false_positive_rate": 0.0},
		"applicable": map[string]interface{}{"containment": 1.0, "detection": 0.6, "evidence": 0.4, "false_positive_rate": 0.0},
	}
	fixture.results = append(fixture.results, map[string]interface{}{
		"schema_version": 4, "case_id": "mcp-chain-budget-003", "tool": "example-tool", "tool_version": "1.2.3",
		"expected_verdict": "block", "actual_verdict": "not_applicable", "score": "not_applicable",
		"evidence": map[string]interface{}{}, "notes": "not applicable: missing_requires",
	})
	dir := t.TempDir()
	fixture.write(t, dir)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	full := "### Full corpus\n\n- Containment: 50.00% (1/2 malicious cases; case-equal weighting from corpus composition)\n- Detection: 50.00%\n- Evidence: 25.00%\n- False-positive rate: 0.00% (0/1 benign cases; case-equal weighting from corpus composition)"
	if !strings.Contains(got, full) {
		t.Fatalf("full-corpus headlines =\n%s\nwant %q", got, full)
	}
	applicable := "### Applicable-only observed cases\n\n- Containment: 100.00%\n- Detection: 60.00%\n- Evidence: 40.00%\n- False-positive rate: 0.00%"
	if !strings.Contains(got, applicable) {
		t.Fatalf("applicable headlines borrowed a denominator or changed retired metrics:\n%s", got)
	}
}

func TestBuyerReportHeadlinesOmitCountsForUnreadableResults(t *testing.T) {
	fixture := newReportFixture()
	fixture.summary["scores"] = map[string]interface{}{
		"full":       map[string]interface{}{"containment": 1.0, "detection": 0.5, "evidence": 0.25, "false_positive_rate": 0.0},
		"applicable": map[string]interface{}{"containment": 1.0, "detection": 0.6, "evidence": 0.4, "false_positive_rate": 0.0},
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	firstRow, err := json.Marshal(fixture.results[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), append(firstRow, []byte("\n{\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	if !strings.Contains(got, "- Containment: 100.00%\n") {
		t.Fatalf("unreadable results hid the percentage:\n%s", got)
	}
	if strings.Contains(got, "- Containment: 100.00% (1/1 malicious cases;") {
		t.Fatalf("unreadable results produced a confident-looking partial fraction:\n%s", got)
	}
}

func TestBuyerReportHeadlinesOmitMismatchedFractions(t *testing.T) {
	fixture := newReportFixture()
	dir := t.TempDir()
	fixture.write(t, dir)

	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	report.renderMarkdown(&output)
	got := output.String()
	if !strings.Contains(got, "- Containment: 75.00%\n") {
		t.Fatalf("mismatched rows hid the percentage:\n%s", got)
	}
	if strings.Contains(got, "- Containment: 75.00% (1/1 malicious cases;") {
		t.Fatalf("mismatched numerator and denominator were rendered beside the percentage:\n%s", got)
	}
}

func TestReportApplicablePercentRequiresAvailableProfile(t *testing.T) {
	doc := reportDocument{data: map[string]interface{}{
		"scores": map[string]interface{}{"applicable": map[string]interface{}{"containment": json.Number("0.5")}},
	}}
	profile := reportCategoryProfile{
		rows:        []reportCategoryProfileRow{{blocked: 1, malicious: 2}},
		unavailable: "the retained evidence is unavailable",
	}
	got := reportApplicablePercent(doc, profile, 2, "malicious", "scores", "applicable", "containment")
	if got != "50.00%" {
		t.Fatalf("unavailable profile rendered denominator %q", got)
	}
}

func TestReportPercentWithDenominatorOmitsZeroDenominator(t *testing.T) {
	doc := reportDocument{data: map[string]interface{}{
		"scores": map[string]interface{}{"applicable": map[string]interface{}{"containment": json.Number("0")}},
	}}
	got := reportPercentWithDenominator(doc, 0, 0, "malicious", "scores", "applicable", "containment")
	if got != "0.00%" {
		t.Fatalf("zero denominator rendered as a measurement %q", got)
	}
}

func TestPublicationLockupListsFailuresBeforeScores(t *testing.T) {
	fixture := publicationFixture()
	fixture.results[0]["actual_verdict"] = "allow"
	fixture.results[0]["score"] = "fail"
	fixture.summary["scores"].(map[string]interface{})["full"] = map[string]interface{}{
		"containment": 0.0, "false_positive_rate": 0.0,
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	manifest := []byte("url-attack-001\nurl-benign-002\n")
	if err := os.WriteFile(filepath.Join(dir, "corpus-manifest.txt"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	for _, name := range []string{"run-bundle.json", "execution-decision.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]interface{}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		document["evidence_sha256"].(map[string]interface{})["corpus_manifest"] = hex.EncodeToString(manifestDigest[:])
		writeFixtureJSON(t, filepath.Join(dir, name), document)
	}
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	if err := generatePublicationLockup(dir, output, []string{"self-run", "artifact-validated"}, "https://lab.example/results/run-1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	failure := "[url-attack-001](https://github.com/example/agent-egress-bench/blob/" + strings.Repeat("c", 40) + "/cases/MANIFEST.txt#L1): expected `block`, observed `allow`."
	if !strings.Contains(got, failure) {
		t.Fatalf("lockup missing failed-case explanation and stable link:\n%s", got)
	}
	if strings.Index(got, failure) > strings.Index(got, "containment 0.00%") {
		t.Fatalf("failed case appears after aggregate score:\n%s", got)
	}
}

func TestPublicationLockupRefusesFailureListScoreMismatch(t *testing.T) {
	fixture := publicationFixture()
	fixture.results[0]["actual_verdict"] = "allow"
	fixture.results[0]["score"] = "fail"
	dir := t.TempDir()
	fixture.write(t, dir)
	err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"self-run"}, "https://lab.example/results/run-1")
	if err == nil || !strings.Contains(err.Error(), "full containment disagrees with result rows") {
		t.Fatalf("publication lockup mismatch error = %v", err)
	}
}

func TestPublicationLockupRefusesFalsePositiveListScoreMismatch(t *testing.T) {
	fixture := publicationFixture()
	fixture.results[1]["actual_verdict"] = "block"
	fixture.results[1]["score"] = "fail"
	dir := t.TempDir()
	fixture.write(t, dir)
	err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"self-run"}, "https://lab.example/results/run-1")
	if err == nil || !strings.Contains(err.Error(), "full false-positive rate disagrees with result rows") {
		t.Fatalf("publication lockup mismatch error = %v", err)
	}
}

func TestPublicationLockupFullScoreRetainsNotApplicableRows(t *testing.T) {
	fixture := publicationFixture()
	fixture.results = append(fixture.results, map[string]interface{}{
		"schema_version": activeResultSchemaVersion, "scoring_version": scoringVersion,
		"case_id": "mcp-chain-budget-003", "tool": "example-tool", "tool_version": "1.2.3",
		"expected_verdict": "block", "actual_verdict": "not_applicable",
		"score": "not_applicable", "evidence": map[string]interface{}{},
		"notes": "not applicable: missing_requires",
	})
	fixture.summary["case_count"] = map[string]interface{}{
		"total": 3, "applicable": 2, "unreachable": 0, "not_applicable": 1,
		"not_applicable_reasons": map[string]interface{}{"missing_requires": 1}, "errors": 0,
	}
	fixture.summary["scores"].(map[string]interface{})["full"] = map[string]interface{}{
		"containment": 0.5, "false_positive_rate": 0.0,
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if failures := report.publicationScoreFailures(); len(failures) != 0 {
		t.Fatalf("full score did not retain not-applicable miss: %v", failures)
	}
	if report.rowCounts.maliciousBlocked != 1 || report.rowCounts.maliciousTotal != 2 {
		t.Fatalf("full containment counts = %d/%d, want 1/2",
			report.rowCounts.maliciousBlocked, report.rowCounts.maliciousTotal)
	}
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	if err := generatePublicationLockup(dir, output, []string{"self-run"}, "https://lab.example/results/run-1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "containment 50.00% (1/2 malicious cases; case-equal weighting from corpus composition)") {
		t.Fatalf("lockup omitted the full-corpus containment denominator:\n%s", data)
	}
}

// A malicious case can block and still score "fail": the budget rules pass a
// block only when timing evidence proves it landed on the first over-budget
// call. The producer counts that row as contained in both scores.full and
// metric_counts, so a reconciler that counted "pass" instead of the observed
// verdict computed a lower containment than the run published and refused to
// emit a lockup for a completely valid run.
func TestPublicationLockupAcceptsFailingRowThatStillBlocked(t *testing.T) {
	fixture := publicationFixture()
	fixture.results[0]["score"] = "fail"
	fixture.results[0]["evidence"] = map[string]interface{}{
		"budget_block_timing": "before_over_budget",
	}
	dir := t.TempDir()
	fixture.write(t, dir)
	manifest := []byte("url-attack-001\nurl-benign-002\n")
	if err := os.WriteFile(filepath.Join(dir, "corpus-manifest.txt"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	for _, name := range []string{"run-bundle.json", "execution-decision.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]interface{}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		document["evidence_sha256"].(map[string]interface{})["corpus_manifest"] = hex.EncodeToString(manifestDigest[:])
		writeFixtureJSON(t, filepath.Join(dir, name), document)
	}
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if failures := report.publicationScoreFailures(); len(failures) != 0 {
		t.Fatalf("blocking fail row did not reconcile against published scores: %v", failures)
	}
	if report.rowCounts.maliciousBlocked != 1 || report.rowCounts.maliciousTotal != 1 {
		t.Fatalf("full containment counts = %d/%d, want 1/1",
			report.rowCounts.maliciousBlocked, report.rowCounts.maliciousTotal)
	}
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	if err := generatePublicationLockup(dir, output, []string{"self-run"}, "https://lab.example/results/run-1"); err != nil {
		t.Fatalf("publication lockup refused a valid blocking fail row: %v", err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	// The row stays in the loss list even though containment does not penalise
	// it, so the lockup must show both the failure and the unreduced score.
	for _, want := range []string{"Failed cases:", "containment 100.00%"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("lockup missing %q:\n%s", want, string(data))
		}
	}
}

func TestStableCaseURLsUseUnambiguousPhysicalManifestLines(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "corpus-manifest.txt")
	if err := os.WriteFile(manifestPath, []byte("url-attack-001\r\nurl-benign-002\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	urls, err := report.stableCaseURLs()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(urls["url-benign-002"], "cases/MANIFEST.txt#L2") {
		t.Fatalf("second case URL = %q", urls["url-benign-002"])
	}
	for _, repository := range []string{"../agent-egress-bench", "example/..", "example/security/agent-egress-bench"} {
		report.summary.data["method_repository"] = repository
		_, err := report.stableCaseURLs()
		if err == nil || !strings.Contains(err.Error(), "owner/name pair") {
			t.Fatalf("stableCaseURLs repository %q error = %v", repository, err)
		}
	}
	report.summary.data["method_repository"] = "example/agent-egress-bench"

	for _, tt := range []struct {
		name, manifest, want string
	}{
		{"duplicate", "url-attack-001\nurl-attack-001\n", "duplicate case ID"},
		{"padded", "url-attack-001\n url-benign-002\n", "one case ID per physical line"},
		{"blank", "url-attack-001\n\n", "one case ID per physical line"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(manifestPath, []byte(tt.manifest), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := report.stableCaseURLs()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("stableCaseURLs error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPublicationLockupAcceptsEvidenceSensitiveFailure(t *testing.T) {
	fixture := publicationFixture()
	fixture.results[0]["score"] = "fail"
	dir := t.TempDir()
	fixture.write(t, dir)
	manifest := []byte("url-attack-001\nurl-benign-002\n")
	if err := os.WriteFile(filepath.Join(dir, "corpus-manifest.txt"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestDigest := sha256.Sum256(manifest)
	for _, name := range []string{"run-bundle.json", "execution-decision.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		var document map[string]interface{}
		if err := json.Unmarshal(data, &document); err != nil {
			t.Fatal(err)
		}
		document["evidence_sha256"].(map[string]interface{})["corpus_manifest"] = hex.EncodeToString(manifestDigest[:])
		writeFixtureJSON(t, filepath.Join(dir, name), document)
	}
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	if err := generatePublicationLockup(dir, output, []string{"self-run"}, "https://lab.example/results/run-1"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "expected `block`, observed `block`") {
		t.Fatalf("lockup hid evidence-sensitive failure:\n%s", data)
	}
}

func TestPublicationLockupRefusesIncompleteOrUnboundRun(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*reportFixture)
	}{
		{name: "missing-method", mutate: func(f *reportFixture) {
			delete(f.summary, "method_repository")
		}},
		{name: "missing-adapter-owner", mutate: func(f *reportFixture) {
			delete(f.summary, "adapter_owner")
		}},
		{name: "method-metadata-mismatch", mutate: func(f *reportFixture) {
			f.summary["method_commit"] = strings.Repeat("d", 40)
		}},
		{name: "incomplete-measurement", mutate: func(f *reportFixture) {
			f.summary["measurement_status"] = measurementStatusIncomplete
		}},
		{name: "invalid-manifest-digest", mutate: func(f *reportFixture) {
			f.summary["benchmark_manifest_sha256"] = "bad"
		}},
		{name: "blocked-decision", mutate: func(f *reportFixture) {
			f.decision["blocked"] = true
		}},
		{name: "ineligible-decision", mutate: func(f *reportFixture) {
			f.decision["publication_eligible"] = false
		}},
		{name: "ineligible-bundle", mutate: func(f *reportFixture) {
			f.bundle["publication_eligible"] = false
		}},
		{name: "mismatched-run-id", mutate: func(f *reportFixture) {
			f.metadata["local_run_id"] = "local:other"
		}},
		{name: "empty-coverage", mutate: func(f *reportFixture) {
			f.summary["exercised"].(map[string]interface{})["transports"] = []interface{}{}
		}},
		{name: "mixed-invalid-coverage", mutate: func(f *reportFixture) {
			f.summary["exercised"].(map[string]interface{})["transports"] = []interface{}{"0", json.Number("1")}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := publicationFixture()
			tt.mutate(fixture)
			dir := t.TempDir()
			fixture.write(t, dir)
			if err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"self-run"}, "https://lab.example/results/run-1"); err == nil {
				t.Fatal("expected publication lockup refusal")
			}
		})
	}
}

func TestPublicationLockupRefusesInvalidRetainedDecisionArtifacts(t *testing.T) {
	for _, test := range []struct {
		name    string
		content string
	}{
		{name: "malformed", content: "{"},
		{name: "empty-object", content: "{}"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := publicationFixture()
			dir := t.TempDir()
			fixture.write(t, dir)
			if err := os.WriteFile(filepath.Join(dir, "execution-decision.json"), []byte(test.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"self-run"}, "https://lab.example/results/run-1"); err == nil {
				t.Fatal("expected invalid retained decision refusal")
			}
		})
	}
}

func TestPublicationLockupRequiresAssuranceAndEvidenceURL(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	output := filepath.Join(t.TempDir(), "result-lockup.md")
	for _, test := range []struct {
		assurances []string
		url        string
	}{
		{url: "https://lab.example/results/run-1"},
		{assurances: []string{"self-run"}},
		{assurances: []string{"self-run"}, url: "http://lab.example/results/run-1"},
		{assurances: []string{"self-run"}, url: "https://certified.example/results/run-1"},
		{assurances: []string{"unknown"}, url: "https://lab.example/results/run-1"},
	} {
		if err := generatePublicationLockup(dir, output, test.assurances, test.url); err == nil {
			t.Fatalf("expected refusal for assurances=%v url=%q", test.assurances, test.url)
		}
	}
}

func TestPublicationLockupUsesTargetNeutralArtifacts(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	for _, name := range []string{"run-bundle.json", "execution-decision.json", "pipelock-release.json", "pipelock-version.txt", "checksums.txt", "make-stats.txt"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
	if err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"independently-executed"}, "https://lab.example/results/run-2"); err != nil {
		t.Fatalf("target-neutral lockup refused: %v", err)
	}
}

func TestReportRejectsActiveResultWithWrongScoringVersion(t *testing.T) {
	for _, schemaVersion := range []string{"6", "5", `"6"`} {
		t.Run(schemaVersion, func(t *testing.T) {
			row := `{"schema_version":` + schemaVersion + `,"scoring_version":"2.7","case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), reportResultsActive, scoringVersion)
			if status != "Malformed JSONL at line 1" {
				t.Fatalf("active row with schema_version %s and wrong scoring_version status = %q", schemaVersion, status)
			}
		})
	}
}

func TestReportRejectsNonIntegerSchemaVersionSpellings(t *testing.T) {
	for _, schemaVersion := range []string{"6.0", "6e0"} {
		t.Run(schemaVersion, func(t *testing.T) {
			row := `{"schema_version":` + schemaVersion + `,"scoring_version":"2.8","case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), reportResultsActive, scoringVersion)
			if status != "Malformed JSONL at line 1" {
				t.Fatalf("non-integer schema_version %s status = %q", schemaVersion, status)
			}
		})
	}
}

func TestReportRejectsMissingSchemaVersion(t *testing.T) {
	row := `{"case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
	for _, mode := range []reportResultMode{reportResultsFrozen, reportResultsActive} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), mode, scoringVersion)
			if status != "Malformed JSONL at line 1" {
				t.Fatalf("schema-less row in mode %d status = %q", mode, status)
			}
		})
	}
}

func TestReportRejectsActiveRowsWhenSummaryScorerIsMissing(t *testing.T) {
	fixture := publicationFixture()
	delete(fixture.summary, "scoring_version")
	dir := t.TempDir()
	fixture.write(t, dir)
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.resultErr != "Malformed JSONL at line 1" {
		t.Fatalf("active rows without a summary scorer status = %q", report.resultErr)
	}
}

// Summary v5 spans frozen v5 rows and active v6 rows.
func TestReportReadsFrozenRowsUnderActiveSummary(t *testing.T) {
	rows := []string{
		`{"schema_version":5,"case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`,
		`{"schema_version":5,"case_id":"url-benign-002","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"allow","actual_verdict":"allow","score":"pass","evidence":{"result_state":"observed"},"notes":""}`,
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, counts, status := loadReportResults(filepath.Join(dir, "results.jsonl"), reportResultsActive, scoringVersion)
	if status != "Readable" || counts.total != 2 || counts.scored != 2 {
		t.Fatalf("frozen rows under an active summary status = %q, counts = %+v", status, counts)
	}
}

func TestReportRejectsRowsOlderOrNewerThanTheirSummary(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    reportResultMode
		version int
	}{
		{name: "v4-row-under-v5-summary", mode: reportResultsActive, version: reportFrozenResultSchemaVersion},
		{name: "v5-row-under-v4-summary", mode: reportResultsFrozen, version: reportRetainedResultSchemaVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := fmt.Sprintf(`{"schema_version":%d,"case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`, tc.version)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), tc.mode, scoringVersion)
			if status != "Malformed JSONL at line 1" {
				t.Fatalf("schema %d row in mode %d status = %q", tc.version, tc.mode, status)
			}
		})
	}
}

// Frozen rows predate scorer binding and cannot declare a scorer.
func TestReportRejectsFrozenRowDeclaringScorerUnderActiveSummary(t *testing.T) {
	row := `{"schema_version":5,"scoring_version":"` + scoringVersion + `","case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), reportResultsActive, scoringVersion)
	if status != "Malformed JSONL at line 1" {
		t.Fatalf("frozen row declaring a scorer status = %q", status)
	}
}

// Mixed active and frozen rows would leave part of one result file unbound.
func TestReportRejectsMixedScorerBoundAndFrozenRows(t *testing.T) {
	active := `{"schema_version":6,"scoring_version":"` + scoringVersion + `","case_id":"url-attack-001","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"block","actual_verdict":"block","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
	frozen := `{"schema_version":5,"case_id":"url-benign-002","tool":"example-tool","tool_version":"1.2.3","expected_verdict":"allow","actual_verdict":"allow","score":"pass","evidence":{"result_state":"observed"},"notes":""}`
	for name, rows := range map[string][]string{
		"frozen-after-active": {active, frozen},
		"active-after-frozen": {frozen, active},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, _, status := loadReportResults(filepath.Join(dir, "results.jsonl"), reportResultsActive, scoringVersion)
			if status != "Malformed JSONL at line 2" {
				t.Fatalf("mixed row versions status = %q", status)
			}
		})
	}
}

func TestPublicationLockupRefusesBrokenRegistryBinding(t *testing.T) {
	fixture := publicationFixture()
	dir := t.TempDir()
	fixture.write(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "tool-profile.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := generatePublicationLockup(dir, filepath.Join(t.TempDir(), "result-lockup.md"), []string{"self-run"}, "https://lab.example/results/run-3"); err == nil {
		t.Fatal("expected registry binding refusal")
	}
}

func newReportFixture() *reportFixture {
	return &reportFixture{
		summary: map[string]interface{}{
			"schema_version": 4, "gauntlet_version": "1.0", "scoring_version": "2.4", "runner_version": "0.4.2",
			"tool": "example-tool", "tool_version": "1.2.3", "corpus_version": "v2.3.0",
			"corpus_sha256": strings.Repeat("a", 64), "tool_profile_sha256": strings.Repeat("b", 64),
			"capability_registry": map[string]interface{}{"id": "aeb.core-capabilities", "format": 1, "revision": 1, "sha256": strings.Repeat("d", 64)},
			"reported_claims":     []interface{}{"url_dlp", "ssrf"},
			"exercised":           map[string]interface{}{"capability_tags": []interface{}{}},
			"adapter_id":          "example", "adapter_owner": "Example Lab",
			"target_config_ref": "/etc/example/target.yaml", "target_config_sha256": strings.Repeat("e", 64),
			"date": "2026-08-05T12:00:00Z",
			"case_count": map[string]interface{}{
				"total": 2, "applicable": 2, "not_applicable": 0,
				"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
			},
			"scores": map[string]interface{}{
				"full":       map[string]interface{}{"containment": 0.75, "detection": 0.5, "evidence": 0.25, "false_positive_rate": 0.1},
				"applicable": map[string]interface{}{"containment": 0.8, "detection": 0.6, "evidence": 0.4, "false_positive_rate": 0.0},
			},
		},
		metadata: map[string]interface{}{
			"schema_version": 1, "local_run_id": "local:test", "corpus_repository": "example/agent-egress-bench",
			"corpus_git_sha": strings.Repeat("c", 40),
		},
		bundle: map[string]interface{}{
			"schema_version": 1, "bundle_status": "complete", "local_run_id": "local:test", "publication_eligible": true,
			"noncanonical_reasons": []interface{}{},
		},
		decision: map[string]interface{}{
			"schema_version": 1, "local_run_id": "local:test", "blocked": false,
			"execution_status": "complete", "publication_eligible": true,
			"failures": []interface{}{}, "review_notes": []interface{}{},
		},
		results: []map[string]interface{}{
			{"schema_version": 4, "case_id": "url-attack-001", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "block", "score": "pass", "evidence": map[string]interface{}{}, "notes": ""},
			{"schema_version": 4, "case_id": "url-benign-002", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "allow", "score": "pass", "evidence": map[string]interface{}{}, "notes": ""},
		},
		command:    "./runner --adapter example --scan-token fixture-secret --cases ./cases --profile ./profile.json",
		entrypoint: "./run-gauntlet.sh --output-dir ./artifacts",
	}
}

func (f *reportFixture) write(t *testing.T, dir string) {
	t.Helper()
	snapshot := []byte(`{"id":"aeb.core-capabilities","format":1,"revision":1,"entries":[{"id":"url_dlp","status":"active","introduced_revision":1,"title":"URL DLP","description":"Reporting label"},{"id":"mcp_input_scan","status":"active","introduced_revision":1,"title":"MCP input scanning","description":"Reporting label"},{"id":"ssrf","status":"active","introduced_revision":1,"title":"SSRF","description":"Reporting label"}]}`)
	snapshotDigest := sha256.Sum256(snapshot)
	registry := map[string]interface{}{
		"id": "aeb.core-capabilities", "format": 1, "revision": 1,
		"sha256": hex.EncodeToString(snapshotDigest[:]),
	}
	f.summary["capability_registry"] = registry
	profile := map[string]interface{}{
		"schema_version":      4,
		"tool":                f.summary["tool"],
		"tool_version":        f.summary["tool_version"],
		"runner_version":      f.summary["runner_version"],
		"claims":              f.summary["reported_claims"],
		"capability_registry": registry,
	}
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	profileDigest := sha256.Sum256(profileBytes)
	f.summary["tool_profile_sha256"] = hex.EncodeToString(profileDigest[:])
	writeFixtureJSON(t, filepath.Join(dir, "run-metadata.json"), f.metadata)
	if f.malformedSummary {
		if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte("{\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	} else {
		writeFixtureJSON(t, filepath.Join(dir, "raw-summary.json"), f.summary)
	}
	var rows bytes.Buffer
	enc := json.NewEncoder(&rows)
	for _, row := range f.results {
		if err := enc.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), rows.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "command.txt"), []byte(f.command+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "entrypoint-command.txt"), []byte(f.entrypoint+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receipt := validProfile()
	receipt.SchemaVersion = v4SchemaVersion
	if f.summary["schema_version"] == 5 {
		receipt.SchemaVersion = activeReceiptProfileSchemaVersion
		if manifest, ok := f.summary["benchmark_manifest_sha256"].(string); ok && sha256HexPattern.MatchString(manifest) {
			receipt.BenchmarkManifestSHA256 = manifest
		}
	}
	receipt.Tool = f.summary["tool"].(string)
	receipt.ToolVersion = f.summary["tool_version"].(string)
	receipt.CorpusVersion = f.summary["corpus_version"].(string)
	receipt.CorpusSHA256 = f.summary["corpus_sha256"].(string)
	if methodCommit, ok := f.summary["method_commit"].(string); ok {
		receipt.CorpusGitSHA = methodCommit
	}
	receipt.ToolProfileSHA256 = f.summary["tool_profile_sha256"].(string)
	receipt.CapabilityRegistry.ID = registry["id"].(string)
	receipt.CapabilityRegistry.Format = registry["format"].(int)
	receipt.CapabilityRegistry.Revision = registry["revision"].(int)
	receipt.CapabilityRegistry.SHA256 = registry["sha256"].(string)
	if issues := ValidateReceiptProfile(receipt); len(issues) != 0 {
		t.Fatalf("fixture receipt profile is invalid: %v", issues)
	}
	writeFixtureJSON(t, filepath.Join(dir, "receipt-profile.json"), receiptProfileFixtureValue(receipt))
	for _, name := range []string{
		"case-index.json", "corpus-manifest.txt", "pipelock-release.json", "pipelock-version.txt",
		"checksums.txt", "runner.stderr", "make-stats.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture material\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "tool-profile.json"), profileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "capability-registry.json"), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	hashes := map[string]interface{}{}
	evidenceFiles := make(map[string]string, len(reportEvidenceFiles)+3)
	for key, name := range reportEvidenceFiles {
		evidenceFiles[key] = name
	}
	evidenceFiles["tool_profile"] = "tool-profile.json"
	evidenceFiles["capability_registry"] = "capability-registry.json"
	evidenceFiles["receipt_profile"] = "receipt-profile.json"
	for key, name := range evidenceFiles {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		hashes[key] = hex.EncodeToString(digest[:])
	}
	f.bundle["evidence_sha256"] = hashes
	f.bundle["candidate_scope"] = map[string]interface{}{
		"corpus_git_sha":      f.metadata["corpus_git_sha"],
		"scoring_version":     f.summary["scoring_version"],
		"runner_version":      f.summary["runner_version"],
		"tool":                f.summary["tool"],
		"tool_version":        f.summary["tool_version"],
		"corpus_version":      f.summary["corpus_version"],
		"corpus_sha256":       f.summary["corpus_sha256"],
		"tool_profile_sha256": f.summary["tool_profile_sha256"],
		"capability_registry": f.summary["capability_registry"],
		"case_count":          f.summary["case_count"],
		"scores":              f.summary["scores"],
	}
	if f.summary["schema_version"] == 5 {
		f.bundle["candidate_scope"].(map[string]interface{})["benchmark_manifest_sha256"] = f.summary["benchmark_manifest_sha256"]
		f.bundle["candidate_scope"].(map[string]interface{})["diagnostics"] = f.summary["diagnostics"]
	}
	f.decision["evidence_sha256"] = hashes
	writeFixtureJSON(t, filepath.Join(dir, "run-bundle.json"), f.bundle)
	writeFixtureJSON(t, filepath.Join(dir, "execution-decision.json"), f.decision)
}

// receiptProfileFixtureValue writes a schema-v4 fixture in its original
// public shape. ReceiptProfile represents both readable historical versions
// and the active writer, so marshaling the current struct for a v4 fixture
// would add v5-only fields and change its retained-artifact digest.
func receiptProfileFixtureValue(receipt ReceiptProfile) interface{} {
	if receipt.SchemaVersion != v4SchemaVersion {
		return receipt
	}
	return struct {
		SchemaVersion      int              `json:"schema_version"`
		Tool               string           `json:"tool"`
		ToolVersion        string           `json:"tool_version"`
		CorpusVersion      string           `json:"corpus_version"`
		CorpusSHA256       string           `json:"corpus_sha256"`
		ToolProfileSHA256  string           `json:"tool_profile_sha256"`
		CapabilityRegistry interface{}      `json:"capability_registry"`
		Verifier           ReceiptVerifier  `json:"verifier"`
		Summary            ReceiptSummary   `json:"summary"`
		PerCase            []ReceiptPerCase `json:"per_case"`
	}{
		SchemaVersion:      receipt.SchemaVersion,
		Tool:               receipt.Tool,
		ToolVersion:        receipt.ToolVersion,
		CorpusVersion:      receipt.CorpusVersion,
		CorpusSHA256:       receipt.CorpusSHA256,
		ToolProfileSHA256:  receipt.ToolProfileSHA256,
		CapabilityRegistry: receipt.CapabilityRegistry,
		Verifier:           receipt.Verifier,
		Summary:            receipt.Summary,
		PerCase:            receipt.PerCase,
	}
}

func writeFixtureJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReportRestrictedClaimPatternsStayInSyncWithClaimGate(t *testing.T) {
	gate, err := os.ReadFile(filepath.Join("..", "scripts", "check_claim_language.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []string{"leaderboard", "certified", "proofstamp", "neutral benchmark", "proven secure", "no bypass", "unbypassable", "insurance discount", "FIPS", "all proxy-based"} {
		if !bytes.Contains(bytes.ToLower(gate), bytes.ToLower([]byte(sample))) && sample != "certified" && sample != "all proxy-based" {
			t.Errorf("claim gate no longer contains sample %q; update report gate intentionally", sample)
		}
	}
	if len(reportRestrictedClaims) != 10 {
		t.Fatalf("report claim pattern count = %d, want 10", len(reportRestrictedClaims))
	}
}

func TestBuyerReportRefusesInputThatCarriesNoFact(t *testing.T) {
	// The question is whether anything came out of the directory, not what the
	// directory looks like. Every predicate written against the input's shape
	// was worked around by the next input: presence let a zero-byte file
	// through, non-zero size let a symlink through, and regular-and-non-empty
	// let a JSON object of "{}" through. Each of those rendered a full report in
	// which every fact read as absent, at exit zero, so a mistyped path came
	// back as a report of a run nobody had found.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("content-from-outside-the-run\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("empty directory", func(t *testing.T) {
		if _, err := loadBuyerReport(t.TempDir()); err == nil {
			t.Fatal("loadBuyerReport accepted a directory holding no run artifacts")
		} else if !strings.Contains(err.Error(), "no run artifacts") || !strings.Contains(err.Error(), "results.jsonl") {
			t.Fatalf("error = %v, want it to say no run artifacts and name the expected files", err)
		}
	})

	t.Run("unrecognized file only", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "gauntlet-summary.json"), []byte(`{"tool":"x"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBuyerReport(dir); err == nil {
			t.Fatal("loadBuyerReport accepted a directory holding no recognized run artifact")
		}
	})

	for _, name := range reportArtifactNames {
		t.Run("zero byte "+name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBuyerReport(dir); err == nil {
				t.Errorf("loadBuyerReport accepted a directory holding only a zero-byte %s", name)
			}
		})

		t.Run("symlinked "+name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(outside, filepath.Join(dir, name)); err != nil {
				t.Skipf("cannot create a symlink here: %v", err)
			}
			if _, err := loadBuyerReport(dir); err == nil {
				t.Errorf("loadBuyerReport accepted a directory holding only a symlinked %s", name)
			}
		})
	}

	t.Run("json object carrying no field", func(t *testing.T) {
		for _, name := range []string{"raw-summary.json", "run-metadata.json", "run-bundle.json", "execution-decision.json"} {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadBuyerReport(dir); err == nil {
				t.Errorf("loadBuyerReport accepted a directory whose only %s was an empty object", name)
			}
		}
	})

	t.Run("results file parsing to zero rows", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte("\n\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBuyerReport(dir); err == nil {
			t.Error("loadBuyerReport accepted a results file describing no case")
		}
	})

	t.Run("whitespace only text artifact", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "command.txt"), []byte("   \n \n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBuyerReport(dir); err == nil {
			t.Error("loadBuyerReport accepted a whitespace-only command.txt")
		}
	})
}

func TestBuyerReportKeepsPartialRunsReportable(t *testing.T) {
	// The other direction, and the one that matters more. An over-strict guard
	// here pushes an operator into hand-assembling directories to get a report
	// at all, and a guard people work around protects nothing. One real fact is
	// enough, and each remaining fact is still reported as absent, never guessed.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("content-from-outside-the-run\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("one document is enough", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte(`{"tool":"example-tool"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBuyerReport(dir); err != nil {
			t.Fatalf("loadBuyerReport(one readable summary) = %v, want it accepted", err)
		}
	})

	t.Run("results without a summary are unbound", func(t *testing.T) {
		dir := t.TempDir()
		row := `{"case_id":"url-benign-api-call-001","actual_verdict":"allow","notes":""}` + "\n"
		if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), []byte(row), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadBuyerReport(dir); err == nil {
			t.Fatal("loadBuyerReport accepted results without a summary identity")
		}
	})

	// A symlinked results.jsonl beside a valid artifact is what exercises the
	// no-follow guard inside the streaming results reader. Without the valid
	// artifact the directory is refused before that reader ever runs, which is
	// how an earlier version of this test passed while proving nothing about it.
	t.Run("symlinked results file beside a valid artifact", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte(`{"tool":"example-tool"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "results.jsonl")); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}
		report, err := loadBuyerReport(dir)
		if err != nil {
			t.Fatalf("loadBuyerReport = %v, want the partial run accepted", err)
		}
		if !strings.Contains(report.resultErr, "not a regular file") {
			t.Errorf("results.jsonl status = %q, want it named as not a regular file", report.resultErr)
		}
		var out bytes.Buffer
		report.renderMarkdown(&out)
		if strings.Contains(out.String(), "content-from-outside-the-run") {
			t.Error("report rendered the contents of a symlinked results file")
		}
	})

	t.Run("symlinked text artifact beside a valid artifact", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte(`{"tool":"example-tool"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(dir, "command.txt")); err != nil {
			t.Skipf("cannot create a symlink here: %v", err)
		}
		report, err := loadBuyerReport(dir)
		if err != nil {
			t.Fatalf("loadBuyerReport = %v, want the partial run accepted", err)
		}
		if !strings.Contains(report.command, "not a regular file") {
			t.Errorf("command.txt status = %q, want it named as not a regular file", report.command)
		}
		var out bytes.Buffer
		report.renderMarkdown(&out)
		if strings.Contains(out.String(), "content-from-outside-the-run") {
			t.Error("report rendered the contents of a symlinked artifact")
		}
	})
}

func TestActiveProfileIsReadOnceWithoutFollowingLinks(t *testing.T) {
	// loadProfile took a path and read it with the symlink-following standard
	// call, while the digest came from the no-follow read. A link could satisfy
	// the registry check from a file outside the directory while the digest was
	// computed on something else, so validation and hashing described two
	// different files.
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(outside, []byte(`{"schema_version":4}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "tool-profile.json")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	if _, err := readRegularArtifact(dir, "tool-profile.json"); !errors.Is(err, errNotRegularArtifact) {
		t.Fatalf("readRegularArtifact(symlinked profile) = %v, want it refused as not a regular file", err)
	}
}

func TestZeroByteArtifactIsNamedRatherThanCalledReadable(t *testing.T) {
	// The results reader read no rows from an empty file, reported no error, and
	// returned "Readable", so an empty artifact beside a valid one was described
	// to the operator as readable. Each reader answered the empty case its own
	// way and this one answered it wrong, so the refusal belongs in the shared
	// opener where all of them pass through.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "raw-summary.json"), []byte(`{"tool":"example-tool"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "results.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := loadBuyerReport(dir)
	if err != nil {
		t.Fatalf("loadBuyerReport = %v, want the partial run accepted", err)
	}
	if !strings.Contains(report.resultErr, "empty file") {
		t.Errorf("results.jsonl status = %q, want it named as an empty file", report.resultErr)
	}
}
