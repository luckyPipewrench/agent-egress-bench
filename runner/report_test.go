package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
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
				"case_id": "mcp-chain-budget-003", "tool": "example-tool", "tool_version": "1.2.3",
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
	fixture.summary["tool_support"].(map[string]interface{})["claims"] = []interface{}{strings.Join(terms, " ")}
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

func newReportFixture() *reportFixture {
	return &reportFixture{
		summary: map[string]interface{}{
			"gauntlet_version": "1.0", "scoring_version": "2.4", "runner_version": "0.4.2",
			"tool": "example-tool", "tool_version": "1.2.3", "corpus_version": "v2.3.0",
			"corpus_sha256": strings.Repeat("a", 64), "tool_profile_sha256": strings.Repeat("b", 64),
			"adapter_id": "example", "adapter_owner": "Example Lab",
			"target_config_ref": "/etc/example/target.yaml", "target_config_sha256": strings.Repeat("e", 64),
			"date": "2026-08-05T12:00:00Z",
			"case_count": map[string]interface{}{
				"total": 2, "applicable": 2, "not_applicable": 0,
				"not_applicable_reasons": map[string]interface{}{}, "errors": 0,
			},
			"tool_support": map[string]interface{}{
				"claims":                 []interface{}{"url_dlp", "ssrf"},
				"unsupported_transports": []interface{}{"a2a"},
				"unsupported_requires":   []interface{}{"dns_rebinding_fixture"},
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
			{"case_id": "url-attack-001", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "block", "actual_verdict": "block", "score": "pass", "evidence": map[string]interface{}{}, "notes": ""},
			{"case_id": "url-benign-002", "tool": "example-tool", "tool_version": "1.2.3", "expected_verdict": "allow", "actual_verdict": "allow", "score": "pass", "evidence": map[string]interface{}{}, "notes": ""},
		},
		command:    "./runner --adapter example --scan-token fixture-secret --cases ./cases --profile ./profile.json",
		entrypoint: "./run-gauntlet.sh --output-dir ./artifacts",
	}
}

func (f *reportFixture) write(t *testing.T, dir string) {
	t.Helper()
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
	for _, name := range []string{
		"case-index.json", "corpus-manifest.txt", "pipelock-release.json", "pipelock-version.txt",
		"checksums.txt", "runner.stderr", "make-stats.txt",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("fixture material\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hashes := map[string]interface{}{}
	for key, name := range reportEvidenceFiles {
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
		"case_count":          f.summary["case_count"],
		"scores":              f.summary["scores"],
	}
	f.decision["evidence_sha256"] = hashes
	writeFixtureJSON(t, filepath.Join(dir, "run-bundle.json"), f.bundle)
	writeFixtureJSON(t, filepath.Join(dir, "execution-decision.json"), f.decision)
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
