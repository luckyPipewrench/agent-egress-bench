package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

func TestResultStateFor(t *testing.T) {
	tests := []struct {
		name      string
		result    adapter.Result
		wantState ResultState
	}{
		{name: "observed allow", result: adapter.Result{Verdict: "allow", DeliveryProven: true, VerdictObserved: true}, wantState: ResultStateObserved},
		{name: "observed block", result: adapter.Result{Verdict: "block", DeliveryProven: true, VerdictObserved: true}, wantState: ResultStateObserved},
		{name: "delivery unavailable", result: adapter.Result{Verdict: "allow", VerdictObserved: true}, wantState: ResultStateDeliveryUnavailable},
		{name: "verdict unobservable", result: adapter.Result{Verdict: "skip", DeliveryProven: true}, wantState: ResultStateVerdictUnobservable},
		{name: "adapter error", result: adapter.Result{Err: errors.New("fixture unavailable")}, wantState: ResultStateAdapterError},
		{name: "invalid observed verdict", result: adapter.Result{Verdict: "warn", DeliveryProven: true, VerdictObserved: true}, wantState: ResultStateInvalidVerdict},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := resultStateFor(tt.result)
			if got != tt.wantState {
				t.Fatalf("resultStateFor() = %q, want %q", got, tt.wantState)
			}
		})
	}
}

func TestRunBadCasesDir(t *testing.T) {
	err := run("/nonexistent", filepath.Join("..", "examples", "pipelock", "tool-profile.json"),
		filepath.Join(t.TempDir(), "out.json"), 10*1e9, "dryrun", "", "", "", "", false, "", "", "", false)
	if err == nil {
		t.Fatal("expected error for nonexistent cases dir")
	}
}

func TestRunBadProfile(t *testing.T) {
	err := run(filepath.Join("..", "cases"), "/nonexistent/profile.json",
		filepath.Join(t.TempDir(), "out.json"), 10*1e9, "dryrun", "", "", "", "", false, "", "", "", false)
	if err == nil {
		t.Fatal("expected error for nonexistent profile")
	}
}

func TestRunUnknownAdapter(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	// Skip if cases or profile don't exist.
	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")
	err := run(casesDir, profilePath, outputPath, 10*1e9, "nonexistent", "", "", "", "", false, "", "", "", false)
	if err == nil {
		t.Fatal("expected error for unknown adapter")
	}
	if !strings.Contains(err.Error(), "unknown adapter") {
		t.Errorf("error should mention unknown adapter, got: %v", err)
	}
}

func TestRunIgnoresReceiptVerifierFileWithoutProfileEmission(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")
	err := run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "/nonexistent/verifier.json", "", false)
	if err != nil {
		t.Fatalf("run should ignore receipt verifier file unless profile emission is enabled: %v", err)
	}
}

func TestIntegrationNullAdapter(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	// Skip if cases or profile don't exist.
	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")

	err := run(casesDir, profilePath, outputPath, 10*1e9, "null", "", "", "", "", false, "", "", "", false)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}

	var summary GauntletSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary: %v", err)
	}

	// Null adapter allows everything, so full containment should be 0.0
	// (no malicious cases blocked).
	if summary.Scores.Full.Containment != nil && *summary.Scores.Full.Containment != 0.0 {
		t.Errorf("null adapter full containment = %f, want 0.0", *summary.Scores.Full.Containment)
	}

	// Should NOT be sufficient (0% containment < 80% gate).
	if summary.Sufficient {
		t.Error("expected sufficient=false for null adapter")
	}
}

func TestIntegrationRealCases(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	// Skip if cases or profile don't exist (e.g., CI without the full repo).
	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping integration test")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping integration test")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")

	// Run the full pipeline.
	err := run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "", "", false) // 10s
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	// Verify summary was written and is valid JSON.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}

	var summary GauntletSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary: %v", err)
	}

	// Basic sanity checks.
	if summary.Tool != "pipelock" {
		t.Errorf("tool = %q, want pipelock", summary.Tool)
	}
	if summary.GauntletVersion != gauntletVersion {
		t.Errorf("gauntlet_version = %q, want %q", summary.GauntletVersion, gauntletVersion)
	}
	if summary.RunnerVersion != runnerVersion {
		t.Errorf("runner_version = %q, want %q", summary.RunnerVersion, runnerVersion)
	}
	if summary.ScoringVersion != scoringVersion {
		t.Errorf("scoring_version = %q, want %q", summary.ScoringVersion, scoringVersion)
	}
	if summary.CaseCount.Total == 0 {
		t.Error("case_count.total should not be 0")
	}
	if summary.CaseCount.Applicable == 0 {
		t.Error("case_count.applicable should not be 0")
	}
	if summary.CaseCount.Total != summary.CaseCount.Applicable+summary.CaseCount.Unreachable+summary.CaseCount.NotApplicable {
		t.Errorf("case counts don't add up: total=%d, applicable=%d (including %d errors), unreachable=%d, na=%d",
			summary.CaseCount.Total, summary.CaseCount.Applicable,
			summary.CaseCount.Errors, summary.CaseCount.Unreachable, summary.CaseCount.NotApplicable)
	}
	if summary.CorpusSHA256 == "" {
		t.Error("corpus_sha256 should not be empty")
	}
	if summary.ToolProfileSHA256 == "" {
		t.Error("tool_profile_sha256 should not be empty")
	}
	if summary.Date == "" {
		t.Error("date should not be empty")
	}

	// In dry-run mode all applicable cases pass, so applicable containment should be 1.0.
	if summary.Scores.Applicable.Containment == nil {
		t.Error("applicable containment should not be nil when malicious cases exist")
	} else if *summary.Scores.Applicable.Containment != 1.0 {
		t.Errorf("dry-run applicable containment = %f, want 1.0", *summary.Scores.Applicable.Containment)
	}

	// Full containment exists whenever the corpus has malicious cases.
	if summary.Scores.Full.Containment == nil {
		t.Error("full containment should not be nil when malicious cases exist")
	}

	// Dry-run: no false positives.
	if summary.Scores.Applicable.FalsePositiveRate != nil && *summary.Scores.Applicable.FalsePositiveRate != 0.0 {
		t.Errorf("dry-run applicable false_positive_rate = %f, want 0.0", *summary.Scores.Applicable.FalsePositiveRate)
	}

	// Dry-run: detection and evidence are 0.0.
	if summary.Scores.Applicable.Detection != nil && *summary.Scores.Applicable.Detection != 0.0 {
		t.Errorf("dry-run applicable detection = %f, want 0.0", *summary.Scores.Applicable.Detection)
	}
	if summary.Scores.Applicable.Evidence != nil && *summary.Scores.Applicable.Evidence != 0.0 {
		t.Errorf("dry-run applicable evidence = %f, want 0.0", *summary.Scores.Applicable.Evidence)
	}

	// Should be sufficient in dry-run mode (full corpus scores used for gate).
	if !summary.Sufficient {
		t.Error("expected sufficient=true in dry-run mode")
	}

	// Per-category should have entries.
	if len(summary.PerCategory) == 0 {
		t.Error("per_category should not be empty")
	}

	// Verify N/A reasons are present if there are N/A cases.
	if summary.CaseCount.NotApplicable > 0 {
		naTotal := 0
		for _, count := range summary.CaseCount.NotApplicableReasons {
			naTotal += count
		}
		if naTotal != summary.CaseCount.NotApplicable {
			t.Errorf("N/A reason counts don't sum to total: reasons=%d, total=%d",
				naTotal, summary.CaseCount.NotApplicable)
		}
	}

	t.Logf("Summary: %d total, %d applicable, %d unreachable, %d N/A, sufficient=%v",
		summary.CaseCount.Total, summary.CaseCount.Applicable,
		summary.CaseCount.Unreachable, summary.CaseCount.NotApplicable, summary.Sufficient)
}

func TestToolVersionOverrideFlag(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")

	err := runWithOptions(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", "", "", "", false, "", "", "", false, "9.9.9-test")
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}
	var summary GauntletSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("parsing summary: %v", err)
	}
	if summary.ToolVersion != "9.9.9-test" {
		t.Errorf("summary tool_version = %q, want %q", summary.ToolVersion, "9.9.9-test")
	}
}

func TestDebugFlag_EmitsPerCaseDiagnostics(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")
	stderrStr := captureStderr(t, func() error {
		return run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "", "", true)
	})

	// With debug=true, every dryrun case produces a PASS line because the
	// synthetic adapter proves delivery and returns the expected verdict.
	if !strings.Contains(stderrStr, debugPrefix) {
		t.Error("expected at least one [DEBUG] line on stderr with debug=true, got none")
	}
	if !strings.Contains(stderrStr, "PASS") {
		t.Error("expected PASS diagnostic in debug output")
	}
}

func TestDebugFlag_OffByDefault_NoDebugLines(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	profilePath := filepath.Join("..", "examples", "pipelock", "tool-profile.json")

	if _, err := os.Stat(casesDir); os.IsNotExist(err) {
		t.Skip("cases directory not found, skipping")
	}
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Skip("profile not found, skipping")
	}

	outputPath := filepath.Join(t.TempDir(), "summary.json")
	stderrStr := captureStderr(t, func() error {
		return run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "", "", false)
	})

	// With debug=false, there must be ZERO [DEBUG] lines.
	if strings.Contains(stderrStr, debugPrefix) {
		t.Errorf("expected no [DEBUG] lines on stderr with debug=false, but found:\n%s",
			stderrStr)
	}
}

// captureStderr temporarily redirects os.Stderr to a temp file for the
// duration of fn, then returns the captured content as a string. Not
// parallel-safe (swaps a global), but run() is synchronous and these
// tests do not use t.Parallel.
func captureStderr(t *testing.T, fn func() error) string {
	t.Helper()

	tmp, tmpErr := os.CreateTemp(t.TempDir(), "stderr-capture-*.txt")
	if tmpErr != nil {
		t.Fatalf("create stderr capture file: %v", tmpErr)
	}
	tmpPath := tmp.Name()

	origStderr := os.Stderr
	os.Stderr = tmp

	err := fn()

	// Restore before reading / asserting so t.Fatal goes to the real stderr.
	_ = tmp.Close()
	os.Stderr = origStderr

	if err != nil {
		t.Fatalf("run() returned error: %v", err)
	}

	data, readErr := os.ReadFile(tmpPath)
	if readErr != nil {
		t.Fatalf("read captured stderr: %v", readErr)
	}
	return string(data)
}

// Profiles retain their v3 claims and supports fields as published metadata,
// but they no longer select cases. Changing a declaration must leave the
// adapter-proven run unchanged rather than shrinking the denominator.
func TestRunIgnoresProfileDeclaredUnsupportedForSelection(t *testing.T) {
	type caseCount struct {
		Applicable    int `json:"applicable"`
		Unreachable   int `json:"unreachable"`
		NotApplicable int `json:"not_applicable"`
	}
	countFor := func(t *testing.T, profileJSON string) caseCount {
		t.Helper()
		dir := t.TempDir()
		profilePath := filepath.Join(dir, "profile.json")
		if err := os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
			t.Fatal(err)
		}
		outPath := filepath.Join(dir, "summary.json")
		if err := run(filepath.Join("..", "cases"), profilePath, outPath,
			10*1e9, "dryrun", "", "", "", "", false, "", "", "", false); err != nil {
			t.Fatalf("run: %v", err)
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		var summary struct {
			CaseCount caseCount `json:"case_count"`
		}
		if err := json.Unmarshal(data, &summary); err != nil {
			t.Fatalf("decode summary: %v", err)
		}
		return summary.CaseCount
	}

	baseline, err := os.ReadFile(filepath.Join("..", "examples", "pipelock", "tool-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	declined := strings.Replace(string(baseline), `"crypto_dlp_scanning": true`, `"crypto_dlp_scanning": false`, 1)
	if declined == string(baseline) {
		t.Fatal("fixture profile no longer declares crypto_dlp_scanning true; update this test")
	}

	before := countFor(t, string(baseline))
	after := countFor(t, declined)
	if before != after {
		t.Fatalf("case counts changed after a profile declaration changed: before=%+v after=%+v", before, after)
	}
	if after.NotApplicable != 0 || after.Unreachable != 0 {
		t.Fatalf("dryrun profile declaration produced N/A/unreachable rows: %+v", after)
	}
}
