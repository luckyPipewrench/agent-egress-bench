package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunBadCasesDir(t *testing.T) {
	err := run("/nonexistent", filepath.Join("..", "examples", "pipelock", "tool-profile.json"),
		filepath.Join(t.TempDir(), "out.json"), 10*1e9, "dryrun", "")
	if err == nil {
		t.Fatal("expected error for nonexistent cases dir")
	}
}

func TestRunBadProfile(t *testing.T) {
	err := run(filepath.Join("..", "cases"), "/nonexistent/profile.json",
		filepath.Join(t.TempDir(), "out.json"), 10*1e9, "dryrun", "")
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
	err := run(casesDir, profilePath, outputPath, 10*1e9, "nonexistent", "")
	if err == nil {
		t.Fatal("expected error for unknown adapter")
	}
	if !strings.Contains(err.Error(), "unknown adapter") {
		t.Errorf("error should mention unknown adapter, got: %v", err)
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

	err := run(casesDir, profilePath, outputPath, 10*1e9, "null", "")
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
	err := run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "") // 10s
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
	if summary.CaseCount.Total != summary.CaseCount.Applicable+summary.CaseCount.NotApplicable+summary.CaseCount.Errors {
		t.Errorf("case counts don't add up: total=%d, applicable=%d, na=%d, errors=%d",
			summary.CaseCount.Total, summary.CaseCount.Applicable,
			summary.CaseCount.NotApplicable, summary.CaseCount.Errors)
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

	// Full containment may be < 1.0 if there are N/A malicious cases.
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

	t.Logf("Summary: %d total, %d applicable, %d N/A, sufficient=%v",
		summary.CaseCount.Total, summary.CaseCount.Applicable,
		summary.CaseCount.NotApplicable, summary.Sufficient)
}
