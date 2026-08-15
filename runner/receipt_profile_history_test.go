package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const retainedPipelockReceiptProfile = "pipelock.json"

type retainedReceiptArtifact struct {
	Path            string `json:"path"`
	Status          string `json:"status"`
	SchemaVersion   int    `json:"schema_version"`
	Tool            string `json:"tool"`
	ToolVersion     string `json:"tool_version"`
	CorpusVersion   string `json:"corpus_version"`
	PerCaseCount    int    `json:"per_case_count"`
	BlockedYesCount int    `json:"blocked_yes_count"`
	SHA256          string `json:"sha256"`
}

type retainedReceiptArtifactManifest struct {
	Format    int                       `json:"format"`
	Artifacts []retainedReceiptArtifact `json:"artifacts"`
}

// TestRetainedPipelockReceiptProfileIsHistorical keeps the old receipt profile
// useful as evidence without allowing its old corpus and tool identity to read
// as a current result. New measurements belong in the active Gauntlet result
// flow, not in this retained historical artifact.
func TestRetainedPipelockReceiptProfileIsHistorical(t *testing.T) {
	manifestPath := filepath.Join("..", "profiles", "retained-artifacts.json")
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read retained artifact manifest: %v", err)
	}
	var manifest retainedReceiptArtifactManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatalf("parse retained artifact manifest: %v", err)
	}
	if manifest.Format != 1 {
		t.Fatalf("retained artifact manifest format = %d, want 1", manifest.Format)
	}

	var entry *retainedReceiptArtifact
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		if artifact.Path != retainedPipelockReceiptProfile {
			continue
		}
		if entry != nil {
			t.Fatalf("retained artifact manifest lists %q more than once", retainedPipelockReceiptProfile)
		}
		entry = artifact
	}
	if entry == nil {
		t.Fatalf("retained artifact manifest must list %q", retainedPipelockReceiptProfile)
	}
	if entry.Status != "historical" {
		t.Fatalf("%s status = %q, want historical", retainedPipelockReceiptProfile, entry.Status)
	}

	profilePath := filepath.Join("..", "profiles", retainedPipelockReceiptProfile)
	profileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("read retained receipt profile: %v", err)
	}
	digest := sha256.Sum256(profileRaw)
	if got := hex.EncodeToString(digest[:]); got != entry.SHA256 {
		t.Fatalf("%s sha256 = %s, manifest pins %s", retainedPipelockReceiptProfile, got, entry.SHA256)
	}

	var profile ReceiptProfile
	if err := decodeStrictJSON(profileRaw, &profile); err != nil {
		t.Fatalf("parse retained receipt profile: %v", err)
	}
	if issues := ValidateReceiptProfile(profile); len(issues) != 0 {
		t.Fatalf("retained receipt profile is structurally invalid: %v", issues)
	}
	if profile.SchemaVersion != entry.SchemaVersion || profile.Tool != entry.Tool || profile.ToolVersion != entry.ToolVersion || profile.CorpusVersion != entry.CorpusVersion {
		t.Fatalf("retained identity = schema v%d, %s %s, corpus %s; manifest pins schema v%d, %s %s, corpus %s", profile.SchemaVersion, profile.Tool, profile.ToolVersion, profile.CorpusVersion, entry.SchemaVersion, entry.Tool, entry.ToolVersion, entry.CorpusVersion)
	}
	if len(profile.PerCase) != entry.PerCaseCount {
		t.Fatalf("retained per_case row count = %d, manifest pins %d", len(profile.PerCase), entry.PerCaseCount)
	}
	if profile.Summary.BlockedYesCount != entry.BlockedYesCount {
		t.Fatalf("retained blocked_yes_count = %d, manifest pins %d", profile.Summary.BlockedYesCount, entry.BlockedYesCount)
	}
}
