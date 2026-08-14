package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestActiveSchemaVersionsMatchArtifactContract binds each family's Go writer
// constant to contracts/artifacts.json.
//
// The manifest is the published statement of which version this repository
// writes for each artifact family, and a clean-room implementation reads it to
// know what to expect. Nothing previously held the code to it, so the two could
// disagree silently: a family could be bumped in Go while the manifest still
// advertised the old version, or the manifest could advertise a version no
// writer emits. Either way an outside reader is told something untrue.
//
// This test also protects the reason those constants are separate at all.
// Before they were split, five families shared one constant, so bumping any one
// of them dragged the rest to a version they had no reason to leave. Per-family
// constants only stay honest if something checks them per family.
func TestActiveSchemaVersionsMatchArtifactContract(t *testing.T) {
	path := filepath.Join("..", "contracts", "artifacts.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read artifact contract: %v", err)
	}

	var manifest struct {
		Families []struct {
			Family              string `json:"family"`
			ActiveWriterVersion int    `json:"active_writer_version"`
		} `json:"artifact_families"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse artifact contract: %v", err)
	}

	declared := make(map[string]int, len(manifest.Families))
	for _, f := range manifest.Families {
		declared[f.Family] = f.ActiveWriterVersion
	}

	// Only families this Go writer actually emits. A family absent here is
	// written elsewhere, and claiming it would make this test lie.
	written := map[string]int{
		"case":                    activeCaseSchemaVersion,
		"multi_file_case":         activeMultiFileCaseSchemaVersion,
		"result_row":              activeResultSchemaVersion,
		"tool_profile":            activeToolProfileSchemaVersion,
		"receipt_scoring_profile": activeReceiptProfileSchemaVersion,
		"summary":                 activeSummarySchemaVersion,
	}

	for family, constant := range written {
		want, ok := declared[family]
		if !ok {
			t.Errorf("family %q is written by this runner but absent from the artifact contract", family)
			continue
		}
		if constant != want {
			t.Errorf("family %q: runner writes v%d, contract declares v%d; bump both together or neither",
				family, constant, want)
		}
	}
}
