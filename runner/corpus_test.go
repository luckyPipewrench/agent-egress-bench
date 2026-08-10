package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadRunCorpusRefusesOverrideWithMultipleFamilies exercises the state the
// repository is not in yet. One multi-file family is registered today, so the
// single-directory override is correct; the moment a second family lands, that
// override silently stops covering it. Registering a temporary second family is
// the only way to reach that path, and reaching it is the point.
func TestLoadRunCorpusRefusesOverrideWithMultipleFamilies(t *testing.T) {
	root := "../cases"
	// Any existing category directory works. The refusal fires on the count of
	// registered families, before anything is loaded, so this directory never has
	// to hold multi-file cases. Skipping instead would prove nothing, so a missing
	// directory is a failure.
	second := "a2a-agent-card"
	if _, err := os.Stat(filepath.Join(root, second)); err != nil {
		t.Fatalf("fixture category %s is required by this test: %v", second, err)
	}
	multiFileCaseCategories[second] = true
	t.Cleanup(func() { delete(multiFileCaseCategories, second) })

	_, _, err := loadRunCorpus(root, filepath.Join(root, "mcp-drift"))
	if err == nil {
		t.Fatal("override accepted while two multi-file families were registered")
	}
	if !strings.Contains(err.Error(), "per-family override") {
		t.Fatalf("error does not name the required change: %v", err)
	}
}
