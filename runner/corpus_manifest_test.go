package main

import (
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateManifest regenerates cases/MANIFEST.txt instead of asserting against it.
// Run via `make cases-manifest` after adding or removing a case.
var updateManifest = flag.Bool("update-manifest", false, "rewrite cases/MANIFEST.txt from the corpus on disk")

const manifestPath = "../cases/MANIFEST.txt"

// TestCorpusMatchesManifest pins the logical case corpus to a committed list of
// case IDs.
//
// Without this, a case that stops loading grades identically to a case that ran
// and passed: loadCases only errors when the corpus is EMPTY, and the published
// score is a percentage over whatever was discovered, so a corpus that shrinks
// produces a clean-looking number over a smaller denominator with nothing
// reporting the loss. The multi-file loader also rejects a case directory
// missing case.yaml rather than silently skipping it.
//
// Removing a case stays possible. It now costs a visible diff in
// cases/MANIFEST.txt instead of silence.
func TestCorpusMatchesManifest(t *testing.T) {
	ids, err := corpusCaseIDs()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	if len(ids) == 0 {
		t.Fatal("corpus loaded zero cases")
	}

	if *updateManifest {
		// Regeneration must not be able to write an expectation that the
		// assertion path would reject. Duplicate IDs collapse when the manifest
		// is read back, so writing one produces a committed artifact that looks
		// regenerated and is invalid.
		if dup, ok := firstDuplicateID(ids); ok {
			t.Fatalf("case ID %q appears more than once; refusing to write %s", dup, manifestPath)
		}
		body := strings.Join(ids, "\n") + "\n"
		if writeErr := os.WriteFile(manifestPath, []byte(body), 0o644); writeErr != nil {
			t.Fatalf("write manifest: %v", writeErr)
		}
		t.Logf("wrote %s with %d case IDs", manifestPath, len(ids))
		return
	}

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read case manifest: %v (regenerate with: make cases-manifest)", err)
	}
	want := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		if id := strings.TrimSpace(line); id != "" {
			if want[id] {
				t.Errorf("case manifest %s lists case %q more than once", manifestPath, id)
				continue
			}
			want[id] = true
		}
	}
	if len(want) == 0 {
		t.Fatalf("case manifest %s is empty", manifestPath)
	}

	got := map[string]bool{}
	for _, id := range ids {
		got[id] = true
	}

	for id := range want {
		if !got[id] {
			t.Errorf("case %q is listed in the manifest but did not load from the corpus", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("case %q loaded from the corpus but is missing from the manifest", id)
		}
	}
}

// TestCorpusCaseIDsAreUnique guards the manifest's own assumption. The manifest
// compares sets of IDs, so two cases sharing an ID would collapse to one entry
// and a case could be replaced rather than added without changing the manifest.
func TestCorpusCaseIDsAreUnique(t *testing.T) {
	ids, err := corpusCaseIDs()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	seen := map[string]int{}
	for _, id := range ids {
		seen[id]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("case ID %q appears %d times; IDs must be unique", id, n)
		}
	}
}

func TestActiveSetRejectsDifferentCorpusVersion(t *testing.T) {
	root := t.TempDir()
	casesRoot := filepath.Join(root, "cases")
	if err := os.MkdirAll(casesRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(casesRoot, "MANIFEST.txt"), []byte("case-001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDir := filepath.Join(root, "corpora", "active-sets", "v1")
	if err := os.MkdirAll(setDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setDir, "v9.9.9.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadActiveCaseIDs(casesRoot, []Case{{ID: "case-001"}}); err == nil || !strings.Contains(err.Error(), "no selection for corpus_version") {
		t.Fatalf("different active-set version error = %v, want rejection", err)
	}
}

func TestCorpusVersionMarkerRequiresActiveSet(t *testing.T) {
	root := t.TempDir()
	casesRoot := filepath.Join(root, "cases")
	if err := os.MkdirAll(casesRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(casesRoot, corpusVersionMarker), []byte(corpusVersion+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadActiveCaseIDs(casesRoot, []Case{{ID: "case-001"}}); err == nil || !strings.Contains(err.Error(), "requires active set") {
		t.Fatalf("missing active-set error = %v, want fail-closed marker rejection", err)
	}
}

// firstDuplicateID returns the first ID that appears more than once. ids is
// sorted by corpusCaseIDs, so duplicates are adjacent.
func firstDuplicateID(ids []string) (string, bool) {
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return ids[i], true
		}
	}
	return "", false
}

// corpusCaseIDs returns every logical case ID, using the same loaders the
// runner uses so the manifest remains a complete source catalog. Single-file
// JSON cases and multi-file case directories are both included; a versioned
// active set may select a scored subset without redefining this catalog.
func corpusCaseIDs() ([]string, error) {
	cases, err := loadCorpus("../cases")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}

	sort.Strings(ids)
	return ids, nil
}
