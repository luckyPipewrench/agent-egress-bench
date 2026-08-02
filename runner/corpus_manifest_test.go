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
// reporting the loss. loadMultiFileCases makes that easier still, because a
// case directory that loses its case.yaml is skipped rather than failed.
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

// corpusCaseIDs returns every logical case ID, using the same loaders the
// runner uses so the manifest reflects what would actually execute. Single-file
// JSON cases and multi-file case directories are both included.
func corpusCaseIDs() ([]string, error) {
	root := filepath.Join("..", "cases")
	cases, err := loadCases(root)
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}

	for name := range multiFileCaseCategories {
		dir := filepath.Join(root, name)
		if _, statErr := os.Stat(dir); statErr != nil {
			if os.IsNotExist(statErr) {
				continue
			}
			return nil, statErr
		}
		mfCases, mfErr := loadMultiFileCases(dir)
		if mfErr != nil {
			return nil, mfErr
		}
		for _, mfc := range mfCases {
			ids = append(ids, mfc.ID)
		}
	}

	sort.Strings(ids)
	return ids, nil
}
