package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEvidenceFiles_StaysInsideEvidenceDir pins the containment property of
// file_glob. The pattern is documented as applying inside evidence_dir, so a
// traversal pattern, an absolute pattern, and a symlink planted in the directory
// must all fail to pull in a file from outside it. Without this test the
// traversal and absolute cases are only defeated incidentally, by the filter
// that restricts matches to the directory's listed entries, and nothing records
// that the behavior is deliberate.
func TestEvidenceFiles_StaysInsideEvidenceDir(t *testing.T) {
	root := t.TempDir()
	evidence := filepath.Join(root, "evidence")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{evidence, outside} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}

	legit := filepath.Join(evidence, "evidence-001.jsonl")
	if err := os.WriteFile(legit, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(outside, "external.jsonl")
	if err := os.WriteFile(external, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(evidence, "linked.jsonl")); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	// A symlink that stays inside the directory remains legitimate evidence.
	if err := os.Symlink(legit, filepath.Join(evidence, "inside-link.jsonl")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		glob string
		want []string
	}{
		{
			name: "plain glob returns only regular files inside the directory",
			glob: "*.jsonl",
			want: []string{filepath.Join(evidence, "evidence-001.jsonl"), filepath.Join(evidence, "inside-link.jsonl")},
		},
		{name: "traversal pattern matches nothing", glob: "../outside/*.jsonl"},
		{name: "absolute pattern matches nothing", glob: filepath.Join(outside, "*.jsonl")},
		{name: "deep traversal pattern matches nothing", glob: "../../*/*.jsonl"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evidenceFiles("", ReceiptEvidenceDeclaration{
				EvidenceDir: evidence,
				FileGlob:    tt.glob,
			})
			if err != nil {
				t.Fatalf("evidenceFiles: %v", err)
			}
			for _, f := range got {
				if filepath.Dir(f) != evidence {
					t.Fatalf("file outside evidence_dir: %q", f)
				}
				if filepath.Base(f) == "linked.jsonl" {
					t.Fatalf("followed a symlink out of evidence_dir: %q", f)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d files %v, want %d %v", len(got), got, len(tt.want), tt.want)
			}
			for i, want := range tt.want {
				if got[i] != want {
					t.Fatalf("file %d = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

// TestEvidenceFiles_SkipsNonRegularEntries confirms a directory whose name
// matches the glob is not treated as an evidence file.
func TestEvidenceFiles_SkipsNonRegularEntries(t *testing.T) {
	evidence := t.TempDir()
	if err := os.MkdirAll(filepath.Join(evidence, "decoy.jsonl"), 0o750); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(evidence, "real.jsonl")
	if err := os.WriteFile(real, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := evidenceFiles("", ReceiptEvidenceDeclaration{EvidenceDir: evidence, FileGlob: "*.jsonl"})
	if err != nil {
		t.Fatalf("evidenceFiles: %v", err)
	}
	if len(got) != 1 || got[0] != real {
		t.Fatalf("got %v, want only %q", got, real)
	}
}
