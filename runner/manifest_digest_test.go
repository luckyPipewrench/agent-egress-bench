package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The regrouping that collides under computeCorpusSHA256 must not collide here.
// This is the exact defect the framed digest exists to close, so it is asserted
// in both directions rather than only on the new function.
func TestBenchmarkManifestDigestSeparatesRegroupedBytes(t *testing.T) {
	single := writeCorpus(t, map[string]string{"url/1.json": `{"a":1}{"b":2}`})
	split := writeCorpus(t, map[string]string{
		"url/1.json": `{"a":1}`,
		"url/2.json": `{"b":2}`,
	})

	legacySingle, err := computeCorpusSHA256(single, "")
	if err != nil {
		t.Fatalf("legacy single: %v", err)
	}
	legacySplit, err := computeCorpusSHA256(split, "")
	if err != nil {
		t.Fatalf("legacy split: %v", err)
	}
	if legacySingle != legacySplit {
		t.Fatalf("legacy digest unexpectedly distinguished these corpora; this test's premise is stale")
	}

	framedSingle, err := computeBenchmarkManifestSHA256(single, "")
	if err != nil {
		t.Fatalf("framed single: %v", err)
	}
	framedSplit, err := computeBenchmarkManifestSHA256(split, "")
	if err != nil {
		t.Fatalf("framed split: %v", err)
	}
	if framedSingle == framedSplit {
		t.Fatalf("framed digest collided on regrouped bytes: %s", framedSingle)
	}
}

// The length prefixes, specifically, are what stop a crafted filename from
// impersonating a boundary. Without them the digest input is a bare
// concatenation of key then content, so a file whose NAME absorbs the start of
// another entry produces a byte-identical stream:
//
//	key "cases/x.json"        + content "y.json{}"   -> cases/x.jsony.json{}
//	key "cases/x.jsony.json"  + content "{}"         -> cases/x.jsony.json{}
//
// Both filenames end in .json, so both are real corpus files. Including the
// path is not sufficient here; only framing separates these.
func TestBenchmarkManifestFramingResistsBoundaryForgery(t *testing.T) {
	honest := writeCorpus(t, map[string]string{"x.json": `y.json{}`})
	forged := writeCorpus(t, map[string]string{"x.jsony.json": `{}`})

	a, err := computeBenchmarkManifestSHA256(honest, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := computeBenchmarkManifestSHA256(forged, "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("a crafted filename forged an entry boundary: both digests %s", a)
	}
}

// A file moving or being renamed changes the corpus, so it must change the
// digest even though the bytes are untouched.
func TestBenchmarkManifestDigestBindsPaths(t *testing.T) {
	before := writeCorpus(t, map[string]string{"url/case.json": `{"a":1}`})
	after := writeCorpus(t, map[string]string{"headers/case.json": `{"a":1}`})

	a, err := computeBenchmarkManifestSHA256(before, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := computeBenchmarkManifestSHA256(after, "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("digest ignored the file's location")
	}

	// The legacy digest cannot see this, which is why the new field is needed.
	la, err := computeCorpusSHA256(before, "")
	if err != nil {
		t.Fatal(err)
	}
	lb, err := computeCorpusSHA256(after, "")
	if err != nil {
		t.Fatal(err)
	}
	if la != lb {
		t.Fatal("legacy digest distinguished a pure move; this test's premise is stale")
	}
}

// The digest must not depend on where the corpus lives on disk, or two machines
// verifying the same corpus would disagree.
func TestBenchmarkManifestDigestIsMachineIndependent(t *testing.T) {
	layout := map[string]string{
		"url/1.json":     `{"a":1}`,
		"headers/2.json": `{"b":2}`,
	}
	first := writeCorpus(t, layout)
	second := writeCorpus(t, layout)
	if first == second {
		t.Fatal("expected two distinct root directories")
	}

	a, err := computeBenchmarkManifestSHA256(first, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := computeBenchmarkManifestSHA256(second, "")
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("digest depended on the absolute root: %s vs %s", a, b)
	}
}

func TestBenchmarkManifestDigestIsDeterministic(t *testing.T) {
	dir := writeCorpus(t, map[string]string{
		"url/1.json":     `{"a":1}`,
		"headers/2.json": `{"b":2}`,
		"ssrf/3.json":    `{"c":3}`,
	})
	first, err := computeBenchmarkManifestSHA256(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, againErr := computeBenchmarkManifestSHA256(dir, "")
		if againErr != nil {
			t.Fatal(againErr)
		}
		if again != first {
			t.Fatalf("digest changed between runs: %s then %s", first, again)
		}
	}
}

// Content still matters. A one-byte edit must move the digest.
func TestBenchmarkManifestDigestBindsContent(t *testing.T) {
	a, err := computeBenchmarkManifestSHA256(writeCorpus(t, map[string]string{"url/1.json": `{"a":1}`}), "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := computeBenchmarkManifestSHA256(writeCorpus(t, map[string]string{"url/1.json": `{"a":2}`}), "")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("digest ignored file content")
	}
}

// The two digests must always describe the same file set, so a corpus that one
// can read and the other cannot is a bug rather than a difference in scope.
func TestBothDigestsCoverTheSameFiles(t *testing.T) {
	dir := writeCorpus(t, map[string]string{
		"url/1.json":   `{"a":1}`,
		"url/skip.txt": `not a case`,
	})
	paths, err := corpusFilePaths(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected only the .json case file, got %v", paths)
	}
	if filepath.Base(paths[0]) != "1.json" {
		t.Fatalf("unexpected file collected: %s", paths[0])
	}
}
