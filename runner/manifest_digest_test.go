package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeDigestCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestBenchmarkManifestDigestSeparatesRegroupedBytes(t *testing.T) {
	single := writeDigestCorpus(t, map[string]string{"url/1.json": `{"a":1}{"b":2}`})
	split := writeDigestCorpus(t, map[string]string{
		"url/1.json": `{"a":1}`,
		"url/2.json": `{"b":2}`,
	})

	legacySingle, err := computeCorpusSHA256(single)
	if err != nil {
		t.Fatal(err)
	}
	legacySplit, err := computeCorpusSHA256(split)
	if err != nil {
		t.Fatal(err)
	}
	if legacySingle != legacySplit {
		t.Fatal("legacy digest unexpectedly distinguished regrouped bytes")
	}

	framedSingle, err := computeBenchmarkManifestSHA256(single)
	if err != nil {
		t.Fatal(err)
	}
	framedSplit, err := computeBenchmarkManifestSHA256(split)
	if err != nil {
		t.Fatal(err)
	}
	if framedSingle == framedSplit {
		t.Fatal("framed digest collided on regrouped bytes")
	}
}

func TestBenchmarkManifestFramingResistsBoundaryForgery(t *testing.T) {
	honest := writeDigestCorpus(t, map[string]string{"x.json": `y.json{}`})
	forged := writeDigestCorpus(t, map[string]string{"x.jsony.json": `{}`})

	a, err := computeBenchmarkManifestSHA256(honest)
	if err != nil {
		t.Fatal(err)
	}
	b, err := computeBenchmarkManifestSHA256(forged)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("a crafted filename forged a manifest entry boundary")
	}
	// Portable test vector: 0x0c || "cases/x.json" || 0x08 || "y.json{}".
	// Keep this fixed so another implementation can verify its unsigned-LEB128
	// framing rather than merely agreeing with a second Go helper.
	if a != "de1c78ea420c6e94f46f8f3a2cfc982ad2cc5acfb6057a5eeb19bc358788e9ed" {
		t.Fatalf("framed digest = %s, want published framing vector", a)
	}
}

func TestRunCorpusSnapshotBindsExecutedBytesAfterMutation(t *testing.T) {
	root := writeDigestCorpus(t, map[string]string{
		"case.json": `{"schema_version":4,"id":"before","category":"url","expected_verdict":"block"}`,
	})
	run, err := loadRunCorpus(root, "")
	if err != nil {
		t.Fatalf("load run corpus: %v", err)
	}
	want := corpusSHA256FromSnapshot(run.snapshot.files)
	if run.cases[0].ID != "before" {
		t.Fatalf("loaded case id = %q, want executed snapshot bytes", run.cases[0].ID)
	}
	if err := os.WriteFile(filepath.Join(root, "case.json"), []byte(`{"schema_version":4,"id":"after","category":"url","expected_verdict":"allow"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := buildSummary(testProfile(), run.cases, nil, nil, nil, run.snapshot, map[string]Case{"before": run.cases[0]}, profilePath, RunProvenance{})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.CorpusSHA256 != want {
		t.Fatalf("summary digest = %s, want executed snapshot digest %s", summary.CorpusSHA256, want)
	}
	current, err := computeCorpusSHA256(root)
	if err != nil {
		t.Fatal(err)
	}
	if current == summary.CorpusSHA256 {
		t.Fatal("summary re-read the mutated corpus instead of using executed bytes")
	}
}

func TestRunCorpusSnapshotRefusesPartialMultiFileCase(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "mcp-drift", "partial"), 0o750); err != nil {
		t.Fatal(err)
	}
	_, err := loadRunCorpus(root, "")
	if err == nil || !strings.Contains(err.Error(), "missing required case.yaml") {
		t.Fatalf("loadRunCorpus error = %v, want missing case.yaml refusal", err)
	}
}

func TestBenchmarkManifestFamilyKeyIsUniqueAndOverrideInvariant(t *testing.T) {
	root := t.TempDir()
	canonical := filepath.Join(root, "mcp-drift")
	copyMultiFileCases(t, filepath.Join("..", "cases", "mcp-drift"), canonical, "mcp-drift-benign-001")
	relocated := filepath.Join(t.TempDir(), "mcp-drift")
	copyMultiFileCases(t, canonical, relocated)

	canonicalDigest, err := computeBenchmarkManifestSHA256(root, canonical)
	if err != nil {
		t.Fatal(err)
	}
	relocatedDigest, err := computeBenchmarkManifestSHA256(root, relocated)
	if err != nil {
		t.Fatal(err)
	}
	if canonicalDigest != relocatedDigest {
		t.Fatalf("relocating a complete override changed digest: %s != %s", canonicalDigest, relocatedDigest)
	}

	secondFamily := "a2a-agent-card"
	multiFileCaseCategories[secondFamily] = true
	t.Cleanup(func() { delete(multiFileCaseCategories, secondFamily) })
	second := filepath.Join(root, secondFamily)
	copyMultiFileCases(t, canonical, second)

	dirs := []multiFileCaseDir{
		{family: "mcp-drift", path: canonical},
		{family: secondFamily, path: second},
	}
	snapshot, err := readCorpusSnapshot(root, dirs...)
	if err != nil {
		t.Fatal(err)
	}
	files, err := selectedCorpusFiles(snapshot, dirs)
	if err != nil {
		t.Fatal(err)
	}
	keys := make(map[string]struct{}, len(files))
	for _, file := range files {
		if _, duplicate := keys[file.manifestKey]; duplicate {
			t.Fatalf("duplicate manifest key %q", file.manifestKey)
		}
		keys[file.manifestKey] = struct{}{}
	}
	for _, family := range []string{"mcp-drift", secondFamily} {
		key := "multifile/" + family + "/mcp-drift-benign-001/case.yaml"
		if _, ok := keys[key]; !ok {
			t.Fatalf("missing family-qualified key %q", key)
		}
	}
}

func TestWriteSummaryRejectsMalformedDigests(t *testing.T) {
	valid := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, corpus, manifest, profile string
	}{
		{"empty manifest", valid, "", valid},
		{"uppercase manifest", valid, strings.ToUpper(valid), valid},
		{"short corpus", "abc123", valid, valid},
		{"malformed profile", valid, valid, strings.Repeat("z", 64)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := writeSummary(GauntletSummary{
				Tool:                    "test",
				CorpusSHA256:            tc.corpus,
				BenchmarkManifestSHA256: tc.manifest,
				ToolProfileSHA256:       tc.profile,
				CapabilityRegistry:      testRegistryReference,
			}, filepath.Join(t.TempDir(), "summary.json"))
			if err == nil {
				t.Fatal("writeSummary accepted malformed digest")
			}
		})
	}
}
