package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCorpusStats(t *testing.T) {
	cases := []corpusStatCase{
		{Category: "url", ExpectedVerdict: "block"},
		{Category: "mcp_drift", ExpectedVerdict: "warn"},
		{Category: "url", ExpectedVerdict: "allow"},
	}
	var got bytes.Buffer
	if err := writeCorpusStats(&got, cases); err != nil {
		t.Fatalf("writeCorpusStats: %v", err)
	}
	want := "# agent-egress-bench stats\n" +
		"cases_total: 3\n" +
		"categories: 2\n" +
		"block: 1\n" +
		"allow: 1\n" +
		"warn: 1\n" +
		"by_category:\n" +
		"  mcp_drift: 1\n" +
		"  url: 2\n"
	if got.String() != want {
		t.Errorf("writeCorpusStats output:\n%s\nwant:\n%s", got.String(), want)
	}
}

func TestWriteCaseIndexUsesNormalizedVerdicts(t *testing.T) {
	cases, err := loadCorpus("../cases")
	if err != nil {
		t.Fatalf("loadCorpus: %v", err)
	}
	var output bytes.Buffer
	if err := writeCaseIndex(&output, cases); err != nil {
		t.Fatalf("writeCaseIndex: %v", err)
	}
	var index caseIndexDocument
	if err := json.Unmarshal(output.Bytes(), &index); err != nil {
		t.Fatalf("decode case index: %v", err)
	}
	if index.SchemaVersion != 1 || len(index.Cases) != len(cases) {
		t.Fatalf("case index scope = schema %d, cases %d; want schema 1, cases %d", index.SchemaVersion, len(index.Cases), len(cases))
	}
	foundNormalizedWarn := false
	for position, entry := range index.Cases {
		if position > 0 && index.Cases[position-1].CaseID >= entry.CaseID {
			t.Fatalf("case index is not strictly sorted at %q then %q", index.Cases[position-1].CaseID, entry.CaseID)
		}
		if entry.CaseID == "mcp-drift-benign-001" && entry.ExpectedVerdict != "allow" {
			t.Fatalf("warn normalization = %q, want allow", entry.ExpectedVerdict)
		}
		if entry.CaseID == "mcp-drift-benign-001" {
			foundNormalizedWarn = true
		}
	}
	if !foundNormalizedWarn {
		t.Fatal("case index omitted normalized warn fixture")
	}
}

func TestLoadCorpusStatsPreservesMultiFileWarnVerdict(t *testing.T) {
	cases, err := loadCorpusStats("../cases")
	if err != nil {
		t.Fatalf("loadCorpusStats: %v", err)
	}
	var warns int
	for _, c := range cases {
		if c.ExpectedVerdict == "warn" {
			warns++
		}
	}
	if warns == 0 {
		t.Fatal("loader-backed corpus stats lost the multi-file warn verdict")
	}
}

func TestLoadCorpusIncludesMultiFileCases(t *testing.T) {
	cases, err := loadCorpus("../cases")
	if err != nil {
		t.Fatalf("loadCorpus: %v", err)
	}
	var found bool
	for _, c := range cases {
		if c.ID == "mcp-drift-rugpull-desc-002" && c.Category == "mcp_drift" && c.ExpectedVerdict == "block" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("loader-backed corpus omitted expected multi-file drift case; IDs: %s", strings.Join(caseIDs(cases), ", "))
	}
}

func TestRegisteredMultiFileCaseDirsRejectsFileAtFamilyPath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "mcp-drift"), []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("write multi-file family path: %v", err)
	}
	_, err := registeredMultiFileCaseDirs(root)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("registeredMultiFileCaseDirs error = %v, want non-directory rejection", err)
	}
}

func TestEnsureExactRunCorpusRejectsMissingMultiFileCase(t *testing.T) {
	canonical, err := loadCorpus("../cases")
	if err != nil {
		t.Fatalf("loadCorpus: %v", err)
	}
	if err := ensureExactRunCorpus(canonical, canonical); err != nil {
		t.Fatalf("exact corpus rejected: %v", err)
	}

	partial := make([]Case, 0, len(canonical)-1)
	for _, c := range canonical {
		if c.ID != "mcp-drift-rugpull-desc-002" {
			partial = append(partial, c)
		}
	}
	err = ensureExactRunCorpus(partial, canonical)
	if err == nil {
		t.Fatal("partial corpus passed the exact run-corpus gate")
	}
	if !strings.Contains(err.Error(), "loader-backed corpus") || !strings.Contains(err.Error(), "mcp-drift-rugpull-desc-002") {
		t.Fatalf("partial corpus error = %v, want missing multi-file ID", err)
	}
}

func caseIDs(cases []Case) []string {
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	return ids
}
