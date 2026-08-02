package main

import (
	"bytes"
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

func caseIDs(cases []Case) []string {
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	return ids
}
