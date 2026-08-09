package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

type labelMeasurement struct {
	rows              []CaseResult
	caseCount         CaseCount
	exercised         ExercisedCapabilities
	scores            DualScores
	measurementStatus string
	receipt           []byte
}

func measureLabelsOnly(t *testing.T, profile Profile) labelMeasurement {
	t.Helper()
	cases := []Case{
		{ID: "labels-block-001", Category: "url", InputType: "url", Transport: "fetch_proxy", ExpectedVerdict: "block", CapabilityTags: []string{"url_dlp"}, Payload: map[string]interface{}{"method": "GET", "url": "https://example.test/block"}},
		{ID: "labels-allow-001", Category: "url", InputType: "url", Transport: "fetch_proxy", ExpectedVerdict: "allow", CapabilityTags: []string{"benign"}, Payload: map[string]interface{}{"method": "GET", "url": "https://example.test/allow"}},
	}
	var output bytes.Buffer
	rows, unreachableRows, unreachableIDs, reasons, err := runCases(cases, profile, adapter.DryRunAdapter{}, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if len(unreachableRows) != 0 || len(unreachableIDs) != 0 || len(reasons) != 0 {
		t.Fatalf("unexpected coverage state: unreachableRows=%v unreachableIDs=%v reasons=%v", unreachableRows, unreachableIDs, reasons)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cases.json"), []byte(`{"fixture":"labels-only"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	profileBytes, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, profileBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	byID := map[string]Case{cases[0].ID: cases[0], cases[1].ID: cases[1]}
	summary, err := buildSummary(profile, cases, rows, unreachableIDs, reasons, dir, "", byID, profilePath, RunProvenance{})
	if err != nil {
		t.Fatalf("buildSummary: %v", err)
	}
	receipt := buildReceiptProfile(profile, rows, byID, ReceiptVerifier{}, summary.CorpusVersion, summary.CorpusSHA256, summary.ToolProfileSHA256)
	receiptRows, err := json.Marshal(receipt.PerCase)
	if err != nil {
		t.Fatal(err)
	}
	return labelMeasurement{rows: rows, caseCount: summary.CaseCount, exercised: summary.Exercised, scores: summary.Scores, measurementStatus: summary.MeasurementStatus, receipt: receiptRows}
}

func TestClaimsDoNotChangeMeasurement(t *testing.T) {
	first := v4TestProfile()
	first.Claims = []string{"url_dlp"}
	second := v4TestProfile()
	second.Claims = []string{"ssrf"}

	baseline := measureLabelsOnly(t, first)
	changed := measureLabelsOnly(t, second)
	if !reflect.DeepEqual(baseline.rows, changed.rows) {
		t.Fatalf("claims changed selected result rows\nbase=%#v\nchanged=%#v", baseline.rows, changed.rows)
	}
	if !reflect.DeepEqual(baseline.caseCount, changed.caseCount) {
		t.Fatalf("claims changed coverage counts: base=%#v changed=%#v", baseline.caseCount, changed.caseCount)
	}
	if !reflect.DeepEqual(baseline.exercised, changed.exercised) {
		t.Fatalf("claims changed exercised coverage: base=%#v changed=%#v", baseline.exercised, changed.exercised)
	}
	if !reflect.DeepEqual(baseline.scores, changed.scores) || baseline.measurementStatus != changed.measurementStatus {
		t.Fatalf("claims changed scores or measurement status: base=%#v/%s changed=%#v/%s", baseline.scores, baseline.measurementStatus, changed.scores, changed.measurementStatus)
	}
	if !bytes.Equal(baseline.receipt, changed.receipt) {
		t.Fatalf("claims changed receipt per_case rows: base=%s changed=%s", baseline.receipt, changed.receipt)
	}
}
