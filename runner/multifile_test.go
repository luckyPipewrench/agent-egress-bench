package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validMultiFileCaseYAML(id string) string {
	return fmt.Sprintf(`schema_version: 3
id: %s
category: mcp_drift
title: Test multi-file case
description: Test description.
threat_model: Test threat model.
input_type: mcp_tool_sequence_temporal
transport: mcp_stdio
files:
  before: before.json
  after: after.json
  expected: expected.json
expected_verdict: block
severity: critical
capability_tags:
  - mcp_tool_poison
requires:
  - mcp_tool_baseline
false_positive_risk: low
why_expected: test_reason
notes: notes.md
source: "synthetic: test fixture"
`, id)
}

// TestLoadMultiFileCases_ValidFixtures loads the four real mcp-drift cases
// from cases/mcp-drift/ and verifies that the loader returns all four with
// non-empty before/after JSON snapshots. This is the happy-path coverage:
// the existing fixtures in the corpus must continue to load without error.
func TestLoadMultiFileCases_ValidFixtures(t *testing.T) {
	cases, err := loadMultiFileCases(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatalf("loadMultiFileCases: %v", err)
	}
	// Corpus is additive: existing case IDs must continue to load with
	// non-empty snapshots, but new mcp-drift cases may be added over time.
	// Assert the floor (>= 4) and check each known ID by map lookup rather
	// than by positional iteration so a fifth case in the future does not
	// fail this test.
	if len(cases) < 4 {
		t.Fatalf("expected at least 4 mcp-drift cases, got %d", len(cases))
	}
	wantIDs := []string{
		"mcp-drift-benign-001",
		"mcp-drift-collusion-004",
		"mcp-drift-rugpull-desc-002",
		"mcp-drift-rugpull-param-003",
	}
	byID := make(map[string]MultiFileCase, len(cases))
	for _, c := range cases {
		byID[c.ID] = c
	}
	for _, want := range wantIDs {
		c, ok := byID[want]
		if !ok {
			t.Errorf("missing expected case ID %q", want)
			continue
		}
		if c.BeforeJSON == nil {
			t.Errorf("%s BeforeJSON is nil", want)
		}
		if c.AfterJSON == nil {
			t.Errorf("%s AfterJSON is nil", want)
		}
	}
}

// TestLoadMultiFileCases_MissingCaseYAML makes a partial case directory a
// loader error. Silently skipping it would shrink the Gauntlet denominator
// while leaving a clean-looking score over the remaining cases.
func TestLoadMultiFileCases_MissingCaseYAML(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "partial-case")
	if err := os.Mkdir(caseDir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", caseDir, err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error when case.yaml is missing, got nil")
	}
	if !strings.Contains(err.Error(), "missing required case.yaml") {
		t.Errorf("error did not name missing case.yaml: %v", err)
	}
	if !strings.Contains(err.Error(), "restore case.yaml or remove the directory") {
		t.Errorf("error did not explain how to fix the partial directory: %v", err)
	}
	if !strings.Contains(err.Error(), "make cases-manifest") {
		t.Errorf("error did not name the manifest regeneration command: %v", err)
	}
}

// TestLoadMultiFileCase_MissingBefore covers the loader's missing-file
// error path: a directory with case.yaml + after.json + expected.json but
// no before.json must produce a load error naming the missing file. This
// is the kickoff's "loader rejects a multi-file directory missing one of
// the three JSON files" requirement.
func TestLoadMultiFileCase_MissingBefore(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "broken-case")
	if mkErr := os.Mkdir(caseDir, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(validMultiFileCaseYAML("broken-case")), 0o600); err != nil {
		t.Fatalf("write case.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "after.json"), []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write after.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "expected.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("write expected.json: %v", err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error when before.json is missing, got nil")
	}
	if !strings.Contains(err.Error(), "before.json") {
		t.Errorf("error did not name missing file: %v", err)
	}
}

// TestLoadMultiFileCase_MissingAfter covers the symmetric case where
// after.json is absent. The loader reads case.yaml + before.json
// successfully then fails on after.json.
func TestLoadMultiFileCase_MissingAfter(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "broken-case")
	if mkErr := os.Mkdir(caseDir, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(validMultiFileCaseYAML("broken-case")), 0o600); err != nil {
		t.Fatalf("write case.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "before.json"), []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write before.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "expected.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("write expected.json: %v", err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error when after.json is missing, got nil")
	}
	if !strings.Contains(err.Error(), "after.json") {
		t.Errorf("error did not name missing file: %v", err)
	}
}

// TestLoadMultiFileCase_MissingExpected covers the third missing-file
// arm: case.yaml + before.json + after.json present, expected.json
// absent. expected.json is part of the case contract even though the
// driver does not consume it; missing-at-load surfaces the gap before
// any tool runs the case.
func TestLoadMultiFileCase_MissingExpected(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "broken-case")
	if mkErr := os.Mkdir(caseDir, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(validMultiFileCaseYAML("broken-case")), 0o600); err != nil {
		t.Fatalf("write case.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "before.json"), []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write before.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "after.json"), []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write after.json: %v", err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error when expected.json is missing, got nil")
	}
	if !strings.Contains(err.Error(), "expected.json") {
		t.Errorf("error did not name missing file: %v", err)
	}
}

func TestLoadMultiFileCase_InvalidExpectedJSON(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "broken-case")
	if mkErr := os.Mkdir(caseDir, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(validMultiFileCaseYAML("broken-case")), 0o600); err != nil {
		t.Fatalf("write case.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "before.json"), []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write before.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "after.json"), []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write after.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "expected.json"), []byte(`{"version":1} trailing`), 0o600); err != nil {
		t.Fatalf("write expected.json: %v", err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error when expected.json is malformed, got nil")
	}
	if !strings.Contains(err.Error(), "expected.json") {
		t.Errorf("error did not name expected.json: %v", err)
	}
}

func TestLoadMultiFileCase_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "broken-case")
	if mkErr := os.Mkdir(caseDir, 0o750); mkErr != nil {
		t.Fatalf("mkdir: %v", mkErr)
	}
	yaml := strings.Replace(validMultiFileCaseYAML("broken-case"), "before: before.json", "before: ../before.json", 1)
	if err := os.WriteFile(filepath.Join(caseDir, "case.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write case.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "after.json"), []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`), 0o600); err != nil {
		t.Fatalf("write after.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "expected.json"), []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("write expected.json: %v", err)
	}

	_, err := loadMultiFileCases(dir)
	if err == nil {
		t.Fatal("expected loader error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "inside the case directory") {
		t.Errorf("error did not explain path confinement: %v", err)
	}
}

// TestMultiFileCase_ToCase_BlockExpected verifies the conversion from a
// block-expected MultiFileCase to the regular Case shape carries the
// four-message JSON-RPC sequence the mcp_stdio adapter expects: two
// client tools/list requests interleaved with the before and after
// server responses, in that order.
func TestMultiFileCase_ToCase_BlockExpected(t *testing.T) {
	cases, err := loadMultiFileCases(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatalf("loadMultiFileCases: %v", err)
	}
	var rugpull MultiFileCase
	for _, c := range cases {
		if c.ID == "mcp-drift-rugpull-desc-002" {
			rugpull = c
			break
		}
	}
	if rugpull.ID == "" {
		t.Fatal("mcp-drift-rugpull-desc-002 not found in mcp-drift fixtures")
	}

	caseRecord, err := rugpull.toCase()
	if err != nil {
		t.Fatalf("toCase: %v", err)
	}
	if caseRecord.ExpectedVerdict != "block" {
		t.Errorf("ExpectedVerdict = %q, want block", caseRecord.ExpectedVerdict)
	}
	if caseRecord.Transport != "mcp_stdio" {
		t.Errorf("Transport = %q, want mcp_stdio", caseRecord.Transport)
	}

	msgs, ok := caseRecord.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(msgs) != 4 {
		t.Fatalf("payload.jsonrpc_messages = %v, want 4-element slice", caseRecord.Payload["jsonrpc_messages"])
	}
	// Indices 0 and 2 are client requests, 1 and 3 are server responses.
	for _, idx := range []int{0, 2} {
		client, ok := msgs[idx].(map[string]interface{})
		if !ok {
			t.Errorf("msgs[%d] not a map", idx)
			continue
		}
		if client["method"] != "tools/list" {
			t.Errorf("msgs[%d].method = %v, want tools/list", idx, client["method"])
		}
	}
	for _, idx := range []int{1, 3} {
		server, ok := msgs[idx].(map[string]interface{})
		if !ok {
			t.Errorf("msgs[%d] not a map", idx)
			continue
		}
		if _, hasResult := server["result"]; !hasResult {
			t.Errorf("msgs[%d] missing result field; not a server response", idx)
		}
	}
}

// TestMultiFileCase_ToCase_MultiServerResponses verifies that multi-server
// snapshots are converted into one request/response pair per server rather
// than leaving the fixture-only "servers" wrapper in the adapter payload.
func TestMultiFileCase_ToCase_MultiServerResponses(t *testing.T) {
	cases, err := loadMultiFileCases(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatalf("loadMultiFileCases: %v", err)
	}
	var collusion MultiFileCase
	for _, c := range cases {
		if c.ID == "mcp-drift-collusion-004" {
			collusion = c
			break
		}
	}
	if collusion.ID == "" {
		t.Fatal("mcp-drift-collusion-004 not found in mcp-drift fixtures")
	}

	caseRecord, err := collusion.toCase()
	if err != nil {
		t.Fatalf("toCase: %v", err)
	}
	msgs, ok := caseRecord.Payload["jsonrpc_messages"].([]interface{})
	if !ok || len(msgs) != 8 {
		t.Fatalf("payload.jsonrpc_messages = %v, want 8-element slice", caseRecord.Payload["jsonrpc_messages"])
	}
	for idx := 0; idx < len(msgs); idx += 2 {
		wantID := float64(idx/2 + 1)
		req, ok := msgs[idx].(map[string]interface{})
		if !ok {
			t.Fatalf("msgs[%d] = %T, want request object", idx, msgs[idx])
		}
		if req["method"] != "tools/list" {
			t.Errorf("msgs[%d].method = %v, want tools/list", idx, req["method"])
		}
		if req["id"] != wantID {
			t.Errorf("msgs[%d].id = %v, want %v", idx, req["id"], wantID)
		}

		resp, ok := msgs[idx+1].(map[string]interface{})
		if !ok {
			t.Fatalf("msgs[%d] = %T, want response object", idx+1, msgs[idx+1])
		}
		if resp["id"] != wantID {
			t.Errorf("msgs[%d].id = %v, want matching request id %v", idx+1, resp["id"], wantID)
		}
		if _, hasResult := resp["result"]; !hasResult {
			t.Errorf("msgs[%d] missing result field; not a server response", idx+1)
		}
		if _, hasServers := resp["servers"]; hasServers {
			t.Errorf("msgs[%d] still has servers wrapper", idx+1)
		}
	}
}

func TestMultiFileSnapshotResponses_RejectsMalformedServers(t *testing.T) {
	tests := []struct {
		name     string
		snapshot map[string]interface{}
		wantErr  string
	}{
		{
			name: "servers not array",
			snapshot: map[string]interface{}{
				"servers": map[string]interface{}{},
			},
			wantErr: "servers must be an array",
		},
		{
			name: "empty servers",
			snapshot: map[string]interface{}{
				"servers": []interface{}{},
			},
			wantErr: "servers must contain at least one entry",
		},
		{
			name: "server not object",
			snapshot: map[string]interface{}{
				"servers": []interface{}{"bad"},
			},
			wantErr: "servers[0] must be an object",
		},
		{
			name: "missing tools list response",
			snapshot: map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{"name": "alpha"},
				},
			},
			wantErr: "servers[0] missing tools_list_response",
		},
		{
			name: "tools list response not object",
			snapshot: map[string]interface{}{
				"servers": []interface{}{
					map[string]interface{}{"tools_list_response": "bad"},
				},
			},
			wantErr: "servers[0].tools_list_response must be an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := multiFileSnapshotResponses(tt.snapshot)
			if err == nil {
				t.Fatal("expected malformed servers error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

// TestMultiFileCase_ToCase_WarnNormalizedToAllow verifies the receipt-
// scoring rubric normalization: a case.yaml with expected_verdict: warn
// (the mcp-drift-benign-001 FP-guardrail case) is converted to a Case
// with ExpectedVerdict: allow so the downstream receipt-profile mapping
// treats it as a benign baseline. The original semantic intent (a tool
// that blocks this case is over-reaching) is preserved.
func TestMultiFileCase_ToCase_WarnNormalizedToAllow(t *testing.T) {
	cases, err := loadMultiFileCases(filepath.Join("..", "cases", "mcp-drift"))
	if err != nil {
		t.Fatalf("loadMultiFileCases: %v", err)
	}
	var benign MultiFileCase
	for _, c := range cases {
		if c.ID == "mcp-drift-benign-001" {
			benign = c
			break
		}
	}
	if benign.ID == "" {
		t.Fatal("mcp-drift-benign-001 not found in mcp-drift fixtures")
	}
	if benign.ExpectedVerdict != "warn" {
		t.Fatalf("fixture expected_verdict = %q, want warn (rubric mapping assumes this)", benign.ExpectedVerdict)
	}
	caseRecord, err := benign.toCase()
	if err != nil {
		t.Fatalf("toCase: %v", err)
	}
	if caseRecord.ExpectedVerdict != "allow" {
		t.Errorf("converted ExpectedVerdict = %q, want allow (warn maps to allow for receipt-scoring)", caseRecord.ExpectedVerdict)
	}
}

// TestRunIntegratesMultiFileCases drives the full runner pipeline with
// the dryrun adapter, single-file cases, AND the four real mcp-drift
// fixtures. The dryrun adapter echoes expected_verdict, so each case
// scores pass. The test verifies that:
//  1. The runner accepts --multifile-cases without error.
//  2. The receipt profile emitted at the end contains rows for the
//     four mcp-drift case IDs.
//  3. The block-expected rugpull rows record blocked=yes and the
//     warn-expected benign row records blocked=n/a, false_positive=no.
func TestRunIntegratesMultiFileCases(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "summary.json")
	profilePath := filepath.Join(tmpDir, "profile.json")
	receiptPath := filepath.Join(tmpDir, "receipt-profile.json")

	if err := os.WriteFile(profilePath, []byte(`{
		"schema_version": 3,
		"tool": "test-tool",
		"tool_version": "0.0.0",
		"runner_version": "test",
		"claims": ["mcp_tool_poison", "mcp_chain"],
		"supports": {
			"mcp_stdio": true,
			"mcp_tool_poison_scanning": true,
			"mcp_tool_baseline": true,
			"mcp_chain_memory": true,
			"mcp_cross_server_chain_memory": true,
			"mcp_data_class_labels": true
		}
	}`), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	casesDir := filepath.Join("..", "cases")
	multiFileDir := filepath.Join("..", "cases", "mcp-drift")

	err := run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, receiptPath, "", multiFileDir, false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("read receipt profile: %v", err)
	}
	var rp ReceiptProfile
	if jsonErr := json.Unmarshal(data, &rp); jsonErr != nil {
		t.Fatalf("parse receipt profile: %v", jsonErr)
	}

	wantIDs := map[string]bool{
		"mcp-drift-benign-001":        false,
		"mcp-drift-rugpull-desc-002":  false,
		"mcp-drift-rugpull-param-003": false,
		"mcp-drift-collusion-004":     false,
	}
	for _, row := range rp.PerCase {
		if _, ok := wantIDs[row.CaseID]; !ok {
			continue
		}
		wantIDs[row.CaseID] = true
		switch row.CaseID {
		case "mcp-drift-benign-001":
			// warn-expected → maps to allow → blocked=n/a, false_positive=no
			// (dryrun returned allow, which matches the mapped expectation).
			if row.Blocked != "n/a" {
				t.Errorf("benign row Blocked = %q, want n/a", row.Blocked)
			}
			if row.FalsePositive != "no" {
				t.Errorf("benign row FalsePositive = %q, want no", row.FalsePositive)
			}
		default:
			// block-expected → blocked=yes, false_positive=n/a
			if row.Blocked != "yes" {
				t.Errorf("%s Blocked = %q, want yes", row.CaseID, row.Blocked)
			}
			if row.FalsePositive != "n/a" {
				t.Errorf("%s FalsePositive = %q, want n/a", row.CaseID, row.FalsePositive)
			}
		}
	}
	for id, found := range wantIDs {
		if !found {
			t.Errorf("multi-file case %s not present in receipt profile per_case", id)
		}
	}
}
