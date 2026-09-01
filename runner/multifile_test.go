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
	return fmt.Sprintf(`schema_version: 4
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

// TestLoadMultiFileCases_ValidFixtures loads the real mcp-drift cases
// from cases/mcp-drift/ and verifies that the loader returns all of them with
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
	// than by positional iteration so a new case in the future does not
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

// The runner has its own multi-file loader, so validation in the separate
// validate module cannot protect a direct runner invocation. The runner must
// reject every malformed prerequisite shape before the case can enter a run.
func TestLoadMultiFileCaseValidatesPrerequisites(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "unknown_kind",
			mutate: func(raw string) string {
				return raw + "prerequisites:\n  - kind: unrecognized_setup\n    value: example.test\n"
			},
			wantErr: "invalid prerequisite kind",
		},
		{
			name:    "empty_value",
			mutate:  func(raw string) string { return raw + "prerequisites:\n  - kind: blocklist_domain\n    value:\n" },
			wantErr: "prerequisite value at index 0 must be non-empty",
		},
		{
			name: "unknown_reserved_sink",
			mutate: func(raw string) string {
				return raw + "prerequisites:\n  - kind: reserved_sink_route\n    value: attacker.example.test\n"
			},
			wantErr: "is not a corpus-reserved sink host",
		},
		{
			name: "duplicate",
			mutate: func(raw string) string {
				return raw + "prerequisites:\n  - kind: blocklist_domain\n    value: exfil.example.test\n  - kind: blocklist_domain\n    value: exfil.example.test\n"
			},
			wantErr: "duplicate prerequisite",
		},
		{
			name: "domain_blocklist_without_prerequisite",
			mutate: func(raw string) string {
				return strings.Replace(raw, "  - mcp_tool_baseline", "  - domain_blocklist", 1)
			},
			wantErr: "requires contains \"domain_blocklist\" but no \"blocklist_domain\" prerequisite",
		},
		{
			name: "dns_rebinding_without_reserved_sink",
			mutate: func(raw string) string {
				return strings.Replace(raw, "  - mcp_tool_baseline", "  - dns_rebinding_fixture", 1)
			},
			wantErr: "requires contains \"dns_rebinding_fixture\" but no \"reserved_sink_route\" prerequisite",
		},
		{
			name: "reserved_sink_is_case_insensitive",
			mutate: func(raw string) string {
				return raw + "prerequisites:\n  - kind: reserved_sink_route\n    value: WS-EXFIL-SINK.TEST\n"
			},
			wantErr: "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			copyMultiFileCases(t, filepath.Join("..", "cases", "mcp-drift"), dir, "mcp-drift-benign-001")
			path := filepath.Join(dir, "mcp-drift-benign-001", "case.yaml")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(test.mutate(string(data))), 0o600); err != nil {
				t.Fatal(err)
			}

			_, err = loadMultiFileCases(dir)
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("loadMultiFileCases: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("loadMultiFileCases error = %v, want %q", err, test.wantErr)
			}
		})
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

func TestLoadMultiFileCase_MissingNotes(t *testing.T) {
	dir := t.TempDir()
	copyMultiFileCases(t, filepath.Join("..", "cases", "mcp-drift"), dir, "mcp-drift-benign-001")
	notesPath := filepath.Join(dir, "mcp-drift-benign-001", "notes.md")
	if err := os.Remove(notesPath); err != nil {
		t.Fatal(err)
	}
	_, err := loadMultiFileCases(dir)
	if err == nil || !strings.Contains(err.Error(), "required notes file") {
		t.Fatalf("missing notes error = %v, want required notes file refusal", err)
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
	if !strings.Contains(err.Error(), "safe relative-path pattern") {
		t.Errorf("error did not explain path confinement: %v", err)
	}
}

func TestMultiFileComponentContractsRejectMalformedShapes(t *testing.T) {
	validResponse := func() map[string]interface{} {
		return map[string]interface{}{
			"jsonrpc": "2.0", "id": json.Number("1"),
			"result": map[string]interface{}{"tools": []interface{}{
				map[string]interface{}{"name": "read_file", "inputSchema": map[string]interface{}{"type": "object"}},
			}},
		}
	}

	objectID := validResponse()
	objectID["id"] = map[string]interface{}{"nested": true}
	if err := validateToolsListResponse(objectID); err == nil || !strings.Contains(err.Error(), "id must be a string, number, or null") {
		t.Fatalf("object-valued JSON-RPC id error = %v, want id type refusal", err)
	}
	missingSchema := validResponse()
	delete(missingSchema["result"].(map[string]interface{})["tools"].([]interface{})[0].(map[string]interface{}), "inputSchema")
	if err := validateToolsListResponse(missingSchema); err == nil || !strings.Contains(err.Error(), "inputSchema must be an object") {
		t.Fatalf("missing inputSchema error = %v, want inputSchema refusal", err)
	}
	bothResultAndError := validResponse()
	bothResultAndError["error"] = map[string]interface{}{"code": json.Number("-32000"), "message": "denied"}
	if err := validateToolsListResponse(bothResultAndError); err == nil || !strings.Contains(err.Error(), "both result and error") {
		t.Fatalf("result-and-error response error = %v, want exclusive response-shape refusal", err)
	}

	c := MultiFileCase{ExpectedVerdict: "block", Transport: "mcp_http", Severity: "critical"}
	record := map[string]interface{}{
		"version": json.Number("1"), "verdict": "block", "transport": "mcp_http",
		"severity": "critical", "layer": "mcp_tool_baseline", "pattern": "drift", "intent": "deny",
	}
	if err := validateExpectedReceiptContract(c, map[string]interface{}{"version": "1", "action_record": record}); err == nil {
		t.Fatal("accepted string top-level receipt version")
	}
	record["version"] = "1"
	if err := validateExpectedReceiptContract(c, map[string]interface{}{"version": json.Number("1"), "action_record": record}); err == nil {
		t.Fatal("accepted string action-record version")
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
// the dryrun adapter and the default, loader-discovered corpus, including the
// real mcp-drift
// fixtures. The dryrun adapter echoes expected_verdict, so each case
// scores pass. The test verifies that:
//  1. The runner discovers multi-file cases without a caller-supplied flag.
//  2. The receipt profile emitted at the end contains rows for the
//     mcp-drift case IDs.
//  3. The block-expected rugpull rows record blocked=yes and the
//     warn-expected benign row records blocked=n/a, false_positive=no.
func TestRunIntegratesMultiFileCases(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "summary.json")
	profilePath := filepath.Join(tmpDir, "profile.json")
	receiptPath := filepath.Join(tmpDir, "receipt-profile.json")

	profile := validV4Profile(t)
	profile["tool"] = "test-tool"
	profile["tool_version"] = "0.0.0"
	profile["runner_version"] = "test"
	profile["claims"] = []string{"mcp_tool_poison", "mcp_chain"}
	profileData, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	if err := os.WriteFile(profilePath, profileData, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	casesDir := filepath.Join("..", "cases")
	// No receipt profile is requested here. Emission refuses a calibration run,
	// because the profile is a buyer-facing statement that a tool blocked things
	// and its schema carries no field that would let a reader tell an asserted
	// run from a measured one. The row mapping this test cares about is still
	// checked below, built directly rather than through the operator path.
	err = run(casesDir, profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "", "", false)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if _, statErr := os.Stat(receiptPath); !os.IsNotExist(statErr) {
		t.Fatalf("run wrote a receipt profile it was not asked for: %v", statErr)
	}

	expectedRun, err := loadRunCorpus(casesDir, "")
	if err != nil {
		t.Fatalf("loadRunCorpus: %v", err)
	}
	expected := expectedRun.cases
	summaryData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary GauntletSummary
	if err := json.Unmarshal(summaryData, &summary); err != nil {
		t.Fatalf("parse summary: %v", err)
	}
	if summary.CaseCount.Total != len(expected) {
		t.Fatalf("default run total = %d, want loader-backed %d", summary.CaseCount.Total, len(expected))
	}
	// Derived from the loader rather than pinned, so adding a multi-file case
	// changes what this asserts instead of failing it. The claim under test is that
	// a default run covers every registered multi-file case, not that there are
	// currently six of them.
	wantMCPDrift := 0
	for _, c := range expected {
		if c.Category == "mcp_drift" {
			wantMCPDrift++
		}
	}
	if wantMCPDrift == 0 {
		t.Fatal("loader reported no mcp_drift cases, so this assertion would prove nothing")
	}
	if summary.PerCategory["mcp_drift"].Applicable != wantMCPDrift {
		t.Fatalf(
			"default run mcp_drift applicability = %+v, want loader-backed %d",
			summary.PerCategory["mcp_drift"], wantMCPDrift,
		)
	}

	// Calibration semantics, stated once: the dryrun adapter echoes the expected
	// verdict, so every row scores pass. Building the rows here keeps the
	// expected-to-blocked mapping under test without asking the runner to write
	// an artifact it now refuses to write for an asserted run.
	byID := make(map[string]Case, len(expected))
	rows := make([]CaseResult, 0, len(expected))
	for _, c := range expected {
		byID[c.ID] = c
		rows = append(rows, CaseResult{
			CaseID:          c.ID,
			ExpectedVerdict: c.ExpectedVerdict,
			ActualVerdict:   c.ExpectedVerdict,
			Score:           "pass",
			Evidence:        map[string]interface{}{"synthetic": true, "synthetic_adapter": "dryrun"},
		})
	}
	rp := buildReceiptProfile(
		Profile{Tool: "test-tool", ToolVersion: "0.0.0"},
		rows,
		byID,
		ReceiptVerifier{},
		summary.CorpusVersion,
		summary.CorpusSHA256,
		summary.ToolProfileSHA256,
		testReceiptProfileProvenance(),
	)
	if len(rp.PerCase) != len(expected) {
		t.Fatalf("receipt profile rows = %d, want loader-backed %d", len(rp.PerCase), len(expected))
	}

	wantIDs := map[string]bool{
		"mcp-drift-benign-001":                 false,
		"mcp-drift-rugpull-desc-002":           false,
		"mcp-drift-rugpull-param-003":          false,
		"mcp-drift-collusion-004":              false,
		"mcp-drift-http-rugpull-desc-005":      false,
		"mcp-drift-http-benign-refinement-006": false,
	}
	for _, row := range rp.PerCase {
		if _, ok := wantIDs[row.CaseID]; !ok {
			continue
		}
		wantIDs[row.CaseID] = true
		switch row.CaseID {
		case "mcp-drift-benign-001", "mcp-drift-http-benign-refinement-006":
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

func copyMultiFileCases(t *testing.T, source, destination string, ids ...string) {
	t.Helper()
	if len(ids) == 0 {
		entries, err := os.ReadDir(source)
		if err != nil {
			t.Fatalf("read multi-file fixture directory: %v", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				ids = append(ids, entry.Name())
			}
		}
	}
	for _, id := range ids {
		caseDir := filepath.Join(destination, id)
		if err := os.MkdirAll(caseDir, 0o750); err != nil {
			t.Fatalf("mkdir override case %s: %v", id, err)
		}
		// Copy whatever the case actually holds. A pinned filename list makes a case
		// that names its fixtures differently, or carries an extra file, fail here on
		// a missing read rather than on the behaviour under test, and it would also
		// leave the copy silently incomplete for any digest comparison.
		caseEntries, err := os.ReadDir(filepath.Join(source, id))
		if err != nil {
			t.Fatalf("read source case %s: %v", id, err)
		}
		for _, entry := range caseEntries {
			if entry.IsDir() {
				t.Fatalf("unexpected nested directory in multi-file case %s: %s", id, entry.Name())
			}
			name := entry.Name()
			data, err := os.ReadFile(filepath.Join(source, id, name))
			if err != nil {
				t.Fatalf("read source %s/%s: %v", id, name, err)
			}
			if err := os.WriteFile(filepath.Join(caseDir, name), data, 0o600); err != nil {
				t.Fatalf("write override %s/%s: %v", id, name, err)
			}
		}
	}
}

func TestRunRejectsPartialMultiFileOverrideBeforeOutput(t *testing.T) {
	tmpDir := t.TempDir()
	profilePath := filepath.Join(tmpDir, "profile.json")
	outputPath := filepath.Join(tmpDir, "summary.json")
	profileData, err := json.Marshal(validV4Profile(t))
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	if err := os.WriteFile(profilePath, profileData, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}

	override := filepath.Join(tmpDir, "mcp-drift")
	copyMultiFileCases(t, filepath.Join("..", "cases", "mcp-drift"), override, "mcp-drift-benign-001")

	err = run(filepath.Join("..", "cases"), profilePath, outputPath, 10*1e9, "dryrun", "", "", "", "", false, "", "", override, false)
	if err == nil {
		t.Fatal("partial multi-file override completed a reduced run")
	}
	if !strings.Contains(err.Error(), "loader-backed corpus") || !strings.Contains(err.Error(), "mcp-drift-rugpull-desc-002") {
		t.Fatalf("partial override error = %v, want exact corpus rejection", err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("partial override wrote summary before failing: %v", statErr)
	}
}

func TestLoadRunCorpusAcceptsCompleteRelocatedMultiFileOverride(t *testing.T) {
	casesDir := filepath.Join("..", "cases")
	override := filepath.Join(t.TempDir(), "mcp-drift")
	copyMultiFileCases(t, filepath.Join(casesDir, "mcp-drift"), override)

	runCorpus, err := loadRunCorpus(casesDir, override)
	if err != nil {
		t.Fatalf("loadRunCorpus with complete relocated override: %v", err)
	}
	cases := runCorpus.cases
	canonical, err := loadCorpus(casesDir)
	if err != nil {
		t.Fatalf("load canonical corpus: %v", err)
	}
	activeIDs, err := loadActiveCaseIDs(casesDir, canonical)
	if err != nil {
		t.Fatalf("load active case IDs: %v", err)
	}
	if err := ensureExactRunCorpus(cases, canonical, activeIDs); err != nil {
		t.Fatalf("relocated override changed corpus identity: %v", err)
	}
	if len(runCorpus.snapshot.files) == 0 {
		t.Fatal("complete relocated override produced an empty corpus snapshot")
	}

	defaultDirs, err := registeredMultiFileCaseDirs(casesDir)
	if err != nil {
		t.Fatalf("registered multi-file directories: %v", err)
	}
	defaultDirPaths := make([]string, 0, len(defaultDirs))
	for _, directory := range defaultDirs {
		defaultDirPaths = append(defaultDirPaths, directory.path)
	}
	defaultHash, err := computeCorpusSHA256(casesDir, defaultDirPaths...)
	if err != nil {
		t.Fatalf("hash default corpus: %v", err)
	}
	overrideHash, err := computeCorpusSHA256(casesDir, override)
	if err != nil {
		t.Fatalf("hash relocated corpus: %v", err)
	}
	if overrideHash != defaultHash {
		t.Fatalf("relocated override hash = %s, want canonical %s", overrideHash, defaultHash)
	}
	defaultRun, err := loadRunCorpus(casesDir, "")
	if err != nil {
		t.Fatalf("load default active corpus: %v", err)
	}
	activeHash := corpusSHA256FromSnapshot(defaultRun.snapshot.files)
	if snapshotHash := corpusSHA256FromSnapshot(runCorpus.snapshot.files); snapshotHash != activeHash {
		t.Fatalf("active snapshot hash = %s, want canonical active %s", snapshotHash, activeHash)
	}

	notesPath := filepath.Join(override, "mcp-drift-benign-001", "notes.md")
	if err := os.WriteFile(notesPath, []byte("changed required narrative\n"), 0o600); err != nil {
		t.Fatalf("mutate required notes: %v", err)
	}
	notesHash, err := computeCorpusSHA256(casesDir, override)
	if err != nil {
		t.Fatalf("hash notes-mutated corpus: %v", err)
	}
	if notesHash == overrideHash {
		t.Fatal("changing required notes.md left the corpus digest unchanged")
	}

	afterPath := filepath.Join(override, "mcp-drift-benign-001", "after.json")
	if err := os.WriteFile(afterPath, []byte(`{"jsonrpc":"2.0","id":99,"result":{"tools":[]}}`), 0o600); err != nil {
		t.Fatalf("mutate multi-file artifact: %v", err)
	}
	mutatedHash, err := computeCorpusSHA256(casesDir, override)
	if err != nil {
		t.Fatalf("hash mutated relocated corpus: %v", err)
	}
	if mutatedHash == overrideHash {
		t.Fatal("changing a multi-file artifact left the corpus digest unchanged")
	}
}

func TestValidateMultiFileNameRejectsSchemaInvalidNames(t *testing.T) {
	for _, test := range []struct {
		name, suffix string
		wantErr      bool
	}{
		{"before.json", ".json", false},
		{"fixtures/before.json", ".json", false},
		{"before file.json", ".json", true},
		{".before.json", ".json", true},
		{"nøtes.md", ".md", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateMultiFileName(test.name, test.suffix, "fixture")
			if test.wantErr && err == nil {
				t.Fatalf("validateMultiFileName(%q) accepted a schema-invalid name", test.name)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateMultiFileName(%q) rejected a valid name: %v", test.name, err)
			}
		})
	}
}
