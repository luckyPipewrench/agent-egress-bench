package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

func syntheticExchangeRecord() *adapter.MCPHTTPExchanges {
	return &adapter.MCPHTTPExchanges{
		Complete: true, PlannedMethods: []string{"initialize", "tools/list"},
		Exchanges: []adapter.MCPHTTPExchange{
			{Request: []byte(`{"jsonrpc":"2.0","id":"aeb-listener-session-setup","method":"initialize","params":{}}`), Response: []byte(`{}`), Status: 200, MediaType: "application/json", Complete: true},
			{Request: []byte(`{"jsonrpc":"2.0","id":"local-synthetic-id","method":"tools/list","params":{}}`), Response: []byte(`{"jsonrpc":"2.0","id":"local-synthetic-id","result":{"tools":[]}}`), Status: 200, MediaType: "application/json", Complete: true},
		},
	}
}

func TestVerifyReturnedContentDirectory(t *testing.T) {
	for _, mutation := range []string{"valid", "tamper", "missing", "malformed", "case-id", "media", "path", "count", "empty", "orphan", "unknown", "trailing", "incomplete", "missing-exchange", "symlink"} {
		t.Run(mutation, func(t *testing.T) {
			dir := t.TempDir()
			if err := retainReturnedContent(dir, "diagnostic-test", map[string]interface{}{}, []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}); err != nil {
				t.Fatal(err)
			}
			record := syntheticExchangeRecord()
			if mutation == "incomplete" {
				record.Complete = false
			}
			if mutation == "missing-exchange" {
				record.Exchanges = record.Exchanges[:1]
			}
			if err := retainMCPHTTPExchanges(dir, "diagnostic-test", record); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "diagnostic-test-0.bin")
			manifest := filepath.Join(dir, "diagnostic-test-0.json")
			switch mutation {
			case "tamper":
				if err := os.WriteFile(bin, []byte("tampered"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				if err := os.Remove(bin); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(manifest, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				dir = t.TempDir()
			case "orphan":
				if err := os.WriteFile(filepath.Join(dir, "orphan.bin"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(bin); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(manifest, bin); err != nil {
					t.Fatal(err)
				}
			case "case-id", "media", "path", "count", "unknown", "trailing":
				body, err := os.ReadFile(manifest)
				if err != nil {
					t.Fatal(err)
				}
				var object map[string]interface{}
				if err := json.Unmarshal(body, &object); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "case-id":
					object["case_id"] = "wrong"
				case "media":
					object["media_type"] = "application/unknown"
				case "path":
					object["path"] = "unknown"
				case "count":
					object["bytes"] = 0
				case "unknown":
					object["unknown"] = true
				}
				body, err = json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				if mutation == "trailing" {
					body = append(body, []byte(" {}")...)
				}
				if err := os.WriteFile(manifest, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := verifyReturnedContentDirectory(dir)
			if mutation == "valid" && err != nil {
				t.Fatal(err)
			}
			if mutation != "valid" && err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}

func TestVerifyReturnedContentMetadataBinding(t *testing.T) {
	dir := t.TempDir()
	manifest := returnedContentManifest{CaseID: "binding-test", Bytes: 1, MediaType: "text/plain", Path: "mcp_stdio_result"}
	// Writing with an incorrect digest must fail before a manifest is published.
	if err := writeReturnedContentSidecar(dir, "binding-test-0", []byte("x"), manifest); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("error: %v", err)
	}
}

func TestMCPHTTPExchangeRetentionOptInAndPermissions(t *testing.T) {
	if err := retainMCPHTTPExchanges("", "diagnostic-test", syntheticExchangeRecord()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := retainMCPHTTPExchanges(dir, "diagnostic-test", syntheticExchangeRecord()); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".bin", ".json"} {
		info, err := os.Stat(filepath.Join(dir, "diagnostic-test-0-exchange"+suffix))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("permissions: %v", info.Mode())
		}
	}
}

func TestMCPHTTPExchangeRunnerRetentionKeepsPublicRowsUnchanged(t *testing.T) {
	c := Case{ID: "diagnostic-test", ExpectedVerdict: "allow", Transport: "mcp_stdio", InputType: "mcp_tool_result"}
	result := adapter.Result{Verdict: "allow", Evidence: map[string]interface{}{}, DeliveryProven: true, VerdictObserved: true, MCPHTTPExchanges: syntheticExchangeRecord()}
	var baseline, retained bytes.Buffer
	if _, _, _, _, err := runCasesWithSetup([]Case{c}, stateTestProfile(), returnedContentAdapter{result}, time.Second, false, &baseline, runSetup{}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, _, _, _, err := runCasesWithSetup([]Case{c}, stateTestProfile(), returnedContentAdapter{result}, time.Second, false, &retained, runSetup{returnedContentDir: dir}); err != nil {
		t.Fatal(err)
	}
	if baseline.String() != retained.String() {
		t.Fatal("exchange opt-in changed public result row")
	}
	if err := verifyReturnedContentDirectory(dir); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyReturnedContentExpectedManifest(t *testing.T) {
	dir := t.TempDir()
	if err := retainReturnedContent(dir, "binding-test", map[string]interface{}{}, []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	body, err := os.ReadFile(filepath.Join(dir, "binding-test-0.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected returnedContentManifest
	if err := json.Unmarshal(body, &expected); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVerifiedReturnedContentSidecarPair(root, "binding-test-0.bin", "binding-test-0.json", expected); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"media", "path", "case-id"} {
		t.Run(field, func(t *testing.T) {
			mismatch := expected
			switch field {
			case "media":
				mismatch.MediaType = "application/json"
			case "path":
				mismatch.Path = "mcp_tools_list"
			case "case-id":
				mismatch.CaseID = "other-case"
			}
			if _, err := loadVerifiedReturnedContentSidecarPair(root, "binding-test-0.bin", "binding-test-0.json", mismatch); err == nil || !strings.Contains(err.Error(), "metadata") {
				t.Fatalf("metadata mismatch not isolated: %v", err)
			}
		})
	}
}

func TestVerifyReturnedContentVerifierModes(t *testing.T) {
	if err := validateReturnedContentVerifierFlags([]string{"verify-returned-content"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"stats", "case-index", "report", "publication-lockup", "version", "cases", "adapter", "require-complete"} {
		if err := validateReturnedContentVerifierFlags([]string{"verify-returned-content", name}); err == nil {
			t.Fatalf("silently accepted --%s", name)
		}
	}
}

func TestVerifyReturnedContentExchangeRelabel(t *testing.T) {
	dir := t.TempDir()
	if err := retainMCPHTTPExchanges(dir, "diagnostic-test", syntheticExchangeRecord()); err != nil {
		t.Fatal(err)
	}
	if err := verifyReturnedContentDirectory(dir); err != nil {
		t.Fatal(err)
	}
	old := "diagnostic-test-0-exchange"
	newName := "other-case-0-exchange"
	body, err := os.ReadFile(filepath.Join(dir, old+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest returnedContentManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.CaseID = "other-case"
	body, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, newName+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, old+".json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, old+".bin"), filepath.Join(dir, newName+".bin")); err != nil {
		t.Fatal(err)
	}
	if err := verifyReturnedContentDirectory(dir); err == nil || !strings.Contains(err.Error(), "exchange case identity") {
		t.Fatalf("relabel accepted: %v", err)
	}
}

func TestVerifyReturnedContentExchangeIdentityIndex(t *testing.T) {
	dir := t.TempDir()
	if err := retainMCPHTTPExchanges(dir, "diagnostic-test", syntheticExchangeRecord()); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{".json", ".bin"} {
		if err := os.Rename(filepath.Join(dir, "diagnostic-test-0-exchange"+suffix), filepath.Join(dir, "diagnostic-test-1-exchange"+suffix)); err != nil {
			t.Fatal(err)
		}
	}
	if err := verifyReturnedContentDirectory(dir); err == nil || !strings.Contains(err.Error(), "invalid sidecar identity") {
		t.Fatalf("nonzero exchange index accepted: %v", err)
	}
}

func TestMCPHTTPExchangeRetentionRejectsWrongCase(t *testing.T) {
	record := syntheticExchangeRecord()
	record.CaseID = "different-case"
	if err := retainMCPHTTPExchanges(t.TempDir(), "diagnostic-test", record); err == nil || !strings.Contains(err.Error(), "case identity mismatch") {
		t.Fatalf("wrong producer identity accepted: %v", err)
	}
}

func TestVerifyReturnedContentPositionalArguments(t *testing.T) {
	if err := validateReturnedContentVerifierFlags([]string{"verify-returned-content"}, "extra"); err == nil {
		t.Fatal("positional argument silently ignored")
	}
}
