package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	defer func() { _ = root.Close() }()
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

func BenchmarkVerifyReturnedContentDirectoryRejectLarge(b *testing.B) {
	dir := b.TempDir()
	for i := 0; i < 20000; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("unrelated-%05d.txt", i)), nil, 0o600); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := verifyReturnedContentDirectory(dir); err == nil {
			b.Fatal("invalid directory accepted")
		}
	}
}

type observedDiagnosticDirectory struct {
	file       *os.File
	calls      int
	entries    int
	finalError error
}

func (d *observedDiagnosticDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	d.calls++
	if n <= 0 || n > diagnosticDirectoryBatchSize {
		return nil, fmt.Errorf("unbounded directory read: %d", n)
	}
	entries, err := d.file.ReadDir(n)
	d.entries += len(entries)
	if err == io.EOF && d.finalError != nil {
		return entries, d.finalError
	}
	return entries, err
}

func TestVerifyReturnedContentDirectoryStreaming(t *testing.T) {
	for _, scenario := range []string{"valid-multiple-batches", "invalid-first-batch", "listing-error", "orphan-bin"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			switch scenario {
			case "invalid-first-batch":
				for i := 0; i < diagnosticDirectoryBatchSize*3; i++ {
					if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("unexpected-%d.txt", i)), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			case "orphan-bin":
				if err := os.WriteFile(filepath.Join(dir, "orphan.bin"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			default:
				for i := 0; i < diagnosticDirectoryBatchSize+1; i++ {
					caseID := fmt.Sprintf("diagnostic-%d", i)
					if err := retainReturnedContent(dir, caseID, map[string]interface{}{}, []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			listing, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listing.Close() }()
			observed := &observedDiagnosticDirectory{file: listing}
			readFailure := errors.New("directory read failed")
			if scenario == "listing-error" {
				observed.finalError = readFailure
			}
			err = verifyReturnedContentEntries(root, observed)
			switch scenario {
			case "valid-multiple-batches":
				if err != nil {
					t.Fatal(err)
				}
				if observed.entries != 2*(diagnosticDirectoryBatchSize+1) || observed.calls < 3 {
					t.Fatalf("incomplete listing: %+v", observed)
				}
			case "invalid-first-batch":
				if err == nil || !strings.Contains(err.Error(), "unexpected diagnostic file") {
					t.Fatalf("invalid directory: %v", err)
				}
				if observed.calls != 1 || observed.entries > diagnosticDirectoryBatchSize {
					t.Fatalf("read past first invalid batch: %+v", observed)
				}
			case "listing-error":
				if !errors.Is(err, readFailure) {
					t.Fatalf("listing failure hidden: %v", err)
				}
			case "orphan-bin":
				if err == nil || !strings.Contains(err.Error(), "missing sidecar pair") {
					t.Fatalf("orphan accepted: %v", err)
				}
				if observed.calls != 1 || observed.entries > diagnosticDirectoryBatchSize {
					t.Fatalf("read past first orphan batch: %+v", observed)
				}
			}
		})
	}
}

type renamedDiagnosticEntry struct {
	os.DirEntry
	name string
}

func (e renamedDiagnosticEntry) Name() string { return e.name }

// Presents a real listing the way another filesystem could list it.
type rewrittenDiagnosticDirectory struct {
	file    *os.File
	rewrite func(os.DirEntry) []os.DirEntry
}

func (d rewrittenDiagnosticDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	entries, err := d.file.ReadDir(n)
	var listed []os.DirEntry
	for _, entry := range entries {
		listed = append(listed, d.rewrite(entry)...)
	}
	return listed, err
}

// A case-insensitive filesystem lists a file under its stored spelling while
// lookups also succeed under the canonical lower-case name.
func listContentUpperCase(entry os.DirEntry) []os.DirEntry {
	name := entry.Name()
	if name != strings.ToLower(name) {
		return nil
	}
	if strings.HasSuffix(name, ".bin") {
		entry = renamedDiagnosticEntry{entry, strings.ToUpper(strings.TrimSuffix(name, ".bin")) + ".bin"}
	}
	return []os.DirEntry{entry}
}

// A directory read while it changes may return an entry more than once.
func listTwice(entry os.DirEntry) []os.DirEntry { return []os.DirEntry{entry, entry} }

func TestVerifyReturnedContentDirectoryExactPairs(t *testing.T) {
	for _, scenario := range []string{"case-alias", "duplicate-manifest", "repeated-listing"} {
		t.Run(scenario, func(t *testing.T) {
			dir := t.TempDir()
			if err := retainReturnedContent(dir, "diagnostic-pair", map[string]interface{}{}, []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}); err != nil {
				t.Fatal(err)
			}
			const stem = "diagnostic-pair-0"
			manifest, err := os.ReadFile(filepath.Join(dir, stem+".json"))
			if err != nil {
				t.Fatal(err)
			}
			// Files are created before the listing is opened: some filesystems
			// list only the entries present when the directory was opened.
			extra := map[string][]byte{}
			if scenario == "duplicate-manifest" {
				extra[stem+".bin.json"] = manifest
			}
			if scenario == "case-alias" {
				// Make the upper-case lookups succeed on a case-sensitive
				// filesystem too; the listing hides these copies.
				content, err := os.ReadFile(filepath.Join(dir, stem+".bin"))
				if err != nil {
					t.Fatal(err)
				}
				upper := strings.ToUpper(stem)
				extra = map[string][]byte{upper + ".json": manifest, upper + ".bin": content}
			}
			for name, body := range extra {
				if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			listing, err := root.Open(".")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listing.Close() }()
			switch scenario {
			case "case-alias":
				err = verifyReturnedContentEntries(root, rewrittenDiagnosticDirectory{listing, listContentUpperCase})
				if err == nil || !strings.Contains(err.Error(), "missing sidecar pair") {
					t.Fatalf("aliased content file accepted: %v", err)
				}
				return
			case "repeated-listing":
				err = verifyReturnedContentEntries(root, rewrittenDiagnosticDirectory{listing, listTwice})
				if err == nil || !strings.Contains(err.Error(), "duplicate sidecar") {
					t.Fatalf("repeated listing accepted: %v", err)
				}
				return
			}
			// Listing order decides which check fires first; both refuse.
			err = verifyReturnedContentEntries(root, listing)
			if err == nil || (!strings.Contains(err.Error(), "duplicate sidecar") && !strings.Contains(err.Error(), "missing sidecar pair")) {
				t.Fatalf("second manifest accepted: %v", err)
			}
		})
	}
}

// Controls filesystem listing order without changing the retained files.
type orderedDiagnosticDirectory struct {
	entries []os.DirEntry
	calls   int
}

func (d *orderedDiagnosticDirectory) ReadDir(n int) ([]os.DirEntry, error) {
	d.calls++
	if n != diagnosticDirectoryBatchSize {
		return nil, fmt.Errorf("unexpected directory batch size %d", n)
	}
	if len(d.entries) == 0 {
		return nil, io.EOF
	}
	count := min(n, len(d.entries))
	entries := d.entries[:count]
	d.entries = d.entries[count:]
	return entries, nil
}

func TestVerifyReturnedContentSeparatedPairs(t *testing.T) {
	for _, order := range []string{"bins-first", "manifests-first"} {
		for _, mutation := range []string{"valid", "first-manifest", "last-manifest"} {
			t.Run(order+"/"+mutation, func(t *testing.T) {
				dir := t.TempDir()
				const pairs = diagnosticDirectoryBatchSize*2 + 1
				for i := 0; i < pairs; i++ {
					if err := retainReturnedContent(dir, fmt.Sprintf("ordered-%04d", i), map[string]interface{}{}, []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}); err != nil {
						t.Fatal(err)
					}
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				var bins, manifests []os.DirEntry
				for _, entry := range entries {
					if strings.HasSuffix(entry.Name(), ".bin") {
						bins = append(bins, entry)
					} else {
						manifests = append(manifests, entry)
					}
				}
				badIndex := 0
				if mutation == "last-manifest" {
					badIndex = pairs - 1
				}
				if mutation != "valid" {
					if err := os.WriteFile(filepath.Join(dir, manifests[badIndex].Name()), []byte("{"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ordered := append(bins, manifests...)
				if order == "manifests-first" {
					ordered = append(manifests, bins...)
				}
				root, err := os.OpenRoot(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = root.Close() }()
				reader := &orderedDiagnosticDirectory{entries: ordered}
				err = verifyReturnedContentEntries(root, reader)
				if mutation == "valid" {
					if err != nil {
						t.Fatal(err)
					}
					if len(reader.entries) != 0 || reader.calls < 5 {
						t.Fatalf("incomplete directory: %+v", reader)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "manifest") {
					t.Fatalf("invalid manifest accepted: %v", err)
				}
				wantCalls := badIndex/diagnosticDirectoryBatchSize + 1
				if reader.calls != wantCalls {
					t.Fatalf("read past invalid pair: calls=%d want=%d", reader.calls, wantCalls)
				}
			})
		}
	}
}

func TestVerifyReturnedContentUnlistedManifest(t *testing.T) {
	for _, scenario := range []struct {
		name       string
		exchange   bool
		tamper     bool
		incomplete bool
		wantError  string
	}{
		{name: "valid-content"},
		{name: "valid-exchange", exchange: true},
		{name: "tampered-content", tamper: true, wantError: "digest"},
		{name: "tampered-exchange", exchange: true, tamper: true, wantError: "digest"},
		{name: "incomplete-exchange", exchange: true, incomplete: true, wantError: "incomplete"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dir := t.TempDir()
			content := []adapter.ReturnedContent{{Bytes: []byte("synthetic"), MediaType: "text/plain", Path: "mcp_stdio_result"}}
			stem := "candidate-pair-0"
			if scenario.exchange {
				record := syntheticExchangeRecord()
				record.Complete = !scenario.incomplete
				if err := retainMCPHTTPExchanges(dir, "candidate-pair", record); err != nil {
					t.Fatal(err)
				}
				stem += "-exchange"
			} else if err := retainReturnedContent(dir, "candidate-pair", map[string]interface{}{}, content); err != nil {
				t.Fatal(err)
			}
			if scenario.tamper {
				path := filepath.Join(dir, stem+".bin")
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				body[0] ^= 1
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			var listed []os.DirEntry
			for _, entry := range entries {
				if entry.Name() != stem+".json" {
					listed = append(listed, entry)
				}
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = verifyReturnedContentEntries(root, &orderedDiagnosticDirectory{entries: listed})
			if scenario.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), scenario.wantError) {
				t.Fatalf("listed candidate was not verified: %v", err)
			}
		})
	}
}
