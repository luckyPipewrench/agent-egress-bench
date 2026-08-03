package verifier

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fixtureExpectation struct {
	ExpectedOutcome string `json:"expected_outcome"`
	Reason          string `json:"reason"`
	NonceStatus     string `json:"nonce_status"`
}

func TestConformanceCorpus(t *testing.T) {
	root := filepath.Join("..", "conformance")
	distribution := map[string]int{}
	packages := 0
	for _, category := range []string{"golden", "edge", "malicious"} {
		entries, err := os.ReadDir(filepath.Join(root, category))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			packages++
			packageDir := filepath.Join(root, category, entry.Name())
			t.Run(entry.Name(), func(t *testing.T) {
				expectation := readExpectation(t, filepath.Join(packageDir, "expect.json"))
				wantOutcome := expectation.ExpectedOutcome
				if wantOutcome == "previously-accepted" {
					wantOutcome = OutcomeValid
				}
				result := verifyPersistent(t, packageDir, filepath.Join(packageDir, "context.json"))
				if result.Outcome != wantOutcome || result.Reason != expectation.Reason || result.NonceStatus != expectation.NonceStatus {
					t.Fatalf("Verify() = %#v, want outcome=%q reason=%q nonce_status=%q", result, wantOutcome, expectation.Reason, expectation.NonceStatus)
				}
				distribution[wantOutcome]++
			})
		}
	}
	if packages != 85 {
		t.Fatalf("tested %d packages, want 85", packages)
	}
	wantDistribution := map[string]int{
		OutcomeValid: 14, outcomeInvalid: 33, outcomeStale: 3, outcomeScopeMismatch: 16,
		outcomeInsufficientEvidence: 15, outcomeUnverifiable: 4,
	}
	if !equalJSON(distribution, wantDistribution) {
		t.Fatalf("outcome distribution = %#v, want %#v", distribution, wantDistribution)
	}
}

func TestVerifierDoesNotUseFixturePathOrExpectOracle(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "renamed-package-with-no-fixture-id")
	copyTree(t, source, destination)
	if err := os.WriteFile(filepath.Join(destination, "expect.json"), []byte(`{"expected_outcome":"invalid","reason":"forged-answer-key"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
	if result.Outcome != OutcomeValid {
		t.Fatalf("Verify() trusted path or expect.json: %#v", result)
	}
}

func TestUncommittedMemberFailsClosed(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	if err := os.WriteFile(filepath.Join(destination, "uncommitted.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := Verify(destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "manifest_member_uncommitted" {
		t.Fatalf("Verify() = %#v, want invalid manifest_member_uncommitted", result)
	}
}

func TestCustomerClockCannotCollapseIntoRunnerSigner(t *testing.T) {
	source := filepath.Join("..", "conformance", "malicious", "m11-vendor-clock-role-laundering")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	contextPath := filepath.Join(destination, "context.json")
	data, err := os.ReadFile(contextPath)
	if err != nil {
		t.Fatal(err)
	}
	var context map[string]any
	if err := json.Unmarshal(data, &context); err != nil {
		t.Fatal(err)
	}
	trusted := context["trusted_keys"].(map[string]any)
	trusted["customer_clock"] = trusted["vendor_runner"]
	data, err = json.MarshalIndent(context, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(contextPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := Verify(destination, contextPath)
	if result.Outcome != outcomeScopeMismatch || result.Reason != "clock_role_mismatch" {
		t.Fatalf("Verify() = %#v, want scope-mismatch clock_role_mismatch", result)
	}
}

func TestMalformedIndependentContextFailsClosed(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	data := []byte(`{"profile":"control-evidence-conformance-context/v0","profile":"control-evidence-conformance-context/v0"}`)
	if err := os.WriteFile(contextPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := Verify(packageDir, contextPath)
	if result.Outcome != outcomeInvalid || result.Reason != "context_invalid" {
		t.Fatalf("Verify() = %#v, want invalid context_invalid", result)
	}
}

func TestDeeplyNestedContextFailsClosed(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	contextPath := filepath.Join(t.TempDir(), "context.json")
	depth := maxJSONDepth + 2
	data := append(bytes.Repeat([]byte("["), depth), bytes.Repeat([]byte("]"), depth)...)
	if err := os.WriteFile(contextPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := Verify(packageDir, contextPath)
	if result.Outcome != outcomeInvalid || result.Reason != "context_invalid" {
		t.Fatalf("Verify() = %#v, want invalid context_invalid", result)
	}
}

func TestStrictJSONDepthLimitIsLoadBearing(t *testing.T) {
	depth := maxJSONDepth + 2
	data := append(bytes.Repeat([]byte("["), depth), bytes.Repeat([]byte("]"), depth)...)
	if _, err := strictJSON(data, nil); err == nil || !strings.Contains(err.Error(), "JSON nesting exceeds") {
		t.Fatalf("strictJSON() error = %v, want explicit nesting-limit rejection", err)
	}
}

func TestSymlinkPackageMemberFailsClosed(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	if err := os.Symlink("summary.json", filepath.Join(destination, "alias.json")); err != nil {
		t.Fatal(err)
	}
	result := Verify(destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "package_invalid" {
		t.Fatalf("Verify() = %#v, want invalid package_invalid", result)
	}
}

func TestSymlinkPackageRootFailsClosed(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "package")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryPackage(root); err == nil || err.Error() != "package is not a directory" {
		t.Fatalf("loadDirectoryPackage() error = %v, want symlink-root rejection", err)
	}
}

func TestPackageDirectoryFanoutIsBounded(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	for i := range maxTreeEntries + 1 {
		if err := os.Mkdir(filepath.Join(destination, fmt.Sprintf("empty-%03d", i)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	result := Verify(destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "package_invalid" {
		t.Fatalf("Verify() = %#v, want invalid package_invalid", result)
	}
}

func TestPackageDirectoryDepthIsBounded(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	deep := destination
	for i := range maxPackageDepth + 1 {
		deep = filepath.Join(deep, fmt.Sprintf("d%d", i))
	}
	if err := os.MkdirAll(deep, 0o750); err != nil {
		t.Fatal(err)
	}
	result := Verify(destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "package_invalid" {
		t.Fatalf("Verify() = %#v, want invalid package_invalid", result)
	}
}

func TestPackageFileLimitIncludesUnmanifestedCoreFiles(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"requirement.dsse.json", "envelope.dsse.json", "manifest.json", "outcomes.json", "summary.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Three of the five core files are manifest entries, leaving 253 attachment
	// entries at the schema's 256-entry boundary. The envelope and manifest are
	// deliberately outside their own manifest.
	for i := range 253 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("attachment-%03d", i)), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := loadDirectoryPackage(root)
	if err != nil || len(files) != maxMembers {
		t.Fatalf("loadDirectoryPackage() files=%d err=%v, want %d files", len(files), err, maxMembers)
	}
	if err := os.WriteFile(filepath.Join(root, "attachment-over-limit"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryPackage(root); err == nil {
		t.Fatal("loadDirectoryPackage() accepted 257 manifest-capable entries")
	}
}

func TestPackageSizeLimitSeparatesCommittedBytesFromWrappers(t *testing.T) {
	if !packageSizeWithinLimits(maxTotalSize, 2*maxMemberSize) {
		t.Fatal("schema-valid committed and wrapper maxima were rejected")
	}
	if packageSizeWithinLimits(maxTotalSize+1, 0) {
		t.Fatal("committed bytes above the manifest limit were accepted")
	}
	if packageSizeWithinLimits(0, 2*maxMemberSize+1) {
		t.Fatal("manifest and envelope wrapper bytes above their limit were accepted")
	}
}

func TestConcurrentVerification(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	contextPath := filepath.Join(packageDir, "context.json")
	replayDir := privateTempDir(t)
	const workers = 12
	var wait sync.WaitGroup
	errors := make(chan Result, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if result := VerifyWithOptions(packageDir, VerifyOptions{ContextPath: contextPath, ReplayLedgerDir: replayDir}); result.Outcome != OutcomeValid {
				errors <- result
			}
		}()
	}
	wait.Wait()
	close(errors)
	for result := range errors {
		t.Errorf("concurrent Verify() = %#v, want valid", result)
	}
}

func TestNonPersistentVerificationCannotReturnValid(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	result := Verify(packageDir, filepath.Join(packageDir, "context.json"))
	if result.Outcome != outcomeUnverifiable || result.Reason != "replay_ledger_required" {
		t.Fatalf("Verify() = %#v, want unverifiable replay_ledger_required", result)
	}
}

func TestPersistentReplayFirstThenReverified(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	options := VerifyOptions{ContextPath: filepath.Join(packageDir, "context.json"), ReplayLedgerDir: privateTempDir(t)}
	first := VerifyWithOptions(packageDir, options)
	if first.Outcome != OutcomeValid || first.NonceStatus != "first_verification" {
		t.Fatalf("first VerifyWithOptions() = %#v", first)
	}
	second := VerifyWithOptions(packageDir, options)
	if second.Outcome != OutcomeValid || second.NonceStatus != "reverified_same_envelope" {
		t.Fatalf("second VerifyWithOptions() = %#v", second)
	}
}

func TestReplayLedgerRejectsPermissiveDirectory(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	replayDir := filepath.Join(t.TempDir(), "ledger")
	if err := os.Mkdir(replayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replayDir, 0o755); err != nil {
		t.Fatal(err)
	}
	result := VerifyWithOptions(packageDir, VerifyOptions{ContextPath: filepath.Join(packageDir, "context.json"), ReplayLedgerDir: replayDir})
	if result.Outcome != outcomeUnverifiable || result.Reason != "replay_ledger_permissions_invalid" {
		t.Fatalf("VerifyWithOptions() = %#v", result)
	}
}

func TestEmbeddedSchemasMatchCanonicalCopies(t *testing.T) {
	entries, err := embeddedSchemas.ReadDir("schemas")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		embedded, err := embeddedSchemas.ReadFile(filepath.Join("schemas", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if string(embedded) != string(canonical) {
			t.Fatalf("embedded schema %s drifted from schemas/%s", entry.Name(), entry.Name())
		}
	}
}

func TestRequirementCannotMakePolicyOrAdapterBytesOptional(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	wrapper := readObject(t, filepath.Join(packageDir, "requirement.dsse.json"))
	payload, err := base64.StdEncoding.Strict().DecodeString(wrapper["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var requirement map[string]any
	_, err = strictJSON(payload, &requirement)
	if err != nil {
		t.Fatal(err)
	}
	requirement["required_artifacts"] = []any{"tool-profile", "observer-evidence"}
	mutated, err := json.Marshal(requirement)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictJSON(mutated, nil)
	if err != nil {
		t.Fatal(err)
	}
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSchema(schemas.requirement, value); err == nil {
		t.Fatal("requirement schema accepted policy/adapter declaration without required artifact bytes")
	}
}

func readExpectation(t *testing.T, path string) fixtureExpectation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var expectation fixtureExpectation
	if err := json.Unmarshal(data, &expectation); err != nil {
		t.Fatal(err)
	}
	return expectation
}

func verifyPersistent(t *testing.T, packageDir, contextPath string) Result {
	t.Helper()
	return VerifyWithOptions(packageDir, VerifyOptions{ContextPath: contextPath, ReplayLedgerDir: privateTempDir(t)})
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	}); err != nil {
		t.Fatal(err)
	}
}
