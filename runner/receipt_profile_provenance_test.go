package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRunCorpusRecordsCleanGitRevision(t *testing.T) {
	root := writeGitCorpus(t)
	wantSHA := runGitForTest(t, root, "rev-parse", "HEAD")

	run, err := loadRunCorpus(root, "")
	if err != nil {
		t.Fatalf("loadRunCorpus: %v", err)
	}
	if run.gitProvenance.Status != corpusGitStatusClean {
		t.Fatalf("corpus_git_status = %q, want clean", run.gitProvenance.Status)
	}
	if run.gitProvenance.SHA == nil || *run.gitProvenance.SHA != wantSHA {
		t.Fatalf("corpus_git_sha = %v, want %q", run.gitProvenance.SHA, wantSHA)
	}
}

func TestLoadRunCorpusRecordsDirtyGitCheckout(t *testing.T) {
	root := writeGitCorpus(t)
	if err := os.WriteFile(filepath.Join(root, "dirty.txt"), []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}

	run, err := loadRunCorpus(root, "")
	if err != nil {
		t.Fatalf("loadRunCorpus: %v", err)
	}
	if run.gitProvenance.Status != corpusGitStatusDirty {
		t.Fatalf("corpus_git_status = %q, want dirty", run.gitProvenance.Status)
	}
	if run.gitProvenance.SHA != nil {
		t.Fatalf("internal corpus_git_sha = %q, want no SHA for dirty source", *run.gitProvenance.SHA)
	}
}

func TestObserveGitCheckoutIgnoresUnrelatedWorktreeChanges(t *testing.T) {
	root := t.TempDir()
	corpus := filepath.Join(root, "cases")
	if err := os.Mkdir(corpus, 0o750); err != nil {
		t.Fatal(err)
	}
	writeMinimalCorpusCase(t, corpus)
	runGitForTest(t, root, "init", "-q")
	runGitForTest(t, root, "config", "user.email", "receipt-profile-test@example.invalid")
	runGitForTest(t, root, "config", "user.name", "Receipt Profile Test")
	runGitForTest(t, root, "add", "cases/case.json")
	runGitForTest(t, root, "commit", "-qm", "fixture")
	if err := os.WriteFile(filepath.Join(root, "unrelated.txt"), []byte("scratch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if observed := observeGitCheckout(corpus); observed.status != corpusGitStatusClean {
		t.Fatalf("scoped corpus status = %q, want clean", observed.status)
	}
}

func TestObserveGitCheckoutIgnoresInheritedRepositoryOverrides(t *testing.T) {
	root := writeGitCorpus(t)
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "not-a-repository"))
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.bare")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	if observed := observeGitCheckout(root); observed.status != corpusGitStatusClean {
		t.Fatalf("corpus status with inherited Git overrides = %q, want clean", observed.status)
	}
}

func TestLoadRunCorpusRecordsNonGitSource(t *testing.T) {
	root := t.TempDir()
	writeMinimalCorpusCase(t, root)

	run, err := loadRunCorpus(root, "")
	if err != nil {
		t.Fatalf("loadRunCorpus: %v", err)
	}
	if run.gitProvenance.Status != corpusGitStatusNotGitCheckout {
		t.Fatalf("corpus_git_status = %q, want not_git_checkout", run.gitProvenance.Status)
	}
	if run.gitProvenance.SHA != nil {
		t.Fatalf("internal corpus_git_sha = %q, want no SHA for non-Git source", *run.gitProvenance.SHA)
	}
}

func TestObserveCorpusGitProvenanceRecordsMultipleSources(t *testing.T) {
	first := writeGitCorpus(t)
	second := writeGitCorpus(t)

	provenance := observeCorpusGitProvenance([]string{first, second})
	if provenance.Status != corpusGitStatusMultipleSources {
		t.Fatalf("corpus_git_status = %q, want multiple_sources", provenance.Status)
	}
	if provenance.SHA != nil {
		t.Fatalf("internal corpus_git_sha = %q, want no SHA for multiple sources", *provenance.SHA)
	}
}

func TestStableCorpusGitProvenanceRecordsChangedDuringCapture(t *testing.T) {
	beforeSHA := strings.Repeat("a", 40)
	afterSHA := strings.Repeat("b", 40)
	provenance := stableCorpusGitProvenance(
		CorpusGitProvenance{SHA: &beforeSHA, Status: corpusGitStatusClean},
		CorpusGitProvenance{SHA: &afterSHA, Status: corpusGitStatusClean},
	)
	if provenance.Status != corpusGitStatusChangedDuringCapture {
		t.Fatalf("corpus_git_status = %q, want changed_during_capture", provenance.Status)
	}
	if provenance.SHA != nil {
		t.Fatalf("internal corpus_git_sha = %q, want no SHA after a changed capture", *provenance.SHA)
	}
}

func TestMergeObservedGitCheckoutsPreservesDirtyStatus(t *testing.T) {
	root := t.TempDir()
	merged := mergeObservedGitCheckouts(
		observedGitCheckout{root: root, sha: strings.Repeat("a", 40), status: corpusGitStatusClean},
		observedGitCheckout{root: root, status: corpusGitStatusDirty},
	)
	if merged.status != corpusGitStatusDirty {
		t.Fatalf("merged status = %q, want dirty", merged.status)
	}
}

func TestObserveToolVersionRecordsToolStdout(t *testing.T) {
	t.Setenv("AEB_RECEIPT_VERSION_HELPER", "success")
	observation := observeToolVersion(testToolVersionCommand(t))
	if observation.Status != toolVersionStatusObserved {
		t.Fatalf("status = %q, want observed", observation.Status)
	}
	if observation.Value == nil || *observation.Value != "fixture-tool 3.4.0" {
		t.Fatalf("value = %v, want tool stdout", observation.Value)
	}
}

func TestObserveToolVersionRecordsUnavailableCommand(t *testing.T) {
	t.Setenv("AEB_RECEIPT_VERSION_HELPER", "fail")
	observation := observeToolVersion(testToolVersionCommand(t))
	if observation.Status != toolVersionStatusCommandFailed {
		t.Fatalf("status = %q, want command_failed", observation.Status)
	}
	if observation.Value != nil {
		t.Fatalf("value = %q, want null after failed command", *observation.Value)
	}
}

func TestObserveToolVersionRecordsNotRequested(t *testing.T) {
	observation := observeToolVersion("")
	if observation.Status != toolVersionStatusNotRequested {
		t.Fatalf("status = %q, want not_requested", observation.Status)
	}
	if observation.Value != nil {
		t.Fatalf("value = %q, want null when no command was supplied", *observation.Value)
	}
}

func TestObserveToolVersionBoundsInheritedStdout(t *testing.T) {
	t.Setenv("AEB_RECEIPT_VERSION_HELPER", "spawn_stdout_holder")
	started := time.Now()
	observation := observeToolVersion(testToolVersionCommand(t))
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("version observation waited %s for inherited stdout", elapsed)
	}
	if observation.Status != toolVersionStatusCommandFailed || observation.Value != nil {
		t.Fatalf("observation = %+v, want command_failed after bounded wait", observation)
	}
}

func TestWriteReceiptProfileRetainsExplicitUnavailableProvenance(t *testing.T) {
	profile := validProfile()
	profile.CorpusGitStatus = corpusGitStatusDirty
	profile.CorpusGitSHA = ""
	profile.ObservedToolVersion = ToolVersionObservation{Status: toolVersionStatusCommandFailed}
	path := filepath.Join(t.TempDir(), "receipt-profile.json")
	if err := writeReceiptProfile(profile, path); err != nil {
		t.Fatalf("writeReceiptProfile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var written ReceiptProfile
	if err := decodeStrictJSON(data, &written); err != nil {
		t.Fatal(err)
	}
	if written.CorpusGitStatus != corpusGitStatusDirty || written.CorpusGitSHA != "" {
		t.Fatalf("written corpus Git provenance = status %q SHA %q, want dirty and empty", written.CorpusGitStatus, written.CorpusGitSHA)
	}
	if written.ObservedToolVersion.Status != toolVersionStatusCommandFailed || written.ObservedToolVersion.Value != nil {
		t.Fatalf("written observed tool version = %+v, want command_failed and null", written.ObservedToolVersion)
	}
}

func TestReceiptProfileV5SchemaAndValidatorRejectBrokenProvenance(t *testing.T) {
	schema := compileJSONSchema(t, filepath.Join("..", "schemas", "receipt-scoring-profile-v5.schema.json"))
	valid := validProfile()
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	var document interface{}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("schema rejected valid v5 profile: %v", err)
	}
	if issues := ValidateReceiptProfile(valid); len(issues) != 0 {
		t.Fatalf("validator rejected valid v5 profile: %v", issues)
	}

	broken := valid
	broken.CorpusGitSHA = ""
	raw, err = json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err == nil {
		t.Fatal("schema accepted clean corpus provenance without a corpus_git_sha")
	}
	if issues := ValidateReceiptProfile(broken); len(issues) == 0 {
		t.Fatal("Go validator accepted clean corpus provenance without a corpus_git_sha")
	}

	broken = valid
	value := "declared-label-is-not-an-observation"
	broken.ObservedToolVersion = ToolVersionObservation{Status: toolVersionStatusCommandFailed, Value: &value}
	raw, err = json.Marshal(broken)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(document); err == nil {
		t.Fatal("schema accepted a version value after command_failed")
	}
	if issues := ValidateReceiptProfile(broken); len(issues) == 0 {
		t.Fatal("Go validator accepted a version value after command_failed")
	}
}

func TestReceiptProfileV4WithoutNewFieldsStillValidates(t *testing.T) {
	zeros := strings.Repeat("0", 64)
	raw := fmt.Sprintf(`{
  "schema_version": 4,
  "tool": "legacy-tool",
  "tool_version": "1.0.0",
  "corpus_version": "v2.0.0",
  "corpus_sha256": %q,
  "tool_profile_sha256": %q,
  "capability_registry": {"id": "legacy", "format": 1, "revision": 1, "sha256": %q},
  "verifier": {"shipped": false, "open_source": false, "verifier_url": null, "license": null, "exit_code_contract": null},
  "summary": {"blocked_yes_count": 1, "blocked_no_count": 0, "explained_yes_count": 0, "receipt_produced_yes_count": 0, "receipt_independently_verifiable_yes_count": 0, "false_positive_yes_count": 0},
  "per_case": [{"case_id": "legacy-case", "blocked": "yes", "explained": "no", "receipt_produced": "no", "receipt_independently_verifiable": "no", "false_positive": "n/a"}]
}`, zeros, zeros, zeros)

	var legacy ReceiptProfile
	if err := decodeStrictJSON([]byte(raw), &legacy); err != nil {
		t.Fatalf("decode legacy v4 profile: %v", err)
	}
	if issues := ValidateReceiptProfile(legacy); len(issues) != 0 {
		t.Fatalf("old-code v4 profile no longer validates: %v", issues)
	}
}

func TestReceiptProfileToolVersionHelper(t *testing.T) {
	switch os.Getenv("AEB_RECEIPT_VERSION_HELPER") {
	case "success":
		_, _ = fmt.Fprintln(os.Stdout, "fixture-tool 3.4.0")
		os.Exit(0)
	case "fail":
		os.Exit(19)
	case "spawn_stdout_holder":
		command := exec.Command(os.Args[0], "-test.run=^TestReceiptProfileToolVersionHelper$")
		command.Env = append(os.Environ(), "AEB_RECEIPT_VERSION_HELPER=hold_stdout")
		command.Stdout = os.Stdout
		if err := command.Start(); err != nil {
			os.Exit(20)
		}
		os.Exit(0)
	case "hold_stdout":
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
}

func testToolVersionCommand(t *testing.T) string {
	t.Helper()
	command, err := json.Marshal([]string{os.Args[0], "-test.run=^TestReceiptProfileToolVersionHelper$"})
	if err != nil {
		t.Fatal(err)
	}
	return string(command)
}

func writeGitCorpus(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeMinimalCorpusCase(t, root)
	runGitForTest(t, root, "init", "-q")
	runGitForTest(t, root, "config", "user.email", "receipt-profile-test@example.invalid")
	runGitForTest(t, root, "config", "user.name", "Receipt Profile Test")
	runGitForTest(t, root, "config", "commit.gpgsign", "false")
	runGitForTest(t, root, "config", "core.hooksPath", "/dev/null")
	runGitForTest(t, root, "add", "case.json")
	runGitForTest(t, root, "commit", "-qm", "fixture")
	return root
}

func writeMinimalCorpusCase(t *testing.T, root string) {
	t.Helper()
	caseJSON := `{"schema_version":4,"id":"fixture-case","category":"url","expected_verdict":"block"}`
	if err := os.WriteFile(filepath.Join(root, "case.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runGitForTest(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	command.Env = append(filteredGitEnvironment(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
