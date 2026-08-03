package verifier

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestReplayStoreConcurrentDifferentEnvelopeHasOneWinner(t *testing.T) {
	store, reason, err := openReplayStore(privateTempDir(t))
	if err != nil {
		t.Fatalf("openReplayStore() reason=%q err=%v", reason, err)
	}
	entries := []replayEntry{testReplayEntry("a"), testReplayEntry("b")}
	statuses := make(chan string, len(entries))
	var wait sync.WaitGroup
	for _, entry := range entries {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, reason, err := store.checkAndRecord(entry)
			if err != nil {
				t.Errorf("checkAndRecord() reason=%q err=%v", reason, err)
				return
			}
			statuses <- status
		}()
	}
	wait.Wait()
	close(statuses)
	counts := map[string]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts["first_verification"] != 1 || counts["different_envelope_replay"] != 1 {
		t.Fatalf("statuses = %#v", counts)
	}
}

func TestReplayStoreConcurrentSameEnvelopeReverifies(t *testing.T) {
	store, reason, err := openReplayStore(privateTempDir(t))
	if err != nil {
		t.Fatalf("openReplayStore() reason=%q err=%v", reason, err)
	}
	const workers = 12
	statuses := make(chan string, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			status, reason, err := store.checkAndRecord(testReplayEntry("a"))
			if err != nil {
				t.Errorf("checkAndRecord() reason=%q err=%v", reason, err)
				return
			}
			statuses <- status
		}()
	}
	wait.Wait()
	close(statuses)
	counts := map[string]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts["first_verification"] != 1 || counts["reverified_same_envelope"] != workers-1 {
		t.Fatalf("statuses = %#v", counts)
	}
}

func TestMalformedReplayRecordFailsClosed(t *testing.T) {
	dir := privateTempDir(t)
	entry := testReplayEntry("a")
	path := filepath.Join(dir, replayFilename(entry))
	if err := os.WriteFile(path, []byte(`{"profile":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, reason, err := openReplayStore(dir); err == nil || reason != "replay_ledger_invalid" {
		t.Fatalf("openReplayStore() reason=%q err=%v", reason, err)
	}
}

func TestInvalidPackageDoesNotConsumeReplayNonce(t *testing.T) {
	packageDir := filepath.Join("..", "conformance", "malicious", "m08-token-mismatch")
	dir := privateTempDir(t)
	result := VerifyWithOptions(packageDir, VerifyOptions{
		ContextPath:     filepath.Join(packageDir, "context.json"),
		ReplayLedgerDir: dir,
	})
	if result.Outcome != outcomeInvalid {
		t.Fatalf("VerifyWithOptions() = %#v", result)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid package wrote replay state: %#v", entries)
	}
}

func testReplayEntry(envelopeSeed string) replayEntry {
	return replayEntry{
		Profile:                replayProfile,
		RequirementSignerKeyID: strings.Repeat("1", 64),
		RequirementID:          strings.Repeat("2", 32),
		ChallengeNonce:         strings.Repeat("3", 64),
		EnvelopePayloadSHA256:  lengthPrefixedDigest(envelopeSeed),
	}
}
