package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

const corpusVersionLedgerPath = "../ci/corpus-versions.json"

// corpusVersionRecord binds one corpus_version label to the executed corpus it
// names. The ledger is append-only on purpose: published results carry the
// label, so redefining an existing entry retroactively changes what an
// already-published number was measured over.
//
// Fields are read by key rather than decoded by struct tag so a missing or
// wrong-typed entry fails loudly here instead of silently becoming a zero value
// that would compare equal to nothing.
type corpusVersionRecord struct {
	CorpusVersion           string
	CaseCount               int
	BenchmarkManifestSHA256 string
}

// TestCorpusVersionNamesThisCorpus is the guard that was missing when corpus
// v2.4.0 came to name two different corpora.
//
// Four scored cases were added without moving corpusVersion. The case-ID
// manifest changed, the executed-corpus digest changed, and the label did not,
// so a published score measured over 242 cases stayed labelled identically to
// the 246-case corpus that superseded it. Every downstream staleness check keys
// on the label, so none of them could see it: comparing v2.4.0 against v2.4.0
// reports agreement no matter what the corpus underneath did.
//
// Binding the label to the digest makes that mistake mechanically impossible.
// Adding, removing or re-expecting a scored case moves the digest, the entry for
// the current label stops matching, and this test fails with the values to
// record under a new label. Documentation and unreferenced files are already
// excluded from the digest by selectedCorpusFiles, so editorial work on the
// corpus does not force a version bump.
func TestCorpusVersionNamesThisCorpus(t *testing.T) {
	records := readCorpusVersionLedger(t)

	seen := map[string]bool{}
	for _, record := range records {
		if seen[record.CorpusVersion] {
			t.Fatalf("%s records corpus_version %q more than once; one label cannot name two corpora, which is the failure this ledger exists to prevent", corpusVersionLedgerPath, record.CorpusVersion)
		}
		seen[record.CorpusVersion] = true
	}

	// The ledger is append-only, so the final entry is the current corpus by
	// construction. Requiring that gives every reader one rule for finding the
	// current label instead of searching, and it catches a new entry appended
	// without moving the runner constant.
	var current *corpusVersionRecord
	if last := &records[len(records)-1]; last.CorpusVersion == corpusVersion {
		current = last
	}
	for i := range records {
		if records[i].CorpusVersion != corpusVersion {
			continue
		}
		if current == nil {
			t.Fatalf("%s records corpus_version %q at position %d of %d, but the current label must be the final entry because the ledger is append-only. Either move the entry to the end or bump corpusVersion in runner/summary.go to the label that was appended last (%q).",
				corpusVersionLedgerPath, corpusVersion, i+1, len(records), records[len(records)-1].CorpusVersion)
		}
	}

	loaded, err := loadRunCorpus("../cases", "")
	if err != nil {
		t.Fatalf("load run corpus: %v", err)
	}
	digest, err := benchmarkManifestSHA256FromSnapshot(loaded.snapshot.files)
	if err != nil {
		t.Fatalf("compute benchmark manifest digest: %v", err)
	}
	count := len(loaded.cases)

	if current == nil {
		t.Fatalf("runner corpusVersion is %q and %s has no entry for it. If the corpus changed, append a NEW entry under a bumped label rather than editing an existing one, using case_count=%d and benchmark_manifest_sha256=%s",
			corpusVersion, corpusVersionLedgerPath, count, digest)
	}

	digestMoved := current.BenchmarkManifestSHA256 != digest
	countMoved := current.CaseCount != count
	if digestMoved || countMoved {
		t.Fatalf("the corpus on disk is not the corpus %q names.\n  recorded: case_count=%d benchmark_manifest_sha256=%s\n  on disk:  case_count=%d benchmark_manifest_sha256=%s\nBump corpusVersion in runner/summary.go and append a new ledger entry with the on-disk values. Do not edit the existing entry: published results already carry that label, and rewriting it changes what those numbers were measured over.",
			corpusVersion, current.CaseCount, current.BenchmarkManifestSHA256, count, digest)
	}
}

// TestCorpusVersionLedgerCountMatchesManifest keeps the ledger's own case_count
// honest against the committed case-ID list. Without it, case_count could drift
// into decoration while only the digest carried meaning, and a reader comparing
// two entries would be told a case-count delta that never happened.
func TestCorpusVersionLedgerCountMatchesManifest(t *testing.T) {
	records := readCorpusVersionLedger(t)

	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read case manifest: %v", err)
	}
	manifestIDs := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			manifestIDs++
		}
	}

	found := false
	for _, record := range records {
		if record.CorpusVersion != corpusVersion {
			continue
		}
		found = true
		if record.CaseCount != manifestIDs {
			t.Fatalf("ledger entry %q records case_count=%d but %s lists %d case IDs", record.CorpusVersion, record.CaseCount, manifestPath, manifestIDs)
		}
	}
	if !found {
		t.Fatalf("%s has no entry for the runner's current corpusVersion %q", corpusVersionLedgerPath, corpusVersion)
	}
}

func readCorpusVersionLedger(t *testing.T) []corpusVersionRecord {
	t.Helper()
	raw, err := os.ReadFile(corpusVersionLedgerPath)
	if err != nil {
		t.Fatalf("read %s: %v", corpusVersionLedgerPath, err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse %s: %v", corpusVersionLedgerPath, err)
	}
	rawVersions, ok := document["versions"]
	if !ok {
		t.Fatalf("%s has no versions array", corpusVersionLedgerPath)
	}
	var entries []map[string]any
	if err := json.Unmarshal(rawVersions, &entries); err != nil {
		t.Fatalf("parse %s versions: %v", corpusVersionLedgerPath, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s records no versions", corpusVersionLedgerPath)
	}
	records := make([]corpusVersionRecord, 0, len(entries))
	for i, entry := range entries {
		label, err := ledgerString(entry, "corpus_version")
		if err != nil {
			t.Fatalf("%s entry %d: %v", corpusVersionLedgerPath, i, err)
		}
		digest, err := ledgerString(entry, "benchmark_manifest_sha256")
		if err != nil {
			t.Fatalf("%s entry %d (%s): %v", corpusVersionLedgerPath, i, label, err)
		}
		count, err := ledgerInt(entry, "case_count")
		if err != nil {
			t.Fatalf("%s entry %d (%s): %v", corpusVersionLedgerPath, i, label, err)
		}
		records = append(records, corpusVersionRecord{CorpusVersion: label, CaseCount: count, BenchmarkManifestSHA256: digest})
	}
	return records
}

func ledgerString(entry map[string]any, key string) (string, error) {
	value, ok := entry[key]
	if !ok {
		return "", fmt.Errorf("missing %s", key)
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %v", key, value)
	}
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("%s must not be empty", key)
	}
	return text, nil
}

func ledgerInt(entry map[string]any, key string) (int, error) {
	value, ok := entry[key]
	if !ok {
		return 0, fmt.Errorf("missing %s", key)
	}
	number, ok := value.(float64)
	if !ok {
		return 0, fmt.Errorf("%s must be a number, got %v", key, value)
	}
	if number <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %v", key, value)
	}
	if number != float64(int(number)) {
		return 0, fmt.Errorf("%s must be a whole number, got %v", key, value)
	}
	return int(number), nil
}
