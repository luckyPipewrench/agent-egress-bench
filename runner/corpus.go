package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type caseIndexDocument struct {
	SchemaVersion int              `json:"schema_version"`
	Cases         []caseIndexEntry `json:"cases"`
}

type caseIndexEntry struct {
	CaseID          string `json:"case_id"`
	Category        string `json:"category"`
	ExpectedVerdict string `json:"expected_verdict"`
}

type corpusStatCase struct {
	Category        string
	ExpectedVerdict string
}

// loadCorpus loads every logical case from the supplied corpus root. It is the
// shared source for the manifest and for human-readable corpus statistics, so
// both surfaces reflect precisely the cases the runner can execute.
func loadCorpus(root string) ([]Case, error) {
	return loadCorpusWithMultiFileDirs(root, registeredMultiFileCaseDirs(root))
}

// loadCorpusWithMultiFileDirs loads the single-file corpus plus exactly the
// multi-file directories supplied by the caller. Keeping this one conversion
// path prevents execution, statistics, and manifest generation from assigning
// different meanings to a multi-file case.
func loadCorpusWithMultiFileDirs(root string, multiFileDirs []string) ([]Case, error) {
	cases, multiFileCases, err := loadCorpusPartsFromMultiFileDirs(root, multiFileDirs)
	if err != nil {
		return nil, err
	}
	for _, mfc := range multiFileCases {
		converted, convertErr := mfc.toCase()
		if convertErr != nil {
			return nil, fmt.Errorf("convert multi-file case %s: %w", mfc.ID, convertErr)
		}
		cases = append(cases, converted)
	}
	return cases, nil
}

// registeredMultiFileCaseDirs returns the multi-file families that belong to a
// corpus root. A missing family directory is valid for a small local corpus;
// a directory that exists is always loaded rather than silently skipped.
func registeredMultiFileCaseDirs(root string) []string {
	categories := make([]string, 0, len(multiFileCaseCategories))
	for category := range multiFileCaseCategories {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	dirs := make([]string, 0, len(categories))
	for _, category := range categories {
		directory := filepath.Join(root, category)
		if _, err := os.Stat(directory); err == nil {
			dirs = append(dirs, directory)
		}
	}
	return dirs
}

// loadCorpusStats preserves each fixture's declared expected verdict. The
// execution pipeline maps multi-file warn fixtures to allow for its binary
// receipt-scoring rubric, but corpus statistics must report the source case
// metadata without that scoring normalization.
func loadCorpusStats(root string) ([]corpusStatCase, error) {
	cases, multiFileCases, err := loadCorpusParts(root)
	if err != nil {
		return nil, err
	}
	stats := make([]corpusStatCase, 0, len(cases)+len(multiFileCases))
	for _, c := range cases {
		stats = append(stats, corpusStatCase{Category: c.Category, ExpectedVerdict: c.ExpectedVerdict})
	}
	for _, c := range multiFileCases {
		stats = append(stats, corpusStatCase{Category: c.Category, ExpectedVerdict: c.ExpectedVerdict})
	}
	return stats, nil
}

func loadCorpusParts(root string) ([]Case, []MultiFileCase, error) {
	return loadCorpusPartsFromMultiFileDirs(root, registeredMultiFileCaseDirs(root))
}

func loadCorpusPartsFromMultiFileDirs(root string, multiFileDirs []string) ([]Case, []MultiFileCase, error) {
	cases, err := loadCases(root)
	if err != nil {
		return nil, nil, err
	}

	var multiFileCases []MultiFileCase
	for _, directory := range multiFileDirs {
		mfCases, mfErr := loadMultiFileCases(directory)
		if mfErr != nil {
			return nil, nil, mfErr
		}
		multiFileCases = append(multiFileCases, mfCases...)
	}
	return cases, multiFileCases, nil
}

// loadRunCorpus treats --multifile-cases as a source-location override, never
// as permission to omit a registered family. The selected IDs must equal the
// loader-backed corpus before a run can start, so a denominator cannot shrink
// into a quieter summary.
func loadRunCorpus(root, multiFileOverride string) ([]Case, []string, error) {
	effectiveDirs := registeredMultiFileCaseDirs(root)
	if multiFileOverride != "" {
		effectiveDirs = []string{multiFileOverride}
	}
	cases, err := loadCorpusWithMultiFileDirs(root, effectiveDirs)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := loadCorpus(root)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureExactRunCorpus(cases, canonical); err != nil {
		return nil, nil, err
	}
	return cases, effectiveDirs, nil
}

func ensureExactRunCorpus(runCases, canonicalCases []Case) error {
	runIDs := make(map[string]struct{}, len(runCases))
	for _, c := range runCases {
		if _, duplicate := runIDs[c.ID]; duplicate {
			return fmt.Errorf("run corpus contains duplicate case ID %q", c.ID)
		}
		runIDs[c.ID] = struct{}{}
	}
	canonicalIDs := make(map[string]struct{}, len(canonicalCases))
	for _, c := range canonicalCases {
		if _, duplicate := canonicalIDs[c.ID]; duplicate {
			return fmt.Errorf("loader-backed corpus contains duplicate case ID %q", c.ID)
		}
		canonicalIDs[c.ID] = struct{}{}
	}
	missing := make([]string, 0)
	for id := range canonicalIDs {
		if _, ok := runIDs[id]; !ok {
			missing = append(missing, id)
		}
	}
	extra := make([]string, 0)
	for id := range runIDs {
		if _, ok := canonicalIDs[id]; !ok {
			extra = append(extra, id)
		}
	}
	if len(missing) == 0 && len(extra) == 0 && len(runCases) == len(canonicalCases) {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Errorf("run corpus does not match loader-backed corpus: missing=%s extra=%s", strings.Join(missing, ","), strings.Join(extra, ","))
}

// writeCorpusStats emits a stable, loader-backed report suitable for checking
// the committed statistics snapshot. Cases are grouped by their declared
// category and expected verdict rather than by filenames or manifest lines.
func writeCorpusStats(w io.Writer, cases []corpusStatCase) error {
	categories := make(map[string]int)
	verdicts := make(map[string]int)
	for _, c := range cases {
		categories[c.Category]++
		verdicts[c.ExpectedVerdict]++
	}

	if _, err := fmt.Fprintln(w, "# agent-egress-bench stats"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "cases_total: %d\n", len(cases)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "categories: %d\n", len(categories)); err != nil {
		return err
	}
	for _, verdict := range []string{"block", "allow", "warn"} {
		if _, err := fmt.Fprintf(w, "%s: %d\n", verdict, verdicts[verdict]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "by_category:"); err != nil {
		return err
	}
	names := make([]string, 0, len(categories))
	for category := range categories {
		names = append(names, category)
	}
	sort.Strings(names)
	for _, category := range names {
		if _, err := fmt.Fprintf(w, "  %s: %d\n", category, categories[category]); err != nil {
			return err
		}
	}
	return nil
}

// writeCaseIndex emits the execution loader's normalized case classification.
// This is the per-case authority for evidence wrappers: notably, multi-file
// warn fixtures are normalized to allow exactly as they are during scoring.
func writeCaseIndex(w io.Writer, cases []Case) error {
	entries := make([]caseIndexEntry, 0, len(cases))
	for _, c := range cases {
		entries = append(entries, caseIndexEntry{CaseID: c.ID, Category: c.Category, ExpectedVerdict: c.ExpectedVerdict})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CaseID < entries[j].CaseID })
	return json.NewEncoder(w).Encode(caseIndexDocument{SchemaVersion: 1, Cases: entries})
}
