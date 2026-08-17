package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type caseIndexDocument struct {
	SchemaVersion int                       `json:"schema_version"`
	Cases         map[string]caseIndexEntry `json:"cases"`
}

type caseIndexEntry struct {
	Category        string   `json:"category"`
	ExpectedVerdict string   `json:"expected_verdict"`
	Transport       string   `json:"transport"`
	CapabilityTags  []string `json:"capability_tags"`
}

const activeCaseIndexSchemaVersion = 3

type corpusStatCase struct {
	Category        string
	ExpectedVerdict string
}

// multiFileCaseDir retains the registered family name beside its source
// directory. The name belongs in the framed manifest key; a directory basename
// is not enough because a complete override may be relocated anywhere.
type multiFileCaseDir struct {
	family string
	path   string
}

// runCorpus is the immutable input used for one run. Cases and both digests
// come from snapshot, captured before parsing or adapter execution.
type runCorpus struct {
	cases    []Case
	snapshot corpusSnapshot
}

// loadCorpus loads every logical case from the supplied corpus root. It is the
// shared source for the manifest and for human-readable corpus statistics, so
// both surfaces reflect precisely the cases the runner can execute.
func loadCorpus(root string) ([]Case, error) {
	multiFileDirs, err := registeredMultiFileCaseDirs(root)
	if err != nil {
		return nil, err
	}
	return loadCorpusWithMultiFileDirs(root, multiFileDirs)
}

// loadCorpusWithMultiFileDirs loads the single-file corpus plus exactly the
// multi-file directories supplied by the caller. Keeping this one conversion
// path prevents execution, statistics, and manifest generation from assigning
// different meanings to a multi-file case.
func loadCorpusWithMultiFileDirs(root string, multiFileDirs []multiFileCaseDir) ([]Case, error) {
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
func registeredMultiFileCaseDirs(root string) ([]multiFileCaseDir, error) {
	categories := make([]string, 0, len(multiFileCaseCategories))
	for category := range multiFileCaseCategories {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	dirs := make([]multiFileCaseDir, 0, len(categories))
	for _, category := range categories {
		directory := filepath.Join(root, category)
		info, err := os.Stat(directory)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("stat multi-file case directory %s: %w", directory, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("multi-file case path is not a directory: %s", directory)
		}
		dirs = append(dirs, multiFileCaseDir{family: category, path: directory})
	}
	return dirs, nil
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
	multiFileDirs, err := registeredMultiFileCaseDirs(root)
	if err != nil {
		return nil, nil, err
	}
	return loadCorpusPartsFromMultiFileDirs(root, multiFileDirs)
}

func loadCorpusPartsFromMultiFileDirs(root string, multiFileDirs []multiFileCaseDir) ([]Case, []MultiFileCase, error) {
	cases, err := loadCases(root)
	if err != nil {
		return nil, nil, err
	}

	var multiFileCases []MultiFileCase
	for _, directory := range multiFileDirs {
		mfCases, mfErr := loadMultiFileCases(directory.path)
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
func loadRunCorpus(root, multiFileOverride string) (runCorpus, error) {
	registeredDirs, err := registeredMultiFileCaseDirs(root)
	if err != nil {
		return runCorpus{}, err
	}
	effectiveDirs := append([]multiFileCaseDir(nil), registeredDirs...)
	if multiFileOverride != "" {
		// The override names one directory, so it can only stand in for the whole
		// registered set while that set holds exactly one family. A second family
		// would be dropped by this replacement. ensureExactRunCorpus below already
		// refuses the resulting short corpus, so nothing scores against a shrunken
		// denominator either way, but that failure would name a missing case ID and
		// point nowhere near the cause. Refuse here instead, so adding a second
		// multi-file family produces a message that says what has to change rather
		// than a confusing corpus mismatch.
		if len(effectiveDirs) > 1 {
			directories := make([]string, 0, len(effectiveDirs))
			for _, directory := range effectiveDirs {
				directories = append(directories, directory.path)
			}
			return runCorpus{}, fmt.Errorf(
				"--multifile-cases overrides a single directory but %d multi-file families are registered (%s); "+
					"the flag needs to become a per-family override before it can be used here",
				len(effectiveDirs), strings.Join(directories, ", "),
			)
		}
		if len(effectiveDirs) == 0 {
			return runCorpus{}, fmt.Errorf("--multifile-cases was supplied but no multi-file family is registered")
		}
		effectiveDirs[0].path = multiFileOverride
	}

	// Capture every candidate byte once before parsing either the executable
	// corpus or its canonical comparator. An override needs both source trees,
	// but the returned snapshot is narrowed to only the chosen run corpus.
	captureDirs := append([]multiFileCaseDir(nil), registeredDirs...)
	seen := make(map[string]struct{}, len(captureDirs))
	for _, directory := range captureDirs {
		seen[directory.path] = struct{}{}
	}
	for _, directory := range effectiveDirs {
		if _, ok := seen[directory.path]; ok {
			continue
		}
		captureDirs = append(captureDirs, directory)
		seen[directory.path] = struct{}{}
	}
	snapshot, err := readCorpusSnapshot(root, captureDirs...)
	if err != nil {
		return runCorpus{}, err
	}
	effectiveFiles, err := selectedCorpusFiles(snapshot, effectiveDirs)
	if err != nil {
		return runCorpus{}, err
	}
	cases, err := loadCasesFromSnapshot(effectiveFiles, effectiveDirs)
	if err != nil {
		return runCorpus{}, err
	}
	canonicalFiles, err := selectedCorpusFiles(snapshot, registeredDirs)
	if err != nil {
		return runCorpus{}, err
	}
	canonical, err := loadCasesFromSnapshot(canonicalFiles, registeredDirs)
	if err != nil {
		return runCorpus{}, err
	}
	if err := ensureExactRunCorpus(cases, canonical); err != nil {
		return runCorpus{}, err
	}
	return runCorpus{cases: cases, snapshot: corpusSnapshot{files: effectiveFiles}}, nil
}

// selectedCorpusFiles removes documentation and unreferenced files from a
// captured snapshot. Multi-file selection follows case.yaml exactly, matching
// the loader's contract while reading no byte a second time.
func selectedCorpusFiles(snapshot corpusSnapshot, multiFileDirs []multiFileCaseDir) ([]corpusFile, error) {
	selected := make(map[string]struct{}, len(snapshot.files))
	for _, file := range snapshot.files {
		if file.family == "" && !file.isDir {
			selected[file.path] = struct{}{}
		}
	}
	for _, directory := range multiFileDirs {
		paths, err := selectedMultiFileSnapshotPaths(snapshot.files, directory)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			selected[path] = struct{}{}
		}
	}
	files := make([]corpusFile, 0, len(selected))
	for _, file := range snapshot.files {
		if _, ok := selected[file.path]; ok {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("corpus contains no case files; refusing to hash an empty corpus")
	}
	return files, nil
}

func loadCasesFromSnapshot(files []corpusFile, multiFileDirs []multiFileCaseDir) ([]Case, error) {
	cases := make([]Case, 0, len(files))
	for _, file := range files {
		if file.family != "" || file.isDir {
			continue
		}
		var c Case
		if err := json.Unmarshal(file.data, &c); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", file.path, err)
		}
		if c.SchemaVersion != activeCaseSchemaVersion {
			return nil, fmt.Errorf("%s: schema_version must be %d for scoring, got %d", file.path, activeCaseSchemaVersion, c.SchemaVersion)
		}
		cases = append(cases, c)
	}
	multiCases, err := loadMultiFileCasesFromSnapshot(files, multiFileDirs)
	if err != nil {
		return nil, err
	}
	for _, multiCase := range multiCases {
		converted, err := multiCase.toCase()
		if err != nil {
			return nil, fmt.Errorf("convert multi-file case %s: %w", multiCase.ID, err)
		}
		cases = append(cases, converted)
	}
	if len(cases) == 0 {
		return nil, fmt.Errorf("no case files found in corpus snapshot")
	}
	return cases, nil
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
	entries := make(map[string]caseIndexEntry, len(cases))
	for _, c := range cases {
		if _, exists := entries[c.ID]; exists {
			return fmt.Errorf("duplicate case ID in case index: %s", c.ID)
		}
		entries[c.ID] = caseIndexEntry{
			Category:        c.Category,
			ExpectedVerdict: c.ExpectedVerdict,
			Transport:       c.Transport,
			CapabilityTags:  append([]string{}, c.CapabilityTags...),
		}
	}
	return json.NewEncoder(w).Encode(caseIndexDocument{SchemaVersion: activeCaseIndexSchemaVersion, Cases: entries})
}
