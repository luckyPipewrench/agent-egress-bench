package main

import (
	"crypto/sha256"
	"encoding/hex"
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

const (
	activeSetSchemaVersion = 1
	corpusVersionMarker    = "CORPUS_VERSION"
)

type activeSetDocument struct {
	SchemaVersion        int      `json:"schema_version"`
	CorpusVersion        string   `json:"corpus_version"`
	SourceManifestSHA256 string   `json:"source_manifest_sha256"`
	ExcludedCaseIDs      []string `json:"excluded_case_ids"`
	CaseCount            int      `json:"case_count"`
}

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
	cases         []Case
	snapshot      corpusSnapshot
	gitProvenance CorpusGitProvenance
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

	// Capture Git provenance on both sides of the byte snapshot. A single clean
	// observation is not enough: a checkout that changed while the runner read
	// it cannot honestly be attributed to either endpoint revision.
	gitSourceRoots := corpusSourceRoots(root, effectiveDirs)
	gitBefore := observeCorpusGitProvenance(gitSourceRoots)

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
	gitProvenance := stableCorpusGitProvenance(gitBefore, observeCorpusGitProvenance(gitSourceRoots))
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
	activeIDs, err := loadActiveCaseIDs(root, canonical)
	if err != nil {
		return runCorpus{}, err
	}
	if activeIDs != nil {
		cases = selectActiveCases(cases, activeIDs)
		effectiveFiles, err = selectActiveCorpusFiles(effectiveFiles, activeIDs)
		if err != nil {
			return runCorpus{}, err
		}
	}
	if err := ensureExactRunCorpus(cases, canonical, activeIDs); err != nil {
		return runCorpus{}, err
	}
	return runCorpus{cases: cases, snapshot: corpusSnapshot{files: effectiveFiles}, gitProvenance: gitProvenance}, nil
}

// loadActiveCaseIDs reads the immutable selection for the current corpus
// version. The source manifest remains a complete catalog; an active-set
// artifact identifies the scored subset and binds itself to that exact catalog.
// A missing artifact leaves isolated test corpora on their complete catalog.
func loadActiveCaseIDs(root string, canonical []Case) (map[string]struct{}, error) {
	markerPath := filepath.Join(root, corpusVersionMarker)
	markerRaw, markerErr := os.ReadFile(markerPath)
	markerFound := markerErr == nil
	if markerErr != nil && !errors.Is(markerErr, os.ErrNotExist) {
		return nil, fmt.Errorf("read corpus version marker: %w", markerErr)
	}
	if markerFound && strings.TrimSpace(string(markerRaw)) != corpusVersion {
		return nil, fmt.Errorf("corpus version marker names %q, runner requires %q", strings.TrimSpace(string(markerRaw)), corpusVersion)
	}

	path := activeSetPath(root)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if markerFound {
			return nil, fmt.Errorf("corpus version marker %s requires active set %s", markerPath, path)
		}
		entries, dirErr := os.ReadDir(filepath.Dir(path))
		if errors.Is(dirErr, os.ErrNotExist) {
			return nil, nil
		}
		if dirErr != nil {
			return nil, fmt.Errorf("read active-set directory: %w", dirErr)
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				return nil, fmt.Errorf("active-set directory contains %s but no selection for corpus_version %q", entry.Name(), corpusVersion)
			}
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read active set %s: %w", path, err)
	}
	if !markerFound {
		return nil, fmt.Errorf("active set %s requires corpus version marker %s", path, markerPath)
	}
	var set activeSetDocument
	if err := decodeStrictJSON(raw, &set); err != nil {
		return nil, fmt.Errorf("parse active set %s: %w", path, err)
	}
	if set.SchemaVersion != activeSetSchemaVersion || set.CorpusVersion != corpusVersion {
		return nil, fmt.Errorf("active set %s must name schema_version %d and corpus_version %q", path, activeSetSchemaVersion, corpusVersion)
	}

	manifestPath := filepath.Join(root, "MANIFEST.txt")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read active-set source manifest: %w", err)
	}
	digest := sha256.Sum256(manifest)
	if set.SourceManifestSHA256 != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("active set %s does not bind the current %s", path, manifestPath)
	}

	ids := make(map[string]struct{})
	for _, line := range strings.Split(string(manifest), "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		if _, exists := ids[id]; exists {
			return nil, fmt.Errorf("active-set source manifest repeats case ID %q", id)
		}
		ids[id] = struct{}{}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("active-set source manifest is empty")
	}
	canonicalIDs := make(map[string]struct{}, len(canonical))
	for _, c := range canonical {
		if _, duplicate := canonicalIDs[c.ID]; duplicate {
			return nil, fmt.Errorf("loader-backed corpus contains duplicate case ID %q", c.ID)
		}
		canonicalIDs[c.ID] = struct{}{}
	}
	if err := sameCaseIDSet(ids, canonicalIDs, "active-set source manifest"); err != nil {
		return nil, err
	}
	excluded := make(map[string]struct{}, len(set.ExcludedCaseIDs))
	for _, id := range set.ExcludedCaseIDs {
		if _, duplicate := excluded[id]; duplicate {
			return nil, fmt.Errorf("active set %s repeats excluded case ID %q", path, id)
		}
		excluded[id] = struct{}{}
		if _, exists := ids[id]; !exists {
			return nil, fmt.Errorf("active set %s excludes unknown case ID %q", path, id)
		}
		delete(ids, id)
	}
	if len(ids) != set.CaseCount || set.CaseCount == 0 {
		return nil, fmt.Errorf("active set %s records case_count=%d, selected %d", path, set.CaseCount, len(ids))
	}
	return ids, nil
}

func activeSetPath(casesRoot string) string {
	return filepath.Join(filepath.Dir(casesRoot), "corpora", "active-sets", "v1", corpusVersion+".json")
}

func sameCaseIDSet(got, want map[string]struct{}, label string) error {
	missing := make([]string, 0)
	extra := make([]string, 0)
	for id := range want {
		if _, ok := got[id]; !ok {
			missing = append(missing, id)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			extra = append(extra, id)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Errorf("%s does not match loader-backed corpus: missing=%s extra=%s", label, strings.Join(missing, ","), strings.Join(extra, ","))
}

func selectActiveCases(cases []Case, active map[string]struct{}) []Case {
	selected := make([]Case, 0, len(active))
	for _, c := range cases {
		if _, ok := active[c.ID]; ok {
			selected = append(selected, c)
		}
	}
	return selected
}

func selectActiveCorpusFiles(files []corpusFile, active map[string]struct{}) ([]corpusFile, error) {
	selected := make([]corpusFile, 0, len(files))
	for _, file := range files {
		id, err := corpusFileCaseID(file)
		if err != nil {
			return nil, err
		}
		if _, ok := active[id]; ok {
			selected = append(selected, file)
		}
	}
	return selected, nil
}

func corpusFileCaseID(file corpusFile) (string, error) {
	if file.family != "" {
		prefix := "multifile/" + file.family + "/"
		relative := strings.TrimPrefix(file.manifestKey, prefix)
		id := strings.SplitN(relative, "/", 2)[0]
		if id == "" || relative == file.manifestKey {
			return "", fmt.Errorf("cannot identify multi-file case for %s", file.manifestKey)
		}
		return id, nil
	}
	var c Case
	if err := json.Unmarshal(file.data, &c); err != nil {
		return "", fmt.Errorf("parse active-set candidate %s: %w", file.path, err)
	}
	return c.ID, nil
}

func corpusSourceRoots(root string, multiFileDirs []multiFileCaseDir) []string {
	roots := make([]string, 0, len(multiFileDirs)+1)
	roots = append(roots, root)
	for _, directory := range multiFileDirs {
		roots = append(roots, directory.path)
	}
	return roots
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

func ensureExactRunCorpus(runCases, canonicalCases []Case, activeIDs map[string]struct{}) error {
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
		if activeIDs == nil {
			canonicalIDs[c.ID] = struct{}{}
		} else if _, active := activeIDs[c.ID]; active {
			canonicalIDs[c.ID] = struct{}{}
		}
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
	if len(missing) == 0 && len(extra) == 0 && len(runCases) == len(canonicalIDs) {
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
