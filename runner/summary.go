package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

const (
	gauntletVersion = "1.0"
	// 2.8 retires detection and evidence as scores. The runner only knew that a
	// result carried a named field, not that the name correctly classified the
	// case or that its contents proved the finding. V5 retains those facts as
	// plainly named diagnostics and leaves outcome metrics in scores.
	//
	// 2.7 is the pass-mark boundary. A hidden 80 percent containment threshold
	// decided whether a run could publish; it is gone, and publication now turns
	// only on whether the run measured what it claims to have measured. Which
	// runs are publishable therefore changed, so results are not comparable
	// across this line and the label must move with the rules.
	//
	// 2.6 was the result-state boundary. Applicability moved from profile
	// declarations to adapter-proven delivery and verdict observation, an
	// unreachable state was added outside every score denominator, and a run
	// with any unreachable row reports an incomplete measurement. Results scored
	// under 2.5 and earlier are therefore not comparable to those, and the
	// repository's own staleness rule requires the bump rather than allowing
	// two different rule sets to publish under one label.
	scoringVersion = "2.8"
	runnerVersion  = "0.4.3"
	corpusVersion  = "v2.4.0"
	summaryDateEnv = "AEB_GAUNTLET_SUMMARY_DATE"

	measurementStatusMeasured   = "measured"
	measurementStatusIncomplete = "incomplete"
)

// activeSummarySchemaVersion is intentionally separate from the v4 case,
// profile, result-row, and receipt-profile contract. This change only affects
// the published summary and its provenance readers; changing immutable cases
// or runner input declarations would add compatibility churn without changing
// the corrected metric.
const activeSummarySchemaVersion = 5

// DualScores holds both full-corpus and applicable-only score views.
type DualScores struct {
	Full       Scores `json:"full"`
	Applicable Scores `json:"applicable"`
}

// DualDiagnostics holds non-scoring observations for both score views.
type DualDiagnostics struct {
	Full       PresenceDiagnostics `json:"full"`
	Applicable PresenceDiagnostics `json:"applicable"`
}

// GauntletSummary is the top-level output written to --output.
type GauntletSummary struct {
	SchemaVersion   int    `json:"schema_version"`
	GauntletVersion string `json:"gauntlet_version"`
	ScoringVersion  string `json:"scoring_version"`
	RunnerVersion   string `json:"runner_version"`
	Tool            string `json:"tool"`
	ToolVersion     string `json:"tool_version"`
	CorpusVersion   string `json:"corpus_version"`
	CorpusSHA256    string `json:"corpus_sha256"`
	// BenchmarkManifestSHA256 binds exact corpus contents: paths, byte
	// lengths, and bytes. CorpusSHA256 above cannot, and is kept only so
	// published records still verify against their original definition.
	BenchmarkManifestSHA256 string                       `json:"benchmark_manifest_sha256"`
	ToolProfileSHA256       string                       `json:"tool_profile_sha256"`
	CapabilityRegistry      capabilityregistry.Reference `json:"capability_registry"`
	ReportedClaims          []string                     `json:"reported_claims"`
	Date                    string                       `json:"date,omitempty"`
	CaseCount               CaseCount                    `json:"case_count"`
	Exercised               ExercisedCapabilities        `json:"exercised"`
	Scores                  DualScores                   `json:"scores"`
	Diagnostics             DualDiagnostics              `json:"diagnostics"`
	MeasurementStatus       string                       `json:"measurement_status"`
	PerCategory             map[string]CategoryScores    `json:"per_category"`

	// Identifying facts that docs/RESULTS-USE.md requires beside any public
	// result and that cannot be derived from the corpus or the profile. They
	// are omitted rather than guessed when the operator does not supply them,
	// so a reader can tell the difference between "not declared" and "declared
	// as empty". The buyer report renders each absence explicitly.
	MethodRepository   string `json:"method_repository,omitempty"`
	MethodCommit       string `json:"method_commit,omitempty"`
	AdapterID          string `json:"adapter_id,omitempty"`
	AdapterOwner       string `json:"adapter_owner,omitempty"`
	TargetConfigRef    string `json:"target_config_ref,omitempty"`
	TargetConfigSHA256 string `json:"target_config_sha256,omitempty"`
}

// RunProvenance carries the identifying facts a published result must declare.
// A score against an unnamed configuration cannot be repeated, and an adapter
// with no stated owner hides who wrote the code that produced the verdict.
// A vendor-authored adapter is normal; concealing authorship is not.
type RunProvenance struct {
	MethodRepository string
	MethodCommit     string
	AdapterID        string
	AdapterOwner     string
	TargetConfigRef  string
	TargetConfigSHA  string
}

// CaseCount tracks scoreable, historical N/A, and adapter-unreachable rows.
type CaseCount struct {
	Total                int            `json:"total"`
	Applicable           int            `json:"applicable"`
	Unreachable          int            `json:"unreachable"`
	NotApplicable        int            `json:"not_applicable"`
	NotApplicableReasons map[string]int `json:"not_applicable_reasons"`
	Errors               int            `json:"errors"`
}

// corpusFilePaths collects every file both corpus digests cover: the
// single-file corpus rooted at casesDir plus, when multiFileDir is set, the
// multi-file case directory. Paths are absolute and sorted so the result is
// deterministic regardless of filesystem ordering. Both digests below share
// this one collector so they can never disagree about which files the corpus
// contains.
func corpusFilePaths(casesDir, multiFileDir string) ([]string, error) {
	var paths []string

	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip multi-file case directories on the single-file walk. The
		// multiFileDir branch below picks them up under its own schema.
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking cases for hash: %w", err)
	}

	if multiFileDir != "" {
		mfPaths, mfErr := computeMultiFileSHA256Paths(multiFileDir)
		if mfErr != nil {
			return nil, mfErr
		}
		paths = append(paths, mfPaths...)
	}

	sort.Strings(paths)
	return paths, nil
}

// computeCorpusSHA256 concatenates case-file contents in sorted-path order.
//
// This digest CANNOT prove which files a corpus contains. It frames nothing, so
// any regrouping of the same total bytes produces the same value: one file
// holding {"a":1}{"b":2} and two files splitting it collide exactly. It is
// retained unchanged because published records carry it and must keep verifying
// against the definition they were produced under. For a digest that actually
// binds paths and boundaries, see computeBenchmarkManifestSHA256.
func computeCorpusSHA256(casesDir, multiFileDir string) (string, error) {
	paths, err := corpusFilePaths(casesDir, multiFileDir)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	for _, p := range paths {
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return "", fmt.Errorf("reading %s for hash: %w", p, readErr)
		}
		_, _ = h.Write(data)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// corpusSHA256FromSnapshot reproduces computeCorpusSHA256 exactly: contents
// concatenated in sorted-path order with no framing. That value appears in
// published records, so it is preserved byte for byte rather than improved here.
func corpusSHA256FromSnapshot(files []corpusFile) string {
	ordered := make([]corpusFile, len(files))
	copy(ordered, files)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })

	h := sha256.New()
	for _, f := range ordered {
		_, _ = h.Write(f.data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// benchmarkManifestSHA256FromSnapshot reproduces computeBenchmarkManifestSHA256:
// entries ordered by canonical key, with each key and body length-prefixed.
func benchmarkManifestSHA256FromSnapshot(files []corpusFile) string {
	ordered := make([]corpusFile, len(files))
	copy(ordered, files)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].key < ordered[j].key })

	h := sha256.New()
	var size [binary.MaxVarintLen64]byte
	writeField := func(b []byte) {
		n := binary.PutUvarint(size[:], uint64(len(b)))
		_, _ = h.Write(size[:n])
		_, _ = h.Write(b)
	}
	for _, f := range ordered {
		writeField([]byte(f.key))
		writeField(f.data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// computeBenchmarkManifestSHA256 binds the exact corpus contents: every file's
// location, its byte length, and its bytes.
//
// Each entry is length-prefixed, so no regrouping, rename, split, or merge of
// the same bytes can produce the same digest. Keys are relative to the root the
// file was found under, and each root carries a distinct prefix, so the value is
// identical on any machine and unambiguous between the two trees.
func computeBenchmarkManifestSHA256(casesDir, multiFileDir string) (string, error) {
	paths, err := corpusFilePaths(casesDir, multiFileDir)
	if err != nil {
		return "", err
	}

	type entry struct {
		key  string
		path string
	}
	entries := make([]entry, 0, len(paths))
	for _, p := range paths {
		key, keyErr := corpusManifestKey(p, casesDir, multiFileDir)
		if keyErr != nil {
			return "", keyErr
		}
		entries = append(entries, entry{key: key, path: p})
	}
	// Sort by the framed key rather than the absolute path, so the digest does
	// not depend on where the trees happen to live on disk.
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	h := sha256.New()
	var size [binary.MaxVarintLen64]byte
	writeField := func(b []byte) {
		n := binary.PutUvarint(size[:], uint64(len(b)))
		_, _ = h.Write(size[:n])
		_, _ = h.Write(b)
	}
	for _, e := range entries {
		data, readErr := os.ReadFile(e.path)
		if readErr != nil {
			return "", fmt.Errorf("reading %s for manifest hash: %w", e.path, readErr)
		}
		writeField([]byte(e.key))
		writeField(data)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// corpusManifestKey renders a machine-independent key for a corpus file. The
// root prefix keeps the two trees distinct even when a relative path could
// appear under either.
// isSHA256Hex reports whether s is exactly 64 lowercase hexadecimal characters.
// Case is not normalized: a digest is compared as a string across consumers in
// several languages, so accepting both cases would let two spellings of one
// value fail an equality check that should have passed.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// corpusFile is one corpus file read exactly once: its absolute path, its
// canonical manifest key, and the bytes both digests are derived from.
type corpusFile struct {
	key  string
	path string
	data []byte
}

// readCorpusSnapshot reads every corpus file once so both digests describe the
// same bytes.
//
// Each digest previously walked the tree and read every file for itself. Sharing
// only the path collector is not enough: two independent reads of the same path
// can return different contents, so a corpus edited between them produced a
// legacy digest over one set of bytes and a framed digest over another, and the
// framed digest's claim to identify the corpus does not survive that. One read
// removes the window between them.
//
// It does not close the window between execution and hashing. Both digests are
// still computed after the run, so they identify the corpus present at summary
// time rather than proving the bytes that were measured. Closing that requires
// snapshotting at case-load time and is separate work.
func readCorpusSnapshot(casesDir, multiFileDir string) ([]corpusFile, error) {
	paths, err := corpusFilePaths(casesDir, multiFileDir)
	if err != nil {
		return nil, err
	}

	files := make([]corpusFile, 0, len(paths))
	for _, p := range paths {
		key, keyErr := corpusManifestKey(p, casesDir, multiFileDir)
		if keyErr != nil {
			return nil, keyErr
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil, fmt.Errorf("reading %s for hash: %w", p, readErr)
		}
		files = append(files, corpusFile{key: key, path: p, data: data})
	}

	// Hashing nothing yields the SHA-256 of the empty string, which is a
	// well-formed 64-hex value and passes every shape check downstream. An empty
	// corpus would therefore publish a valid-looking corpus identity for a run
	// that measured no cases. A corpus with no files is not a corpus, so this is
	// an error rather than a digest.
	if len(files) == 0 {
		return nil, fmt.Errorf("corpus at %s contains no case files; refusing to hash an empty corpus", casesDir)
	}
	return files, nil
}

func corpusManifestKey(path, casesDir, multiFileDir string) (string, error) {
	roots := []struct {
		prefix string
		dir    string
	}{
		{prefix: "multifile", dir: multiFileDir},
		{prefix: "cases", dir: casesDir},
	}
	for _, root := range roots {
		if root.dir == "" {
			continue
		}
		rel, err := filepath.Rel(root.dir, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return root.prefix + "/" + filepath.ToSlash(rel), nil
	}
	return "", fmt.Errorf("corpus file %s is outside every corpus root", path)
}

// computeProfileSHA256 hashes the tool profile file contents.
func computeProfileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading profile for hash: %w", err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

func summaryDate() (string, error) {
	if date, ok := os.LookupEnv(summaryDateEnv); ok {
		if date == "" {
			return "", nil
		}
		if _, err := time.Parse(time.RFC3339, date); err != nil {
			return "", fmt.Errorf("%s must be empty or RFC3339: %w", summaryDateEnv, err)
		}
		return date, nil
	}
	return time.Now().UTC().Format(time.RFC3339), nil
}

// buildSummary assembles the GauntletSummary from run results.
func buildSummary(
	p Profile,
	allCases []Case,
	applicableResults []CaseResult,
	unreachableIDs map[string]struct{},
	naReasons map[NAKind]int,
	casesDir, multiFileDir string,
	casesByID map[string]Case,
	profilePath string,
	prov RunProvenance,
) (GauntletSummary, error) {
	// One read for both digests. Reading the corpus twice let them describe
	// different bytes, which is exactly what the framed digest exists to rule out.
	corpusFiles, err := readCorpusSnapshot(casesDir, multiFileDir)
	if err != nil {
		return GauntletSummary{}, err
	}
	corpusSHA := corpusSHA256FromSnapshot(corpusFiles)
	manifestSHA := benchmarkManifestSHA256FromSnapshot(corpusFiles)

	profileSHA, err := computeProfileSHA256(profilePath)
	if err != nil {
		return GauntletSummary{}, err
	}
	date, err := summaryDate()
	if err != nil {
		return GauntletSummary{}, err
	}

	unmeasuredIDs := make(map[string]struct{}, len(unreachableIDs))
	for caseID := range unreachableIDs {
		unmeasuredIDs[caseID] = struct{}{}
	}
	for _, result := range applicableResults {
		if !measuredResult(result) {
			unmeasuredIDs[result.CaseID] = struct{}{}
		}
	}

	applicableScores := computeScores(applicableResults)
	fullScores := computeFullCorpusScores(applicableResults, allCases, unmeasuredIDs)
	applicableDiagnostics := computePresenceDiagnostics(applicableResults)
	fullDiagnostics := computePresenceDiagnostics(applicableResults)
	perCategory := computeCategoryScores(applicableResults, casesByID)

	naReasonsStr := make(map[string]int, len(naReasons))
	for k, v := range naReasons {
		naReasonsStr[string(k)] = v
	}

	totalNA := 0
	for _, v := range naReasons {
		totalNA += v
	}
	errorCount, err := countErrors(applicableResults)
	if err != nil {
		return GauntletSummary{}, err
	}

	return GauntletSummary{
		SchemaVersion:           activeSummarySchemaVersion,
		GauntletVersion:         gauntletVersion,
		ScoringVersion:          scoringVersion,
		RunnerVersion:           runnerVersion,
		Tool:                    p.Tool,
		ToolVersion:             p.ToolVersion,
		CorpusVersion:           corpusVersion,
		CorpusSHA256:            corpusSHA,
		BenchmarkManifestSHA256: manifestSHA,
		ToolProfileSHA256:       profileSHA,
		CapabilityRegistry:      p.CapabilityRegistry,
		ReportedClaims:          append([]string(nil), p.Claims...),
		Date:                    date,
		CaseCount: CaseCount{
			Total:                len(allCases),
			Applicable:           len(applicableResults),
			Unreachable:          len(unreachableIDs),
			NotApplicable:        totalNA,
			NotApplicableReasons: naReasonsStr,
			Errors:               errorCount,
		},
		Exercised: computeExercised(applicableResults, casesByID),
		Scores: DualScores{
			Full:       fullScores,
			Applicable: applicableScores,
		},
		Diagnostics: DualDiagnostics{
			Full:       fullDiagnostics,
			Applicable: applicableDiagnostics,
		},
		// Calibration adapters assert proof flags rather than observing them, so
		// they do not produce a complete measurement and cannot publish.
		MeasurementStatus: measurementStatus(len(allCases), len(applicableResults), errorCount, len(unreachableIDs), totalNA, hasSyntheticEvidence(applicableResults)),
		PerCategory:       perCategory,

		MethodRepository:   prov.MethodRepository,
		MethodCommit:       prov.MethodCommit,
		AdapterID:          prov.AdapterID,
		AdapterOwner:       prov.AdapterOwner,
		TargetConfigRef:    prov.TargetConfigRef,
		TargetConfigSHA256: prov.TargetConfigSHA,
	}, nil
}

// hasSyntheticEvidence reports whether a row came from a calibration adapter.
// Treat an unrecognized marker conservatively: a synthetic claim can make the
// measurement incomplete, but can never make an incomplete run publishable.
func hasSyntheticEvidence(results []CaseResult) bool {
	for _, result := range results {
		raw, present := result.Evidence["synthetic"]
		if !present {
			continue
		}
		// An explicit boolean false is an honest negative and is honored. Every
		// other present value counts as a synthetic claim, including a
		// non-boolean such as "synthetic": "calibration". Requiring the boolean
		// true here would let a malformed marker be the reason a run reads as
		// measured, which is the opposite of what the comment above promises.
		if asBool, isBool := raw.(bool); isBool && !asBool {
			continue
		}
		return true
	}
	return false
}

func countErrors(results []CaseResult) (int, error) {
	count := 0
	for _, result := range results {
		actualError := result.ActualVerdict == "error"
		scoreError := result.Score == "error"
		if actualError != scoreError {
			return 0, fmt.Errorf("case %s has inconsistent error result", result.CaseID)
		}
		if actualError {
			count++
		}
	}
	return count, nil
}

// writeSummary writes the GauntletSummary as indented JSON to a file.
func writeSummary(s GauntletSummary, path string) error {
	// Every newly emitted summary belongs to the active summary contract. Tests
	// and library callers may construct a summary directly, so make the writer
	// enforce the same boundary as buildSummary.
	if s.SchemaVersion == 0 {
		s.SchemaVersion = activeSummarySchemaVersion
	}
	if s.SchemaVersion != activeSummarySchemaVersion {
		return fmt.Errorf("summary schema_version must be %d, got %d", activeSummarySchemaVersion, s.SchemaVersion)
	}
	if err := validateRegistryReference(s.CapabilityRegistry); err != nil {
		return fmt.Errorf("invalid summary capability_registry: %w", err)
	}
	// The schema requires these keys but cannot constrain their values on its
	// own, so a direct caller could emit an empty or malformed digest and have
	// it rejected only later, by provenance, after the artifact already exists.
	for _, digest := range []struct {
		field string
		value string
	}{
		{"corpus_sha256", s.CorpusSHA256},
		{"benchmark_manifest_sha256", s.BenchmarkManifestSHA256},
	} {
		if !isSHA256Hex(digest.value) {
			return fmt.Errorf("summary %s must be 64 lowercase hex characters, got %q", digest.field, digest.value)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}
	data = append(data, '\n')

	if writeErr := os.WriteFile(path, data, 0o600); writeErr != nil {
		return fmt.Errorf("writing summary to %s: %w", path, writeErr)
	}

	return nil
}
