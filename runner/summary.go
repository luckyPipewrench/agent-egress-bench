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
	SchemaVersion           int                          `json:"schema_version"`
	GauntletVersion         string                       `json:"gauntlet_version"`
	ScoringVersion          string                       `json:"scoring_version"`
	RunnerVersion           string                       `json:"runner_version"`
	Tool                    string                       `json:"tool"`
	ToolVersion             string                       `json:"tool_version"`
	CorpusVersion           string                       `json:"corpus_version"`
	CorpusSHA256            string                       `json:"corpus_sha256"`
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
	// How this run drove an MCP HTTP target that issues its own session token.
	// Empty for a target that declares none, which is every target by default.
	//
	// Not serialized into the summary: that schema is closed, so carrying it
	// there is a published-contract change and its own decision. The exact
	// flags already appear in the run's recorded command, so an accommodation
	// stays auditable without one.
	MCPHTTPSessionHeader string
	MCPHTTPSessionFormat string
	// How that target signals it refused a request for want of a session, so
	// the runner can tell transport failure from a decision about the case
	// without knowing any particular vendor's refusal shape.
	MCPHTTPSessionRefusalHeader string
	MCPHTTPSessionRefusalValue  string
	// RequireComplete changes the process result after every run artifact has
	// been written. It is an execution policy rather than summary provenance,
	// so it must not enter the closed summary schema.
	RequireComplete bool
}

// CaseCount tracks routed, historical N/A, and adapter-unreachable rows. The
// retained Applicable field is the routed partition, including error rows; it
// is not a count of observed measurements.
type CaseCount struct {
	Total                int            `json:"total"`
	Applicable           int            `json:"applicable"`
	Unreachable          int            `json:"unreachable"`
	NotApplicable        int            `json:"not_applicable"`
	NotApplicableReasons map[string]int `json:"not_applicable_reasons"`
	Errors               int            `json:"errors"`
}

// hashPath is one candidate file in the run corpus. logical is deliberately
// retained for corpus_sha256: it preserves that published digest's ordering.
// manifestKey is unique across registered multi-file families and is used only
// by the framed digest.
type hashPath struct {
	logical     string
	manifestKey string
	path        string
	family      string
	sourceRoot  string
	isDir       bool
}

// corpusFile is one corpus file captured before parsing or execution.
type corpusFile struct {
	hashPath
	data []byte
}

// corpusSnapshot is immutable input to both case loading and digesting.
// Its files are intentionally private to prevent later code from replacing a
// captured byte slice with a second filesystem read.
type corpusSnapshot struct {
	files []corpusFile
}

// corpusFilePaths collects the complete candidate set once. It keeps the
// variadic multi-file directories, logical-key structure, and stable ordering
// used by corpus_sha256. Both digests consume the same post-load snapshot.
func corpusFilePaths(casesDir string, multiFileDirs ...multiFileCaseDir) ([]hashPath, error) {
	var paths []hashPath
	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		relative, relErr := filepath.Rel(casesDir, path)
		if relErr != nil {
			return fmt.Errorf("finding logical case path for hash: %w", relErr)
		}
		relative = filepath.ToSlash(relative)
		paths = append(paths, hashPath{logical: "single/" + relative, manifestKey: "cases/" + relative, path: path, sourceRoot: casesDir})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking cases for hash: %w", err)
	}

	for _, multiFileDir := range multiFileDirs {
		err := filepath.Walk(multiFileDir.path, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if info.IsDir() {
				if path != multiFileDir.path {
					relative, relErr := filepath.Rel(multiFileDir.path, path)
					if relErr != nil {
						return fmt.Errorf("finding logical multi-file case directory for hash: %w", relErr)
					}
					relative = filepath.ToSlash(relative)
					paths = append(paths, hashPath{
						logical:     "multi/" + relative,
						manifestKey: "multifile/" + multiFileDir.family + "/" + relative,
						path:        path,
						family:      multiFileDir.family,
						sourceRoot:  multiFileDir.path,
						isDir:       true,
					})
				}
				return nil
			}
			relative, relErr := filepath.Rel(multiFileDir.path, path)
			if relErr != nil {
				return fmt.Errorf("finding logical multi-file case path for hash: %w", relErr)
			}
			relative = filepath.ToSlash(relative)
			paths = append(paths, hashPath{
				logical:     "multi/" + relative,
				manifestKey: "multifile/" + multiFileDir.family + "/" + relative,
				path:        path,
				family:      multiFileDir.family,
				sourceRoot:  multiFileDir.path,
			})
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking multi-file cases for hash: %w", err)
		}
	}

	// Stable because corpus_sha256's legacy logical key is intentionally not
	// unique across relocated multi-file families. Input order is deterministic:
	// lexical walks, then registered-family order. Do not replace this with an
	// unstable sort or change the published legacy digest definition.
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].logical < paths[j].logical })
	return paths, nil
}

func readCorpusSnapshot(casesDir string, multiFileDirs ...multiFileCaseDir) (corpusSnapshot, error) {
	paths, err := corpusFilePaths(casesDir, multiFileDirs...)
	if err != nil {
		return corpusSnapshot{}, err
	}
	files := make([]corpusFile, 0, len(paths))
	for _, candidate := range paths {
		if candidate.isDir {
			files = append(files, corpusFile{hashPath: candidate})
			continue
		}
		data, readErr := os.ReadFile(candidate.path)
		if readErr != nil {
			return corpusSnapshot{}, fmt.Errorf("reading %s for corpus snapshot: %w", candidate.path, readErr)
		}
		files = append(files, corpusFile{hashPath: candidate, data: data})
	}
	return corpusSnapshot{files: files}, nil
}

func directMultiFileCaseDirs(dirs []string) []multiFileCaseDir {
	resolved := make([]multiFileCaseDir, 0, len(dirs))
	for _, dir := range dirs {
		resolved = append(resolved, multiFileCaseDir{family: filepath.Base(dir), path: dir})
	}
	return resolved
}

// corpusSHA256FromSnapshot preserves corpus_sha256 exactly: selected case-file
// bytes concatenate in stable legacy logical-key order with no framing.
func corpusSHA256FromSnapshot(files []corpusFile) string {
	ordered := append([]corpusFile(nil), files...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].logical < ordered[j].logical })
	h := sha256.New()
	for _, file := range ordered {
		_, _ = h.Write(file.data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// benchmarkManifestSHA256FromSnapshot frames every canonical key and byte
// sequence with unsigned varint lengths. Framing binds file boundaries, while
// family-qualified keys bind a file to its registered multi-file family.
func benchmarkManifestSHA256FromSnapshot(files []corpusFile) (string, error) {
	ordered := append([]corpusFile(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].manifestKey < ordered[j].manifestKey })
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].manifestKey == ordered[i].manifestKey {
			return "", fmt.Errorf("duplicate benchmark manifest key %q", ordered[i].manifestKey)
		}
	}
	h := sha256.New()
	var size [binary.MaxVarintLen64]byte
	writeField := func(value []byte) {
		n := binary.PutUvarint(size[:], uint64(len(value)))
		_, _ = h.Write(size[:n])
		_, _ = h.Write(value)
	}
	for _, file := range ordered {
		writeField([]byte(file.manifestKey))
		writeField(file.data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeCorpusSHA256 is retained for compatibility tests and standalone
// callers. Runs use the snapshot created by loadRunCorpus instead.
func computeCorpusSHA256(casesDir string, multiFileDirs ...string) (string, error) {
	dirs := directMultiFileCaseDirs(multiFileDirs)
	snapshot, err := readCorpusSnapshot(casesDir, dirs...)
	if err != nil {
		return "", err
	}
	files, err := selectedCorpusFiles(snapshot, dirs)
	if err != nil {
		return "", err
	}
	return corpusSHA256FromSnapshot(files), nil
}

// computeBenchmarkManifestSHA256 is retained for compatibility tests and
// independent implementations. Runs use the load-time snapshot instead.
func computeBenchmarkManifestSHA256(casesDir string, multiFileDirs ...string) (string, error) {
	dirs := directMultiFileCaseDirs(multiFileDirs)
	snapshot, err := readCorpusSnapshot(casesDir, dirs...)
	if err != nil {
		return "", err
	}
	files, err := selectedCorpusFiles(snapshot, dirs)
	if err != nil {
		return "", err
	}
	return benchmarkManifestSHA256FromSnapshot(files)
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
	corpus corpusSnapshot,
	casesByID map[string]Case,
	profilePath string,
	prov RunProvenance,
) (GauntletSummary, error) {
	if len(corpus.files) == 0 {
		return GauntletSummary{}, fmt.Errorf("refusing to summarize an empty corpus snapshot")
	}
	corpusSHA := corpusSHA256FromSnapshot(corpus.files)
	manifestSHA, err := benchmarkManifestSHA256FromSnapshot(corpus.files)
	if err != nil {
		return GauntletSummary{}, err
	}

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
		ReportedClaims:          append([]string{}, p.Claims...),
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
	for _, digest := range []struct {
		field string
		value string
	}{
		{"corpus_sha256", s.CorpusSHA256},
		{"benchmark_manifest_sha256", s.BenchmarkManifestSHA256},
		{"tool_profile_sha256", s.ToolProfileSHA256},
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

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
