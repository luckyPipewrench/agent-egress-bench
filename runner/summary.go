package main

import (
	"crypto/sha256"
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
	scoringVersion = "2.7"
	runnerVersion  = "0.4.2"
	corpusVersion  = "v2.4.0"
	summaryDateEnv = "AEB_GAUNTLET_SUMMARY_DATE"

	measurementStatusMeasured   = "measured"
	measurementStatusIncomplete = "incomplete"
)

// DualScores holds both full-corpus and applicable-only score views.
type DualScores struct {
	Full       Scores `json:"full"`
	Applicable Scores `json:"applicable"`
}

// GauntletSummary is the top-level output written to --output.
type GauntletSummary struct {
	SchemaVersion      int                          `json:"schema_version"`
	GauntletVersion    string                       `json:"gauntlet_version"`
	ScoringVersion     string                       `json:"scoring_version"`
	RunnerVersion      string                       `json:"runner_version"`
	Tool               string                       `json:"tool"`
	ToolVersion        string                       `json:"tool_version"`
	CorpusVersion      string                       `json:"corpus_version"`
	CorpusSHA256       string                       `json:"corpus_sha256"`
	ToolProfileSHA256  string                       `json:"tool_profile_sha256"`
	CapabilityRegistry capabilityregistry.Reference `json:"capability_registry"`
	ReportedClaims     []string                     `json:"reported_claims"`
	Date               string                       `json:"date,omitempty"`
	CaseCount          CaseCount                    `json:"case_count"`
	Exercised          ExercisedCapabilities        `json:"exercised"`
	Scores             DualScores                   `json:"scores"`
	MeasurementStatus  string                       `json:"measurement_status"`
	PerCategory        map[string]CategoryScores    `json:"per_category"`

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

// computeCorpusSHA256 hashes case-file contents across both the single-file
// corpus rooted at casesDir and (optionally) the multi-file case directory
// at multiFileDir. Files are sorted by absolute path before hashing so the
// output is deterministic regardless of filesystem ordering. multiFileDir
// may be empty: the single-file walker skips directories listed in
// multiFileCaseCategories on its own, so the hash covers exactly the case
// surface the runner loaded.
func computeCorpusSHA256(casesDir, multiFileDir string) (string, error) {
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
		return "", fmt.Errorf("walking cases for hash: %w", err)
	}

	if multiFileDir != "" {
		mfPaths, mfErr := computeMultiFileSHA256Paths(multiFileDir)
		if mfErr != nil {
			return "", mfErr
		}
		paths = append(paths, mfPaths...)
	}

	sort.Strings(paths)

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
	corpusSHA, err := computeCorpusSHA256(casesDir, multiFileDir)
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
		SchemaVersion:      activeSchemaVersion,
		GauntletVersion:    gauntletVersion,
		ScoringVersion:     scoringVersion,
		RunnerVersion:      runnerVersion,
		Tool:               p.Tool,
		ToolVersion:        p.ToolVersion,
		CorpusVersion:      corpusVersion,
		CorpusSHA256:       corpusSHA,
		ToolProfileSHA256:  profileSHA,
		CapabilityRegistry: p.CapabilityRegistry,
		ReportedClaims:     append([]string(nil), p.Claims...),
		Date:               date,
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
	// Every newly emitted summary belongs to the active coordinated artifact
	// set. Tests and library callers may construct a summary directly, so make
	// the writer enforce the same boundary as buildSummary.
	if s.SchemaVersion == 0 {
		s.SchemaVersion = activeSchemaVersion
	}
	if s.SchemaVersion != activeSchemaVersion {
		return fmt.Errorf("summary schema_version must be %d, got %d", activeSchemaVersion, s.SchemaVersion)
	}
	if err := validateRegistryReference(s.CapabilityRegistry); err != nil {
		return fmt.Errorf("invalid summary capability_registry: %w", err)
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
