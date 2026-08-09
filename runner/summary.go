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
)

const (
	gauntletVersion = "1.0"
	// 2.6 is the result-state boundary. Applicability moved from profile
	// declarations to adapter-proven delivery and verdict observation, an
	// unreachable state was added outside every score denominator, and a run
	// with any unreachable row reports itself insufficient. Results scored
	// under 2.5 and earlier are therefore not comparable to these, and the
	// repository's own staleness rule requires the bump rather than allowing
	// two different rule sets to publish under one label.
	scoringVersion = "2.6"
	runnerVersion  = "0.4.2"
	corpusVersion  = "v2.4.0"
	summaryDateEnv = "AEB_GAUNTLET_SUMMARY_DATE"
)

// DualScores holds both full-corpus and applicable-only score views.
type DualScores struct {
	Full       Scores `json:"full"`
	Applicable Scores `json:"applicable"`
}

// GauntletSummary is the top-level output written to --output.
type GauntletSummary struct {
	SchemaVersion     int                       `json:"schema_version"`
	GauntletVersion   string                    `json:"gauntlet_version"`
	ScoringVersion    string                    `json:"scoring_version"`
	RunnerVersion     string                    `json:"runner_version"`
	Tool              string                    `json:"tool"`
	ToolVersion       string                    `json:"tool_version"`
	CorpusVersion     string                    `json:"corpus_version"`
	CorpusSHA256      string                    `json:"corpus_sha256"`
	ToolProfileSHA256 string                    `json:"tool_profile_sha256"`
	Date              string                    `json:"date,omitempty"`
	CaseCount         CaseCount                 `json:"case_count"`
	ToolSupport       ToolSupport               `json:"tool_support"`
	Exercised         ExercisedCapabilities     `json:"exercised"`
	Scores            DualScores                `json:"scores"`
	Sufficient        bool                      `json:"sufficient"`
	PerCategory       map[string]CategoryScores `json:"per_category"`

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

// ToolSupport summarizes what the tool claims and what it doesn't support.
type ToolSupport struct {
	Claims                []string `json:"claims"`
	UnsupportedTransports []string `json:"unsupported_transports"`
	UnsupportedRequires   []string `json:"unsupported_requires"`
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

// buildToolSupport extracts unsupported transports and requires from the profile.
func buildToolSupport(p Profile) ToolSupport {
	// Known transport keys in supports.
	transportKeys := []string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}
	// Known requires keys in supports.
	requiresKeys := []string{
		"tls_interception",
		"url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning",
		"response_prompt_injection_scanning",
		"mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning",
		"mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning",
		"mcp_tool_poison_scanning", "mcp_tool_baseline", "mcp_chain_memory",
		"mcp_cross_server_chain_memory", "mcp_data_class_labels",
		"a2a_dlp_scanning", "a2a_prompt_injection_scanning",
		"a2a_card_prompt_injection_scanning", "a2a_card_drift_scanning",
		"a2a_ssrf_scanning",
		"websocket_dlp_scanning", "websocket_prompt_injection_scanning",
		"ssrf_scanning", "ssrf_bypass_scanning",
		"domain_blocklist", "entropy_scanning", "encoding_evasion_scanning",
		"shell_analysis", "crypto_dlp_scanning", "hostname_exfil_scanning",
		"dns_rebinding_fixture", "budget_enforcement",
	}

	var unsupportedTransports, unsupportedRequires []string

	for _, k := range transportKeys {
		if v, exists := p.Supports[k]; !exists || !v {
			unsupportedTransports = append(unsupportedTransports, k)
		}
	}
	for _, k := range requiresKeys {
		if v, exists := p.Supports[k]; !exists || !v {
			unsupportedRequires = append(unsupportedRequires, k)
		}
	}

	// Ensure non-nil slices for JSON output.
	if unsupportedTransports == nil {
		unsupportedTransports = []string{}
	}
	if unsupportedRequires == nil {
		unsupportedRequires = []string{}
	}

	claims := p.Claims
	if claims == nil {
		claims = []string{}
	}

	return ToolSupport{
		Claims:                claims,
		UnsupportedTransports: unsupportedTransports,
		UnsupportedRequires:   unsupportedRequires,
	}
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
		SchemaVersion:     activeSchemaVersion,
		GauntletVersion:   gauntletVersion,
		ScoringVersion:    scoringVersion,
		RunnerVersion:     runnerVersion,
		Tool:              p.Tool,
		ToolVersion:       p.ToolVersion,
		CorpusVersion:     corpusVersion,
		CorpusSHA256:      corpusSHA,
		ToolProfileSHA256: profileSHA,
		Date:              date,
		CaseCount: CaseCount{
			Total:                len(allCases),
			Applicable:           len(applicableResults),
			Unreachable:          len(unreachableIDs),
			NotApplicable:        totalNA,
			NotApplicableReasons: naReasonsStr,
			Errors:               errorCount,
		},
		ToolSupport: buildToolSupport(p),
		Exercised:   computeExercised(applicableResults, casesByID),
		Scores: DualScores{
			Full:       fullScores,
			Applicable: applicableScores,
		},
		// Calibration adapters assert their proof flags so the runner can test
		// scoring math. Their per-case marker keeps that assertion visible;
		// this gate keeps the resulting summary out of a publication path,
		// which requires sufficient=true.
		Sufficient:  !hasSyntheticEvidence(applicableResults) && isSufficient(fullScores, len(applicableResults), errorCount, len(unreachableIDs)),
		PerCategory: perCategory,

		MethodRepository:   prov.MethodRepository,
		MethodCommit:       prov.MethodCommit,
		AdapterID:          prov.AdapterID,
		AdapterOwner:       prov.AdapterOwner,
		TargetConfigRef:    prov.TargetConfigRef,
		TargetConfigSHA256: prov.TargetConfigSHA,
	}, nil
}

// hasSyntheticEvidence reports whether a row came from a calibration adapter.
// Treat an unrecognized marker conservatively: an accidental synthetic claim
// can make a run insufficient, but can never make a measured run publishable.
func hasSyntheticEvidence(results []CaseResult) bool {
	for _, result := range results {
		if synthetic, ok := result.Evidence["synthetic"].(bool); ok && synthetic {
			return true
		}
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
