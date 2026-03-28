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
	runnerVersion   = "0.1.0"
)

// GauntletSummary is the top-level output written to --output.
type GauntletSummary struct {
	GauntletVersion string                    `json:"gauntlet_version"`
	RunnerVersion   string                    `json:"runner_version"`
	Tool            string                    `json:"tool"`
	ToolVersion     string                    `json:"tool_version"`
	CorpusVersion   string                    `json:"corpus_version"`
	CorpusSHA256    string                    `json:"corpus_sha256"`
	Date            string                    `json:"date"`
	CaseCount       CaseCount                 `json:"case_count"`
	ToolSupport     ToolSupport               `json:"tool_support"`
	Scores          Scores                    `json:"scores"`
	Sufficient      bool                      `json:"sufficient"`
	PerCategory     map[string]CategoryScores `json:"per_category"`
}

// CaseCount tracks totals and N/A breakdown.
type CaseCount struct {
	Total               int            `json:"total"`
	Applicable          int            `json:"applicable"`
	NotApplicable       int            `json:"not_applicable"`
	NotApplicableReasons map[string]int `json:"not_applicable_reasons"`
	Errors              int            `json:"errors"`
}

// ToolSupport summarizes what the tool claims and what it doesn't support.
type ToolSupport struct {
	Claims                []string `json:"claims"`
	UnsupportedTransports []string `json:"unsupported_transports"`
	UnsupportedRequires   []string `json:"unsupported_requires"`
}

// computeCorpusSHA256 hashes all case file contents, sorted by path.
func computeCorpusSHA256(casesDir string) (string, error) {
	var paths []string

	err := filepath.Walk(casesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
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

// buildToolSupport extracts unsupported transports and requires from the profile.
func buildToolSupport(p Profile) ToolSupport {
	// Known transport keys in supports.
	transportKeys := []string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}
	// Known requires keys in supports.
	requiresKeys := []string{
		"tls_interception", "request_body_scanning", "header_scanning",
		"response_scanning", "mcp_tool_baseline", "mcp_chain_memory",
		"websocket_frame_scanning", "a2a_scanning", "shell_analysis",
		"dns_rebinding_fixture",
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

// buildSummary assembles the GauntletSummary from run results.
func buildSummary(
	p Profile,
	allCases []Case,
	applicableResults []CaseResult,
	naReasons map[NAKind]int,
	errorCount int,
	casesDir string,
	casesByID map[string]Case,
) (GauntletSummary, error) {
	corpusSHA, err := computeCorpusSHA256(casesDir)
	if err != nil {
		return GauntletSummary{}, err
	}

	scores := computeScores(applicableResults)
	perCategory := computeCategoryScores(applicableResults, casesByID)

	naReasonsStr := make(map[string]int, len(naReasons))
	for k, v := range naReasons {
		naReasonsStr[string(k)] = v
	}

	totalNA := 0
	for _, v := range naReasons {
		totalNA += v
	}

	return GauntletSummary{
		GauntletVersion: gauntletVersion,
		RunnerVersion:   runnerVersion,
		Tool:            p.Tool,
		ToolVersion:     p.ToolVersion,
		CorpusVersion:   "v1.0.0",
		CorpusSHA256:    corpusSHA,
		Date:            time.Now().UTC().Format(time.RFC3339),
		CaseCount: CaseCount{
			Total:                len(allCases),
			Applicable:           len(applicableResults),
			NotApplicable:        totalNA,
			NotApplicableReasons: naReasonsStr,
			Errors:               errorCount,
		},
		ToolSupport: buildToolSupport(p),
		Scores:      scores,
		Sufficient:  isSufficient(scores, len(applicableResults), errorCount),
		PerCategory: perCategory,
	}, nil
}

// writeSummary writes the GauntletSummary as indented JSON to a file.
func writeSummary(s GauntletSummary, path string) error {
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
