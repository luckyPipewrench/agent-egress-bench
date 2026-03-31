// aeb-gauntlet runs agent-egress-bench cases against a tool profile and produces
// per-case JSONL results on stdout and a Gauntlet summary JSON file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

func main() {
	casesDir := flag.String("cases", "", "directory of case JSON files (required)")
	profilePath := flag.String("profile", "", "tool profile JSON file (required)")
	outputPath := flag.String("output", "gauntlet-summary.json", "path for Gauntlet summary JSON")
	adapterName := flag.String("adapter", "dryrun", "adapter name: dryrun, null")
	timeout := flag.Duration("timeout", 10*time.Second, "per-case timeout")

	flag.Parse()

	if *casesDir == "" || *profilePath == "" {
		_, _ = fmt.Fprintf(os.Stderr, "usage: aeb-gauntlet --cases <dir> --profile <profile.json> [--output <summary.json>] [--adapter dryrun|null] [--timeout 10s]\n")
		os.Exit(1)
	}

	if err := run(*casesDir, *profilePath, *outputPath, *timeout, *adapterName); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(casesDir, profilePath, outputPath string, timeout time.Duration, adapterName string) error {
	profile, err := loadProfile(profilePath)
	if err != nil {
		return err
	}

	cases, err := loadCases(casesDir)
	if err != nil {
		return err
	}

	// Build case lookup by ID for category scoring.
	casesByID := make(map[string]Case, len(cases))
	for _, c := range cases {
		casesByID[c.ID] = c
	}

	// Select adapter based on flag.
	var adapt adapter.Adapter
	switch adapterName {
	case "dryrun":
		adapt = adapter.DryRunAdapter{}
	case "null":
		adapt = adapter.NullAdapter{}
	default:
		return fmt.Errorf("unknown adapter: %q (available: dryrun, null)", adapterName)
	}

	var applicableResults []CaseResult
	naReasons := make(map[NAKind]int)
	errorCount := 0
	enc := json.NewEncoder(os.Stdout)

	for _, c := range cases {
		// Check applicability.
		reason, applicable := checkApplicability(c, profile)
		if !applicable {
			naReasons[reason]++
			result := CaseResult{
				CaseID:          c.ID,
				Tool:            profile.Tool,
				ToolVersion:     profile.ToolVersion,
				ExpectedVerdict: c.ExpectedVerdict,
				ActualVerdict:   "not_applicable",
				Score:           "not_applicable",
				Evidence:        map[string]interface{}{},
				Notes:           fmt.Sprintf("not applicable: %s", string(reason)),
			}
			if encErr := enc.Encode(result); encErr != nil {
				return fmt.Errorf("writing result for %s: %w", c.ID, encErr)
			}
			continue
		}

		// Run the case through the adapter.
		adapterCase := adapter.Case{
			ID:              c.ID,
			ExpectedVerdict: c.ExpectedVerdict,
		}
		adapterResult := adapt.Run(adapterCase, timeout)

		if adapterResult.Err != nil {
			errorCount++
			result := CaseResult{
				CaseID:          c.ID,
				Tool:            profile.Tool,
				ToolVersion:     profile.ToolVersion,
				ExpectedVerdict: c.ExpectedVerdict,
				ActualVerdict:   "error",
				Score:           "error",
				Evidence:        map[string]interface{}{},
				Notes:           fmt.Sprintf("adapter error: %v", adapterResult.Err),
			}
			if encErr := enc.Encode(result); encErr != nil {
				return fmt.Errorf("writing result for %s: %w", c.ID, encErr)
			}
			continue
		}

		score := scoreCase(c.ExpectedVerdict, adapterResult.Verdict)
		evidence := adapterResult.Evidence
		if evidence == nil {
			evidence = map[string]interface{}{}
		}

		result := CaseResult{
			CaseID:          c.ID,
			Tool:            profile.Tool,
			ToolVersion:     profile.ToolVersion,
			ExpectedVerdict: c.ExpectedVerdict,
			ActualVerdict:   adapterResult.Verdict,
			Score:           score,
			Evidence:        evidence,
			Notes:           "",
		}

		applicableResults = append(applicableResults, result)

		if encErr := enc.Encode(result); encErr != nil {
			return fmt.Errorf("writing result for %s: %w", c.ID, encErr)
		}
	}

	// Build and write summary.
	summary, err := buildSummary(profile, cases, applicableResults, naReasons, errorCount, casesDir, casesByID, profilePath)
	if err != nil {
		return err
	}

	if err := writeSummary(summary, outputPath); err != nil {
		return err
	}

	// Human-readable summary to stderr.
	_, _ = fmt.Fprintf(os.Stderr, "\n--- Gauntlet Summary ---\n")
	_, _ = fmt.Fprintf(os.Stderr, "Tool:       %s %s\n", profile.Tool, profile.ToolVersion)
	_, _ = fmt.Fprintf(os.Stderr, "Adapter:    %s\n", adapterName)
	_, _ = fmt.Fprintf(os.Stderr, "Cases:      %d total, %d applicable, %d N/A, %d errors\n",
		len(cases), len(applicableResults), summary.CaseCount.NotApplicable, errorCount)

	printScores(os.Stderr, "Full Corpus Scores (primary)", summary.Scores.Full)
	printScores(os.Stderr, "Applicable Scores (diagnostic)", summary.Scores.Applicable)

	_, _ = fmt.Fprintf(os.Stderr, "Sufficient:       %v\n", summary.Sufficient)
	_, _ = fmt.Fprintf(os.Stderr, "Summary written:  %s\n", outputPath)

	return nil
}

// printScores writes a score block with a label to the given writer.
func printScores(w *os.File, label string, scores Scores) {
	_, _ = fmt.Fprintf(w, "\n  %s:\n", label)
	if scores.Containment != nil {
		_, _ = fmt.Fprintf(w, "    Containment:      %.1f%%\n", *scores.Containment*100)
	} else {
		_, _ = fmt.Fprintf(w, "    Containment:      N/A\n")
	}
	if scores.FalsePositiveRate != nil {
		_, _ = fmt.Fprintf(w, "    False Positive:   %.1f%%\n", *scores.FalsePositiveRate*100)
	} else {
		_, _ = fmt.Fprintf(w, "    False Positive:   N/A\n")
	}
	if scores.Detection != nil {
		_, _ = fmt.Fprintf(w, "    Detection:        %.1f%%\n", *scores.Detection*100)
	} else {
		_, _ = fmt.Fprintf(w, "    Detection:        N/A\n")
	}
	if scores.Evidence != nil {
		_, _ = fmt.Fprintf(w, "    Evidence:         %.1f%%\n", *scores.Evidence*100)
	} else {
		_, _ = fmt.Fprintf(w, "    Evidence:         N/A\n")
	}
}
