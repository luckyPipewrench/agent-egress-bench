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
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

func main() {
	casesDir := flag.String("cases", "", "directory of case JSON files (required)")
	profilePath := flag.String("profile", "", "tool profile JSON file (required)")
	outputPath := flag.String("output", "gauntlet-summary.json", "path for Gauntlet summary JSON")
	adapterName := flag.String("adapter", "dryrun", "adapter name: dryrun, null, blockall, proxy, mcp-gateway")
	gatewayPluginPath := flag.String("gateway-plugin", "", "path to a generic MCP gateway plugin JSON (required with --adapter mcp-gateway)")
	proxyAddr := flag.String("proxy-addr", "", "proxy address for proxy adapter (e.g. 127.0.0.1:18899; avoid 8888, commonly an already-running proxy)")
	scanAddr := flag.String("scan-addr", "", "scan API address for MCP/A2A cases (defaults to proxy-addr)")
	scanToken := flag.String("scan-token", "", "bearer token for scan API authentication")
	mcpCmd := flag.String("mcp-cmd", "", "MCP stdio proxy command for MCP/A2A/shell cases; commands may opt in to AEB_MCP_STDIO_UPSTREAM_ADDR for runner-observed upstream proof")
	mcpHTTPURL := flag.String("mcp-http-url", "", "MCP HTTP listener URL for mcp_http cases")
	managedProxyCmd := flag.String("managed-proxy-cmd", "", "optional shell command to start a proxy under test; receives AEB_* endpoint and fixture environment variables")
	managedMCPHTTPCmd := flag.String("managed-mcp-http-cmd", "", "optional shell command to start an MCP HTTP endpoint under test; receives AEB_* endpoint and fixture environment variables")
	fixtures := flag.Bool("fixtures", false, "start TLS, WebSocket, and DNS test fixtures for full coverage")
	timeout := flag.Duration("timeout", 10*time.Second, "per-case timeout")
	toolVersion := flag.String("tool-version", "", "override the tool_version field from the profile in result summaries (uses profile value when empty)")
	emitReceiptProfile := flag.String("emit-receipt-profile", "", "if set, write a receipt-scoring profile (schemas/receipt-scoring-profile.schema.json) to this path alongside the Gauntlet summary")
	receiptVerifierFile := flag.String("receipt-verifier-file", "", "JSON file describing the tool's receipt verifier (shipped, open_source, verifier_url, license, exit_code_contract). Used only when --emit-receipt-profile is set; omitted means \"no verifier shipped\".")
	multiFileCases := flag.String("multifile-cases", "", "directory of multi-file MCP-drift cases (each subdirectory has case.yaml + before.json + after.json + expected.json). Driver replays before then after through a single MCP session and observes the verdict on the second tools/list response.")
	stats := flag.Bool("stats", false, "print loader-backed corpus statistics (requires --cases; ignores runner profile flags)")
	caseIndex := flag.Bool("case-index", false, "print loader-normalized case IDs and expected verdicts as JSON (requires --cases; ignores runner profile flags)")
	reportDir := flag.String("report", "", "render a buyer-readable Markdown report from an existing Gauntlet artifact directory")
	reportOutput := flag.String("report-output", "gauntlet-report.md", "report output path, or - for stdout (used with --report)")
	methodRepository := flag.String("method-repository", "", "repository this corpus came from, recorded in the summary so a reader can reproduce the run")
	methodCommit := flag.String("method-commit", "", "exact commit of the corpus under test, recorded in the summary")
	adapterOwner := flag.String("adapter-owner", "", "who authored the adapter driving the target; a vendor-authored adapter is normal, leaving it unstated is not")
	targetConfig := flag.String("target-config", "", "path to the target's configuration file; its path and digest are recorded so the score can be repeated")

	// --debug / -v: emit verbose per-case diagnostics to stderr. Both
	// flag names point at the same variable so either can be used.
	var debug bool
	flag.BoolVar(&debug, "debug", false, "emit verbose per-case diagnostics to stderr")
	flag.BoolVar(&debug, "v", false, "alias for --debug")

	flag.Parse()
	if *reportDir != "" {
		if err := generateBuyerReport(*reportDir, *reportOutput); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *stats {
		if *casesDir == "" {
			flag.Usage()
			os.Exit(1)
		}
		cases, err := loadCorpusStats(*casesDir)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := writeCorpusStats(os.Stdout, cases); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: write corpus stats: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if *caseIndex {
		if *casesDir == "" {
			flag.Usage()
			os.Exit(1)
		}
		cases, err := loadCorpus(*casesDir)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		if err := writeCaseIndex(os.Stdout, cases); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: write case index: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *casesDir == "" || *profilePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	prov := RunProvenance{
		MethodRepository: *methodRepository,
		MethodCommit:     *methodCommit,
		AdapterID:        *adapterName,
		AdapterOwner:     *adapterOwner,
	}
	if *targetConfig != "" {
		sha, hashErr := computeProfileSHA256(*targetConfig)
		if hashErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: hashing target config: %v\n", hashErr)
			os.Exit(1)
		}
		prov.TargetConfigRef = *targetConfig
		prov.TargetConfigSHA = sha
	}

	if err := runWithGatewayPluginOptions(*casesDir, *profilePath, *outputPath, *timeout, *adapterName, *proxyAddr, *scanAddr, *scanToken, *mcpCmd, *mcpHTTPURL, *managedProxyCmd, *managedMCPHTTPCmd, *gatewayPluginPath, *fixtures, *emitReceiptProfile, *receiptVerifierFile, *multiFileCases, debug, *toolVersion, prov); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(casesDir, profilePath, outputPath string, timeout time.Duration, adapterName, proxyAddr, scanAddr, scanToken, mcpCmd string, useFixtures bool, emitReceiptProfile, receiptVerifierFile, multiFileCases string, debug bool) error {
	return runWithOptions(casesDir, profilePath, outputPath, timeout, adapterName, proxyAddr, scanAddr, scanToken, mcpCmd, "", "", "", useFixtures, emitReceiptProfile, receiptVerifierFile, multiFileCases, debug, "")
}

func runWithOptions(casesDir, profilePath, outputPath string, timeout time.Duration, adapterName, proxyAddr, scanAddr, scanToken, mcpCmd, mcpHTTPURL, managedProxyCmd, managedMCPHTTPCmd string, useFixtures bool, emitReceiptProfile, receiptVerifierFile, multiFileCases string, debug bool, toolVersion string) error {
	return runWithGatewayPluginOptions(casesDir, profilePath, outputPath, timeout, adapterName, proxyAddr, scanAddr, scanToken, mcpCmd, mcpHTTPURL, managedProxyCmd, managedMCPHTTPCmd, "", useFixtures, emitReceiptProfile, receiptVerifierFile, multiFileCases, debug, toolVersion, RunProvenance{AdapterID: adapterName})
}

func runWithGatewayPluginOptions(casesDir, profilePath, outputPath string, timeout time.Duration, adapterName, proxyAddr, scanAddr, scanToken, mcpCmd, mcpHTTPURL, managedProxyCmd, managedMCPHTTPCmd, gatewayPluginPath string, useFixtures bool, emitReceiptProfile, receiptVerifierFile, multiFileCases string, debug bool, toolVersion string, prov RunProvenance) error {
	profile, err := loadProfile(profilePath)
	if err != nil {
		return err
	}

	if toolVersion != "" {
		profile.ToolVersion = toolVersion
	}

	cases, err := loadCases(casesDir)
	if err != nil {
		return err
	}

	// Load multi-file MCP-drift cases (cases/mcp-drift/<id>/{case.yaml, before.json,
	// after.json, expected.json}). Each MultiFileCase is converted to a regular Case
	// whose payload carries the four-message JSON-RPC sequence the mcp_stdio adapter
	// already understands, so downstream scoring and receipt-profile code does not
	// need to branch on case format. Cases are appended after the sorted single-file
	// corpus; the receipt profile sorts per_case by case_id at emission time so
	// ordering between the two sources does not affect byte-reproducibility.
	if multiFileCases != "" {
		mfCases, mfErr := loadMultiFileCases(multiFileCases)
		if mfErr != nil {
			return mfErr
		}
		for _, mfc := range mfCases {
			converted, convertErr := mfc.toCase()
			if convertErr != nil {
				return fmt.Errorf("convert multi-file case %s: %w", mfc.ID, convertErr)
			}
			cases = append(cases, converted)
		}
	}

	// Build case lookup by ID for category scoring.
	casesByID := make(map[string]Case, len(cases))
	for _, c := range cases {
		casesByID[c.ID] = c
	}

	// Select adapter based on flag.
	var adapt adapter.Adapter
	var fm *fixture.Manager
	if useFixtures || managedProxyCmd != "" || managedMCPHTTPCmd != "" || adapterName == "mcp-gateway" {
		var fErr error
		fm, fErr = fixture.StartAll()
		if fErr != nil {
			return fmt.Errorf("starting fixtures: %w", fErr)
		}
		defer fm.Close()
	}
	var managed *managedProcesses
	if managedProxyCmd != "" || managedMCPHTTPCmd != "" {
		var managedErr error
		managed, managedErr = startManagedProcesses(managedProxyCmd, managedMCPHTTPCmd, fm, timeout)
		if managedErr != nil {
			return managedErr
		}
		defer managed.Close()
		if managed.proxyAddr != "" {
			proxyAddr = managed.proxyAddr
		}
		if managed.scanAddr != "" {
			scanAddr = managed.scanAddr
		}
		if managed.mcpHTTPURL != "" {
			mcpHTTPURL = managed.mcpHTTPURL
		}
	}
	switch adapterName {
	case "dryrun":
		adapt = adapter.DryRunAdapter{}
	case "null":
		adapt = adapter.NullAdapter{}
	case "blockall":
		adapt = adapter.BlockAllAdapter{}
	case "proxy":
		if proxyAddr == "" {
			return fmt.Errorf("--proxy-addr is required when using the proxy adapter")
		}
		pa, proxyErr := adapter.NewProxyAdapter(proxyAddr, scanAddr, scanToken, mcpCmd)
		if proxyErr != nil {
			return proxyErr
		}
		if fm != nil {
			pa.SetHTTPFixtureWithContentType(fm.HTTP().Addr(), fm.HTTP().SetRouteWithContentType)
			pa.SetTLSFixtureWithContentType(fm.TLS().Addr(), fm.TLS().CAFile(), fm.TLS().SetRouteWithContentType, fm.TLS().SetRouteForHostWithContentType)
			pa.SetTLSRequestCounter(fm.TLS().Requests)
			pa.SetWSFixtures(fm.WS().Addr(), fm.WS().UntrustedAddr())
			pa.SetWSUpstreamMessageCounter(fm.WS().Messages)
			pa.SetMCPHTTPUpstreamCallCounter(fm.MCPHTTP().Calls)
			pa.SetMCPHTTPFixture(fm.MCPHTTP())
			_, _ = fmt.Fprintf(os.Stderr, "Fixtures: HTTP=%s TLS=%s WS=%s DNS=%s MCP_HTTP=%s\n",
				fm.HTTP().Addr(), fm.TLS().Addr(), fm.WS().Addr(), fm.DNS().Addr(), fm.MCPHTTP().Addr())
		}
		if mcpHTTPURL != "" {
			pa.SetMCPHTTPURL(mcpHTTPURL)
		}
		adapt = pa
	case "mcp-gateway":
		if gatewayPluginPath == "" {
			return fmt.Errorf("--gateway-plugin is required when using the mcp-gateway adapter")
		}
		gatewayAdapter, managedGW, gatewayErr := buildManagedGatewayAdapter(gatewayPluginPath, fm, timeout)
		if gatewayErr != nil {
			return gatewayErr
		}
		if managedGW != nil {
			defer managedGW.Close()
		}
		adapt = gatewayAdapter
	default:
		return fmt.Errorf("unknown adapter: %q (available: dryrun, null, blockall, proxy, mcp-gateway)", adapterName)
	}

	var applicableResults []CaseResult
	naReasons := make(map[NAKind]int)
	enc := json.NewEncoder(os.Stdout)

	for _, c := range cases {
		// Check applicability.
		reason, applicable := checkApplicability(c, profile)
		if !applicable {
			debugf(debug, "case %s: not_applicable (%s)", c.ID, reason)
			naReasons[reason]++
			result := CaseResult{
				SchemaVersion:   activeSchemaVersion,
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
			Transport:       c.Transport,
			InputType:       c.InputType,
			Requires:        c.Requires,
			Payload:         c.Payload,
		}
		adapterResult := adapt.Run(adapterCase, timeout)

		if adapterResult.Err != nil {
			debugf(debug, "case %s: ERROR expected=%s err=%v evidence=%v",
				c.ID, c.ExpectedVerdict, adapterResult.Err, adapterResult.Evidence)
			result := CaseResult{
				SchemaVersion:   activeSchemaVersion,
				CaseID:          c.ID,
				Tool:            profile.Tool,
				ToolVersion:     profile.ToolVersion,
				ExpectedVerdict: c.ExpectedVerdict,
				ActualVerdict:   "error",
				Score:           "error",
				Evidence:        map[string]interface{}{},
				Notes:           fmt.Sprintf("adapter error: %v", adapterResult.Err),
			}
			applicableResults = append(applicableResults, result)
			if encErr := enc.Encode(result); encErr != nil {
				return fmt.Errorf("writing result for %s: %w", c.ID, encErr)
			}
			continue
		}

		// Applicability was already established from the tool profile. A skip or
		// an out-of-contract verdict at this point is a runner/adapter failure,
		// not a tool capability exception. Count it as an error so an incomplete
		// or malformed adapter cannot launder an unexecuted case into a normal
		// pass/fail result.
		if verdictError, invalid := adapterVerdictError(adapterResult); invalid {
			debugf(debug, "case %s: ERROR %s (%v)", c.ID, verdictError, adapterResult.Evidence)
			result := CaseResult{
				SchemaVersion:   activeSchemaVersion,
				CaseID:          c.ID,
				Tool:            profile.Tool,
				ToolVersion:     profile.ToolVersion,
				ExpectedVerdict: c.ExpectedVerdict,
				ActualVerdict:   "error",
				Score:           "error",
				Evidence:        adapterResult.Evidence,
				Notes:           verdictError,
			}
			applicableResults = append(applicableResults, result)
			if encErr := enc.Encode(result); encErr != nil {
				return fmt.Errorf("writing result for %s: %w", c.ID, encErr)
			}
			continue
		}

		evidence := adapterResult.Evidence
		if evidence == nil {
			evidence = map[string]interface{}{}
		}
		score := scoreCaseWithEvidence(c, adapterResult.Verdict, evidence)

		if score == "pass" {
			debugf(debug, "case %s: PASS expected=%s actual=%s", c.ID, c.ExpectedVerdict, adapterResult.Verdict)
		} else {
			debugf(debug, "case %s: FAIL expected=%s actual=%s evidence=%v",
				c.ID, c.ExpectedVerdict, adapterResult.Verdict, evidence)
		}

		result := CaseResult{
			SchemaVersion:   activeSchemaVersion,
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
	summary, err := buildSummary(profile, cases, applicableResults, naReasons, casesDir, multiFileCases, casesByID, profilePath, prov)
	if err != nil {
		return err
	}

	if err := writeSummary(summary, outputPath); err != nil {
		return err
	}

	// Emit the receipt-scoring profile if requested. Reuses corpus and
	// tool-profile hashes already computed for the gauntlet summary so
	// repeated runs are byte-reproducible against the same inputs.
	if emitReceiptProfile != "" {
		// Load receipt verifier only when profile emission is requested.
		// An empty path yields a "no verifier" block; a malformed path fails
		// before writing the receipt profile.
		receiptVerifier, err := loadReceiptVerifier(receiptVerifierFile)
		if err != nil {
			return err
		}
		rp := buildReceiptProfile(
			profile,
			applicableResults,
			casesByID,
			receiptVerifier,
			summary.CorpusVersion,
			summary.CorpusSHA256,
			summary.ToolProfileSHA256,
		)
		if err := writeReceiptProfile(rp, emitReceiptProfile); err != nil {
			return err
		}
	}

	// Human-readable summary to stderr.
	_, _ = fmt.Fprintf(os.Stderr, "\n--- Gauntlet Summary ---\n")
	_, _ = fmt.Fprintf(os.Stderr, "Tool:       %s %s\n", profile.Tool, profile.ToolVersion)
	_, _ = fmt.Fprintf(os.Stderr, "Adapter:    %s\n", adapterName)
	_, _ = fmt.Fprintf(os.Stderr, "Cases:      %d total, %d applicable, %d N/A, %d errors\n",
		len(cases), len(applicableResults), summary.CaseCount.NotApplicable, summary.CaseCount.Errors)

	printScores(os.Stderr, "Full Corpus Scores (primary)", summary.Scores.Full)
	printScores(os.Stderr, "Applicable Scores (diagnostic)", summary.Scores.Applicable)

	_, _ = fmt.Fprintf(os.Stderr, "Sufficient:       %v\n", summary.Sufficient)
	_, _ = fmt.Fprintf(os.Stderr, "Summary written:  %s\n", outputPath)
	if emitReceiptProfile != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Receipt profile:  %s\n", emitReceiptProfile)
	}

	return nil
}

func adapterVerdictError(result adapter.Result) (string, bool) {
	switch result.Verdict {
	case "allow", "block":
		return "", false
	case "skip":
		reason := "adapter skip"
		if value, ok := result.Evidence["reason"].(string); ok && value != "" {
			reason += ": " + value
		}
		return reason, true
	default:
		return fmt.Sprintf("invalid adapter verdict: %q", result.Verdict), true
	}
}

// debugPrefix is the marker written at the start of every debug line.
// Tests match on this to distinguish debug output from the normal summary.
const debugPrefix = "[DEBUG] "

// debugf is a gated debug logger. When debug is false, it is a no-op and
// adds zero cost. When debug is true, it writes a single prefixed line to
// stderr. It is deliberately NOT a method — it is called from the loop
// body with a captured bool, keeping the structure simple (no new types).
func debugf(debug bool, format string, args ...interface{}) {
	if !debug {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, debugPrefix+format+"\n", args...)
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
