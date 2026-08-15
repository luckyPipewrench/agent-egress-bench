// aeb-gauntlet runs agent-egress-bench cases against a tool profile and produces
// per-case JSONL results on stdout and a Gauntlet summary JSON file.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
	"github.com/luckyPipewrench/agent-egress-bench/runner/fixture"
)

// releaseVersion and releaseCommit are set by the tagged release build. They
// stay usable in local builds so an operator never mistakes an unpinned binary
// for a release artifact.
var (
	releaseVersion = "devel"
	releaseCommit  = "unknown"
)

func main() {
	version := flag.Bool("version", false, "print the runner release version and commit")
	releaseMetadata := flag.Bool("release-identity-metadata", false, "print runner metadata used in a release identity")
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
	mcpHTTPSessionHeader := flag.String("mcp-http-session-header", "", "response header a target uses to issue an MCP HTTP session token, replayed on that case's later requests; unset disables token extraction and replay, and does not suppress the MCP initialize every client sends")
	mcpHTTPSessionFormat := flag.String("mcp-http-session-format", "", "declared format of the issued session token, currently base64url_256; unset accepts any header-safe value")
	mcpHTTPSessionRefusalHeader := flag.String("mcp-http-session-refusal-header", "", "response header a target sets when it refuses a stateful request for want of a session, so that refusal is recorded as unproven rather than scored as a block it never made")
	mcpHTTPSessionRefusalValue := flag.String("mcp-http-session-refusal-value", "", "exact value of --mcp-http-session-refusal-header identifying a session refusal")
	managedProxyCmd := flag.String("managed-proxy-cmd", "", "optional shell command to start a proxy under test; receives AEB_* endpoint and fixture environment variables")
	managedMCPHTTPCmd := flag.String("managed-mcp-http-cmd", "", "optional shell command to start an MCP HTTP endpoint under test; receives AEB_* endpoint and fixture environment variables")
	fixtures := flag.Bool("fixtures", false, "start TLS, WebSocket, and DNS test fixtures for full coverage")
	timeout := flag.Duration("timeout", 10*time.Second, "per-case timeout")
	toolVersion := flag.String("tool-version", "", "override the tool_version field from the profile in result summaries (uses profile value when empty)")
	emitReceiptProfile := flag.String("emit-receipt-profile", "", "if set, write a receipt-scoring profile (schemas/receipt-scoring-profile-v4.schema.json) to this path alongside the Gauntlet summary")
	receiptVerifierFile := flag.String("receipt-verifier-file", "", "JSON file describing the tool's receipt verifier (shipped, open_source, verifier_url, license, exit_code_contract). Used only when --emit-receipt-profile is set; omitted means \"no verifier shipped\".")
	multiFileCases := flag.String("multifile-cases", "", "override the auto-discovered multi-file case directory. The selected case IDs must equal the loader-backed corpus.")
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
	if *version {
		_, _ = fmt.Fprintf(os.Stdout, "aeb-gauntlet %s %s\n", releaseVersion, releaseCommit)
		return
	}
	if *releaseMetadata {
		metadata := struct {
			RunnerVersion  string `json:"runner_version"`
			ScoringVersion string `json:"scoring_version"`
			CorpusVersion  string `json:"corpus_version"`
		}{
			RunnerVersion:  runnerVersion,
			ScoringVersion: scoringVersion,
			CorpusVersion:  corpusVersion,
		}
		if err := json.NewEncoder(os.Stdout).Encode(metadata); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: write release metadata: %v\n", err)
			os.Exit(1)
		}
		return
	}
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
	prov.MCPHTTPSessionHeader = *mcpHTTPSessionHeader
	prov.MCPHTTPSessionFormat = *mcpHTTPSessionFormat
	prov.MCPHTTPSessionRefusalHeader = *mcpHTTPSessionRefusalHeader
	prov.MCPHTTPSessionRefusalValue = *mcpHTTPSessionRefusalValue

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

	runCorpus, err := loadRunCorpus(casesDir, multiFileCases)
	if err != nil {
		return err
	}
	cases := runCorpus.cases

	// Fail before fixture startup, adapter invocation, JSONL emission, summary,
	// or receipt output when the immutable reporting vocabulary cannot be
	// resolved exactly. Labels are validated here and never used below to pick
	// rows or calculate a score.
	if _, err := preflightRegistry(profile, cases, casesDir); err != nil {
		return fmt.Errorf("capability registry preflight: %w", err)
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
			pa.SetHTTPFixtureRequestCounter(fm.HTTP().Requests)
			pa.SetTLSFixtureWithContentType(fm.TLS().Addr(), fm.TLS().CAFile(), fm.TLS().SetRouteWithContentType, fm.TLS().SetRouteForHostWithContentType)
			pa.SetTLSRequestCounter(fm.TLS().Requests)
			pa.SetWSFixtures(fm.WS().Addr(), fm.WS().UntrustedAddr())
			pa.SetWSUpstreamMessageCounter(fm.WS().Messages)
			pa.SetWSRSV1Outcome(fm.WS().RSV1Outcome)
			pa.SetMCPHTTPUpstreamCallCounter(fm.MCPHTTP().Calls)
			pa.SetMCPHTTPFixture(fm.MCPHTTP())
			_, _ = fmt.Fprintf(os.Stderr, "Fixtures: HTTP=%s TLS=%s WS=%s DNS=%s MCP_HTTP=%s\n",
				fm.HTTP().Addr(), fm.TLS().Addr(), fm.WS().Addr(), fm.DNS().Addr(), fm.MCPHTTP().Addr())
		}
		if mcpHTTPURL != "" {
			pa.SetMCPHTTPURL(mcpHTTPURL)
		}
		session := adapter.ListenerSessionDeclaration{
			TokenHeader:   prov.MCPHTTPSessionHeader,
			TokenFormat:   prov.MCPHTTPSessionFormat,
			RefusalHeader: prov.MCPHTTPSessionRefusalHeader,
			RefusalValue:  prov.MCPHTTPSessionRefusalValue,
		}
		// Refuse a half-declared session before the run rather than after the
		// score. The adapter owns the rule so one definition covers the CLI and
		// every other caller.
		if err := session.Validate(); err != nil {
			return fmt.Errorf("mcp http session declaration: %w", err)
		}
		pa.SetMCPHTTPListenerSession(session)
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

	applicableResults, unreachableResults, unreachableIDs, naReasons, runErr := runCases(cases, profile, adapt, timeout, debug, os.Stdout)
	if runErr != nil {
		return runErr
	}

	// Build and write summary.
	summary, err := buildSummary(profile, cases, applicableResults, unreachableIDs, naReasons, runCorpus.snapshot, casesByID, profilePath, prov)
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
			receiptProfileRows(applicableResults, unreachableResults),
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
	_, _ = fmt.Fprintf(os.Stderr, "Cases:      %d total, %d routed, %d unreachable, %d N/A, %d errors\n",
		len(cases), len(applicableResults), summary.CaseCount.Unreachable, summary.CaseCount.NotApplicable, summary.CaseCount.Errors)

	printScores(os.Stderr, "Full Corpus Scores (primary)", summary.Scores.Full)
	printScores(os.Stderr, "Applicable Scores (diagnostic)", summary.Scores.Applicable)

	_, _ = fmt.Fprintf(os.Stderr, "Measurement:      %s\n", summary.MeasurementStatus)
	_, _ = fmt.Fprintf(os.Stderr, "Summary written:  %s\n", outputPath)
	if emitReceiptProfile != "" {
		_, _ = fmt.Fprintf(os.Stderr, "Receipt profile:  %s\n", emitReceiptProfile)
	}

	return nil
}

// runCases executes the result-state transition for each case. Profile fields
// remain carried into output as v4 registry-bound reporting labels, but no
// claim, requirement, or capability tag selects a case. Only an exact adapter route,
// proven delivery, and observed verdict can create a scoreable measurement.
func runCases(cases []Case, profile Profile, adapt adapter.Adapter, timeout time.Duration, debug bool, output io.Writer) ([]CaseResult, []CaseResult, map[string]struct{}, map[NAKind]int, error) {
	var applicableResults []CaseResult
	var unreachableResults []CaseResult
	unreachableIDs := make(map[string]struct{})
	naReasons := make(map[NAKind]int)
	enc := json.NewEncoder(output)

	for _, c := range cases {
		adapterCase := adapter.Case{
			ID:              c.ID,
			ExpectedVerdict: c.ExpectedVerdict,
			Transport:       c.Transport,
			InputType:       c.InputType,
			Requires:        c.Requires,
			Payload:         c.Payload,
		}

		_, routed := adapter.SupportsTuple(adapt, adapterCase)
		if !routed {
			// The adapter declared no exact route, so its tuple carries no
			// information about this case. Derive the tuple from the case
			// itself for the evidence record.
			tuple := adapter.TupleForCase(adapterCase)
			result := caseResultForState(
				profile, c, ResultStateUnreachable, tupleEvidence(tuple),
				"unreachable: adapter has no exact delivery route for this case",
			)
			unreachableResults = append(unreachableResults, result)
			unreachableIDs[c.ID] = struct{}{}
			debugf(debug, "case %s: UNREACHABLE %s/%s/%s", c.ID, tuple.WireTransport, tuple.SemanticSurface, tuple.Lifecycle)
			if err := enc.Encode(result); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("writing result for %s: %w", c.ID, err)
			}
			continue
		}

		adapterResult := adapt.Run(adapterCase, timeout)
		state, notes := resultStateFor(adapterResult)
		if state != ResultStateObserved {
			result := caseResultForState(profile, c, state, adapterResult.Evidence, notes)
			applicableResults = append(applicableResults, result)
			debugf(debug, "case %s: ERROR state=%s expected=%s evidence=%v", c.ID, state, c.ExpectedVerdict, result.Evidence)
			if err := enc.Encode(result); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("writing result for %s: %w", c.ID, err)
			}
			continue
		}

		evidence := evidenceWithResultState(adapterResult.Evidence, state)
		score := scoreCaseWithEvidence(c, adapterResult.Verdict, evidence)
		if score == "pass" {
			debugf(debug, "case %s: PASS expected=%s actual=%s", c.ID, c.ExpectedVerdict, adapterResult.Verdict)
		} else {
			debugf(debug, "case %s: FAIL expected=%s actual=%s evidence=%v", c.ID, c.ExpectedVerdict, adapterResult.Verdict, evidence)
		}
		result := CaseResult{
			SchemaVersion:      activeResultSchemaVersion,
			CaseID:             c.ID,
			Tool:               profile.Tool,
			ToolVersion:        profile.ToolVersion,
			CapabilityRegistry: profile.CapabilityRegistry,
			ExpectedVerdict:    c.ExpectedVerdict,
			ActualVerdict:      adapterResult.Verdict,
			Score:              score,
			Evidence:           evidence,
			Notes:              "",
		}
		applicableResults = append(applicableResults, result)
		if err := enc.Encode(result); err != nil {
			return nil, nil, nil, nil, fmt.Errorf("writing result for %s: %w", c.ID, err)
		}
	}
	return applicableResults, unreachableResults, unreachableIDs, naReasons, nil
}

// receiptProfileRows retains every runner-emitted row that can describe a
// measurement gap. An unreachable row never enters scoring, but omitting it
// from a receipt profile would make absence read as coverage. Historical N/A
// rows remain outside this artifact because the runner did not exercise them.
func receiptProfileRows(applicableResults, unreachableResults []CaseResult) []CaseResult {
	rows := make([]CaseResult, 0, len(applicableResults)+len(unreachableResults))
	rows = append(rows, applicableResults...)
	rows = append(rows, unreachableResults...)
	return rows
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

// printScores writes outcome metrics with a label to the given writer.
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
}
