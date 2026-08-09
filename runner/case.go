package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const activeSchemaVersion = 3

// requiredSupportsKeys is the complete, closed v3 supports vocabulary. A
// profile is a scored input, so omitted keys must never silently become false
// and an unknown key must never disappear from applicability decisions.
var requiredSupportsKeys = map[string]struct{}{
	"fetch_proxy": {}, "http_proxy": {}, "mcp_stdio": {}, "mcp_http": {},
	"websocket": {}, "a2a": {}, "tls_interception": {},
	"url_dlp_scanning": {}, "request_body_dlp_scanning": {},
	"header_dlp_scanning": {}, "response_prompt_injection_scanning": {},
	"mcp_input_dlp_scanning": {}, "mcp_input_prompt_injection_scanning": {},
	"mcp_tool_policy": {}, "mcp_tool_result_prompt_injection_scanning": {},
	"mcp_tool_poison_scanning": {}, "mcp_tool_baseline": {},
	"mcp_chain_memory": {}, "mcp_cross_server_chain_memory": {},
	"mcp_data_class_labels": {}, "a2a_dlp_scanning": {},
	"a2a_prompt_injection_scanning": {}, "a2a_card_prompt_injection_scanning": {},
	"a2a_card_drift_scanning": {}, "a2a_ssrf_scanning": {},
	"websocket_dlp_scanning": {}, "websocket_prompt_injection_scanning": {},
	"ssrf_scanning": {}, "ssrf_bypass_scanning": {}, "domain_blocklist": {},
	"entropy_scanning": {}, "encoding_evasion_scanning": {}, "shell_analysis": {},
	"crypto_dlp_scanning": {}, "hostname_exfil_scanning": {},
	"dns_rebinding_fixture": {}, "budget_enforcement": {},
}

// knownClaims is the closed vocabulary of capability claims. Claims never affect
// applicability, scoring, or sufficiency: they are reporting labels. They are
// still published, reaching summary.json's tool_support and the buyer-facing
// report, so an unrecognised claim would be republished as though the corpus had
// accepted it. Validated here because the runner is the code path that produces
// published output, and it does not call the standalone validator.
//
// Duplicated from validate/main.go's validCapabilityTags because runner/ and
// validate/ are separate Go modules and cannot share a package.
// TestToolProfileClaimVocabularyParity binds the two copies.
var knownClaims = map[string]struct{}{
	"url_dlp": {}, "request_body_dlp": {}, "header_dlp": {},
	"response_injection": {}, "mcp_input_scan": {}, "mcp_tool_poison": {},
	"mcp_chain": {}, "ssrf": {}, "domain_blocklist": {},
	"entropy": {}, "encoding_evasion": {}, "benign": {},
	"a2a_scan": {}, "a2a_card_poison": {}, "websocket_dlp": {},
	"ssrf_bypass": {}, "shell_obfuscation": {}, "crypto_dlp": {},
	"hostname_exfil": {}, "denial_of_wallet": {},
}

// Case represents a single benchmark case loaded from JSON.
type Case struct {
	SchemaVersion   int                    `json:"schema_version"`
	ID              string                 `json:"id"`
	Category        string                 `json:"category"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	InputType       string                 `json:"input_type"`
	Transport       string                 `json:"transport"`
	Payload         map[string]interface{} `json:"payload"`
	ExpectedVerdict string                 `json:"expected_verdict"`
	Severity        string                 `json:"severity"`
	CapabilityTags  []string               `json:"capability_tags"`
	Requires        []string               `json:"requires"`
	FPRisk          string                 `json:"false_positive_risk"`
	WhyExpected     string                 `json:"why_expected"`
	SafeExample     *bool                  `json:"safe_example,omitempty"`
	Notes           string                 `json:"notes"`
	Source          string                 `json:"source"`
}

// Profile represents a tool profile JSON file.
type Profile struct {
	SchemaVersion int    `json:"schema_version"`
	Tool          string `json:"tool"`
	ToolVersion   string `json:"tool_version"`
	RunnerVersion string `json:"runner_version"`
	// Claims and Supports are retained as v3 reporting metadata. They do not
	// select cases: active scoring uses adapter delivery and observation proof.
	Claims          []string                    `json:"claims"`
	Supports        map[string]bool             `json:"supports"`
	ReceiptEvidence *ReceiptEvidenceDeclaration `json:"receipt_evidence,omitempty"`

	profileDir string
}

// ReceiptEvidenceDeclaration is the optional tool-profile block that tells
// the runner where a tool writes structured receipt evidence and how to run
// the tool's own verifier over that evidence. The runner treats the block as
// declarative metadata; it does not implement any tool-specific verifier.
type ReceiptEvidenceDeclaration struct {
	EvidenceDir                 string   `json:"evidence_dir"`
	FileGlob                    string   `json:"file_glob"`
	JSONLRecordType             string   `json:"jsonl_record_type"`
	DetailJSONPointer           string   `json:"detail_json_pointer"`
	DetailEncoding              string   `json:"detail_encoding"`
	RecordCaseIDJSONPointer     string   `json:"record_case_id_json_pointer,omitempty"`
	RecordIdentifierJSONPointer string   `json:"record_identifier_json_pointer"`
	CaseIdentifierJSONPointer   string   `json:"case_identifier_json_pointer"`
	VerifyCommand               []string `json:"verify_command"`
	VerifyTimeoutSeconds        int      `json:"verify_timeout_seconds"`
	ValidExitCodes              []int    `json:"valid_exit_codes"`
	PartialExitCodes            []int    `json:"partial_exit_codes,omitempty"`
}

// NAKind describes why a case is not applicable.
type NAKind string

const (
	NAMissingRequires      NAKind = "missing_requires"
	NAUnsupportedTransport NAKind = "unsupported_transport"
)

// multiFileCaseCategories lists case-directory names that use the multi-file
// case format (per-case directory with case.yaml + before.json + after.json
// + expected.json + notes.md). The single-JSON runner and corpus hasher skip
// these — the multi-file schema is documented in each directory's README.md.
var multiFileCaseCategories = map[string]bool{
	"mcp-drift": true,
}

func isMultiFileCaseDir(name string) bool {
	return multiFileCaseCategories[name]
}

// loadCases walks a directory recursively and loads active v3 cases only.
// Historical v2 cases have a separate reader below and cannot enter scoring.
func loadCases(dir string) ([]Case, error) {
	var cases []Case

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip multi-file case directories — they use a different schema.
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", path, readErr)
		}

		var c Case
		if jsonErr := json.Unmarshal(data, &c); jsonErr != nil {
			return fmt.Errorf("parsing %s: %w", path, jsonErr)
		}
		if c.SchemaVersion != activeSchemaVersion {
			return fmt.Errorf("%s: schema_version must be %d for scoring, got %d", path, activeSchemaVersion, c.SchemaVersion)
		}

		cases = append(cases, c)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(cases) == 0 {
		return nil, fmt.Errorf("no case files found in %s", dir)
	}

	return cases, nil
}

// readHistoricalCase reads a frozen v2 case for historical reproduction. It
// deliberately does not return an active scoring input: callers that score
// must use loadCases, which accepts v3 only.
func readHistoricalCase(path string) (Case, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Case{}, fmt.Errorf("reading historical case: %w", err)
	}
	var c Case
	if err := json.Unmarshal(data, &c); err != nil {
		return Case{}, fmt.Errorf("parsing historical case: %w", err)
	}
	if c.SchemaVersion != 2 {
		return Case{}, fmt.Errorf("%s: historical case schema_version must be 2, got %d", path, c.SchemaVersion)
	}
	return c, nil
}

// loadProfile reads and parses a tool profile JSON file.
func loadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("reading profile: %w", err)
	}

	var p Profile
	if jsonErr := decodeStrictJSON(data, &p); jsonErr != nil {
		return Profile{}, fmt.Errorf("parsing profile: %w", jsonErr)
	}
	p.profileDir = filepath.Dir(path)
	if p.SchemaVersion != activeSchemaVersion {
		return Profile{}, fmt.Errorf("profile schema_version must be %d for scoring, got %d", activeSchemaVersion, p.SchemaVersion)
	}
	if err := validateProfileForRun(p); err != nil {
		return Profile{}, fmt.Errorf("invalid profile: %w", err)
	}

	return p, nil
}

// validateProfileForRun checks the fields whose absence would otherwise turn
// into zero values before a run begins. Supports is closed at schema v3 so a
// typo cannot quietly disable an exercised surface.
func validateProfileForRun(p Profile) error {
	if p.Tool == "" {
		return fmt.Errorf("missing required field tool")
	}
	if p.ToolVersion == "" {
		return fmt.Errorf("missing required field tool_version")
	}
	if p.RunnerVersion == "" {
		return fmt.Errorf("missing required field runner_version")
	}
	if p.Claims == nil {
		return fmt.Errorf("missing required field claims")
	}
	// An unrecognised claim fails the run rather than being dropped from the
	// output. Dropping it would let a profile assert something the report never
	// shows and nobody ever sees rejected; refusing makes the disagreement
	// visible at the point the operator can fix it.
	for _, claim := range p.Claims {
		if _, known := knownClaims[claim]; !known {
			return fmt.Errorf("unknown claim: %q", claim)
		}
	}
	if p.Supports == nil {
		return fmt.Errorf("missing required field supports")
	}
	for key := range p.Supports {
		if _, known := requiredSupportsKeys[key]; !known {
			return fmt.Errorf("unknown supports key: %q", key)
		}
	}
	for key := range requiredSupportsKeys {
		if _, present := p.Supports[key]; !present {
			return fmt.Errorf("missing required supports key: %q", key)
		}
	}
	return nil
}

// checkApplicability preserves the legacy profile interpretation for tests and
// historical analysis. Active runner execution does not call it: profile claims,
// supports, requires, and capability tags never choose a case for scoring.
func checkApplicability(c Case, p Profile) (NAKind, bool) {
	// 1. Any requires value where supports.<value> is false
	for _, req := range c.Requires {
		if supported, exists := p.Supports[req]; !exists || !supported {
			return NAMissingRequires, false
		}
	}

	// 2. Transport not supported
	if supported, exists := p.Supports[c.Transport]; !exists || !supported {
		return NAUnsupportedTransport, false
	}

	return "", true
}
