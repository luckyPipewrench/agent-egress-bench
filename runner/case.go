package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const activeSchemaVersion = 3

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
	// Claims are reporting labels retained for backward compatibility.
	// Deprecated for applicability: use Supports plus case Requires instead.
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

	return p, nil
}

// checkApplicability determines if a case is applicable given a profile.
// Returns ("", true) if applicable, or (reason, false) if not.
// Checks are ordered: requires first, then transport. capability_tags are
// reporting labels only; applicability is driven by requires ⊆ supports.
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
