package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

const (
	activeSchemaVersion = 4
	v4SchemaVersion     = 4
)

// Case represents a single active benchmark case. CapabilityTags are
// registry-backed reporting labels. They are not scope declarations.
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

// Profile contains tool identity, reporting claims, and the exact immutable
// registry reference. It intentionally has no supports or other scored-scope
// declaration.
type Profile struct {
	SchemaVersion      int                          `json:"schema_version"`
	Tool               string                       `json:"tool"`
	ToolVersion        string                       `json:"tool_version"`
	RunnerVersion      string                       `json:"runner_version"`
	Claims             []string                     `json:"claims"`
	CapabilityRegistry capabilityregistry.Reference `json:"capability_registry"`
	ReceiptEvidence    *ReceiptEvidenceDeclaration  `json:"receipt_evidence,omitempty"`

	profileDir string
}

// ReceiptEvidenceDeclaration is declarative metadata for a tool's own
// receipt verifier. It cannot influence scoring or case selection.
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

// NAKind is retained in the summary reader for historical v3 record shape.
// Active v4 execution never creates an N/A row.
type NAKind string

var multiFileCaseCategories = map[string]bool{"mcp-drift": true}

func isMultiFileCaseDir(name string) bool { return multiFileCaseCategories[name] }

// loadCases walks a directory recursively and loads active v4 cases only.
func loadCases(dir string) ([]Case, error) {
	var cases []Case
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && isMultiFileCaseDir(info.Name()) {
			return filepath.SkipDir
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		var c Case
		if err := json.Unmarshal(data, &c); err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		if c.SchemaVersion != activeSchemaVersion {
			return fmt.Errorf("%s: schema_version must be %d for scoring, got %d", path, activeSchemaVersion, c.SchemaVersion)
		}
		// Schema v4 historically accepted warn. Active result rows are binary,
		// so a warning expectation is measured as the benign allow boundary.
		if c.ExpectedVerdict == "warn" {
			c.ExpectedVerdict = "allow"
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

// readHistoricalCase is intentionally isolated from the active scorer.
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

func loadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("reading profile: %w", err)
	}
	var p Profile
	if err := decodeStrictJSON(data, &p); err != nil {
		return Profile{}, fmt.Errorf("parsing profile: %w", err)
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
	if err := validateRegistryReference(p.CapabilityRegistry); err != nil {
		return fmt.Errorf("invalid capability_registry: %w", err)
	}
	seen := make(map[string]struct{}, len(p.Claims))
	for _, claim := range p.Claims {
		if claim == "" {
			return fmt.Errorf("claim must be non-empty")
		}
		if _, duplicate := seen[claim]; duplicate {
			return fmt.Errorf("duplicate claim: %q", claim)
		}
		seen[claim] = struct{}{}
	}
	return nil
}

func validateRegistryReference(ref capabilityregistry.Reference) error {
	if ref.ID == "" || filepath.Base(ref.ID) != ref.ID || strings.Contains(ref.ID, "..") {
		return fmt.Errorf("invalid id")
	}
	if ref.Format != capabilityregistry.SupportedFormat {
		return fmt.Errorf("unsupported format: %d", ref.Format)
	}
	if ref.Revision < 1 {
		return fmt.Errorf("invalid revision: %d", ref.Revision)
	}
	if len(ref.SHA256) != 64 || strings.ToLower(ref.SHA256) != ref.SHA256 {
		return fmt.Errorf("invalid sha256")
	}
	if _, err := hex.DecodeString(ref.SHA256); err != nil {
		return fmt.Errorf("invalid sha256")
	}
	return nil
}

// registryRootForCases finds the repository registry relative to the corpus
// or accepts an explicit test/deployment root. It never falls back to a
// mutable current snapshot.
func registryRootForCases(casesDir string) (string, error) {
	if root := os.Getenv("AEB_CAPABILITY_REGISTRY"); root != "" {
		return root, nil
	}
	abs, err := filepath.Abs(casesDir)
	if err != nil {
		return "", err
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "capability-registry")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
	}
	return "", fmt.Errorf("capability registry not found for cases directory %s", casesDir)
}

// preflightRegistry resolves the exact reference and validates every active
// claim/tag before adapter setup or result output. This is the sole registry
// interaction in the runner; it returns no scope policy.
func preflightRegistry(p Profile, cases []Case, casesDir string) (capabilityregistry.ResolvedSnapshot, error) {
	root, err := registryRootForCases(casesDir)
	if err != nil {
		return capabilityregistry.ResolvedSnapshot{}, err
	}
	resolved, err := (capabilityregistry.Resolver{Root: root}).Resolve(p.CapabilityRegistry)
	if err != nil {
		return capabilityregistry.ResolvedSnapshot{}, err
	}
	if err := resolved.ValidateActiveIDs("claim", p.Claims); err != nil {
		return capabilityregistry.ResolvedSnapshot{}, err
	}
	seenCases := make(map[string]struct{}, len(cases))
	for _, c := range cases {
		if c.ID == "" {
			return capabilityregistry.ResolvedSnapshot{}, fmt.Errorf("case has empty id")
		}
		if _, duplicate := seenCases[c.ID]; duplicate {
			return capabilityregistry.ResolvedSnapshot{}, fmt.Errorf("duplicate case ID: %q", c.ID)
		}
		seenCases[c.ID] = struct{}{}
		if err := resolved.ValidateActiveIDs("case capability_tag", c.CapabilityTags); err != nil {
			return capabilityregistry.ResolvedSnapshot{}, fmt.Errorf("case %s: %w", c.ID, err)
		}
	}
	return resolved, nil
}
