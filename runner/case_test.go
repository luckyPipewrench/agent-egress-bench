package main

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestLoadCases(t *testing.T) {
	dir := t.TempDir()

	caseJSON := `{
		"schema_version": 3,
		"id": "test-case-001",
		"category": "url",
		"title": "Test case",
		"description": "A test case",
		"input_type": "url",
		"transport": "fetch_proxy",
		"payload": {"method": "GET", "url": "https://example.com"},
		"expected_verdict": "block",
		"severity": "high",
		"capability_tags": ["url_dlp"],
		"requires": [],
		"false_positive_risk": "low",
		"why_expected": "test",
		"notes": "",
		"source": "test"
	}`

	if err := os.WriteFile(filepath.Join(dir, "test-case-001.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected 1 case, got %d", len(cases))
	}
	if cases[0].ID != "test-case-001" {
		t.Errorf("expected ID test-case-001, got %s", cases[0].ID)
	}
	if cases[0].ExpectedVerdict != "block" {
		t.Errorf("expected verdict block, got %s", cases[0].ExpectedVerdict)
	}
}

func TestScorerRejectsV2CaseButHistoricalReaderPreservesIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "historical-v2.json")
	v2 := `{"schema_version":2,"id":"historical-v2","category":"url","title":"Historical","description":"Frozen v2 record","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"historical","notes":"","source":"original"}`
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadCases(dir); err == nil {
		t.Fatal("scorer accepted a v2 case instead of rejecting the active/historical version mix")
	}
	historical, err := readHistoricalCase(path)
	if err != nil {
		t.Fatalf("readHistoricalCase: %v", err)
	}
	if historical.SchemaVersion != 2 || historical.ID != "historical-v2" {
		t.Fatalf("historical record changed while reading: %#v", historical)
	}

	v3Path := filepath.Join(dir, "active-v3.json")
	if err := os.WriteFile(v3Path, []byte(strings.Replace(v2, `"schema_version":2`, `"schema_version":3`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readHistoricalCase(v3Path); err == nil {
		t.Fatal("historical reader accepted an active v3 case")
	}
}

func TestLoadCasesEmpty(t *testing.T) {
	dir := t.TempDir()
	_, err := loadCases(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
}

func TestLoadProfile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	data, err := os.ReadFile(filepath.Join("..", "examples", "runner-template", "tool-profile-template.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	p, err := loadProfile(path)
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	if p.Tool != "YOUR_TOOL_NAME" {
		t.Errorf("expected tool YOUR_TOOL_NAME, got %s", p.Tool)
	}
	if len(p.Claims) != 0 {
		t.Errorf("unexpected claims: %v", p.Claims)
	}
}

func TestLoadProfileRejectsMissingRunField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	profileJSON := `{"schema_version":3,"tool":"test-tool","tool_version":"1.0.0","claims":[],"supports":{}}`
	if err := os.WriteFile(path, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "missing required field runner_version") {
		t.Fatalf("loadProfile error = %v, want missing runner_version", err)
	}
}

func validV3Profile(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "examples", "runner-template", "tool-profile-template.json"))
	if err != nil {
		t.Fatal(err)
	}
	var profile map[string]any
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func writeV3Profile(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	profile := validV3Profile(t)
	mutate(profile["supports"].(map[string]any))
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// These replace permissive tests added on this branch. An omitted capability
// does not mean unsupported in v3: it is an invalid scored profile because a
// typo otherwise silently removes cases from execution.
func TestLoadProfileRejectsMissingSupportsKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	writeV3Profile(t, path, func(supports map[string]any) { delete(supports, "mcp_http") })
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), `missing required supports key: "mcp_http"`) {
		t.Fatalf("loadProfile error = %v, want missing mcp_http", err)
	}
}

func TestLoadProfileRejectsUnknownSupportsKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	writeV3Profile(t, path, func(supports map[string]any) { supports["mcp_htttp"] = true })
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), `unknown supports key: "mcp_htttp"`) {
		t.Fatalf("loadProfile error = %v, want unknown mcp_htttp", err)
	}
}

func TestLoadProfileRejectsEmptySupports(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	writeV3Profile(t, path, func(supports map[string]any) {
		for key := range supports {
			delete(supports, key)
		}
	})
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "missing required supports key") {
		t.Fatalf("loadProfile error = %v, want missing required supports key", err)
	}
}

type supportsSchema struct {
	Properties map[string]json.RawMessage `json:"properties"`
	Required   []string                   `json:"required"`
	// Pointer, so an ABSENT keyword is distinguishable from an explicit false.
	// A plain bool decodes an absent keyword as false, which would read as
	// "unknown keys are forbidden" while JSON Schema treats the absent case as
	// permissive. Deleting the line would then silently reopen the contract
	// with this guard still passing.
	AdditionalProperties *bool `json:"additionalProperties"`
}

func supportsVocabularyFromSchema(t *testing.T, path string) (map[string]struct{}, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	var supports supportsSchema
	if err := json.Unmarshal(schema.Properties["supports"], &supports); err != nil {
		t.Fatal(err)
	}
	if supports.AdditionalProperties == nil {
		t.Fatalf("%s omits additionalProperties on supports; JSON Schema treats that as permissive, so it must be stated explicitly", path)
	}
	if *supports.AdditionalProperties {
		t.Fatalf("%s permits unknown supports keys", path)
	}
	vocabulary := make(map[string]struct{}, len(supports.Properties))
	for key := range supports.Properties {
		vocabulary[key] = struct{}{}
	}
	assertSameVocabulary(t, path+" properties", vocabulary, path+" required", stringsToSet(supports.Required))
	return vocabulary, data
}

func supportsVocabularyFromValidator(t *testing.T) map[string]struct{} {
	t.Helper()
	return vocabularyFromValidator(t, "validSupportsKeys")
}

// vocabularyFromValidator reads a map[string]bool vocabulary out of the
// validator's source by name. The runner and the validator are separate Go
// modules, so a vocabulary they both enforce has to be duplicated; reading the
// declaration directly is what keeps the duplicate honest.
func vocabularyFromValidator(t *testing.T, declName string) map[string]struct{} {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "validate", "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok || len(value.Names) != 1 || value.Names[0].Name != declName || len(value.Values) != 1 {
				continue
			}
			literal, ok := value.Values[0].(*ast.CompositeLit)
			if !ok {
				t.Fatalf("validate %s is not a composite literal", declName)
			}
			vocabulary := make(map[string]struct{}, len(literal.Elts))
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					t.Fatalf("validate %s contains a non-keyed entry", declName)
				}
				key, ok := pair.Key.(*ast.BasicLit)
				if !ok || key.Kind != token.STRING {
					t.Fatalf("validate %s contains a non-string key", declName)
				}
				name, err := strconv.Unquote(key.Value)
				if err != nil {
					t.Fatal(err)
				}
				vocabulary[name] = struct{}{}
			}
			return vocabulary
		}
	}
	t.Fatalf("validate %s declaration not found", declName)
	return nil
}

// allRunnerSupportsKeys builds a profile's supports map with every required key
// present and true, so a test can vary claims without tripping the separate
// supports completeness check.
func allRunnerSupportsKeys() map[string]bool {
	supports := make(map[string]bool, len(requiredSupportsKeys))
	for key := range requiredSupportsKeys {
		supports[key] = true
	}
	return supports
}

func stringsToSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func assertSameVocabulary(t *testing.T, leftName string, left map[string]struct{}, rightName string, right map[string]struct{}) {
	t.Helper()
	if len(left) != len(right) {
		t.Fatalf("%s has %d keys; %s has %d", leftName, len(left), rightName, len(right))
	}
	for key := range left {
		if _, found := right[key]; !found {
			t.Fatalf("%s contains %q but %s does not", leftName, key, rightName)
		}
	}
}

// A claim is a published assertion: it reaches summary.json's tool_support and
// from there the buyer-facing report. The Go validator has always rejected an
// unrecognised claim, but the runner never calls that validator, so a profile
// could invent one and the run would publish it verbatim as though the corpus
// had accepted it. The runner's own preflight is the only gate on the path that
// actually produces published output.
func TestValidateProfileForRunRejectsUnknownClaim(t *testing.T) {
	p := Profile{
		Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
		Claims:   []string{"url_dlp", "blocks_every_known_attack"},
		Supports: allRunnerSupportsKeys(),
	}
	err := validateProfileForRun(p)
	if err == nil {
		t.Fatal("validateProfileForRun accepted an unrecognised claim, so it would be published as a claim the corpus never checked")
	}
	if !strings.Contains(err.Error(), "blocks_every_known_attack") {
		t.Fatalf("error = %v, want it to name the offending claim", err)
	}
}

// An empty claims list is a tool declaring nothing, which is legitimate and must
// keep working. Rejecting unknown values must not become rejecting absence.
func TestValidateProfileForRunAcceptsKnownAndEmptyClaims(t *testing.T) {
	for name, claims := range map[string][]string{
		"empty": {},
		"known": {"url_dlp", "ssrf", "denial_of_wallet"},
	} {
		t.Run(name, func(t *testing.T) {
			p := Profile{
				Tool: "test", ToolVersion: "1.0", RunnerVersion: "v1",
				Claims:   claims,
				Supports: allRunnerSupportsKeys(),
			}
			if err := validateProfileForRun(p); err != nil {
				t.Fatalf("validateProfileForRun(%v) = %v, want accepted", claims, err)
			}
		})
	}
}

// The claim vocabulary is duplicated because runner/ and validate/ are separate
// Go modules and cannot share a package. Duplication without a binding check is
// how the supports contract drifted into three disagreeing copies, so this test
// binds the two the same way TestToolProfileSupportsVocabularyParity does.
func TestToolProfileClaimVocabularyParity(t *testing.T) {
	assertSameVocabulary(t, "runner claim vocabulary", knownClaims,
		"validator vocabulary", vocabularyFromValidator(t, "validCapabilityTags"))
}

// TestToolProfileSupportsVocabularyParity keeps all five v3 contract copies in
// lockstep: the runner's preflight, the Go validator, schema properties and
// required list, plus the embedded verifier mirror. The branch used to test a
// permissive runner and schema against a strict validator; this test makes that
// disagreement fail before a profile can hide cases by typo or omission.
func TestToolProfileSupportsVocabularyParity(t *testing.T) {
	rootPath := filepath.Join("..", "schemas", "tool-profile.schema.json")
	embeddedPath := filepath.Join("..", "control-evidence", "v0", "verifier", "schemas", "tool-profile.schema.json")
	rootVocabulary, rootBytes := supportsVocabularyFromSchema(t, rootPath)
	embeddedVocabulary, embeddedBytes := supportsVocabularyFromSchema(t, embeddedPath)
	if !bytes.Equal(rootBytes, embeddedBytes) {
		t.Fatal("tool-profile schema and embedded verifier mirror differ")
	}
	assertSameVocabulary(t, "runner required set", requiredSupportsKeys, "validator vocabulary", supportsVocabularyFromValidator(t))
	assertSameVocabulary(t, "runner required set", requiredSupportsKeys, "schema properties", rootVocabulary)
	assertSameVocabulary(t, "runner required set", requiredSupportsKeys, "embedded schema properties", embeddedVocabulary)
}

// Every active tool-profile artifact must pass runner preflight. The profiles/
// receipt records use their own historical reader and are covered by the
// committed-profile validation tests in receipt_profile_test.go.
func TestShippedToolProfilesSatisfyV3Contract(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "examples", "pipelock", "tool-profile.json"),
		filepath.Join("..", "examples", "runner-template", "tool-profile-template.json"),
	} {
		if _, err := loadProfile(path); err != nil {
			t.Errorf("%s violates the v3 tool-profile contract: %v", path, err)
		}
	}
}

func TestLoadProfileRejectsPreV3Artifact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":2,"tool":"old-tool","tool_version":"1.0.0","runner_version":"v1","claims":[],"supports":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil {
		t.Fatal("scorer accepted a pre-v3 profile")
	}
}

func TestLoadCasesInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadCases(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadCasesNonexistentDir(t *testing.T) {
	_, err := loadCases("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestLoadCasesSkipsNonJSON(t *testing.T) {
	dir := t.TempDir()
	// Write a valid case and a non-JSON file.
	caseJSON := `{"schema_version": 3,"id":"test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.com"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"test"}`
	if err := os.WriteFile(filepath.Join(dir, "test-001.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a case"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := loadCases(dir)
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	if len(cases) != 1 {
		t.Fatalf("expected 1 case (skip .txt), got %d", len(cases))
	}
}

func TestLoadProfileNotFound(t *testing.T) {
	_, err := loadProfile("/nonexistent/profile.json")
	if err == nil {
		t.Fatal("expected error for missing profile")
	}
}

func TestLoadProfileInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProfile(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProfileRejectsUnknownReceiptEvidenceField(t *testing.T) {
	dir := t.TempDir()
	profileJSON := `{
		"schema_version": 3,
		"tool": "test-tool",
		"tool_version": "1.0.0",
		"runner_version": "v1",
		"claims": [],
		"supports": {},
		"receipt_evidence": {
			"evidence_dir": "/tmp/evidence",
			"file_glob": "*.jsonl",
			"jsonl_record_type": "action_receipt",
			"detail_json_pointer": "/detail",
			"detail_encoding": "object_or_json_string",
			"record_identifier_json_pointer": "/action_record/target",
			"case_identifier_json_pointer": "/payload/url",
			"verify_command": ["receipt-verify", "{evidence_file}"],
			"verify_timeout_seconds": 10,
			"valid_exit_codes": [0],
			"unexpected": true
		}
	}`
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProfile(path)
	if err == nil {
		t.Fatal("expected error for unknown receipt_evidence field")
	}
}

func TestCheckApplicability(t *testing.T) {
	profile := Profile{
		Claims: []string{"url_dlp", "benign"},
		Supports: map[string]bool{
			"fetch_proxy":               true,
			"http_proxy":                true,
			"mcp_stdio":                 false,
			"tls_interception":          true,
			"request_body_dlp_scanning": false,
			"dns_rebinding_fixture":     false,
		},
	}

	tests := []struct {
		name      string
		c         Case
		wantNA    NAKind
		wantApply bool
	}{
		{
			name: "fully applicable",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"tls_interception"},
				Transport:      "fetch_proxy",
			},
			wantApply: true,
		},
		{
			name: "capability tags do not affect applicability",
			c: Case{
				CapabilityTags: []string{"mcp_input_scan"},
				Requires:       []string{},
				Transport:      "fetch_proxy",
			},
			wantApply: true,
		},
		{
			name: "missing requires",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"request_body_dlp_scanning"},
				Transport:      "fetch_proxy",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
		{
			name: "unsupported transport",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAUnsupportedTransport,
			wantApply: false,
		},
		{
			name: "requires checked before transport",
			c: Case{
				CapabilityTags: []string{"mcp_input_scan"},
				Requires:       []string{"request_body_dlp_scanning"},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
		{
			name: "requires checked before transport with claimed tag",
			c: Case{
				CapabilityTags: []string{"url_dlp"},
				Requires:       []string{"dns_rebinding_fixture"},
				Transport:      "mcp_stdio",
			},
			wantNA:    NAMissingRequires,
			wantApply: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, applicable := checkApplicability(tt.c, profile)
			if applicable != tt.wantApply {
				t.Errorf("applicable = %v, want %v", applicable, tt.wantApply)
			}
			if !applicable && reason != tt.wantNA {
				t.Errorf("reason = %q, want %q", reason, tt.wantNA)
			}
		})
	}
}

// The denial-of-wallet cases used to gate on budget_enforcement, an enforcement
// claim rather than an observation surface. Because the Pipelock profile
// declines that claim, all three -- including the benign control that measures
// over-blocking -- were rendered not_applicable, so a tool could opt out of the
// family by not claiming it. They now gate on the chain surface their nine
// malicious siblings already use, and the benign control gates on nothing.
//
// This test previously asserted the opposite (that the three were
// not_applicable), which locked the escape hatch in place. It is inverted
// deliberately: a test that encodes the dodge is a liability, not coverage.
func TestPipelockDenialOfWalletCasesAreApplicable(t *testing.T) {
	profile, err := loadProfile("../examples/pipelock/tool-profile.json")
	if err != nil {
		t.Fatalf("loadProfile: %v", err)
	}
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}

	wantIDs := map[string]bool{
		"mcp-chain-dow-budget-exceeded-010":             true,
		"mcp-chain-dow-under-budget-011":                true,
		"mcp-chain-dow-interleaved-budget-exceeded-012": true,
	}
	seen := make(map[string]bool)
	for _, c := range cases {
		// Identify the family by capability tag, not by requires: the whole
		// point of the fix is that requires no longer names the feature.
		if !slices.Contains(c.CapabilityTags, "denial_of_wallet") {
			continue
		}
		seen[c.ID] = true

		if _, applicable := checkApplicability(c, profile); !applicable {
			t.Errorf("case %s is not applicable to the Pipelock profile; a denial-of-wallet case must not be skippable by declining budget_enforcement", c.ID)
		}
		if slices.Contains(c.Requires, "budget_enforcement") {
			t.Errorf("case %s gates on budget_enforcement; applicability must gate on the observation surface, not the enforcement claim under test", c.ID)
		}
	}

	if len(seen) != len(wantIDs) {
		t.Fatalf("denial_of_wallet case IDs = %v, want %v", seen, wantIDs)
	}
	for id := range wantIDs {
		if !seen[id] {
			t.Errorf("missing denial-of-wallet case %s", id)
		}
	}
}
