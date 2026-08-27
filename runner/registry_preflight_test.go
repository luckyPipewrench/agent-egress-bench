package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	capabilityregistry "github.com/luckyPipewrench/agent-egress-bench/capability-registry"
)

type readerContract struct {
	Consumer         string `json:"consumer"`
	Role             string `json:"role"`
	Path             string `json:"path"`
	AcceptedVersions []int  `json:"accepted_versions"`
}

func toolProfileReaderContract(t *testing.T, consumer string) readerContract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "contracts", "artifacts.json"))
	if err != nil {
		t.Fatalf("read compatibility manifest: %v", err)
	}
	var manifest struct {
		ArtifactFamilies []struct {
			Family          string           `json:"family"`
			ReaderContracts []readerContract `json:"reader_contracts"`
		} `json:"artifact_families"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode compatibility manifest: %v", err)
	}
	for _, family := range manifest.ArtifactFamilies {
		if family.Family != "tool_profile" {
			continue
		}
		for _, contract := range family.ReaderContracts {
			if contract.Consumer == consumer {
				return contract
			}
		}
	}
	t.Fatalf("compatibility manifest has no tool_profile reader contract for %q", consumer)
	return readerContract{}
}

var testRegistryReference = capabilityregistry.Reference{
	ID:       "aeb.core-capabilities",
	Format:   1,
	Revision: 1,
	SHA256:   "f5ae9fa9cbb79e8539d50f0284e584eb6ea834232e801d3e1c269411a9527e9b",
}

func v4TestProfile() Profile {
	return Profile{
		SchemaVersion:      activeToolProfileSchemaVersion,
		Tool:               "test-tool",
		ToolVersion:        "1.0.0",
		RunnerVersion:      "v1",
		Claims:             []string{"url_dlp"},
		CapabilityRegistry: testRegistryReference,
	}
}

func testProfile() Profile { return v4TestProfile() }

func validV4Profile(t *testing.T) map[string]any {
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

func v4TestCase() Case {
	return Case{
		SchemaVersion:   activeCaseSchemaVersion,
		ID:              "registry-test-001",
		Category:        "url",
		InputType:       "url",
		Transport:       "fetch_proxy",
		ExpectedVerdict: "block",
		CapabilityTags:  []string{"url_dlp"},
		Payload:         map[string]interface{}{"method": "GET", "url": "https://example.test/"},
	}
}

func TestLoadProfileRejectsRetiredScopeDeclaration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	data := `{"schema_version":4,"tool":"test","tool_version":"1","runner_version":"v1","claims":[],"supports":{},"capability_registry":{"id":"aeb.core-capabilities","format":1,"revision":1,"sha256":"f5ae9fa9cbb79e8539d50f0284e584eb6ea834232e801d3e1c269411a9527e9b"}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("loadProfile error = %v, want strict rejection of retired supports", err)
	}
}

func TestLoadProfileRefusesNMinusOneProfileWithMachineReadableVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile-v3.json")
	data := `{"schema_version":3,"tool":"test","tool_version":"1","runner_version":"v1","claims":[],"supports":{}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadProfile(path)
	if err == nil || err.Error() != "incompatible_schema_version: family=tool_profile accepted=[4] got=3" {
		t.Fatalf("loadProfile error = %v, want machine-readable v3 incompatibility", err)
	}
	contract := toolProfileReaderContract(t, "runner_scoring")
	if contract.Role != "scoring" || contract.Path != "runner/case.go" || !reflect.DeepEqual(contract.AcceptedVersions, []int{activeToolProfileSchemaVersion}) {
		t.Fatalf("runner reader contract = %#v, want scoring runner/case.go v%d", contract, activeToolProfileSchemaVersion)
	}
}

func TestLoadProfileRejectsMissingRegistry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	data := `{"schema_version":4,"tool":"test","tool_version":"1","runner_version":"v1","claims":[]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadProfile(path); err == nil || !strings.Contains(err.Error(), "capability_registry") {
		t.Fatalf("loadProfile error = %v, want missing registry rejection", err)
	}
}

func TestShippedToolProfilesSatisfyV4Contract(t *testing.T) {
	for _, path := range []string{
		filepath.Join("..", "examples", "pipelock", "tool-profile.json"),
		filepath.Join("..", "examples", "runner-template", "tool-profile-template.json"),
	} {
		if _, err := loadProfile(path); err != nil {
			t.Errorf("%s violates the v4 tool-profile contract: %v", path, err)
		}
	}
}

func TestPreflightRegistryRejectsUnknownIDs(t *testing.T) {
	profile := v4TestProfile()
	profile.Claims = []string{"invented_label"}
	if _, err := preflightRegistry(profile, []Case{v4TestCase()}, filepath.Join("..", "cases")); err == nil || !strings.Contains(err.Error(), "invented_label") {
		t.Fatalf("unknown claim error = %v", err)
	}

	profile = v4TestProfile()
	caseWithUnknownTag := v4TestCase()
	caseWithUnknownTag.CapabilityTags = []string{"invented_label"}
	if _, err := preflightRegistry(profile, []Case{caseWithUnknownTag}, filepath.Join("..", "cases")); err == nil || !strings.Contains(err.Error(), "invented_label") {
		t.Fatalf("unknown tag error = %v", err)
	}
}

func TestRevisionOneProfileRejectsCurrentCorpusCapabilities(t *testing.T) {
	cases, err := loadCases(filepath.Join("..", "cases"))
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	profile := v4TestProfile()
	_, err = preflightRegistry(profile, cases, filepath.Join("..", "cases"))
	if err == nil || !strings.Contains(err.Error(), "mcp_tool_result_dlp_scanning") {
		t.Fatalf("revision 1 corpus preflight error = %v, want new capability rejection", err)
	}
}

func TestPreflightRegistryRejectsDigestAndFormatMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*capabilityregistry.Reference){
		"digest": func(ref *capabilityregistry.Reference) { ref.SHA256 = strings.Repeat("0", 64) },
		"format": func(ref *capabilityregistry.Reference) { ref.Format = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			profile := v4TestProfile()
			mutate(&profile.CapabilityRegistry)
			if _, err := preflightRegistry(profile, []Case{v4TestCase()}, filepath.Join("..", "cases")); err == nil {
				t.Fatal("preflight accepted a mismatched registry reference")
			}
		})
	}
}

func TestRegistryFailurePrecedesAnyScoreOutput(t *testing.T) {
	dir := t.TempDir()
	casesDir := filepath.Join(dir, "cases")
	if err := os.Mkdir(casesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	caseJSON := `{"schema_version":4,"id":"registry-test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.test/"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"original"}`
	if err := os.WriteFile(filepath.Join(casesDir, "registry-test-001.json"), []byte(caseJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	profileJSON := `{"schema_version":4,"tool":"test","tool_version":"1","runner_version":"v1","claims":["invented_label"],"capability_registry":{"id":"aeb.core-capabilities","format":1,"revision":1,"sha256":"f5ae9fa9cbb79e8539d50f0284e584eb6ea834232e801d3e1c269411a9527e9b"}}`
	if err := os.WriteFile(profilePath, []byte(profileJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
	outputPath := filepath.Join(dir, "summary.json")
	err := run(casesDir, profilePath, outputPath, time.Second, "dryrun", "", "", "", "", false, "", "", "", false)
	if err == nil || !strings.Contains(err.Error(), "capability registry preflight") {
		t.Fatalf("run error = %v, want registry preflight failure", err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("summary exists after registry failure: stat error = %v", statErr)
	}
}

func TestRegistryReferenceFailuresPrecedeAnyScoreOutput(t *testing.T) {
	for name, mutate := range map[string]func(t *testing.T, profile map[string]any){
		"missing_snapshot": func(t *testing.T, profile map[string]any) {
			t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join(t.TempDir(), "missing"))
		},
		"digest_mismatch": func(t *testing.T, profile map[string]any) {
			profile["capability_registry"].(map[string]any)["sha256"] = strings.Repeat("0", 64)
			t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
		},
		"unsupported_format": func(t *testing.T, profile map[string]any) {
			profile["capability_registry"].(map[string]any)["format"] = 2
			t.Setenv("AEB_CAPABILITY_REGISTRY", filepath.Join("..", "capability-registry"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			casesDir := filepath.Join(dir, "cases")
			if err := os.Mkdir(casesDir, 0o700); err != nil {
				t.Fatal(err)
			}
			caseJSON := `{"schema_version":4,"id":"registry-test-001","category":"url","title":"T","description":"D","input_type":"url","transport":"fetch_proxy","payload":{"method":"GET","url":"https://example.test/"},"expected_verdict":"block","severity":"high","capability_tags":["url_dlp"],"requires":[],"false_positive_risk":"low","why_expected":"test","notes":"","source":"original"}`
			if err := os.WriteFile(filepath.Join(casesDir, "registry-test-001.json"), []byte(caseJSON), 0o600); err != nil {
				t.Fatal(err)
			}
			profile := validV4Profile(t)
			mutate(t, profile)
			profileBytes, err := json.Marshal(profile)
			if err != nil {
				t.Fatal(err)
			}
			profilePath := filepath.Join(dir, "profile.json")
			if err := os.WriteFile(profilePath, profileBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			outputPath := filepath.Join(dir, "summary.json")
			if err := run(casesDir, profilePath, outputPath, time.Second, "dryrun", "", "", "", "", false, "", "", "", false); err == nil {
				t.Fatal("run unexpectedly emitted a score")
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("summary exists after %s registry failure: %v", name, err)
			}
		})
	}
}
