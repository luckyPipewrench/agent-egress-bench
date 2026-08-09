package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func provenanceTestDirs(t *testing.T) (dir, profilePath string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath = filepath.Join(dir, "profile.json")
	if err := os.WriteFile(profilePath, []byte(`{"tool":"test"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, profilePath
}

func buildProvenanceSummary(t *testing.T, dir, profilePath string, prov RunProvenance) GauntletSummary {
	t.Helper()
	summary, err := buildSummary(
		testProfile(),
		[]Case{{ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		nil,
		nil,
		nil,
		dir,
		"",
		map[string]Case{"a": {ID: "a", Category: "url", ExpectedVerdict: "allow"}},
		profilePath,
		prov,
	)
	if err != nil {
		t.Fatalf("buildSummary: %v", err)
	}
	return summary
}

// TestBuildSummaryRecordsDeclaredProvenance covers the facts docs/RESULTS-USE.md
// requires beside a public result. Before these fields existed the summary could
// not carry three of them, so an operator following the policy had nowhere to put
// the repository and commit, the adapter's author, or the configuration the score
// actually describes.
func TestBuildSummaryRecordsDeclaredProvenance(t *testing.T) {
	dir, profilePath := provenanceTestDirs(t)

	prov := RunProvenance{
		MethodRepository: "example/agent-egress-bench",
		MethodCommit:     "cccccccccccccccccccccccccccccccccccccccc",
		AdapterID:        "proxy",
		AdapterOwner:     "Example Lab",
		TargetConfigRef:  "/etc/example/config.yaml",
		TargetConfigSHA:  "d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0",
	}
	summary := buildProvenanceSummary(t, dir, profilePath, prov)

	for _, tc := range []struct{ name, got, want string }{
		{"method_repository", summary.MethodRepository, prov.MethodRepository},
		{"method_commit", summary.MethodCommit, prov.MethodCommit},
		{"adapter_id", summary.AdapterID, prov.AdapterID},
		{"adapter_owner", summary.AdapterOwner, prov.AdapterOwner},
		{"target_config_ref", summary.TargetConfigRef, prov.TargetConfigRef},
		{"target_config_sha256", summary.TargetConfigSHA256, prov.TargetConfigSHA},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// An undeclared fact is omitted from the JSON entirely rather than serialized as
// an empty string, so a reader can tell "not declared" from "declared as
// nothing" and the buyer report can say which.
func TestBuildSummaryOmitsUndeclaredProvenance(t *testing.T) {
	dir, profilePath := provenanceTestDirs(t)
	summary := buildProvenanceSummary(t, dir, profilePath, RunProvenance{})

	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("marshalling summary: %v", err)
	}
	for _, field := range []string{
		"method_repository", "method_commit", "adapter_id",
		"adapter_owner", "target_config_ref", "target_config_sha256",
	} {
		if strings.Contains(string(encoded), field) {
			t.Errorf("undeclared %s was serialized; it should be omitted", field)
		}
	}
}
