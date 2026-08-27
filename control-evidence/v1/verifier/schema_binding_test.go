package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSchemaBindingsFailClosedWhenRequiredBindingIsMissing(t *testing.T) {
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	schemas.requirement = nil
	err = validateSchemaBindings(schemas)
	if err == nil || !strings.Contains(err.Error(), "requirement") {
		t.Fatalf("validateSchemaBindings() error = %v, want missing requirement binding", err)
	}
}

func TestV1VerifierRetainsToolProfileV1AndV4Readers(t *testing.T) {
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	profiles := map[int]string{
		1: filepath.Join("..", "..", "v0", "conformance", "golden", "g01-vendor-time", "tool-profile.json"),
		4: filepath.Join("..", "conformance", "golden", "g01-valid-registry-bound", "tool-profile.json"),
	}
	for version, path := range profiles {
		profile, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read v%d retained tool profile: %v", version, err)
		}
		if !validToolProfileSchema(profile, schemas) {
			t.Fatalf("v%d retained tool profile was rejected", version)
		}
	}
	retainedProfiles, err := filepath.Glob(filepath.Join("..", "conformance", "*", "*", "tool-profile.json"))
	if err != nil {
		t.Fatalf("find retained v1 tool profiles: %v", err)
	}
	for _, path := range retainedProfiles {
		profile, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read retained v1 tool profile %s: %v", path, err)
		}
		var header struct {
			SchemaVersion int `json:"schema_version"`
		}
		if err := json.Unmarshal(profile, &header); err != nil {
			t.Fatalf("decode retained v1 tool profile %s: %v", path, err)
		}
		if header.SchemaVersion != 4 {
			t.Fatalf("retained v1 tool profile %s has schema v%d, want v4; add an explicit reader before publishing another version", path, header.SchemaVersion)
		}
	}
	contract := toolProfileReaderContract(t, "control_evidence_v1")
	if contract.Role != "retained_evidence" || contract.Path != "control-evidence/v1/verifier" || !reflect.DeepEqual(contract.AcceptedVersions, toolProfileSchemaVersions(schemas)) {
		t.Fatalf("v1 reader contract = %#v, want retained_evidence control-evidence/v1/verifier versions %v", contract, toolProfileSchemaVersions(schemas))
	}
}

type readerContract struct {
	Consumer         string `json:"consumer"`
	Role             string `json:"role"`
	Path             string `json:"path"`
	AcceptedVersions []int  `json:"accepted_versions"`
}

func toolProfileReaderContract(t *testing.T, consumer string) readerContract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "artifacts.json"))
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

func toolProfileSchemaVersions(schemas *schemaSet) []int {
	if len(schemas.toolProfiles) != 2 || schemas.toolProfiles[1] == nil || schemas.toolProfiles[4] == nil {
		return nil
	}
	return []int{1, 4}
}
