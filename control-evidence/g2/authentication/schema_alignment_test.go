package authentication

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestEmbeddedV0SchemaCopiesMatchCanonicalSchemas(t *testing.T) {
	names := []string{"control-evidence-dsse-v0.schema.json", "control-evidence-requirement-v0.schema.json", "control-evidence-run-envelope-v0.schema.json", "control-evidence-manifest-v0.schema.json", "control-evidence-clock-evidence-v0.schema.json", "control-evidence-observer-evidence-v0.schema.json"}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			copied, err := os.ReadFile(filepath.Join("schemas", "cee-v0", name))
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", name))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(copied, canonical) {
				t.Fatalf("copy differs from canonical %s", name)
			}
		})
	}
}

func TestTrustPolicySchemaRejectsRolePurposeMismatch(t *testing.T) {
	schemaRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "control-evidence-trust-policy-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("trust-policy.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("trust-policy.json")
	if err != nil {
		t.Fatal(err)
	}

	fixture := newFixture(t)
	fixture.policy.Revocations = []revocation{}
	baselineRaw, err := json.Marshal(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	baselineValue, err := jsonschema.UnmarshalJSON(bytes.NewReader(baselineRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(baselineValue); err != nil {
		t.Fatalf("baseline fixture must validate: %v", err)
	}
	fixture.policyKey(t, "run-envelope").Purpose = typeObserver
	raw, err := json.Marshal(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err == nil {
		t.Fatal("schema accepted a run-envelope key with observer-evidence purpose")
	}
}
