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
	names := []string{"control-evidence-dsse.schema.json", "control-evidence-requirement.schema.json", "control-evidence-run-envelope.schema.json", "control-evidence-manifest.schema.json", "control-evidence-clock-evidence.schema.json", "control-evidence-observer-evidence.schema.json"}
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
	schemaRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "control-evidence-trust-policy.schema.json"))
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
