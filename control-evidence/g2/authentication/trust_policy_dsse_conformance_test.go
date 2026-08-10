package authentication

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// TestTrustPolicyDSSESchemaConformance keeps the public wrapper schema and
// verifyPolicy aligned. The signed fixture is built by the same test helper
// used for a complete authenticated-at(T) assessment, so the positive vector
// exercises the real JCS, DSSE PAE, and Ed25519 verification path.
//
// Go-only checks are named separately. JSON Schema can describe the wrapper
// shape, but cannot prove canonical bytes, bootstrap-key binding, or a PAE
// signature.
func TestTrustPolicyDSSESchemaConformance(t *testing.T) {
	schema := compileTrustPolicyDSSESchema(t)
	fixture := newFixture(t)
	raw, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var ctx authContext
	ctxRaw, err := os.ReadFile(fixture.contextPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(ctxRaw, &ctx); err != nil {
		t.Fatal(err)
	}

	assertTrustPolicySchemaAndGoAccept(t, schema, raw, ctx)

	var baseline map[string]any
	if err := json.Unmarshal(raw, &baseline); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"payloadType", "payload", "signatures"} {
		t.Run("required_"+required, func(t *testing.T) {
			mutated := cloneJSONMap(t, baseline)
			delete(mutated, required)
			assertTrustPolicySchemaAndGoReject(t, schema, marshalJSON(t, mutated), ctx)
		})
	}

	for name, mutate := range map[string]func(map[string]any){
		"payload_type_const": func(v map[string]any) {
			v["payloadType"] = "application/not-the-trust-policy"
		},
		"payload_base64_pattern": func(v map[string]any) {
			v["payload"] = "$"
		},
		"signature_keyid_pattern": func(v map[string]any) {
			v["signatures"].([]any)[0].(map[string]any)["keyid"] = "bad"
		},
		"signature_base64_pattern": func(v map[string]any) {
			v["signatures"].([]any)[0].(map[string]any)["sig"] = "$"
		},
		"unknown_property": func(v map[string]any) {
			v["unexpected"] = true
		},
		"zero_signatures": func(v map[string]any) {
			v["signatures"] = []any{}
		},
		"two_signatures": func(v map[string]any) {
			sig := v["signatures"].([]any)[0]
			v["signatures"] = []any{sig, sig}
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := cloneJSONMap(t, baseline)
			mutate(mutated)
			assertTrustPolicySchemaAndGoReject(t, schema, marshalJSON(t, mutated), ctx)
		})
	}

	t.Run("go_only_noncanonical_wrapper", func(t *testing.T) {
		noncanonical := append(append([]byte(nil), raw...), '\n')
		assertTrustPolicySchemaAccepts(t, schema, noncanonical)
		if _, reason := verifyPolicy(noncanonical, ctx); reason != "policy_wrapper_not_jcs" {
			t.Fatalf("verifyPolicy(noncanonical) reason = %q, want policy_wrapper_not_jcs", reason)
		}
	})

	t.Run("go_only_ed25519_signature", func(t *testing.T) {
		mutated := cloneJSONMap(t, baseline)
		mutated["signatures"].([]any)[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 64))
		canonical, err := canonicalize(marshalJSON(t, mutated))
		if err != nil {
			t.Fatal(err)
		}
		assertTrustPolicySchemaAccepts(t, schema, canonical)
		if _, reason := verifyPolicy(canonical, ctx); reason != "policy_signature_invalid" {
			t.Fatalf("verifyPolicy(mutated signature) reason = %q, want policy_signature_invalid", reason)
		}
	})
}

func compileTrustPolicyDSSESchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "schemas", "control-evidence-trust-policy-dsse-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("trust-policy-dsse.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("trust-policy-dsse.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertTrustPolicySchemaAndGoAccept(t *testing.T, schema *jsonschema.Schema, raw []byte, ctx authContext) {
	t.Helper()
	assertTrustPolicySchemaAccepts(t, schema, raw)
	if _, reason := verifyPolicy(raw, ctx); reason != "" {
		t.Fatalf("verifyPolicy rejected schema-valid policy wrapper: %s", reason)
	}
}

func assertTrustPolicySchemaAndGoReject(t *testing.T, schema *jsonschema.Schema, raw []byte, ctx authContext) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err == nil {
		t.Fatalf("schema accepted mutation: %s", raw)
	}
	if _, reason := verifyPolicy(raw, ctx); reason == "" {
		t.Fatalf("verifyPolicy accepted schema-rejected mutation: %s", raw)
	}
}

func assertTrustPolicySchemaAccepts(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected vector: %v\n%s", err, raw)
	}
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var cloned map[string]any
	if err := json.Unmarshal(marshalJSON(t, value), &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
