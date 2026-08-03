package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestGoldenAndEdgeArtifactsMatchSchemas(t *testing.T) {
	t.Parallel()

	schemaDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas"))
	schemas := map[string]*jsonschema.Schema{
		"dsse":         compileSchema(t, filepath.Join(schemaDir, "control-evidence-dsse.schema.json")),
		"requirement":  compileSchema(t, filepath.Join(schemaDir, "control-evidence-requirement.schema.json")),
		"envelope":     compileSchema(t, filepath.Join(schemaDir, "control-evidence-run-envelope.schema.json")),
		"manifest":     compileSchema(t, filepath.Join(schemaDir, "control-evidence-manifest.schema.json")),
		"outcomes":     compileSchema(t, filepath.Join(schemaDir, "control-evidence-outcomes.schema.json")),
		"clock":        compileSchema(t, filepath.Join(schemaDir, "control-evidence-clock-evidence.schema.json")),
		"observer":     compileSchema(t, filepath.Join(schemaDir, "control-evidence-observer-evidence.schema.json")),
		"tool-profile": compileSchema(t, filepath.Join(schemaDir, "tool-profile.schema.json")),
	}

	for _, category := range []string{"golden", "edge"} {
		entries, err := os.ReadDir(filepath.Join("..", category))
		if err != nil {
			t.Fatalf("read %s fixtures: %v", category, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			fixtureDir := filepath.Join("..", category, entry.Name())
			t.Run(category+"/"+entry.Name(), func(t *testing.T) {
				validateJSONFile(t, schemas["manifest"], filepath.Join(fixtureDir, "manifest.json"))
				validateJSONFile(t, schemas["outcomes"], filepath.Join(fixtureDir, "outcomes.json"))
				validateJSONFile(t, schemas["tool-profile"], filepath.Join(fixtureDir, "tool-profile.json"))
				validateDSSEFile(t, schemas["dsse"], schemas["requirement"], filepath.Join(fixtureDir, "requirement.dsse.json"))
				validateDSSEFile(t, schemas["dsse"], schemas["envelope"], filepath.Join(fixtureDir, "envelope.dsse.json"))

				clockFiles, globErr := filepath.Glob(filepath.Join(fixtureDir, "*clock*.json"))
				if globErr != nil {
					t.Fatalf("glob clock evidence: %v", globErr)
				}
				for _, path := range clockFiles {
					validateDSSEFile(t, schemas["dsse"], schemas["clock"], path)
				}
				observerFiles, globErr := filepath.Glob(filepath.Join(fixtureDir, "observer-*.dsse.json"))
				if globErr != nil {
					t.Fatalf("glob observer evidence: %v", globErr)
				}
				for _, path := range observerFiles {
					validateDSSEFile(t, schemas["dsse"], schemas["observer"], path)
				}
			})
		}
	}
}

func TestMaliciousFixturesHaveOnlyDeclaredSchemaFailure(t *testing.T) {
	t.Parallel()

	schemaDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas"))
	schemas := map[string]*jsonschema.Schema{
		"dsse":        compileSchema(t, filepath.Join(schemaDir, "control-evidence-dsse.schema.json")),
		"requirement": compileSchema(t, filepath.Join(schemaDir, "control-evidence-requirement.schema.json")),
		"envelope":    compileSchema(t, filepath.Join(schemaDir, "control-evidence-run-envelope.schema.json")),
		"manifest":    compileSchema(t, filepath.Join(schemaDir, "control-evidence-manifest.schema.json")),
		"outcomes":    compileSchema(t, filepath.Join(schemaDir, "control-evidence-outcomes.schema.json")),
		"clock":       compileSchema(t, filepath.Join(schemaDir, "control-evidence-clock-evidence.schema.json")),
		"observer":    compileSchema(t, filepath.Join(schemaDir, "control-evidence-observer-evidence.schema.json")),
	}
	expectedFailure := map[string]string{
		"m01-dsse-multi-signature": "envelope-wrapper",
		"m03-row-omission":         "outcomes",
		"m05-unknown-scoring-fact": "outcomes",
		"m06-one-sided-health":     "outcomes",
		"m12-receipt-only-clock":   "clock-payload",
	}

	entries, err := os.ReadDir(filepath.Join("..", "malicious"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		id := entry.Name()
		t.Run(id, func(t *testing.T) {
			dir := filepath.Join("..", "malicious", id)
			failures := []string{}
			if schemaValidationError(t, schemas["manifest"], filepath.Join(dir, "manifest.json")) != nil {
				failures = append(failures, "manifest")
			}
			if schemaValidationError(t, schemas["outcomes"], filepath.Join(dir, "outcomes.json")) != nil {
				failures = append(failures, "outcomes")
			}
			for _, item := range []struct {
				name, payloadSchema string
			}{
				{"requirement.dsse.json", "requirement"},
				{"envelope.dsse.json", "envelope"},
			} {
				wrapperErr, payloadErr := dsseSchemaErrors(t, schemas["dsse"], schemas[item.payloadSchema], filepath.Join(dir, item.name))
				prefix := strings.TrimSuffix(item.name, ".dsse.json")
				if wrapperErr != nil {
					failures = append(failures, prefix+"-wrapper")
				}
				if payloadErr != nil {
					failures = append(failures, prefix+"-payload")
				}
			}
			for _, glob := range []struct {
				pattern, payloadSchema, label string
			}{
				{"*clock*.dsse.json", "clock", "clock"},
				{"observer-*.dsse.json", "observer", "observer"},
			} {
				paths, globErr := filepath.Glob(filepath.Join(dir, glob.pattern))
				if globErr != nil {
					t.Fatal(globErr)
				}
				for _, path := range paths {
					wrapperErr, payloadErr := dsseSchemaErrors(t, schemas["dsse"], schemas[glob.payloadSchema], path)
					if wrapperErr != nil {
						failures = append(failures, glob.label+"-wrapper")
					}
					if payloadErr != nil {
						failures = append(failures, glob.label+"-payload")
					}
				}
			}
			sort.Strings(failures)
			want := expectedFailure[id]
			if want == "" && len(failures) != 0 {
				t.Fatalf("unexpected earlier schema failures: %v", failures)
			}
			if want != "" && (len(failures) != 1 || failures[0] != want) {
				t.Fatalf("schema failures = %v, want only %s", failures, want)
			}
		})
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schema, err := compiler.Compile(path)
	if err != nil {
		t.Fatalf("compile schema %s: %v", path, err)
	}
	return schema
}

func validateJSONFile(t *testing.T, schema *jsonschema.Schema, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	validateJSONBytes(t, schema, path, data)
}

func validateJSONBytes(t *testing.T, schema *jsonschema.Schema, name string, data []byte) {
	t.Helper()
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("validate %s: %v", name, err)
	}
}

func validateDSSEFile(t *testing.T, dsseSchema, payloadSchema *jsonschema.Schema, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	validateJSONBytes(t, dsseSchema, path, data)

	var wrapper struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		t.Fatalf("decode wrapper %s: %v", path, err)
	}
	payload, err := base64.StdEncoding.DecodeString(wrapper.Payload)
	if err != nil {
		t.Fatalf("decode payload %s: %v", path, err)
	}
	validateJSONBytes(t, payloadSchema, fmt.Sprintf("%s payload", path), payload)
}

func schemaValidationError(t *testing.T, schema *jsonschema.Schema, path string) error {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	return schema.Validate(instance)
}

func dsseSchemaErrors(t *testing.T, dsseSchema, payloadSchema *jsonschema.Schema, path string) (error, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err, err
	}
	payload, err := base64.StdEncoding.DecodeString(wrapper.Payload)
	if err != nil {
		return schemaValidationError(t, dsseSchema, path), err
	}
	instance, err := jsonschema.UnmarshalJSON(strings.NewReader(string(payload)))
	if err != nil {
		return schemaValidationError(t, dsseSchema, path), err
	}
	return schemaValidationError(t, dsseSchema, path), payloadSchema.Validate(instance)
}
