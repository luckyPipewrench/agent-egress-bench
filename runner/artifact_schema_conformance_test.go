package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type artifactVectorFile struct {
	Schema   string           `json:"schema"`
	Accepted []artifactVector `json:"accepted"`
	Rejected []artifactVector `json:"rejected"`
}

type artifactVector struct {
	Description   string                   `json:"description"`
	Instance      any                      `json:"instance"`
	Source        string                   `json:"source"`
	Mutations     []artifactVectorMutation `json:"mutations"`
	Mutation      *artifactVectorMutation  `json:"mutation"`
	AcceptedIndex int                      `json:"accepted_index"`
}

type artifactVectorMutation struct {
	Replace []any `json:"replace"`
	Remove  []any `json:"remove"`
	Value   any   `json:"value"`
}

func validateArtifactVectorDirections(vectors artifactVectorFile) error {
	if len(vectors.Accepted) == 0 || len(vectors.Rejected) == 0 {
		return fmt.Errorf("artifact conformance corpus must contain accepted and rejected vectors")
	}
	return nil
}

func TestArtifactSchemaConformanceVectors(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "schemas", "conformance", "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("find artifact conformance vectors: paths=%d err=%v", len(paths), err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			vectors := readArtifactVectors(t, path)
			if err := validateArtifactVectorDirections(vectors); err != nil {
				t.Fatal(err)
			}
			schema := compileArtifactSchema(t, filepath.Join(filepath.Dir(path), vectors.Schema))
			accepted := make([]any, len(vectors.Accepted))
			for index, vector := range vectors.Accepted {
				accepted[index] = materializeArtifactVector(t, path, vector)
				if err := validateArtifactVector(schema, accepted[index]); err != nil {
					t.Fatalf("accepted %q: %v", vector.Description, err)
				}
			}
			for _, vector := range vectors.Rejected {
				if vector.AcceptedIndex < 0 || vector.AcceptedIndex >= len(accepted) {
					t.Fatalf("rejected %q has invalid accepted_index", vector.Description)
				}
				value := cloneArtifactVector(t, accepted[vector.AcceptedIndex])
				applyArtifactMutation(t, value, *vector.Mutation)
				if err := validateArtifactVector(schema, value); err == nil {
					t.Fatalf("rejected %q was accepted", vector.Description)
				}
			}
		})
	}
}

func TestArtifactSchemaConformanceVectorsRequireBothDirections(t *testing.T) {
	vectors := artifactVectorFile{Accepted: []artifactVector{{Description: "valid"}}}
	if err := validateArtifactVectorDirections(vectors); err == nil {
		t.Fatal("accepted-only artifact conformance corpus passed")
	}
}

func readArtifactVectors(t *testing.T, path string) artifactVectorFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors artifactVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func compileArtifactSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(filepath.Base(path), document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func materializeArtifactVector(t *testing.T, vectorPath string, vector artifactVector) any {
	t.Helper()
	value := vector.Instance
	if vector.Source != "" {
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(vectorPath), vector.Source))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
	}
	value = cloneArtifactVector(t, value)
	for _, mutation := range vector.Mutations {
		applyArtifactMutation(t, value, mutation)
	}
	return value
}

func cloneArtifactVector(t *testing.T, value any) any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone any
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func applyArtifactMutation(t *testing.T, value any, mutation artifactVectorMutation) {
	t.Helper()
	path := mutation.Replace
	remove := false
	if len(mutation.Remove) > 0 {
		path = mutation.Remove
		remove = true
	}
	if len(path) == 0 {
		t.Fatal("mutation has no path")
	}
	parent := value
	for _, part := range path[:len(path)-1] {
		parent = artifactVectorChild(t, parent, part)
	}
	last := path[len(path)-1]
	switch current := parent.(type) {
	case map[string]any:
		key, ok := last.(string)
		if !ok {
			t.Fatalf("object path component is %T", last)
		}
		if remove {
			delete(current, key)
		} else {
			current[key] = mutation.Value
		}
	case []any:
		index := int(last.(float64))
		if remove {
			current[index] = nil
		} else {
			current[index] = mutation.Value
		}
	default:
		t.Fatalf("mutation parent has type %T", parent)
	}
}

func artifactVectorChild(t *testing.T, value any, part any) any {
	t.Helper()
	switch current := value.(type) {
	case map[string]any:
		return current[part.(string)]
	case []any:
		return current[int(part.(float64))]
	default:
		t.Fatal(fmt.Sprintf("path enters %T", value))
		return nil
	}
}

func validateArtifactVector(schema *jsonschema.Schema, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(document)
}
