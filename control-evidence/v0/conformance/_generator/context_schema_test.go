package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"testing"
)

func TestContextSchema(t *testing.T) {
	t.Parallel()
	schemaDir := filepath.Clean(filepath.Join("..", "..", "..", "..", "schemas"))
	schema := compileSchema(t, filepath.Join(schemaDir, "control-evidence-context.schema.json"))
	for path, data := range allFiles() {
		if filepath.Base(path) != "context.json" {
			continue
		}
		if err := rejectDuplicateJSONKeys(data); err != nil {
			t.Fatalf("duplicate-key check %s: %v", path, err)
		}
		validateJSONBytes(t, schema, path, data)
	}
}

func TestContextDuplicateKeyRejection(t *testing.T) {
	t.Parallel()
	if err := rejectDuplicateJSONKeys([]byte(`{"profile":"a","profile":"b"}`)); err == nil {
		t.Fatal("duplicate object key accepted")
	}
}

func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("object close: %v", err)
		}
	case '[':
		for dec.More() {
			if err := walkJSONValue(dec); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("array close: %v", err)
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delim)
	}
	return nil
}
