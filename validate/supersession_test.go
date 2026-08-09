package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSupersessionCorpus writes one file per entry and returns the id-to-path
// map validateSupersessionGraph consumes. Only the fields the graph check reads
// are populated, because a full valid case would obscure what is under test.
func writeSupersessionCorpus(t *testing.T, entries map[string]any) map[string]string {
	t.Helper()
	dir := t.TempDir()
	ids := make(map[string]string, len(entries))
	for id, supersedes := range entries {
		body := map[string]any{"schema_version": 4, "id": id}
		if supersedes != nil {
			body["supersedes"] = supersedes
		}
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, id+".json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		ids[id] = path
	}
	return ids
}

func TestValidateSupersessionGraph(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]any
		wantErr string
	}{
		{
			name:    "no supersessions at all, which is the current corpus",
			entries: map[string]any{"a": nil, "b": nil},
		},
		{
			name:    "a valid replacement relationship",
			entries: map[string]any{"old": nil, "new": "old"},
		},
		{
			name:    "a chain that terminates",
			entries: map[string]any{"v1": nil, "v2": "v1", "v3": "v2"},
		},
		{
			name:    "a case superseding itself",
			entries: map[string]any{"loop": "loop"},
			wantErr: "supersedes itself",
		},
		{
			name:    "a target that is not in the corpus",
			entries: map[string]any{"orphan": "gone"},
			wantErr: "not a case in this corpus",
		},
		{
			name:    "present but empty, which is different from absent",
			entries: map[string]any{"blank": ""},
			wantErr: "present but empty",
		},
		{
			name:    "whitespace only is still empty",
			entries: map[string]any{"spaces": "   "},
			wantErr: "present but empty",
		},
		{
			name:    "a two node cycle",
			entries: map[string]any{"x": "y", "y": "x"},
			wantErr: "cyclic",
		},
		{
			name:    "a three node cycle",
			entries: map[string]any{"p": "q", "q": "r", "r": "p"},
			wantErr: "cyclic",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errs := validateSupersessionGraph(writeSupersessionCorpus(t, tc.entries))
			if tc.wantErr == "" {
				if len(errs) != 0 {
					t.Fatalf("expected no errors, got %v", errs)
				}
				return
			}
			for _, e := range errs {
				if strings.Contains(e, tc.wantErr) {
					return
				}
			}
			t.Fatalf("expected an error containing %q, got %v", tc.wantErr, errs)
		})
	}
}

// An absent field and a field set to an empty string are different mistakes, and
// the Go zero value cannot tell them apart, which is why the check reads the raw
// JSON rather than the decoded struct.
func TestRawSupersedesDistinguishesAbsentFromEmpty(t *testing.T) {
	value, declared := rawSupersedes([]byte(`{"id":"a"}`))
	if declared || value != "" {
		t.Fatalf("absent field: got (%q, %v), want (\"\", false)", value, declared)
	}

	value, declared = rawSupersedes([]byte(`{"id":"a","supersedes":""}`))
	if !declared || value != "" {
		t.Fatalf("empty field: got (%q, %v), want (\"\", true)", value, declared)
	}

	value, declared = rawSupersedes([]byte(`{"id":"a","supersedes":"b"}`))
	if !declared || value != "b" {
		t.Fatalf("set field: got (%q, %v), want (\"b\", true)", value, declared)
	}
}
