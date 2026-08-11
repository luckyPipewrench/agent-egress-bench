package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestVectorsAreDeterministicAndPayloadBearing(t *testing.T) {
	if len(vectors) != 7 {
		t.Fatalf("vector count = %d, want 7", len(vectors))
	}
	for _, item := range vectors {
		first := build(item)
		second := build(item)
		for _, required := range []string{"requirement.dsse.json", "envelope.dsse.json", "manifest.json", "outcomes.json", "summary.json", "context.json", "expect.json"} {
			if len(first[required]) == 0 {
				t.Fatalf("%s missing payload-bearing %s", item.id, required)
			}
		}
		if len(first) != len(second) {
			t.Fatalf("%s file count changed between builds", item.id)
		}
		for name, data := range first {
			if !bytes.Equal(data, second[name]) {
				t.Fatalf("%s/%s is nondeterministic", item.id, name)
			}
		}
	}
}

func TestReplaceFilesStaysInsideGeneratedTargets(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "contexts")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "stale.json"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	replaceFiles(root, target, map[string][]byte{"fresh.json": []byte("fresh\n")})
	if _, err := os.Stat(filepath.Join(target, "stale.json")); !os.IsNotExist(err) {
		t.Fatalf("stale file survived replacement: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, "fresh.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte("fresh\n")) {
		t.Fatalf("fresh file = %q", data)
	}

	outside := filepath.Join(t.TempDir(), "contexts")
	assertPanics(t, "target outside root", func() {
		replaceFiles(root, outside, map[string][]byte{"escape.json": []byte("escape\n")})
	})

	escapeParent := t.TempDir()
	if err := os.Symlink(escapeParent, filepath.Join(root, "edge")); err != nil {
		t.Fatal(err)
	}
	assertPanics(t, "symlinked parent outside root", func() {
		replaceFiles(root, filepath.Join(root, "edge", "e01-expired-requirement"), map[string][]byte{"escape.json": []byte("escape\n")})
	})
}

func assertPanics(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s did not panic", name)
		}
	}()
	fn()
}
