package main

import (
	"bytes"
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
