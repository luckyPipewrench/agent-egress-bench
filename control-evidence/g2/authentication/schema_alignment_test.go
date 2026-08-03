package authentication

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
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
