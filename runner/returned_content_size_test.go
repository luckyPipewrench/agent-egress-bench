package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyReturnedContentSelfConsistentOversize(t *testing.T) {
	dir := t.TempDir()
	data := make([]byte, maxReportArtifactBytes+1)
	digest := sha256.Sum256(data)
	manifest := returnedContentManifest{CaseID: "size-test", SHA256: hex.EncodeToString(digest[:]), Bytes: len(data), MediaType: "text/plain", Path: "mcp_stdio_result"}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "size-test-0.bin"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "size-test-0.json"), encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := loadVerifiedReturnedContentSidecarPair(root, "size-test-0.bin", "size-test-0.json", manifest); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize guard not isolated: %v", err)
	}
}
