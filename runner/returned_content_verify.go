package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

const mcpHTTPExchangePath = "mcp_http_exchange"

// Exchange manifests reuse the private sidecar format. This path is never
// admitted into public returned-content evidence.
func retainMCPHTTPExchanges(dir, caseID string, record *adapter.MCPHTTPExchanges) error {
	if dir == "" || record == nil {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return err
	}
	stem, err := returnedContentSidecarStem(caseID, 0)
	if err != nil {
		return err
	}
	retained := *record
	if retained.CaseID != "" && retained.CaseID != caseID {
		return fmt.Errorf("exchange case identity mismatch")
	}
	retained.CaseID = caseID
	body, err := json.Marshal(&retained)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(body)
	manifest := returnedContentManifest{caseID, hex.EncodeToString(digest[:]), len(body), "application/json", mcpHTTPExchangePath}
	return writeReturnedContentSidecar(dir, stem+"-exchange", body, manifest)
}

func verifyReturnedContentDirectory(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	listing, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = listing.Close() }()
	return verifyReturnedContentEntries(root, listing)
}

// Read a fixed-size batch and validate it before requesting more entries. The
// batch size bounds listing memory, not the number of valid diagnostic files.
const diagnosticDirectoryBatchSize = 128

type diagnosticDirectoryReader interface {
	ReadDir(int) ([]os.DirEntry, error)
}

func verifyReturnedContentEntries(root *os.Root, listing diagnosticDirectoryReader) error {
	verifiedPair := false
	for {
		entries, readErr := listing.ReadDir(diagnosticDirectoryBatchSize)
		if readErr != nil && readErr != io.EOF {
			return fmt.Errorf("read diagnostic directory: %w", readErr)
		}
		// Directory entries are unique in a stable directory. Refuse repeated
		// names within a batch without retaining names from earlier batches.
		seen := make(map[string]bool, len(entries))
		for _, entry := range entries {
			name := entry.Name()
			half := ".json"
			if !strings.HasSuffix(name, half) {
				half = ".bin"
				if !strings.HasSuffix(name, half) {
					return fmt.Errorf("unexpected diagnostic file %q", name)
				}
			}
			stem := strings.TrimSuffix(name, half)
			if seen[name] {
				return fmt.Errorf("duplicate sidecar for %q", stem)
			}
			seen[name] = true
			partners := []string{stem + ".json", stem + ".bin"}
			for _, partner := range partners {
				info, err := root.Lstat(partner)
				if os.IsNotExist(err) {
					return fmt.Errorf("missing sidecar pair for %q", stem)
				}
				if err != nil || !info.Mode().IsRegular() {
					return fmt.Errorf("sidecar %q is not a regular file", partner)
				}
			}
			// Bind either listed half to the canonical identity in its manifest.
			// Rooted lookups alone can accept case aliases on some filesystems.
			manifestName := stem + ".json"
			body, err := readRootedDiagnostic(root, manifestName)
			if err != nil {
				return err
			}
			var manifest returnedContentManifest
			decoder := json.NewDecoder(bytes.NewReader(body))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&manifest); err != nil {
				return fmt.Errorf("manifest %q: %w", name, err)
			}
			if err := decoder.Decode(new(interface{})); err != io.EOF {
				return fmt.Errorf("manifest %q: trailing input", name)
			}
			exchange := manifest.Path == mcpHTTPExchangePath
			expectedStem := stem
			if exchange {
				expectedStem = strings.TrimSuffix(stem, "-exchange")
			}
			prefix := manifest.CaseID + "-"
			if !strings.HasPrefix(expectedStem, prefix) {
				return fmt.Errorf("missing sidecar pair for %q: manifest case identity mismatch", stem)
			}
			index, err := strconv.Atoi(strings.TrimPrefix(expectedStem, prefix))
			if err != nil || index < 0 {
				return fmt.Errorf("missing sidecar pair for %q: invalid observation index", stem)
			}
			canonical, err := returnedContentSidecarStem(manifest.CaseID, index)
			if err != nil || canonical != expectedStem || (exchange && (index != 0 || stem != canonical+"-exchange")) {
				return fmt.Errorf("manifest %q: invalid sidecar identity", name)
			}
			if _, ok := returnedContentPaths[manifest.Path]; !ok && !exchange {
				return fmt.Errorf("manifest %q: invalid path", name)
			}
			if _, ok := returnedContentMediaTypes[manifest.MediaType]; !ok {
				return fmt.Errorf("manifest %q: invalid media type", name)
			}
			if manifest.Bytes <= 0 {
				return fmt.Errorf("manifest %q: invalid byte count", name)
			}
			content, err := loadVerifiedReturnedContentSidecarPair(root, stem+".bin", manifestName, manifest)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			if exchange {
				if manifest.MediaType != "application/json" {
					return fmt.Errorf("exchange manifest requires application/json")
				}
				record, err := adapter.DecodeMCPHTTPExchanges(content)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if record.CaseID != manifest.CaseID {
					return fmt.Errorf("%s: exchange case identity mismatch", name)
				}
			}
			verifiedPair = true
		}
		if readErr == io.EOF {
			break
		}
	}
	if !verifiedPair {
		return fmt.Errorf("no retained diagnostics found")
	}
	return nil
}

// Use the report reader's descriptor checks and size ceiling so an untrusted
// diagnostic directory cannot hang verification on a FIFO or exhaust memory.
func readRootedDiagnostic(root *os.Root, name string) ([]byte, error) {
	handle, err := openRootedArtifact(root, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()
	content, err := io.ReadAll(io.LimitReader(handle, maxReportArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxReportArtifactBytes {
		return nil, errArtifactTooLarge
	}
	return content, nil
}

// The offline verifier is a separate mode; explicit run and reporting flags
// must not be silently ignored, even when supplied with their default values.
func validateReturnedContentVerifierFlags(names []string, positional ...string) error {
	if len(positional) != 0 {
		return fmt.Errorf("--verify-returned-content does not accept positional arguments")
	}
	for _, name := range names {
		if name != "verify-returned-content" {
			return fmt.Errorf("--verify-returned-content is a separate mode; cannot combine with --%s", name)
		}
	}
	return nil
}
