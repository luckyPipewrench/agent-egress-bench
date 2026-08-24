package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

const (
	returnedContentSHA256    = "returned_content_sha256"
	returnedContentBytes     = "returned_content_bytes"
	returnedContentMediaType = "returned_content_media_type"
	returnedContentPath      = "returned_content_path"
)

var returnedContentPaths = map[string]struct{}{
	"mcp_tools_list":              {},
	"mcp_tools_call_result":       {},
	"mcp_initialize_instructions": {},
	"mcp_stdio_result":            {},
}

var returnedContentMediaTypes = map[string]struct{}{
	"application/json":         {},
	"text/event-stream":        {},
	"application/octet-stream": {},
	"text/plain":               {},
}

var returnedContentBooleanMetadata = map[string]struct{}{
	"returned_content_has_title":        {},
	"returned_content_has_inputschema":  {},
	"returned_content_has_outputschema": {},
	"returned_content_has_annotations":  {},
	"returned_content_has_instructions": {},
}

const maxReturnedContentToolCount = 1 << 20

type returnedContentManifest struct {
	CaseID    string `json:"case_id"`
	SHA256    string `json:"sha256"`
	Bytes     int    `json:"bytes"`
	MediaType string `json:"media_type"`
	Path      string `json:"path"`
}

// retainReturnedContent copies raw bytes only when the operator explicitly
// asks for it. Public evidence receives a digest and bounded shape facts.
func retainReturnedContent(dir, caseID string, evidence map[string]interface{}, observations []adapter.ReturnedContent) error {
	primary := primaryReturnedContentIndex(observations)
	for index, observation := range observations {
		if len(observation.Bytes) == 0 {
			continue
		}
		if _, ok := returnedContentPaths[observation.Path]; !ok {
			return fmt.Errorf("unknown returned-content path %q", observation.Path)
		}
		digest := sha256.Sum256(observation.Bytes)
		digestText := hex.EncodeToString(digest[:])
		mediaType := boundedReturnedContentMediaType(observation.MediaType)
		if index == primary {
			evidence[returnedContentSHA256] = digestText
			evidence[returnedContentBytes] = len(observation.Bytes)
			evidence[returnedContentMediaType] = mediaType
			evidence[returnedContentPath] = observation.Path
			copyBoundedReturnedContentMetadata(evidence, observation.Metadata)
		}
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create returned-content directory: %w", err)
		}
		if err := os.Chmod(dir, 0o750); err != nil {
			return fmt.Errorf("set returned-content directory permissions: %w", err)
		}
		name, err := returnedContentSidecarStem(caseID, index)
		if err != nil {
			return err
		}
		manifest := returnedContentManifest{caseID, digestText, len(observation.Bytes), mediaType, observation.Path}
		if err := writeReturnedContentSidecar(dir, name, observation.Bytes, manifest); err != nil {
			return err
		}
	}
	return nil
}

func writeReturnedContentSidecar(dir, name string, content []byte, manifest returnedContentManifest) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("open returned-content directory: %w", err)
	}
	defer func() { _ = root.Close() }()

	binName := name + ".bin"
	if err := writeReturnedContentSidecarFile(root, binName, content); err != nil {
		return fmt.Errorf("write returned-content sidecar: %w", err)
	}
	stored, err := root.ReadFile(binName)
	if err != nil {
		return fmt.Errorf("read returned-content sidecar: %w", err)
	}
	storedDigest := sha256.Sum256(stored)
	if len(stored) != manifest.Bytes || hex.EncodeToString(storedDigest[:]) != manifest.SHA256 {
		return fmt.Errorf("returned-content sidecar digest does not match public evidence")
	}
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode returned-content manifest: %w", err)
	}
	if err := writeReturnedContentSidecarFile(root, name+".json", append(encodedManifest, '\n')); err != nil {
		return fmt.Errorf("write returned-content manifest: %w", err)
	}
	return nil
}

func writeReturnedContentSidecarFile(root *os.Root, name string, data []byte) error {
	if info, err := root.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("returned-content sidecar %q is not a regular file", name)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect returned-content sidecar %q: %w", name, err)
	}
	tmpName := name + ".tmp"
	if err := removeReturnedContentIfRegular(root, tmpName); err != nil {
		return err
	}
	file, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	writeErr := writeReturnedContentExclusive(file, data)
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = root.Remove(tmpName)
		return writeErr
	}
	if err := root.Rename(tmpName, name); err != nil {
		_ = root.Remove(tmpName)
		return err
	}
	return nil
}

func writeReturnedContentExclusive(file *os.File, data []byte) error {
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return fmt.Errorf("wrote %d of %d returned-content bytes", written, len(data))
	}
	return nil
}

func removeReturnedContentIfRegular(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect returned-content sidecar %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("returned-content sidecar %q is not a regular file", name)
	}
	if err := root.Remove(name); err != nil {
		return fmt.Errorf("remove returned-content sidecar %q: %w", name, err)
	}
	return nil
}

func primaryReturnedContentIndex(observations []adapter.ReturnedContent) int {
	for index, observation := range observations {
		if observation.Path != "mcp_initialize_instructions" || len(observation.Bytes) == 0 {
			continue
		}
		hasInstructions, ok := observation.Metadata["returned_content_has_instructions"].(bool)
		if ok && hasInstructions {
			return index
		}
	}
	for index, observation := range observations {
		if len(observation.Bytes) > 0 {
			return index
		}
	}
	return 0
}

func returnedContentSidecarStem(caseID string, index int) (string, error) {
	if caseID == "" || caseID == "." || caseID == ".." {
		return "", fmt.Errorf("invalid returned-content case id %q", caseID)
	}
	for _, r := range caseID {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '_' && r != '-' {
			return "", fmt.Errorf("invalid returned-content case id %q", caseID)
		}
	}
	return fmt.Sprintf("%s-%d", caseID, index), nil
}

func boundedReturnedContentMediaType(mediaType string) string {
	if _, ok := returnedContentMediaTypes[mediaType]; ok {
		return mediaType
	}
	return "application/octet-stream"
}

func copyBoundedReturnedContentMetadata(evidence, metadata map[string]interface{}) {
	if toolCount, ok := metadata["returned_content_tool_count"].(int); ok && toolCount >= 0 && toolCount <= maxReturnedContentToolCount {
		evidence["returned_content_tool_count"] = toolCount
	}
	for key := range returnedContentBooleanMetadata {
		if value, ok := metadata[key].(bool); ok && value {
			evidence[key] = true
		}
	}
}
