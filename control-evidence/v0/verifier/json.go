package verifier

import (
	"bytes"
	"crypto/ed25519"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type schemaSet struct {
	dsse, requirement, envelope, manifest, outcomes, clock, observer, tokenMaterial, healthMaterial, context,
	buyerReproduction, buyerReproductionStatement, buyerReproductionTranscript *jsonschema.Schema
	toolProfiles map[int]*jsonschema.Schema
}

const maxJSONDepth = 128

var errEvidenceNotExternal = errors.New("evidence is not external to the source package")

//go:embed schemas/*.json
var embeddedSchemas embed.FS

func loadSchemas() (*schemaSet, error) {
	compile := func(name string) (*jsonschema.Schema, error) {
		data, err := embeddedSchemas.ReadFile(filepath.Join("schemas", name))
		if err != nil {
			return nil, fmt.Errorf("read embedded %s: %w", name, err)
		}
		compiler := jsonschema.NewCompiler()
		compiler.AssertFormat()
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("parse embedded %s: %w", name, err)
		}
		if err := compiler.AddResource(name, doc); err != nil {
			return nil, fmt.Errorf("register embedded %s: %w", name, err)
		}
		schema, err := compiler.Compile(name)
		if err != nil {
			return nil, fmt.Errorf("compile %s: %w", name, err)
		}
		return schema, nil
	}
	names := []string{
		"control-evidence-dsse.schema.json",
		"control-evidence-requirement.schema.json",
		"control-evidence-run-envelope.schema.json",
		"control-evidence-manifest.schema.json",
		"control-evidence-outcomes.schema.json",
		"control-evidence-clock-evidence.schema.json",
		"control-evidence-observer-evidence.schema.json",
		"control-evidence-token-material.schema.json",
		"control-evidence-health-control-material.schema.json",
		"control-evidence-context.schema.json",
		"tool-profile-v1.schema.json",
		"tool-profile.schema.json",
		"control-evidence-buyer-reproduction.schema.json",
		"control-evidence-buyer-reproduction-statement.schema.json",
		"control-evidence-buyer-reproduction-transcript.schema.json",
	}
	// Keyed by filename rather than by position. The previous form indexed a
	// slice, so inserting a schema anywhere above shifted every index below it
	// and silently rebound the wrong schema to a name. In a verifier that
	// decides which schema an artifact is judged against, that failure mode is
	// invisible: the artifact still validates, just against the wrong contract.
	compiled := make(map[string]*jsonschema.Schema, len(names))
	for _, name := range names {
		schema, err := compile(name)
		if err != nil {
			return nil, err
		}
		compiled[name] = schema
	}
	return &schemaSet{
		dsse:           compiled["control-evidence-dsse.schema.json"],
		requirement:    compiled["control-evidence-requirement.schema.json"],
		envelope:       compiled["control-evidence-run-envelope.schema.json"],
		manifest:       compiled["control-evidence-manifest.schema.json"],
		outcomes:       compiled["control-evidence-outcomes.schema.json"],
		clock:          compiled["control-evidence-clock-evidence.schema.json"],
		observer:       compiled["control-evidence-observer-evidence.schema.json"],
		tokenMaterial:  compiled["control-evidence-token-material.schema.json"],
		healthMaterial: compiled["control-evidence-health-control-material.schema.json"],
		context:        compiled["control-evidence-context.schema.json"],
		// Superseded profile versions stay compiled so historical evidence keeps
		// validating against the contract it was recorded under.
		toolProfiles: map[int]*jsonschema.Schema{
			1: compiled["tool-profile-v1.schema.json"],
			3: compiled["tool-profile.schema.json"],
		},
		buyerReproduction:           compiled["control-evidence-buyer-reproduction.schema.json"],
		buyerReproductionStatement:  compiled["control-evidence-buyer-reproduction-statement.schema.json"],
		buyerReproductionTranscript: compiled["control-evidence-buyer-reproduction-transcript.schema.json"],
	}, nil
}

func strictJSON(data []byte, dst any) (any, error) {
	if len(data) == 0 {
		return nil, errors.New("empty JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	value, err := strictValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("trailing JSON token %v", tok)
		}
		return nil, fmt.Errorf("trailing JSON: %w", err)
	}
	if dst != nil {
		plain := json.NewDecoder(bytes.NewReader(data))
		plain.DisallowUnknownFields()
		if err := plain.Decode(dst); err != nil {
			return nil, err
		}
	}
	return value, nil
}

func strictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			out := map[string]any{}
			seen := map[string]struct{}{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				seen[key] = struct{}{}
				child, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				out[key] = child
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return out, nil
		case '[':
			var out []any
			for dec.More() {
				child, err := strictValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				out = append(out, child)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return out, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", v)
		}
	default:
		return tok, nil
	}
}

func validateSchema(schema *jsonschema.Schema, value any) error {
	if err := schema.Validate(value); err != nil {
		return err
	}
	return nil
}

func canonicalJSON(data []byte) error {
	canonical, err := jsoncanonicalizer.Transform(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, canonical) {
		return errors.New("JSON is not RFC 8785 canonical")
	}
	return nil
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

type verifiedDSSE[T any] struct {
	Wrapper      dsseEnvelope
	Payload      T
	PayloadBytes []byte
	SignerKeyID  string
}

func verifyDSSE[T any](data []byte, expectedType, trustedKey string, schemas *schemaSet, payloadSchema *jsonschema.Schema) (*verifiedDSSE[T], string, error) {
	wrapper, payload, reason, err := decodeDSSEWrapper(data, expectedType, schemas)
	if err != nil {
		return nil, reason, err
	}
	sig := wrapper.Signatures[0]
	if trustedKey != "" && sig.KeyID != trustedKey {
		return nil, "signer_key_untrusted", errors.New("DSSE key is not independently trusted")
	}
	pub, err := hex.DecodeString(sig.KeyID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, "signer_key_invalid", errors.New("invalid Ed25519 public key")
	}
	sigBytes, err := decodeBase64(sig.Sig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, "dsse_signature_invalid", errors.New("invalid Ed25519 signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), pae(wrapper.PayloadType, payload), sigBytes) {
		return nil, "dsse_signature_invalid", errors.New("Ed25519 signature verification failed")
	}
	decoded, reason, err := decodeCanonicalPayload[T](payload, payloadSchema)
	if err != nil {
		return nil, reason, err
	}
	return &verifiedDSSE[T]{Wrapper: wrapper, Payload: decoded, PayloadBytes: payload, SignerKeyID: sig.KeyID}, "", nil
}

func decodeDSSEWrapper(data []byte, expectedType string, schemas *schemaSet) (dsseEnvelope, []byte, string, error) {
	var wrapper dsseEnvelope
	wrapperValue, err := strictJSON(data, &wrapper)
	if err != nil {
		return wrapper, nil, "dsse_wrapper_invalid", err
	}
	if len(wrapper.Signatures) != 1 {
		return wrapper, nil, "dsse_signature_count", errors.New("DSSE must carry exactly one signature")
	}
	if wrapper.PayloadType != expectedType {
		reason := "payload_type_mismatch"
		switch expectedType {
		case typeRequirement:
			reason = "requirement_payload_type_mismatch"
		case typeObserver:
			reason = "observer_payload_type_mismatch"
		}
		return wrapper, nil, reason, errors.New("DSSE payload type mismatch")
	}
	if err := validateSchema(schemas.dsse, wrapperValue); err != nil {
		return wrapper, nil, "dsse_wrapper_invalid", err
	}
	payload, err := decodeBase64(wrapper.Payload)
	if err != nil {
		return wrapper, nil, "dsse_payload_base64_invalid", err
	}
	return wrapper, payload, "", nil
}

func decodeCanonicalPayload[T any](payload []byte, payloadSchema *jsonschema.Schema) (T, string, error) {
	var decoded T
	if err := canonicalJSON(payload); err != nil {
		return decoded, "signed_payload_not_jcs", err
	}
	payloadValue, err := strictJSON(payload, &decoded)
	if err != nil {
		return decoded, "signed_payload_invalid", err
	}
	if payloadSchema != nil {
		if err := validateSchema(payloadSchema, payloadValue); err != nil {
			return decoded, "signed_payload_schema_invalid", err
		}
	}
	return decoded, "", nil
}

func readBounded(path string, max int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}
	return data, nil
}

// readExternalBounded validates the external-path boundary against the same
// already-open file descriptor that supplies the returned bytes. Keeping the
// descriptor open through the final path checks prevents a symlink or rename
// swap from validating one file while the assessor consumes another.
func readExternalBounded(root, path string, max int64) ([]byte, error) {
	return readExternalBoundedWithHook(root, path, max, nil)
}

func readExternalBoundedWithHook(root, path string, max int64, afterOpen func() error) ([]byte, error) {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(resolvedRoot)
	if err != nil || !rootInfo.IsDir() {
		return nil, errors.New("source package root is not a directory")
	}

	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("evidence is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, errors.New("evidence changed while opening")
	}
	if afterOpen != nil {
		if err := afterOpen(); err != nil {
			return nil, fmt.Errorf("after-open check: %w", err)
		}
	}

	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	resolvedInfo, err := os.Stat(resolvedPath)
	if err != nil || !os.SameFile(opened, resolvedInfo) {
		return nil, errors.New("evidence path changed while opening")
	}
	if !pathOutsideRoot(resolvedRoot, resolvedPath) {
		return nil, errEvidenceNotExternal
	}

	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("file exceeds %d bytes", max)
	}

	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("evidence changed while reading")
	}
	resolvedPathAfter, err := filepath.EvalSymlinks(path)
	if err != nil || resolvedPathAfter != resolvedPath {
		return nil, errors.New("evidence path changed while reading")
	}
	resolvedRootAfter, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRootAfter != resolvedRoot {
		return nil, errors.New("source package root changed while reading evidence")
	}
	rootInfoAfter, err := os.Stat(resolvedRootAfter)
	if err != nil || !os.SameFile(rootInfo, rootInfoAfter) {
		return nil, errors.New("source package root changed while reading evidence")
	}
	return data, nil
}

func pathOutsideRoot(root, path string) bool {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		// Absolute paths on different volumes cannot be descendants.
		return true
	}
	if relative == "." || relative == "" {
		return false
	}
	return relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func normalizedPath(path string) bool {
	return path != "" && len(path) <= 240 && path == filepath.ToSlash(filepath.Clean(path)) && !filepath.IsAbs(path) &&
		!strings.HasPrefix(path, "../") && path != ".." && !strings.Contains(path, "\\") && !strings.ContainsRune(path, '\x00')
}
