package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const assessmentProfile = "control-evidence-assessment/v1"

type SchemaOptions struct {
	PackageDir               string
	VerifierName             string
	VerifierVersion          string
	VerifierSHA256           string
	AssessmentTime           time.Time
	AllowConformanceSidecars bool
}

type AssessmentPredicate struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason"`
}

type SchemaEvidence struct {
	EnvelopePayloadSHA256 string `json:"envelope_payload_sha256"`
	ManifestSHA256        string `json:"manifest_sha256"`
}

type SchemaAssessment struct {
	Profile        string `json:"profile"`
	AssessmentTime string `json:"assessment_time,omitempty"`
	Verifier       struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	} `json:"verifier"`
	Evidence   *SchemaEvidence       `json:"evidence,omitempty"`
	Predicates []AssessmentPredicate `json:"predicates"`
}

func AssessSchema(options SchemaOptions) SchemaAssessment {
	result := SchemaAssessment{Profile: assessmentProfile}
	result.Verifier.Name = options.VerifierName
	result.Verifier.Version = options.VerifierVersion
	if lowerHexDigest(options.VerifierSHA256) {
		result.Verifier.SHA256 = options.VerifierSHA256
	}
	finish := func(status, reason string) SchemaAssessment {
		result.Predicates = []AssessmentPredicate{{Name: "schema-valid", Status: status, Reason: reason}}
		return result
	}
	if strings.TrimSpace(options.VerifierName) == "" || strings.TrimSpace(options.VerifierVersion) == "" || !lowerHexDigest(options.VerifierSHA256) {
		return finish("UNVERIFIABLE", "verifier_identity_invalid")
	}
	assessmentTime := options.AssessmentTime
	if assessmentTime.IsZero() {
		assessmentTime = time.Now()
	}
	result.AssessmentTime = assessmentTime.UTC().Format(time.RFC3339)

	schemas, err := loadSchemas()
	if err != nil {
		return finish("UNVERIFIABLE", "verifier_schema_load_failed")
	}
	if _, err := os.Lstat(options.PackageDir); err != nil {
		return finish("UNVERIFIABLE", "package_unavailable")
	}
	files, err := loadDirectoryPackageWithOptions(options.PackageDir, options.AllowConformanceSidecars)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return finish("UNVERIFIABLE", "package_unavailable")
		}
		return finish("FAIL", "package_structure_invalid")
	}

	var packageManifest manifest
	manifestValue, err := strictJSON(files["manifest.json"], &packageManifest)
	if err != nil || validateSchema(schemas.manifest, manifestValue) != nil {
		return finish("FAIL", "manifest_invalid")
	}
	entriesByRole := make(map[string][]manifestEntry)
	for _, entry := range packageManifest.Entries {
		entriesByRole[entry.Role] = append(entriesByRole[entry.Role], entry)
	}
	if reason := validateManifestPackage(files, packageManifest, entriesByRole); reason != "" {
		return finish("FAIL", reason)
	}

	_, reason := validateStructuralDSSE[requirement](files["requirement.dsse.json"], typeRequirement, schemas, schemas.requirement)
	if reason != "" {
		return finish("FAIL", reason)
	}
	envelopeDSSE, reason := validateStructuralDSSE[runEnvelope](files["envelope.dsse.json"], typeEnvelope, schemas, schemas.envelope)
	if reason != "" {
		return finish("FAIL", reason)
	}
	if envelopeDSSE.Payload.Artifacts.ManifestSHA256 != digestBytes(files["manifest.json"]) || envelopeDSSE.Payload.Artifacts.Count != len(packageManifest.Entries) {
		return finish("FAIL", "envelope_manifest_binding_mismatch")
	}
	if reason := validateGovernedMembers(files, entriesByRole, schemas); reason != "" {
		return finish("FAIL", reason)
	}

	result.Evidence = &SchemaEvidence{
		EnvelopePayloadSHA256: digestBytes(envelopeDSSE.PayloadBytes),
		ManifestSHA256:        digestBytes(files["manifest.json"]),
	}
	return finish("PASS", "package_format_valid")
}

func validateStructuralDSSE[T any](data []byte, expectedType string, schemas *schemaSet, payloadSchema *jsonschema.Schema) (*verifiedDSSE[T], string) {
	wrapper, payload, reason, err := decodeDSSEWrapper(data, expectedType, schemas)
	if err != nil {
		return nil, reason
	}
	if _, err := decodeBase64(wrapper.Signatures[0].Sig); err != nil {
		return nil, "dsse_signature_base64_invalid"
	}
	decoded, reason, err := decodeCanonicalPayload[T](payload, payloadSchema)
	if err != nil {
		return nil, reason
	}
	return &verifiedDSSE[T]{Wrapper: wrapper, Payload: decoded, PayloadBytes: payload, SignerKeyID: wrapper.Signatures[0].KeyID}, ""
}

func validateGovernedMembers(files map[string][]byte, entriesByRole map[string][]manifestEntry, schemas *schemaSet) string {
	for _, role := range []string{"requirement", "summary"} {
		if entries := entriesByRole[role]; len(entries) != 1 || entries[0].MediaType != "application/json" {
			return "manifest_media_type_mismatch"
		}
	}
	for _, entry := range entriesByRole["outcomes"] {
		if entry.MediaType != "application/json" || !validJSONSchema(files[entry.Path], schemas.outcomes) {
			return "outcomes_schema_invalid"
		}
	}
	for _, entry := range entriesByRole["tool-profile"] {
		if entry.MediaType != "application/json" || !validJSONSchema(files[entry.Path], schemas.toolProfile) {
			return "tool_profile_schema_invalid"
		}
	}
	for _, entry := range entriesByRole["observer-evidence"] {
		if entry.MediaType != "application/json" {
			return "observer_evidence_schema_invalid"
		}
		if _, reason := validateStructuralDSSE[observerEvidence](files[entry.Path], typeObserver, schemas, schemas.observer); reason != "" {
			return "observer_evidence_schema_invalid"
		}
	}
	for _, entry := range entriesByRole["clock-evidence"] {
		if entry.MediaType != "application/json" {
			return "clock_evidence_schema_invalid"
		}
		if _, reason := validateStructuralDSSE[clockEvidence](files[entry.Path], typeClock, schemas, schemas.clock); reason != "" {
			return "clock_evidence_schema_invalid"
		}
	}
	for _, entries := range entriesByRole {
		for _, entry := range entries {
			if entry.MediaType != "application/json" || governedRole(entry.Role) {
				continue
			}
			if _, err := strictJSON(files[entry.Path], nil); err != nil {
				return "json_member_invalid"
			}
		}
	}
	return ""
}

func validJSONSchema(data []byte, schema *jsonschema.Schema) bool {
	value, err := strictJSON(data, nil)
	return err == nil && validateSchema(schema, value) == nil
}

func governedRole(role string) bool {
	switch role {
	case "requirement", "outcomes", "tool-profile", "observer-evidence", "clock-evidence":
		return true
	default:
		return false
	}
}

func lowerHexDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
