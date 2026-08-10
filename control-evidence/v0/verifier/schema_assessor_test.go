package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const testVerifierDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAssessSchemaGoldenPackage(t *testing.T) {
	packageDir := schemaFixture(t)
	result := assessSchemaFixture(packageDir)
	if got := result.Predicates[0]; got.Status != "PASS" || got.Reason != "package_format_valid" {
		t.Fatalf("AssessSchema() = %#v", result)
	}
	if result.Evidence == nil || result.Evidence.ManifestSHA256 != digestBytes(mustRead(t, filepath.Join(packageDir, "manifest.json"))) {
		t.Fatalf("evidence = %#v", result.Evidence)
	}
}

func TestV0VerifierRejectsActiveV4ToolProfile(t *testing.T) {
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatalf("load schemas: %v", err)
	}
	profile, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "pipelock", "tool-profile.json"))
	if err != nil {
		t.Fatalf("read v4 tool profile: %v", err)
	}
	if validToolProfileSchema(profile, schemas) {
		t.Fatal("frozen v0 verifier accepted an active v4 tool profile")
	}
}

func TestAssessSchemaAcceptsAllGoldenAndEdgePackages(t *testing.T) {
	for _, class := range []string{"golden", "edge"} {
		packages, err := filepath.Glob(filepath.Join("..", "conformance", class, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, packageDir := range packages {
			t.Run(filepath.Join(class, filepath.Base(packageDir)), func(t *testing.T) {
				options := schemaOptions(packageDir)
				options.AllowConformanceSidecars = true
				assertSchemaResult(t, AssessSchema(options), "PASS", "package_format_valid")
			})
		}
	}
}

func TestAssessSchemaRejectsConformanceSidecarsByDefault(t *testing.T) {
	packageDir := schemaFixture(t)
	if err := os.WriteFile(filepath.Join(packageDir, "context.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := assessSchemaFixture(packageDir)
	assertSchemaResult(t, result, "FAIL", "manifest_member_uncommitted")

	options := schemaOptions(packageDir)
	options.AllowConformanceSidecars = true
	result = AssessSchema(options)
	assertSchemaResult(t, result, "PASS", "package_format_valid")
}

func TestAssessSchemaUnavailablePackageIsNotAFormatFailure(t *testing.T) {
	assertSchemaResult(t, assessSchemaFixture(filepath.Join(t.TempDir(), "missing")), "UNVERIFIABLE", "package_unavailable")
}

func TestAssessSchemaRejectsInvalidVerifierIdentity(t *testing.T) {
	for _, mutate := range []func(*SchemaOptions){
		func(options *SchemaOptions) { options.VerifierName = "" },
		func(options *SchemaOptions) { options.VerifierVersion = " " },
		func(options *SchemaOptions) { options.VerifierSHA256 = "AAAA" + testVerifierDigest[4:] },
		func(options *SchemaOptions) { options.VerifierSHA256 = "abcd" },
	} {
		options := schemaOptions(schemaFixture(t))
		mutate(&options)
		assertSchemaResult(t, AssessSchema(options), "UNVERIFIABLE", "verifier_identity_invalid")
	}
}

func TestAssessSchemaSuppliesAssessmentTimeWhenCallerOmitsIt(t *testing.T) {
	options := schemaOptions(schemaFixture(t))
	options.AssessmentTime = time.Time{}
	result := AssessSchema(options)
	assertSchemaResult(t, result, "PASS", "package_format_valid")
	if _, err := time.Parse(time.RFC3339, result.AssessmentTime); err != nil {
		t.Fatalf("assessment_time = %q: %v", result.AssessmentTime, err)
	}
}

func TestAssessSchemaRejectsNonDirectoryPackage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.json")
	mustWrite(t, path, []byte("{}"))
	assertSchemaResult(t, assessSchemaFixture(path), "FAIL", "package_structure_invalid")
}

func TestAssessSchemaHostilePackages(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		mutate func(*testing.T, string)
	}{
		{"undeclared-member", "manifest_member_uncommitted", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "undeclared.bin"), []byte("not committed"))
		}},
		{"manifest-length-mismatch", "manifest_member_mismatch", func(t *testing.T, root string) {
			mutateManifest(t, root, func(value map[string]any) {
				entries := value["entries"].([]any)
				entries[0].(map[string]any)["byte_length"] = json.Number("1")
			}, false)
		}},
		{"duplicate-manifest-path", "manifest_path_ambiguous", func(t *testing.T, root string) {
			mutateManifest(t, root, func(value map[string]any) {
				entries := value["entries"].([]any)
				value["entries"] = append(entries, entries[0])
			}, false)
		}},
		{"envelope-manifest-binding", "envelope_manifest_binding_mismatch", func(t *testing.T, root string) {
			path := filepath.Join(root, "manifest.json")
			mustWrite(t, path, append(mustRead(t, path), '\n'))
		}},
		{"duplicate-manifest-key", "manifest_invalid", func(t *testing.T, root string) {
			data := mustRead(t, filepath.Join(root, "manifest.json"))
			data = bytes.Replace(data, []byte(`"profile":`), []byte(`"profile":"control-evidence-manifest/v0","profile":`), 1)
			mustWrite(t, filepath.Join(root, "manifest.json"), data)
		}},
		{"noncanonical-envelope-payload", "signed_payload_not_jcs", func(t *testing.T, root string) {
			mutateEnvelopePayload(t, root, func(payload []byte) []byte {
				return append([]byte(" \n"), payload...)
			})
		}},
		{"invalid-signature-base64", "dsse_signature_base64_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "envelope.dsse.json")
			var wrapper map[string]any
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			wrapper["signatures"].([]any)[0].(map[string]any)["sig"] = strings.Repeat("A", 65)
			mustWrite(t, path, marshalJSON(t, wrapper))
		}},
		{"wrong-signature-length", "dsse_signature_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "envelope.dsse.json")
			var wrapper map[string]any
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			// This is valid base64 and passes the JSON schema's encoded-length
			// floor, but decodes to 48 bytes rather than an Ed25519 signature.
			wrapper["signatures"].([]any)[0].(map[string]any)["sig"] = strings.Repeat("A", 64)
			mustWrite(t, path, marshalJSON(t, wrapper))
		}},
		{"requirement-payload-type", "requirement_payload_type_mismatch", func(t *testing.T, root string) {
			path := filepath.Join(root, "requirement.dsse.json")
			var wrapper map[string]any
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			wrapper["payloadType"] = typeEnvelope
			mustWrite(t, path, marshalJSON(t, wrapper))
			rebindManifestAndEnvelope(t, root)
		}},
		{"invalid-outcomes-schema", "outcomes_schema_invalid", func(t *testing.T, root string) {
			var value map[string]any
			strictDecodeTest(t, mustRead(t, filepath.Join(root, "outcomes.json")), &value)
			value["unexpected"] = true
			mustWrite(t, filepath.Join(root, "outcomes.json"), marshalJSON(t, value))
			rebindManifestAndEnvelope(t, root)
		}},
		{"wrong-outcomes-media-type", "outcomes_schema_invalid", func(t *testing.T, root string) {
			changeRoleMediaType(t, root, "outcomes", "application/octet-stream")
		}},
		{"wrong-core-media-type", "manifest_media_type_mismatch", func(t *testing.T, root string) {
			mutateManifest(t, root, func(value map[string]any) {
				for _, raw := range value["entries"].([]any) {
					entry := raw.(map[string]any)
					if entry["role"] == "summary" {
						entry["media_type"] = "text/plain"
					}
				}
			}, true)
		}},
		{"invalid-tool-profile-schema", "tool_profile_schema_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "tool-profile.json")
			var value map[string]any
			strictDecodeTest(t, mustRead(t, path), &value)
			value["unexpected"] = true
			mustWrite(t, path, marshalJSON(t, value))
			rebindManifestAndEnvelope(t, root)
		}},
		{"unknown-tool-profile-schema-version", "tool_profile_schema_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "tool-profile.json")
			var value map[string]any
			strictDecodeTest(t, mustRead(t, path), &value)
			value["schema_version"] = json.Number("99")
			mustWrite(t, path, marshalJSON(t, value))
			rebindManifestAndEnvelope(t, root)
		}},
		{"wrong-tool-profile-media-type", "tool_profile_schema_invalid", func(t *testing.T, root string) {
			changeRoleMediaType(t, root, "tool-profile", "application/octet-stream")
		}},
		{"invalid-observer-payload", "observer_evidence_schema_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "observer-target-1.dsse.json")
			mutateDSSEPayload(t, path, func(payload []byte) []byte { return append([]byte(" "), payload...) })
			rebindManifestAndEnvelope(t, root)
		}},
		{"wrong-observer-media-type", "observer_evidence_schema_invalid", func(t *testing.T, root string) {
			changeRoleMediaType(t, root, "observer-evidence", "application/octet-stream")
		}},
		{"invalid-opaque-json", "json_member_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "policy.json")
			mustWrite(t, path, []byte(`{"profile":"synthetic-policy/v1"} trailing`))
			rebindManifestAndEnvelope(t, root)
		}},
		{"trailing-json-member", "json_member_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "summary.json")
			mustWrite(t, path, append(mustRead(t, path), []byte("\nnull")...))
			rebindManifestAndEnvelope(t, root)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := schemaFixture(t)
			tc.mutate(t, root)
			assertSchemaResult(t, assessSchemaFixture(root), "FAIL", tc.reason)
		})
	}
}

func TestAssessSchemaRejectsInvalidClockPayload(t *testing.T) {
	root := schemaFixtureNamed(t, "golden", "g02-customer-completion-clock")
	var manifestValue manifest
	if _, err := strictJSON(mustRead(t, filepath.Join(root, "manifest.json")), &manifestValue); err != nil {
		t.Fatal(err)
	}
	var clockPath string
	for _, entry := range manifestValue.Entries {
		if entry.Role == "clock-evidence" {
			clockPath = filepath.Join(root, entry.Path)
			break
		}
	}
	if clockPath == "" {
		t.Fatal("golden clock fixture has no clock-evidence member")
	}
	mutateDSSEPayload(t, clockPath, func(payload []byte) []byte { return append([]byte(" "), payload...) })
	rebindManifestAndEnvelope(t, root)
	assertSchemaResult(t, assessSchemaFixture(root), "FAIL", "clock_evidence_schema_invalid")
}

func TestAssessSchemaRejectsWrongClockMediaType(t *testing.T) {
	root := schemaFixtureNamed(t, "golden", "g02-customer-completion-clock")
	changeRoleMediaType(t, root, "clock-evidence", "application/octet-stream")
	assertSchemaResult(t, assessSchemaFixture(root), "FAIL", "clock_evidence_schema_invalid")
}

func TestAssessSchemaDoesNotClaimSignatureAuthentication(t *testing.T) {
	root := schemaFixture(t)
	path := filepath.Join(root, "envelope.dsse.json")
	var wrapper map[string]any
	strictDecodeTest(t, mustRead(t, path), &wrapper)
	signatures := wrapper["signatures"].([]any)
	signature := signatures[0].(map[string]any)["sig"].(string)
	replacement := "A"
	if signature[0] == 'A' {
		replacement = "B"
	}
	signatures[0].(map[string]any)["sig"] = replacement + signature[1:]
	mustWrite(t, path, marshalJSON(t, wrapper))
	assertSchemaResult(t, assessSchemaFixture(root), "PASS", "package_format_valid")
}

func TestAssessSchemaDoesNotClaimRequiredArtifactCompleteness(t *testing.T) {
	root := schemaFixture(t)
	if err := os.Remove(filepath.Join(root, "policy.json")); err != nil {
		t.Fatal(err)
	}
	mutateManifest(t, root, func(value map[string]any) {
		entries := value["entries"].([]any)
		filtered := make([]any, 0, len(entries)-1)
		for _, raw := range entries {
			if raw.(map[string]any)["role"] != "policy" {
				filtered = append(filtered, raw)
			}
		}
		value["entries"] = filtered
	}, false)
	rebindManifestAndEnvelope(t, root)
	assertSchemaResult(t, assessSchemaFixture(root), "PASS", "package_format_valid")
}

func TestSchemaAssessmentMatchesPublishedSchema(t *testing.T) {
	result := assessSchemaFixture(schemaFixture(t))
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	schema := assessmentSchema(t)
	value, err := strictJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("assessment schema validation: %v\n%s", err, raw)
	}
}

func TestAssessmentSchemaRejectsIncompletePassClaims(t *testing.T) {
	schema := assessmentSchema(t)
	base, err := json.Marshal(assessSchemaFixture(schemaFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"schema-pass-without-manifest-digest", func(value map[string]any) {
			delete(value["evidence"].(map[string]any), "manifest_sha256")
		}},
		{"schema-pass-without-assessment-time", func(value map[string]any) {
			delete(value, "assessment_time")
		}},
		{"schema-pass-with-external-state", func(value map[string]any) {
			value["external_state"] = map[string]any{}
		}},
		{"authentication-pass-without-external-state", func(value map[string]any) {
			value["predicates"].([]any)[0].(map[string]any)["name"] = "authenticated-at(T)"
			delete(value["evidence"].(map[string]any), "manifest_sha256")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var value map[string]any
			if _, err := strictJSON(base, &value); err != nil {
				t.Fatal(err)
			}
			tc.mutate(value)
			if err := schema.Validate(value); err == nil {
				t.Fatal("assessment schema accepted incomplete PASS claim")
			}
		})
	}

	failure := AssessSchema(SchemaOptions{})
	raw, err := json.Marshal(failure)
	if err != nil {
		t.Fatal(err)
	}
	value, err := strictJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("schema rejected honest UNVERIFIABLE without evidence: %v", err)
	}
}

func assessmentSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	schemaPath := filepath.Join("..", "..", "..", "schemas", "control-evidence-assessment-v1.schema.json")
	schemaBytes := mustRead(t, schemaPath)
	compiler := jsonschema.NewCompiler()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("assessment.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("assessment.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func schemaFixture(t *testing.T) string {
	return schemaFixtureNamed(t, "golden", "g01-vendor-time")
}

func schemaFixtureNamed(t *testing.T, class, name string) string {
	t.Helper()
	source := filepath.Join("..", "conformance", class, name)
	destination := t.TempDir()
	err := filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == "." {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.Mkdir(target, 0o750)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(destination, "context.json"))
	_ = os.Remove(filepath.Join(destination, "expect.json"))
	return destination
}

func schemaOptions(packageDir string) SchemaOptions {
	return SchemaOptions{PackageDir: packageDir, VerifierName: "schema-test", VerifierVersion: "v1", VerifierSHA256: testVerifierDigest, AssessmentTime: time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)}
}

func assessSchemaFixture(packageDir string) SchemaAssessment {
	return AssessSchema(schemaOptions(packageDir))
}

func assertSchemaResult(t *testing.T, result SchemaAssessment, status, reason string) {
	t.Helper()
	if len(result.Predicates) != 1 || result.Predicates[0].Status != status || result.Predicates[0].Reason != reason {
		t.Fatalf("result = %#v, want %s/%s", result, status, reason)
	}
}

func mutateManifest(t *testing.T, root string, mutate func(map[string]any), rebind bool) {
	t.Helper()
	var value map[string]any
	strictDecodeTest(t, mustRead(t, filepath.Join(root, "manifest.json")), &value)
	mutate(value)
	mustWrite(t, filepath.Join(root, "manifest.json"), marshalJSON(t, value))
	if rebind {
		rebindEnvelope(t, root)
	}
}

func changeRoleMediaType(t *testing.T, root, role, mediaType string) {
	t.Helper()
	mutateManifest(t, root, func(value map[string]any) {
		for _, raw := range value["entries"].([]any) {
			entry := raw.(map[string]any)
			if entry["role"] == role {
				entry["media_type"] = mediaType
			}
		}
	}, true)
}

func rebindManifestAndEnvelope(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, "manifest.json")
	var value map[string]any
	strictDecodeTest(t, mustRead(t, path), &value)
	var total int64
	for _, raw := range value["entries"].([]any) {
		entry := raw.(map[string]any)
		data := mustRead(t, filepath.Join(root, entry["path"].(string)))
		entry["byte_length"] = json.Number(fmt.Sprint(len(data)))
		entry["sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
		total += int64(len(data))
	}
	value["total_uncompressed_bytes"] = json.Number(fmt.Sprint(total))
	mustWrite(t, path, marshalJSON(t, value))
	rebindEnvelope(t, root)
}

func rebindEnvelope(t *testing.T, root string) {
	t.Helper()
	mutateEnvelopePayload(t, root, func(payload []byte) []byte {
		var value map[string]any
		strictDecodeTest(t, payload, &value)
		artifacts := value["artifacts"].(map[string]any)
		manifestBytes := mustRead(t, filepath.Join(root, "manifest.json"))
		artifacts["manifest_sha256"] = fmt.Sprintf("%x", sha256.Sum256(manifestBytes))
		var manifestValue map[string]any
		strictDecodeTest(t, manifestBytes, &manifestValue)
		artifacts["count"] = json.Number(fmt.Sprint(len(manifestValue["entries"].([]any))))
		return marshalJSON(t, value)
	})
}

func mutateEnvelopePayload(t *testing.T, root string, mutate func([]byte) []byte) {
	t.Helper()
	mutateDSSEPayload(t, filepath.Join(root, "envelope.dsse.json"), mutate)
}

func mutateDSSEPayload(t *testing.T, path string, mutate func([]byte) []byte) {
	t.Helper()
	var wrapper map[string]any
	strictDecodeTest(t, mustRead(t, path), &wrapper)
	payload, err := base64.StdEncoding.Strict().DecodeString(wrapper["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	wrapper["payload"] = base64.StdEncoding.EncodeToString(mutate(payload))
	mustWrite(t, path, marshalJSON(t, wrapper))
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func strictDecodeTest(t *testing.T, data []byte, target any) {
	t.Helper()
	if _, err := strictJSON(data, target); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
