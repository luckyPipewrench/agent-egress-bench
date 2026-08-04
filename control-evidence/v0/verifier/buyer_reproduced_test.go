package verifier

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAssessBuyerReproduced(t *testing.T) {
	options, _, _, _ := buyerReproducedFixture(t)
	result := AssessBuyerReproduced(options)
	assertBuyerReproducedResult(t, result, "PASS", "buyer_signed_reproduction_matches")

	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var value any
	strictDecodeTest(t, raw, &value)
	if err := buyerAssessmentSchema(t).Validate(value); err != nil {
		t.Fatalf("assessment schema: %v", err)
	}
	if result.Evidence == nil || result.Evidence.ReproductionTranscriptSHA256 == "" ||
		result.Evidence.ReproductionStatementSHA256 == "" || result.Evidence.OutcomesProjectionSHA256 == "" {
		t.Fatalf("missing evidence bindings: %#v", result.Evidence)
	}
}

func TestAssessmentSchemaRejectsIncompleteBuyerReproducedPass(t *testing.T) {
	options, _, _, _ := buyerReproducedFixture(t)
	raw, err := json.Marshal(AssessBuyerReproduced(options))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		"envelope_payload_sha256",
		"reproduction_statement_sha256",
		"reproduction_payload_sha256",
		"reproduction_transcript_sha256",
		"outcomes_projection_sha256",
	} {
		t.Run(field, func(t *testing.T) {
			var value map[string]any
			strictDecodeTest(t, raw, &value)
			delete(value["evidence"].(map[string]any), field)
			if err := buyerAssessmentSchema(t).Validate(value); err == nil {
				t.Fatalf("assessment schema accepted buyer-reproduced PASS without %s", field)
			}
		})
	}
}

func TestAssessBuyerReproducedHostile(t *testing.T) {
	tests := []struct {
		name, reason string
		mutate       func(*testing.T, *buyerReproduction, string, string)
	}{
		{"source-envelope-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.EnvelopePayloadSHA256 = stringsOfA(64)
		}},
		{"source-requirement-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.RequirementPayloadSHA256 = stringsOfA(64)
		}},
		{"source-tool-profile-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.ToolProfileSHA256 = stringsOfA(64)
		}},
		{"source-runner-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.RunnerBinarySHA256 = stringsOfA(64)
		}},
		{"source-corpus-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.CorpusSHA256 = stringsOfA(64)
		}},
		{"source-corpus-manifest-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.CorpusManifestSHA256 = stringsOfA(64)
		}},
		{"source-scoring-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.ScoringVersion = "different"
		}},
		{"source-policy-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.PolicySHA256 = stringsOfA(64)
		}},
		{"source-adapter-binding", "buyer_statement_source_binding_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Source.AdapterSHA256 = stringsOfA(64)
		}},
		{"same-run-id", "reproduction_run_id_not_fresh", func(t *testing.T, statement *buyerReproduction, _, transcriptPath string) {
			statement.Reproduction.RunID = statement.Source.OriginalRunID
			transcript := readBuyerTranscript(t, transcriptPath)
			transcript.ReproductionRunID = statement.Source.OriginalRunID
			writeBuyerTranscript(t, transcriptPath, transcript)
			statement.Reproduction.TranscriptSHA256 = digestBytes(mustRead(t, transcriptPath))
		}},
		{"transcript-digest", "reproduction_transcript_digest_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Reproduction.TranscriptSHA256 = stringsOfA(64)
		}},
		{"projection-digest", "reproduction_projection_digest_mismatch", func(_ *testing.T, statement *buyerReproduction, _, _ string) {
			statement.Reproduction.OutcomesProjectionSHA256 = stringsOfA(64)
		}},
		{"outcomes-mismatch", "reproduction_outcomes_mismatch", func(t *testing.T, statement *buyerReproduction, _, transcriptPath string) {
			transcript := readBuyerTranscript(t, transcriptPath)
			transcript.Outcomes[0].ActualVerdict = "allow"
			transcript.Outcomes[0].Outcome = "fail"
			transcript.Outcomes[0].ScoringFacts.Classification = "incorrect"
			writeBuyerTranscript(t, transcriptPath, transcript)
			statement.Reproduction.TranscriptSHA256 = digestBytes(mustRead(t, transcriptPath))
			projection, ok := canonicalProjection(transcript.Outcomes)
			if !ok {
				t.Fatal("invalid test projection")
			}
			statement.Reproduction.OutcomesProjectionSHA256 = digestBytes(projection)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
			test.mutate(t, statement, statementPath, transcriptPath)
			writeBuyerStatement(t, statementPath, *statement, buyerTestKey("buyer"))
			result := AssessBuyerReproduced(options)
			assertBuyerReproducedResult(t, result, "FAIL", test.reason)
		})
	}
}

func TestAssessBuyerReproducedSignatureAndInputFailures(t *testing.T) {
	t.Run("rogue-signer", func(t *testing.T) {
		options, statement, statementPath, _ := buyerReproducedFixture(t)
		rogue := buyerTestKey("vendor-runner")
		statement.Signer.KeyID = hex.EncodeToString(rogue.Public().(ed25519.PublicKey))
		writeBuyerStatement(t, statementPath, *statement, rogue)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "buyer_statement_signer_mismatch")
	})
	t.Run("corrupted-signature", func(t *testing.T) {
		options, _, statementPath, _ := buyerReproducedFixture(t)
		var wrapper dsseEnvelope
		strictDecodeTest(t, mustRead(t, statementPath), &wrapper)
		signature, err := base64.StdEncoding.Strict().DecodeString(wrapper.Signatures[0].Sig)
		if err != nil {
			t.Fatal(err)
		}
		signature[0] ^= 0xff
		wrapper.Signatures[0].Sig = base64.StdEncoding.EncodeToString(signature)
		mustWrite(t, statementPath, marshalJSON(t, wrapper))
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "buyer_statement_signature_invalid")
	})
	t.Run("statement-inside-package", func(t *testing.T) {
		options, _, statementPath, _ := buyerReproducedFixture(t)
		inside := filepath.Join(options.PackageDir, "reproduction.dsse.json")
		if err := os.Rename(statementPath, inside); err != nil {
			t.Fatal(err)
		}
		options.StatementPath = inside
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_evidence_not_external")
	})
	t.Run("missing-transcript", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		options.TranscriptPath = filepath.Join(t.TempDir(), "missing")
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "UNVERIFIABLE", "reproduction_transcript_unavailable")
	})
	t.Run("empty-transcript", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		empty := filepath.Join(t.TempDir(), "empty.bin")
		mustWrite(t, empty, nil)
		options.TranscriptPath = empty
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "UNVERIFIABLE", "reproduction_transcript_unavailable")
	})
}

func TestAssessBuyerReproducedEarlyFailures(t *testing.T) {
	t.Run("invalid-verifier", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		options.VerifierName = ""
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "UNVERIFIABLE", "verifier_identity_invalid")
	})
	t.Run("default-assessment-time", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		options.AssessmentTime = time.Time{}
		result := AssessBuyerReproduced(options)
		assertBuyerReproducedResult(t, result, "PASS", "buyer_signed_reproduction_matches")
		if _, err := time.Parse(time.RFC3339, result.AssessmentTime); err != nil {
			t.Fatalf("assessment time = %q: %v", result.AssessmentTime, err)
		}
	})
	t.Run("missing-source", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		options.PackageDir = filepath.Join(t.TempDir(), "missing")
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "UNVERIFIABLE", "source_package_unavailable")
	})
	t.Run("missing-statement", func(t *testing.T) {
		options, _, _, _ := buyerReproducedFixture(t)
		options.StatementPath = filepath.Join(t.TempDir(), "missing")
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "UNVERIFIABLE", "reproduction_statement_unavailable")
	})
	t.Run("transcript-inside-package", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		inside := filepath.Join(options.PackageDir, "reproduction-transcript.json")
		mustWrite(t, inside, mustRead(t, transcriptPath))
		options.TranscriptPath = inside
		statement.Reproduction.TranscriptSHA256 = digestBytes(mustRead(t, inside))
		writeBuyerStatement(t, statementPath, *statement, buyerTestKey("buyer"))
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_evidence_not_external")
	})
	t.Run("statement-metadata-mismatch", func(t *testing.T) {
		options, statement, statementPath, _ := buyerReproducedFixture(t)
		statement.BuyerID = "different-buyer"
		writeBuyerStatement(t, statementPath, *statement, buyerTestKey("buyer"))
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "buyer_statement_signer_mismatch")
	})
}

func TestAssessBuyerReproducedRejectsMalformedSource(t *testing.T) {
	tests := []struct {
		name, reason string
		mutate       func(*testing.T, string)
	}{
		{"manifest-syntax", "source_manifest_invalid", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "manifest.json"), []byte("{"))
		}},
		{"manifest-closure", "source_manifest_invalid", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "undeclared.bin"), []byte("undeclared"))
		}},
		{"requirement-signature", "source_requirement_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "requirement.dsse.json")
			var wrapper dsseEnvelope
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			sig, err := base64.StdEncoding.Strict().DecodeString(wrapper.Signatures[0].Sig)
			if err != nil {
				t.Fatal(err)
			}
			sig[0] ^= 0xff
			wrapper.Signatures[0].Sig = base64.StdEncoding.EncodeToString(sig)
			mustWrite(t, path, marshalJSON(t, wrapper))
			rebindManifestAndEnvelope(t, root)
		}},
		{"envelope-structural", "source_envelope_invalid", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "envelope.dsse.json"), []byte("{}"))
		}},
		{"outcomes-schema", "source_outcomes_invalid", func(t *testing.T, root string) {
			mustWrite(t, filepath.Join(root, "outcomes.json"), []byte("{}"))
			rebindManifestAndEnvelope(t, root)
		}},
		{"outcomes-binding", "source_binding_invalid", func(t *testing.T, root string) {
			path := filepath.Join(root, "outcomes.json")
			var value map[string]any
			strictDecodeTest(t, mustRead(t, path), &value)
			value["run_id"] = stringsOfA(64)
			mustWrite(t, path, marshalJSON(t, value))
			rebindManifestAndEnvelope(t, root)
		}},
		{"input-binding", "source_input_binding_invalid", func(t *testing.T, root string) {
			mutateEnvelopePayload(t, root, func(payload []byte) []byte {
				var value map[string]any
				strictDecodeTest(t, payload, &value)
				value["runner"].(map[string]any)["binary_sha256"] = stringsOfA(64)
				return marshalJSON(t, value)
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, _, _, _ := buyerReproducedFixture(t)
			test.mutate(t, options.PackageDir)
			assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", test.reason)
		})
	}
}

func TestAssessBuyerReproducedRejectsMalformedStatement(t *testing.T) {
	tests := []struct {
		name, reason string
		mutate       func(*testing.T, string)
	}{
		{"wrapper", "buyer_statement_wrapper_invalid", func(t *testing.T, path string) {
			mustWrite(t, path, []byte("{"))
		}},
		{"payload-base64", "buyer_statement_wrapper_invalid", func(t *testing.T, path string) {
			var wrapper dsseEnvelope
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			wrapper.Payload = "AAAA="
			mustWrite(t, path, marshalJSON(t, wrapper))
		}},
		{"payload-not-jcs", "buyer_statement_payload_not_jcs", func(t *testing.T, path string) {
			var wrapper dsseEnvelope
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			wrapper.Payload = base64.StdEncoding.EncodeToString([]byte(" {}"))
			mustWrite(t, path, marshalJSON(t, wrapper))
		}},
		{"payload-schema", "buyer_statement_payload_invalid", func(t *testing.T, path string) {
			var wrapper dsseEnvelope
			strictDecodeTest(t, mustRead(t, path), &wrapper)
			wrapper.Payload = base64.StdEncoding.EncodeToString([]byte("{}"))
			mustWrite(t, path, marshalJSON(t, wrapper))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			options, _, statementPath, _ := buyerReproducedFixture(t)
			test.mutate(t, statementPath)
			assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", test.reason)
		})
	}
}

func TestAssessBuyerReproducedRejectsMalformedTranscript(t *testing.T) {
	t.Run("not-jcs", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		mustWrite(t, transcriptPath, append([]byte(" "), mustRead(t, transcriptPath)...))
		rebindBuyerTranscript(t, statement, statementPath, transcriptPath)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_transcript_not_jcs")
	})
	t.Run("schema", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		mustWrite(t, transcriptPath, []byte("{}"))
		rebindBuyerTranscript(t, statement, statementPath, transcriptPath)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_transcript_invalid")
	})
	t.Run("source-binding", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		transcript := readBuyerTranscript(t, transcriptPath)
		transcript.SourceEnvelopePayloadSHA256 = stringsOfA(64)
		writeBuyerTranscript(t, transcriptPath, transcript)
		rebindBuyerTranscript(t, statement, statementPath, transcriptPath)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_transcript_binding_mismatch")
	})
	t.Run("run-binding", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		transcript := readBuyerTranscript(t, transcriptPath)
		transcript.ReproductionRunID = stringsOfA(64)
		writeBuyerTranscript(t, transcriptPath, transcript)
		rebindBuyerTranscript(t, statement, statementPath, transcriptPath)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_transcript_binding_mismatch")
	})
	t.Run("contradictory-outcome", func(t *testing.T) {
		options, statement, statementPath, transcriptPath := buyerReproducedFixture(t)
		transcript := readBuyerTranscript(t, transcriptPath)
		transcript.Outcomes[0].Outcome = "fail"
		writeBuyerTranscript(t, transcriptPath, transcript)
		rebindBuyerTranscript(t, statement, statementPath, transcriptPath)
		assertBuyerReproducedResult(t, AssessBuyerReproduced(options), "FAIL", "reproduction_transcript_invalid")
	})
}

func TestCanonicalProjectionNormalizationAndRejection(t *testing.T) {
	_, _, _, transcriptPath := buyerReproducedFixture(t)
	rows := readBuyerTranscript(t, transcriptPath).Outcomes
	if _, ok := canonicalProjection(nil); ok {
		t.Fatal("empty projection accepted")
	}
	second := rows[0]
	second.CaseID += "-second"
	rows = append(rows, second)
	reversed := append([]buyerOutcomeProjection(nil), rows...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	want, ok := canonicalProjection(rows)
	if !ok {
		t.Fatal("fixture projection invalid")
	}
	got, ok := canonicalProjection(reversed)
	if !ok || !bytes.Equal(got, want) {
		t.Fatal("projection was not order-independent")
	}
	for _, mutate := range []func([]buyerOutcomeProjection){
		func(candidate []buyerOutcomeProjection) { candidate[0].CaseID = "" },
		func(candidate []buyerOutcomeProjection) { candidate[0].TrialIndex = 0 },
		func(candidate []buyerOutcomeProjection) { candidate[1] = candidate[0] },
		func(candidate []buyerOutcomeProjection) { candidate[0].Outcome = "fail" },
		func(candidate []buyerOutcomeProjection) { candidate[0].Outcome = "unknown" },
	} {
		candidate := append([]buyerOutcomeProjection(nil), rows...)
		mutate(candidate)
		if _, ok := canonicalProjection(candidate); ok {
			t.Fatalf("invalid projection accepted: %#v", candidate[0])
		}
	}
}

func TestValidLogicalProjectionRow(t *testing.T) {
	_, _, _, transcriptPath := buyerReproducedFixture(t)
	base := readBuyerTranscript(t, transcriptPath).Outcomes[0]
	if !validLogicalProjectionRow(base) {
		t.Fatal("valid pass/fail fixture row rejected")
	}

	notApplicable := base
	notApplicable.ActualVerdict = "not_applicable"
	notApplicable.Outcome = "not_applicable"
	notApplicable.ScoringFacts = scoringFacts{Classification: "not_applicable", BudgetTiming: "not_measured", StructuredEvidence: "not_applicable"}
	notApplicable.NotApplicableReason = "unsupported transport"
	if !validLogicalProjectionRow(notApplicable) {
		t.Fatal("valid not-applicable row rejected")
	}
	notApplicable.ErrorReason = "contradiction"
	if validLogicalProjectionRow(notApplicable) {
		t.Fatal("not-applicable row with error reason accepted")
	}

	errorRow := base
	errorRow.ActualVerdict = "error"
	errorRow.Outcome = "error"
	errorRow.ScoringFacts = scoringFacts{Classification: "error", BudgetTiming: "not_measured", StructuredEvidence: "not_applicable"}
	errorRow.ErrorReason = "runner timeout"
	if !validLogicalProjectionRow(errorRow) {
		t.Fatal("valid error row rejected")
	}
	errorRow.NotApplicableReason = "contradiction"
	if validLogicalProjectionRow(errorRow) {
		t.Fatal("error row with not-applicable reason accepted")
	}
}

func TestReadExternalBounded(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside.json")
	mustWrite(t, inside, []byte("{}"))
	outside := filepath.Join(t.TempDir(), "outside.json")
	mustWrite(t, outside, []byte("{}"))
	if _, err := readExternalBounded(root, inside, 16); !errors.Is(err, errEvidenceNotExternal) {
		t.Fatalf("inside evidence error = %v, want not-external", err)
	}
	if data, err := readExternalBounded(root, outside, 16); err != nil || string(data) != "{}" {
		t.Fatalf("outside evidence = %q, %v", data, err)
	}
	if _, err := readExternalBounded(filepath.Join(root, "missing"), outside, 16); err == nil {
		t.Fatal("missing root accepted")
	}
	if _, err := readExternalBounded(root, filepath.Join(root, "missing"), 16); err == nil {
		t.Fatal("missing evidence accepted")
	}
	if _, err := readExternalBounded(inside, outside, 16); err == nil {
		t.Fatal("regular file accepted as package root")
	}
	if _, err := readExternalBounded(root, t.TempDir(), 16); err == nil {
		t.Fatal("directory accepted as evidence file")
	}
	symlink := filepath.Join(t.TempDir(), "evidence-link.json")
	if err := os.Symlink(outside, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readExternalBounded(root, symlink, 16); err == nil {
		t.Fatal("symlink evidence accepted")
	}
	if _, err := readExternalBounded(root, outside, 1); err == nil {
		t.Fatal("oversized evidence accepted")
	}
	replacePath := filepath.Join(t.TempDir(), "replace.json")
	replacementPath := filepath.Join(t.TempDir(), "replacement.json")
	mustWrite(t, replacePath, []byte("original"))
	mustWrite(t, replacementPath, []byte("replacement"))
	swapped := false
	_, replacementErr := readExternalBoundedWithHook(root, replacePath, 32, func() error {
		if err := os.Rename(replacementPath, replacePath); err != nil {
			return err
		}
		swapped = true
		return nil
	})
	if !swapped {
		t.Fatal("test did not replace evidence after open")
	}
	if replacementErr == nil {
		t.Fatal("evidence replacement after open was accepted")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeRoot, err := filepath.Rel(workingDir, root)
	if err != nil {
		t.Fatal(err)
	}
	if !pathOutsideRoot(relativeRoot, outside) {
		t.Fatal("mixed relative/absolute external path rejected")
	}
}

func TestBuyerReproductionTranscriptSchemaBindsClassification(t *testing.T) {
	_, _, _, transcriptPath := buyerReproducedFixture(t)
	transcript := readBuyerTranscript(t, transcriptPath)
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	validate := func(candidate buyerReproductionTranscript) error {
		value, err := strictJSON(marshalJSON(t, candidate), nil)
		if err != nil {
			return err
		}
		return validateSchema(schemas.buyerReproductionTranscript, value)
	}
	if err := validate(transcript); err != nil {
		t.Fatalf("valid transcript rejected: %v", err)
	}
	transcript.Outcomes[0].ScoringFacts.Classification = "incorrect"
	if err := validate(transcript); err == nil {
		t.Fatal("pass outcome with incorrect classification accepted")
	}
	transcript.Outcomes[0].Outcome = "fail"
	if err := validate(transcript); err != nil {
		t.Fatalf("fail outcome with incorrect classification rejected: %v", err)
	}
}

func TestBuyerReproductionStatementLimitCoversPublishedPayloadMaximum(t *testing.T) {
	const compactWrapperOverhead = int64(512)
	var published struct {
		Properties struct {
			Payload struct {
				MaxLength int64 `json:"maxLength"`
			} `json:"payload"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(mustRead(t, filepath.Join("..", "..", "..", "schemas", "control-evidence-buyer-reproduction-statement.schema.json")), &published); err != nil {
		t.Fatal(err)
	}
	if published.Properties.Payload.MaxLength < 1 {
		t.Fatal("published statement schema has no payload maximum")
	}
	if maxReproductionStatement < published.Properties.Payload.MaxLength+compactWrapperOverhead {
		t.Fatalf("statement limit %d cannot hold maximum payload plus wrapper", maxReproductionStatement)
	}
}

func TestBuyerReproductionEmbeddedSchemasMatchCanonical(t *testing.T) {
	for _, name := range []string{
		"control-evidence-buyer-reproduction.schema.json",
		"control-evidence-buyer-reproduction-statement.schema.json",
		"control-evidence-buyer-reproduction-transcript.schema.json",
	} {
		embedded, err := embeddedSchemas.ReadFile(filepath.Join("schemas", name))
		if err != nil {
			t.Fatal(err)
		}
		canonical := mustRead(t, filepath.Join("..", "..", "..", "schemas", name))
		if string(embedded) != string(canonical) {
			t.Fatalf("embedded %s differs from canonical schema", name)
		}
	}
}

func buyerReproducedFixture(t *testing.T) (BuyerReproducedOptions, *buyerReproduction, string, string) {
	t.Helper()
	root := schemaFixture(t)
	schemas, err := loadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	files, err := loadDirectoryPackageWithOptions(root, false)
	if err != nil {
		t.Fatal(err)
	}
	source, reason := loadBuyerReproductionSource(files, schemas)
	if reason != "" {
		t.Fatal(reason)
	}
	external := t.TempDir()
	projection, ok := canonicalProjection(source.outcomes)
	if !ok {
		t.Fatal("source projection invalid")
	}
	statement := &buyerReproduction{Profile: buyerReproductionProfile, BuyerID: source.requirement.BuyerID}
	statement.Signer.KeyID = source.requirementSignerKeyID
	statement.Signer.Role = "buyer-reproducer"
	statement.Source.EnvelopePayloadSHA256 = source.envelopePayloadSHA256
	statement.Source.RequirementPayloadSHA256 = source.requirementPayloadSHA256
	statement.Source.ToolProfileSHA256 = source.toolProfileSHA256
	statement.Source.RunnerBinarySHA256 = source.envelope.Runner.BinarySHA256
	statement.Source.CorpusSHA256 = source.envelope.Corpus.CorpusSHA256
	statement.Source.CorpusManifestSHA256 = source.envelope.Corpus.ManifestSHA256
	statement.Source.ScoringVersion = source.envelope.Corpus.ScoringVersion
	statement.Source.PolicySHA256 = source.envelope.Policy.SHA256
	statement.Source.AdapterSHA256 = source.envelope.Adapter.SHA256
	statement.Source.OriginalRunID = source.envelope.RunID
	statement.Reproduction.RunID = digestBytes([]byte("buyer reproduction run"))
	transcriptPath := filepath.Join(external, "reproduction-transcript.json")
	writeBuyerTranscript(t, transcriptPath, buyerReproductionTranscript{
		Profile:                     "control-evidence-buyer-reproduction-transcript/v0",
		SourceEnvelopePayloadSHA256: source.envelopePayloadSHA256,
		ReproductionRunID:           statement.Reproduction.RunID,
		Outcomes:                    append([]buyerOutcomeProjection(nil), source.outcomes...),
	})
	statement.Reproduction.TranscriptSHA256 = digestBytes(mustRead(t, transcriptPath))
	statement.Reproduction.OutcomesProjectionSHA256 = digestBytes(projection)

	statementPath := filepath.Join(external, "buyer-reproduction.dsse.json")
	writeBuyerStatement(t, statementPath, *statement, buyerTestKey("buyer"))
	return BuyerReproducedOptions{
		PackageDir: root, StatementPath: statementPath, TranscriptPath: transcriptPath,
		VerifierName: "buyer-reproduction-test", VerifierVersion: "v1",
		VerifierSHA256: testVerifierDigest, AssessmentTime: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC),
	}, statement, statementPath, transcriptPath
}

func readBuyerTranscript(t *testing.T, path string) buyerReproductionTranscript {
	t.Helper()
	var transcript buyerReproductionTranscript
	strictDecodeTest(t, mustRead(t, path), &transcript)
	return transcript
}

func writeBuyerTranscript(t *testing.T, path string, transcript buyerReproductionTranscript) {
	t.Helper()
	mustWrite(t, path, marshalJSON(t, transcript))
}

func rebindBuyerTranscript(t *testing.T, statement *buyerReproduction, statementPath, transcriptPath string) {
	t.Helper()
	statement.Reproduction.TranscriptSHA256 = digestBytes(mustRead(t, transcriptPath))
	writeBuyerStatement(t, statementPath, *statement, buyerTestKey("buyer"))
}

func buyerAssessmentSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	data := mustRead(t, filepath.Join("..", "..", "..", "schemas", "control-evidence-assessment-v2.schema.json"))
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("assessment-v2.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("assessment-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func writeBuyerStatement(t *testing.T, path string, statement buyerReproduction, privateKey ed25519.PrivateKey) {
	t.Helper()
	raw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	wrapper := dsseEnvelope{
		PayloadType: buyerReproductionType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []dsseSignature{{
			KeyID: hex.EncodeToString(publicKey),
			Sig:   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, pae(buyerReproductionType, payload))),
		}},
	}
	mustWrite(t, path, marshalJSON(t, wrapper))
}

func buyerTestKey(role string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("agent-egress-bench-control-evidence-" + role + "-test-key-v0"))
	return ed25519.NewKeyFromSeed(seed[:])
}

func assertBuyerReproducedResult(t *testing.T, result BuyerReproducedAssessment, status, reason string) {
	t.Helper()
	if len(result.Predicates) != 1 || result.Predicates[0].Status != status || result.Predicates[0].Reason != reason {
		t.Fatalf("result = %#v, want %s/%s", result, status, reason)
	}
}

func stringsOfA(length int) string {
	value := make([]byte, length)
	for i := range value {
		value[i] = 'a'
	}
	return string(value)
}
