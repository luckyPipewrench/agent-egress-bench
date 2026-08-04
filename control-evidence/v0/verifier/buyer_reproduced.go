package verifier

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	buyerReproductionProfile  = "control-evidence-buyer-reproduction/v0"
	buyerReproductionType     = "application/vnd.agent-egress-bench.control-evidence-buyer-reproduction.v0+json"
	buyerAssessmentProfile    = "control-evidence-assessment/v2"
	maxReproductionStatement  = int64(2 << 20)
	maxReproductionTranscript = int64(64 << 20)
)

type BuyerReproducedOptions struct {
	PackageDir      string
	StatementPath   string
	TranscriptPath  string
	VerifierName    string
	VerifierVersion string
	VerifierSHA256  string
	AssessmentTime  time.Time
}

type BuyerReproducedEvidence struct {
	EnvelopePayloadSHA256        string `json:"envelope_payload_sha256"`
	ReproductionStatementSHA256  string `json:"reproduction_statement_sha256"`
	ReproductionPayloadSHA256    string `json:"reproduction_payload_sha256"`
	ReproductionTranscriptSHA256 string `json:"reproduction_transcript_sha256"`
	OutcomesProjectionSHA256     string `json:"outcomes_projection_sha256"`
}

type BuyerReproducedAssessment struct {
	Profile        string `json:"profile"`
	AssessmentTime string `json:"assessment_time,omitempty"`
	Verifier       struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	} `json:"verifier"`
	Evidence   *BuyerReproducedEvidence `json:"evidence,omitempty"`
	Predicates []AssessmentPredicate    `json:"predicates"`
}

type buyerReproduction struct {
	Profile string `json:"profile"`
	BuyerID string `json:"buyer_id"`
	Signer  struct {
		KeyID string `json:"key_id"`
		Role  string `json:"role"`
	} `json:"signer"`
	Source struct {
		EnvelopePayloadSHA256    string `json:"envelope_payload_sha256"`
		RequirementPayloadSHA256 string `json:"requirement_payload_sha256"`
		ToolProfileSHA256        string `json:"tool_profile_sha256"`
		RunnerBinarySHA256       string `json:"runner_binary_sha256"`
		CorpusSHA256             string `json:"corpus_sha256"`
		CorpusManifestSHA256     string `json:"corpus_manifest_sha256"`
		ScoringVersion           string `json:"scoring_version"`
		PolicySHA256             string `json:"policy_sha256"`
		AdapterSHA256            string `json:"adapter_sha256"`
		OriginalRunID            string `json:"original_run_id"`
	} `json:"source"`
	Reproduction struct {
		RunID                    string `json:"run_id"`
		TranscriptSHA256         string `json:"transcript_sha256"`
		OutcomesProjectionSHA256 string `json:"outcomes_projection_sha256"`
	} `json:"reproduction"`
}

type buyerReproductionTranscript struct {
	Profile                     string                   `json:"profile"`
	SourceEnvelopePayloadSHA256 string                   `json:"source_envelope_payload_sha256"`
	ReproductionRunID           string                   `json:"reproduction_run_id"`
	Outcomes                    []buyerOutcomeProjection `json:"outcomes"`
}

type buyerOutcomeProjection struct {
	CaseID              string       `json:"case_id"`
	TrialIndex          int          `json:"trial_index"`
	Transport           string       `json:"transport"`
	ExpectedVerdict     string       `json:"expected_verdict"`
	ActualVerdict       string       `json:"actual_verdict"`
	Outcome             string       `json:"outcome"`
	ScoringFacts        scoringFacts `json:"scoring_facts"`
	NotApplicableReason string       `json:"not_applicable_reason,omitempty"`
	ErrorReason         string       `json:"error_reason,omitempty"`
}

func AssessBuyerReproduced(options BuyerReproducedOptions) BuyerReproducedAssessment {
	result := BuyerReproducedAssessment{Profile: buyerAssessmentProfile}
	result.Verifier.Name = options.VerifierName
	result.Verifier.Version = options.VerifierVersion
	if lowerHexDigest(options.VerifierSHA256) {
		result.Verifier.SHA256 = options.VerifierSHA256
	}
	finish := func(status, reason string) BuyerReproducedAssessment {
		result.Predicates = []AssessmentPredicate{{Name: "buyer-reproduced", Status: status, Reason: reason}}
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
		return finish("UNVERIFIABLE", "source_package_unavailable")
	}
	statementBytes, err := readExternalBounded(options.PackageDir, options.StatementPath, maxReproductionStatement)
	if err != nil {
		if errors.Is(err, errEvidenceNotExternal) {
			return finish("FAIL", "reproduction_evidence_not_external")
		}
		return finish("UNVERIFIABLE", "reproduction_statement_unavailable")
	}
	transcriptBytes, err := readExternalBounded(options.PackageDir, options.TranscriptPath, maxReproductionTranscript)
	if err != nil || len(transcriptBytes) == 0 {
		if errors.Is(err, errEvidenceNotExternal) {
			return finish("FAIL", "reproduction_evidence_not_external")
		}
		return finish("UNVERIFIABLE", "reproduction_transcript_unavailable")
	}
	files, err := loadDirectoryPackageWithOptions(options.PackageDir, false)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return finish("UNVERIFIABLE", "source_package_unavailable")
		}
		return finish("FAIL", "source_package_invalid")
	}
	source, reason := loadBuyerReproductionSource(files, schemas)
	if reason != "" {
		return finish("FAIL", reason)
	}
	statement, payload, signerKeyID, reason := verifyBuyerReproductionStatement(statementBytes, source.requirementSignerKeyID, schemas)
	if reason != "" {
		return finish("FAIL", reason)
	}
	if statement.Profile != buyerReproductionProfile || statement.BuyerID != source.requirement.BuyerID ||
		statement.Signer.KeyID != signerKeyID || statement.Signer.Role != "buyer-reproducer" {
		return finish("FAIL", "buyer_statement_signer_mismatch")
	}
	if !buyerSourceMatches(statement, source) {
		return finish("FAIL", "buyer_statement_source_binding_mismatch")
	}
	if statement.Reproduction.RunID == source.envelope.RunID {
		return finish("FAIL", "reproduction_run_id_not_fresh")
	}
	transcriptDigest := digestBytes(transcriptBytes)
	if statement.Reproduction.TranscriptSHA256 != transcriptDigest {
		return finish("FAIL", "reproduction_transcript_digest_mismatch")
	}
	transcript, reason := verifyBuyerReproductionTranscript(transcriptBytes, schemas)
	if reason != "" {
		return finish("FAIL", reason)
	}
	if transcript.SourceEnvelopePayloadSHA256 != source.envelopePayloadSHA256 ||
		transcript.ReproductionRunID != statement.Reproduction.RunID {
		return finish("FAIL", "reproduction_transcript_binding_mismatch")
	}
	reproducedProjection, ok := canonicalProjection(transcript.Outcomes)
	if !ok {
		return finish("FAIL", "reproduction_transcript_invalid")
	}
	if digestBytes(reproducedProjection) != statement.Reproduction.OutcomesProjectionSHA256 {
		return finish("FAIL", "reproduction_projection_digest_mismatch")
	}
	sourceProjection, ok := canonicalProjection(source.outcomes)
	if !ok || !bytes.Equal(sourceProjection, reproducedProjection) {
		return finish("FAIL", "reproduction_outcomes_mismatch")
	}
	result.Evidence = &BuyerReproducedEvidence{
		EnvelopePayloadSHA256:        source.envelopePayloadSHA256,
		ReproductionStatementSHA256:  digestBytes(statementBytes),
		ReproductionPayloadSHA256:    digestBytes(payload),
		ReproductionTranscriptSHA256: transcriptDigest,
		OutcomesProjectionSHA256:     digestBytes(reproducedProjection),
	}
	return finish("PASS", "buyer_signed_reproduction_matches")
}

func verifyBuyerReproductionTranscript(data []byte, schemas *schemaSet) (buyerReproductionTranscript, string) {
	var transcript buyerReproductionTranscript
	if err := canonicalJSON(data); err != nil {
		return transcript, "reproduction_transcript_not_jcs"
	}
	value, err := strictJSON(data, &transcript)
	if err != nil || validateSchema(schemas.buyerReproductionTranscript, value) != nil {
		return transcript, "reproduction_transcript_invalid"
	}
	return transcript, ""
}

type buyerReproductionSource struct {
	requirement              requirement
	envelope                 runEnvelope
	outcomes                 []buyerOutcomeProjection
	requirementPayloadSHA256 string
	envelopePayloadSHA256    string
	toolProfileSHA256        string
	requirementSignerKeyID   string
}

func loadBuyerReproductionSource(files map[string][]byte, schemas *schemaSet) (buyerReproductionSource, string) {
	var source buyerReproductionSource
	var packageManifest manifest
	manifestValue, err := strictJSON(files["manifest.json"], &packageManifest)
	if err != nil || validateSchema(schemas.manifest, manifestValue) != nil {
		return source, "source_manifest_invalid"
	}
	entriesByRole := make(map[string][]manifestEntry)
	for _, entry := range packageManifest.Entries {
		entriesByRole[entry.Role] = append(entriesByRole[entry.Role], entry)
	}
	if reason := validateManifestPackage(files, packageManifest, entriesByRole); reason != "" {
		return source, "source_manifest_invalid"
	}
	req, _, err := verifyDSSE[requirement](files["requirement.dsse.json"], typeRequirement, "", schemas, schemas.requirement)
	if err != nil {
		return source, "source_requirement_invalid"
	}
	env, reason := validateStructuralDSSE[runEnvelope](files["envelope.dsse.json"], typeEnvelope, schemas, schemas.envelope)
	if reason != "" {
		return source, "source_envelope_invalid"
	}
	var sourceOutcomes outcomes
	outcomesValue, err := strictJSON(files["outcomes.json"], &sourceOutcomes)
	if err != nil || validateSchema(schemas.outcomes, outcomesValue) != nil {
		return source, "source_outcomes_invalid"
	}
	requirementDigest := digestBytes(req.PayloadBytes)
	if env.Payload.RequirementSHA256 != requirementDigest || sourceOutcomes.RequirementSHA256 != requirementDigest ||
		sourceOutcomes.RunID != env.Payload.RunID || env.Payload.Observations.SHA256 != digestBytes(files["outcomes.json"]) ||
		env.Payload.Observations.RowCount != len(sourceOutcomes.Rows) {
		return source, "source_binding_invalid"
	}
	if env.Payload.Artifacts.ManifestSHA256 != digestBytes(files["manifest.json"]) || env.Payload.Artifacts.Count != len(packageManifest.Entries) {
		return source, "source_binding_invalid"
	}
	profiles := entriesByRole["tool-profile"]
	if len(profiles) != 1 || profiles[0].SHA256 != req.Payload.ApprovedToolProfile.SHA256 ||
		env.Payload.Runner.BinarySHA256 != req.Payload.ApprovedRunner.SHA256 ||
		env.Payload.Policy.SHA256 != req.Payload.ApprovedPolicy.SHA256 ||
		env.Payload.Adapter.SHA256 != req.Payload.ApprovedAdapter.SHA256 {
		return source, "source_input_binding_invalid"
	}
	source.requirement = req.Payload
	source.envelope = env.Payload
	source.requirementPayloadSHA256 = requirementDigest
	source.envelopePayloadSHA256 = digestBytes(env.PayloadBytes)
	source.toolProfileSHA256 = profiles[0].SHA256
	source.requirementSignerKeyID = req.SignerKeyID
	source.outcomes = make([]buyerOutcomeProjection, len(sourceOutcomes.Rows))
	for i, row := range sourceOutcomes.Rows {
		source.outcomes[i] = buyerOutcomeProjection{
			CaseID: row.CaseID, TrialIndex: row.TrialIndex, Transport: row.Transport,
			ExpectedVerdict: row.ExpectedVerdict, ActualVerdict: row.ActualVerdict, Outcome: row.Outcome,
			ScoringFacts: row.ScoringFacts, NotApplicableReason: row.NotApplicableReason, ErrorReason: row.ErrorReason,
		}
	}
	return source, ""
}

func verifyBuyerReproductionStatement(data []byte, requiredSigner string, schemas *schemaSet) (buyerReproduction, []byte, string, string) {
	var statement buyerReproduction
	var wrapper dsseEnvelope
	wrapperValue, err := strictJSON(data, &wrapper)
	if err != nil || validateSchema(schemas.buyerReproductionStatement, wrapperValue) != nil ||
		wrapper.PayloadType != buyerReproductionType || len(wrapper.Signatures) != 1 {
		return statement, nil, "", "buyer_statement_wrapper_invalid"
	}
	payload, err := decodeBase64(wrapper.Payload)
	if err != nil {
		return statement, nil, "", "buyer_statement_wrapper_invalid"
	}
	if err := canonicalJSON(payload); err != nil {
		return statement, nil, "", "buyer_statement_payload_not_jcs"
	}
	payloadValue, err := strictJSON(payload, &statement)
	if err != nil || validateSchema(schemas.buyerReproduction, payloadValue) != nil {
		return statement, nil, "", "buyer_statement_payload_invalid"
	}
	signature := wrapper.Signatures[0]
	if signature.KeyID != requiredSigner {
		return statement, nil, "", "buyer_statement_signer_mismatch"
	}
	publicKey, err := hex.DecodeString(signature.KeyID)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return statement, nil, "", "buyer_statement_signer_invalid"
	}
	signatureBytes, err := decodeBase64(signature.Sig)
	if err != nil || len(signatureBytes) != ed25519.SignatureSize ||
		!ed25519.Verify(ed25519.PublicKey(publicKey), pae(wrapper.PayloadType, payload), signatureBytes) {
		return statement, nil, "", "buyer_statement_signature_invalid"
	}
	return statement, payload, signature.KeyID, ""
}

func buyerSourceMatches(statement buyerReproduction, source buyerReproductionSource) bool {
	return statement.Source.EnvelopePayloadSHA256 == source.envelopePayloadSHA256 &&
		statement.Source.RequirementPayloadSHA256 == source.requirementPayloadSHA256 &&
		statement.Source.ToolProfileSHA256 == source.toolProfileSHA256 &&
		statement.Source.RunnerBinarySHA256 == source.envelope.Runner.BinarySHA256 &&
		statement.Source.CorpusSHA256 == source.envelope.Corpus.CorpusSHA256 &&
		statement.Source.CorpusManifestSHA256 == source.envelope.Corpus.ManifestSHA256 &&
		statement.Source.ScoringVersion == source.envelope.Corpus.ScoringVersion &&
		statement.Source.PolicySHA256 == source.envelope.Policy.SHA256 &&
		statement.Source.AdapterSHA256 == source.envelope.Adapter.SHA256 &&
		statement.Source.OriginalRunID == source.envelope.RunID
}

func canonicalProjection(rows []buyerOutcomeProjection) ([]byte, bool) {
	if len(rows) == 0 {
		return nil, false
	}
	sorted := append([]buyerOutcomeProjection(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].CaseID == sorted[j].CaseID {
			return sorted[i].TrialIndex < sorted[j].TrialIndex
		}
		return sorted[i].CaseID < sorted[j].CaseID
	})
	for i := range sorted {
		if sorted[i].CaseID == "" || sorted[i].TrialIndex < 1 ||
			(i > 0 && sorted[i].CaseID == sorted[i-1].CaseID && sorted[i].TrialIndex == sorted[i-1].TrialIndex) ||
			!validLogicalProjectionRow(sorted[i]) {
			return nil, false
		}
	}
	raw, err := json.Marshal(sorted)
	if err != nil {
		return nil, false
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return nil, false
	}
	return canonical, true
}

func validLogicalProjectionRow(row buyerOutcomeProjection) bool {
	switch row.Outcome {
	case "pass", "fail":
		matches := row.ActualVerdict == row.ExpectedVerdict
		return (row.Outcome == "pass") == matches &&
			(row.Outcome == "pass") == (row.ScoringFacts.Classification == "correct") &&
			row.NotApplicableReason == "" && row.ErrorReason == ""
	case "not_applicable":
		return row.ActualVerdict == "not_applicable" &&
			row.ScoringFacts.Classification == "not_applicable" &&
			row.ScoringFacts.BudgetTiming == "not_measured" &&
			row.ScoringFacts.StructuredEvidence == "not_applicable" &&
			row.NotApplicableReason != "" && row.ErrorReason == ""
	case "error":
		return row.ActualVerdict == "error" &&
			row.ScoringFacts.Classification == "error" &&
			row.ScoringFacts.BudgetTiming == "not_measured" &&
			row.ScoringFacts.StructuredEvidence == "not_applicable" &&
			row.ErrorReason != "" && row.NotApplicableReason == ""
	default:
		return false
	}
}
