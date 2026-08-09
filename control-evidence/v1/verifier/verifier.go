package verifier

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	resultProfile   = "control-evidence-verification-result/v1"
	maxMemberSize   = int64(64 << 20)
	maxTotalSize    = int64(256 << 20)
	maxMembers      = 258 // 256 manifest entries plus manifest.json and envelope.dsse.json.
	maxTreeEntries  = 512
	maxPackageDepth = 8
)

type verificationState struct {
	packageDir      string
	files           map[string][]byte
	schemas         *schemaSet
	context         verifierContext
	req             *verifiedDSSE[requirement]
	env             *verifiedDSSE[runEnvelope]
	manifest        manifest
	outcomes        outcomes
	summary         map[string]any
	toolProfile     map[string]any
	entriesByRole   map[string][]manifestEntry
	entriesByDigest map[string]manifestEntry
}

// VerifyOptions supplies trust inputs that must remain outside the evidence
// package. ReplayLedgerDir must name a buyer-controlled private directory.
type VerifyOptions struct {
	ContextPath     string
	ReplayLedgerDir string
}

func failure(outcome, reason string) *Result {
	return &Result{Profile: resultProfile, Outcome: outcome, Reason: reason}
}

func success(nonceStatus, requirementSHA, runID string) Result {
	return Result{Profile: resultProfile, Outcome: OutcomeValid, NonceStatus: nonceStatus, RequirementSHA256: requirementSHA, RunID: runID}
}

// Verify evaluates a package without durable replay state. It can return
// semantic failures, but an otherwise-valid package is unverifiable because a
// stateless caller cannot safely consume a single-use challenge nonce.
func Verify(packageDir, contextPath string) Result {
	return VerifyWithOptions(packageDir, VerifyOptions{ContextPath: contextPath})
}

// VerifyWithOptions evaluates one directory package against independently
// supplied context and durable replay state. It never reads expect.json and
// never imports the fixture generator.
func VerifyWithOptions(packageDir string, options VerifyOptions) Result {
	schemas, err := loadSchemas()
	if err != nil {
		return *failure(outcomeInvalid, "verifier_schema_load_failed")
	}
	state := &verificationState{packageDir: packageDir, schemas: schemas}
	contextBytes, err := readBounded(options.ContextPath, maxMemberSize)
	if err != nil {
		return *failure(outcomeUnverifiable, "context_unavailable")
	}
	contextValue, err := strictJSON(contextBytes, &state.context)
	if err != nil {
		return *failure(outcomeInvalid, "context_invalid")
	}
	if err := validateSchema(schemas.context, contextValue); err != nil {
		return *failure(outcomeInvalid, "context_invalid")
	}
	if duplicateNonceTuple(state.context.NonceLedger) {
		return *failure(outcomeInvalid, "ambiguous_replay_ledger")
	}
	state.files, err = loadDirectoryPackage(packageDir)
	if err != nil {
		return *failure(outcomeInvalid, "package_invalid")
	}

	reqPeek := peekPayload(state.files["requirement.dsse.json"])
	if numberField(reqPeek, "minimum_trials_per_case") != 1 {
		return *failure(outcomeInvalid, "minimum_trials_per_case_unsupported")
	}
	var reason string
	state.req, reason, err = verifyDSSE[requirement](state.files["requirement.dsse.json"], typeRequirement, state.context.TrustedKeys.Buyer, schemas, schemas.requirement)
	if err != nil {
		return *failure(outcomeInvalid, reason)
	}
	if digestBytes(state.req.PayloadBytes) != state.context.RequirementPayloadSHA256 {
		return *failure(outcomeScopeMismatch, "requirement_pin_mismatch")
	}
	if state.req.Payload.TrustPolicyID != state.context.TrustPolicy.ID || state.req.Payload.TrustPolicySHA256 != state.context.TrustPolicy.SHA256 {
		return *failure(outcomeScopeMismatch, "trust_policy_mismatch")
	}
	if overlapping(state.req.Payload.RequiredPositiveCanaries, state.req.Payload.RequiredNegativeCanaries) {
		return *failure(outcomeInvalid, "required_canary_polarity_overlap")
	}
	if _, ok := requiredCaseExpectations(state.req.Payload); !ok {
		return *failure(outcomeInvalid, "required_case_expectations_invalid")
	}

	envPeek := peekPayload(state.files["envelope.dsse.json"])
	if nestedString(envPeek, "runner", "execution_mode") != "approved-binary" {
		return *failure(outcomeInvalid, "runner_execution_mode_unsupported")
	}
	state.env, reason, err = verifyDSSE[runEnvelope](state.files["envelope.dsse.json"], typeEnvelope, state.context.TrustedKeys.VendorRunner, schemas, schemas.envelope)
	if err != nil {
		return *failure(outcomeInvalid, reason)
	}
	if state.env.Payload.Corpus.Version != state.context.Corpus.Version || state.env.Payload.Corpus.CorpusSHA256 != state.context.Corpus.SHA256 ||
		state.env.Payload.Corpus.ManifestSHA256 != state.context.Corpus.ManifestSHA256 || state.env.Payload.Corpus.ScoringVersion != state.context.Corpus.ScoringVersion {
		return *failure(outcomeScopeMismatch, "corpus_identity_mismatch")
	}
	replay, result := state.prepareReplay(options.ReplayLedgerDir)
	if result != nil {
		return *result
	}
	if result := state.loadCoreArtifacts(); result != nil {
		return *result
	}
	if result := state.verifyBindingsAndManifest(); result != nil {
		return *result
	}
	if result := state.verifyRegistryBinding(); result != nil {
		return *result
	}
	if result := state.verifyScopeAndTime(); result != nil {
		return *result
	}
	materials, result := resolveMaterials(state.req.Payload, state.context, state.entriesByRole, state.files, schemas)
	if result != nil {
		return *result
	}
	if result := state.verifyOutcomesAndEvidence(materials); result != nil {
		return *result
	}
	if result := state.verifySummary(); result != nil {
		return *result
	}
	nonceStatus, result := replay.commit()
	if result != nil {
		return *result
	}
	return success(nonceStatus, digestBytes(state.req.PayloadBytes), state.env.Payload.RunID)
}

func loadDirectoryPackage(root string) (map[string][]byte, error) {
	return loadDirectoryPackageWithOptions(root, true)
}

func loadDirectoryPackageWithOptions(root string, allowConformanceSidecars bool) (map[string][]byte, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() {
		return nil, errors.New("package is not a directory")
	}
	files := map[string][]byte{}
	var committedTotal, wrapperTotal int64
	entriesSeen := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		entriesSeen++
		if entriesSeen > maxTreeEntries {
			return errors.New("package tree entry count exceeds limit")
		}
		if strings.Count(filepath.ToSlash(rel), "/")+1 > maxPackageDepth {
			return errors.New("package tree depth exceeds limit")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink member %s", rel)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular member %s", rel)
		}
		rel = filepath.ToSlash(rel)
		if !normalizedPath(rel) {
			return fmt.Errorf("unsafe member path %s", rel)
		}
		// Conformance sidecars are independent verifier inputs, not package members.
		if allowConformanceSidecars && (rel == "context.json" || rel == "expect.json") {
			return nil
		}
		if len(files) >= maxMembers {
			return errors.New("package member count exceeds limit")
		}
		data, err := readBounded(path, maxMemberSize)
		if err != nil {
			return err
		}
		if rel == "manifest.json" || rel == "envelope.dsse.json" {
			wrapperTotal += int64(len(data))
		} else {
			committedTotal += int64(len(data))
		}
		if !packageSizeWithinLimits(committedTotal, wrapperTotal) {
			return errors.New("package total size exceeds limit")
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, required := range []string{"requirement.dsse.json", "envelope.dsse.json", "manifest.json", "outcomes.json", "summary.json"} {
		if _, ok := files[required]; !ok {
			return nil, fmt.Errorf("missing required member %s", required)
		}
	}
	return files, nil
}

func packageSizeWithinLimits(committed, wrappers int64) bool {
	return committed <= maxTotalSize && wrappers <= 2*maxMemberSize
}

func (s *verificationState) loadCoreArtifacts() *Result {
	manifestValue, err := strictJSON(s.files["manifest.json"], &s.manifest)
	if err != nil || validateSchema(s.schemas.manifest, manifestValue) != nil {
		return failure(outcomeInvalid, "manifest_invalid")
	}
	if unknownScoringFact(s.files["outcomes.json"]) {
		return failure(outcomeInvalid, "unknown_scoring_fact")
	}
	if oneSidedNegativeHealth(s.files["outcomes.json"]) {
		return failure(outcomeInvalid, "negative_canary_health_incomplete")
	}
	var rawOutcomes map[string]any
	if _, err := strictJSON(s.files["outcomes.json"], &rawOutcomes); err == nil {
		if rows, ok := rawOutcomes["rows"].([]any); ok && len(rows) == 0 {
			return failure(outcomeInvalid, "outcomes_row_missing")
		}
	}
	outcomesValue, err := strictJSON(s.files["outcomes.json"], &s.outcomes)
	if err != nil || validateSchema(s.schemas.outcomes, outcomesValue) != nil {
		return failure(outcomeInvalid, "outcomes_invalid")
	}
	value, err := strictJSON(s.files["summary.json"], &s.summary)
	if err != nil || value == nil {
		return failure(outcomeInvalid, "summary_invalid")
	}
	s.entriesByRole = map[string][]manifestEntry{}
	s.entriesByDigest = map[string]manifestEntry{}
	for _, entry := range s.manifest.Entries {
		s.entriesByRole[entry.Role] = append(s.entriesByRole[entry.Role], entry)
		if _, exists := s.entriesByDigest[entry.SHA256]; exists {
			return failure(outcomeInvalid, "manifest_digest_ambiguous")
		}
		s.entriesByDigest[entry.SHA256] = entry
	}
	return nil
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func duplicateNonceTuple(entries []nonceEntry) bool {
	seen := map[string]bool{}
	for _, entry := range entries {
		key := entry.RequirementSignerKeyID + "\x00" + entry.RequirementID + "\x00" + entry.ChallengeNonce
		if seen[key] {
			return true
		}
		seen[key] = true
	}
	return false
}

func overlapping(a, b []string) bool {
	seen := map[string]bool{}
	for _, value := range a {
		seen[value] = true
	}
	for _, value := range b {
		if seen[value] {
			return true
		}
	}
	return false
}

func peekPayload(data []byte) map[string]any {
	var wrapper dsseEnvelope
	if _, err := strictJSON(data, &wrapper); err != nil {
		return nil
	}
	payload, err := decodeBase64(wrapper.Payload)
	if err != nil {
		return nil
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil
	}
	return out
}

func decodeBase64(value string) ([]byte, error) {
	return base64.StdEncoding.Strict().DecodeString(value)
}

func numberField(value map[string]any, key string) int {
	if value == nil {
		return 0
	}
	switch n := value[key].(type) {
	case json.Number:
		v, _ := n.Int64()
		return int(v)
	case float64:
		return int(n)
	default:
		return 0
	}
}

func nestedString(value map[string]any, outer, inner string) string {
	child, _ := value[outer].(map[string]any)
	text, _ := child[inner].(string)
	return text
}

func unknownScoringFact(data []byte) bool {
	var raw map[string]any
	if _, err := strictJSON(data, &raw); err != nil {
		return false
	}
	rows, _ := raw["rows"].([]any)
	for _, item := range rows {
		row, _ := item.(map[string]any)
		facts, _ := row["scoring_facts"].(map[string]any)
		for key := range facts {
			if key != "budget_timing" && key != "classification" && key != "structured_evidence" {
				return true
			}
		}
	}
	return false
}

func oneSidedNegativeHealth(data []byte) bool {
	var raw map[string]any
	if _, err := strictJSON(data, &raw); err != nil {
		return false
	}
	rows, _ := raw["rows"].([]any)
	for _, item := range rows {
		row, _ := item.(map[string]any)
		canaries, _ := row["canaries"].([]any)
		for _, rawCanary := range canaries {
			canary, _ := rawCanary.(map[string]any)
			if canary["polarity"] != "negative" {
				continue
			}
			_, pre := canary["preceding_health_ref"]
			_, post := canary["following_health_ref"]
			if pre != post {
				return true
			}
		}
	}
	return false
}
