package authentication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestAssessAuthenticatedAtT(t *testing.T) {
	fixture := newFixture(t)
	result := fixture.assess(t)
	if result.Predicates[0].Status != StatusPass {
		t.Fatalf("status = %#v, want PASS", result)
	}
	if result.Evidence.EnvelopePayloadSHA256 != fixture.envelopeDigest {
		t.Fatalf("envelope binding = %q, want %q", result.Evidence.EnvelopePayloadSHA256, fixture.envelopeDigest)
	}
}

func TestAssessExistingV0GoldenWithExternalPolicy(t *testing.T) {
	packageDir := filepath.Join("..", "..", "v0", "conformance", "golden", "g05-independent-witness-clock")
	files, err := loadPackage(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	artifacts, envelopeDigest, reason := requiredArtifacts(files)
	if reason != "" {
		t.Fatalf("requiredArtifacts: %s", reason)
	}
	root := newTestKey(t.Name() + "root")
	keys := make([]policyKey, 0, len(artifacts))
	seen := map[string]bool{}
	for _, artifact := range artifacts {
		if seen[artifact.signer] {
			continue
		}
		seen[artifact.signer] = true
		keys = append(keys, policyKey{KeyID: artifact.signer, PublicKey: artifact.signer, AuthorityID: firstNonEmpty(artifact.authority, "observer"), Role: artifact.role, Purpose: artifact.expectedType, NotBefore: "2025-01-01T00:00:00Z", ExpiresAt: "2027-01-01T00:00:00Z"})
	}
	rootDir := t.TempDir()
	policyPath := filepath.Join(rootDir, "policy.dsse.json")
	contextPath := filepath.Join(rootDir, "context.json")
	state := filepath.Join(rootDir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	policyBytes := signed(t, root, policyType, policy{Profile: policyProfile, PolicyID: "external-golden-policy", Epoch: 1, IssuedAt: "2026-01-01T00:00:00Z", NextUpdate: "2027-01-01T00:00:00Z", Keys: keys})
	if err := os.WriteFile(policyPath, policyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	contextBytes, err := json.Marshal(authContext{Profile: contextProfile, AssessmentTime: "2026-08-03T12:00:00Z", PolicyID: "external-golden-policy", PolicySHA256: digest(policyBytes), BootstrapKeyID: root.ID, BootstrapPublicKey: root.ID, EnvelopePayloadSHA256: envelopeDigest})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contextPath, contextBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	result := Assess(testOptions(packageDir, policyPath, contextPath, state))
	if result.Predicates[0].Status != StatusPass {
		t.Fatalf("result = %#v", result)
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func TestAssessRejectsEveryManifestDeclaredObserverWrapper(t *testing.T) {
	for _, name := range observerWrapperNames {
		t.Run(name, func(t *testing.T) {
			fixture := newFixture(t)
			fixture.signerFor[name] = fixture.rogue
			fixture.writePackage(t)
			fixture.writePolicy(t)
			result := fixture.assess(t)
			if result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != "signer_key_untrusted" {
				t.Fatalf("result = %#v, want untrusted observer FAIL", result)
			}
		})
	}
}

func TestAssessWrongPurposeAndAuthorityFail(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*testFixture)
	}{
		{"purpose", "policy_payload_invalid", func(f *testFixture) { f.policyKey(t, "run-envelope").Purpose = typeObserver }},
		{"authority", "signer_role_or_authority_mismatch", func(f *testFixture) { f.policyKey(t, "run-envelope").AuthorityID = "wrong-authority" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFixture(t)
			tc.mutate(fixture)
			fixture.writePolicy(t)
			result := fixture.assess(t)
			if result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != tc.reason {
				t.Fatalf("result = %#v, want FAIL %s", result, tc.reason)
			}
		})
	}
}

func TestAssessFutureAndRevokedKeysFail(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		mutate       func(*testFixture)
	}{
		{"future", "signer_key_not_valid_at_assessment", func(f *testFixture) { f.policyKey(t, "run-envelope").NotBefore = "2026-09-01T00:00:00Z" }},
		{"revoked", "signer_key_revoked", func(f *testFixture) {
			f.policy.Revocations = []revocation{{KeyID: f.runner.ID, EffectiveAt: "2026-01-01T00:00:00Z", Reason: "test"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newFixture(t)
			tc.mutate(fixture)
			fixture.writePolicy(t)
			result := fixture.assess(t)
			if result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != tc.reason {
				t.Fatalf("result = %#v, want FAIL %s", result, tc.reason)
			}
		})
	}
}

func TestAssessPolicyAndCheckpointAvailabilityAreUnverifiable(t *testing.T) {
	t.Run("stale-policy", func(t *testing.T) {
		fixture := newFixture(t)
		fixture.policy.NextUpdate = "2026-07-01T00:00:00Z"
		fixture.writePolicy(t)
		if result := fixture.assess(t); result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "policy_stale" {
			t.Fatalf("stale result = %#v", result)
		}
	})
	t.Run("unsafe-checkpoint-mode", func(t *testing.T) {
		fixture := newFixture(t)
		if err := os.Chmod(fixture.state, 0o755); err != nil {
			t.Fatal(err)
		}
		if result := fixture.assess(t); result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_unavailable" {
			t.Fatalf("unsafe-state result = %#v", result)
		}
	})
	t.Run("missing-checkpoint-directory", func(t *testing.T) {
		fixture := newFixture(t)
		missing := filepath.Join(t.TempDir(), "missing")
		result := Assess(testOptions(fixture.pkg, fixture.policyPath, fixture.contextPath, missing))
		if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_not_external" {
			t.Fatalf("missing-state result = %#v", result)
		}
	})
}

func TestAssessCheckpointRejectsRollbackAndEquivocation(t *testing.T) {
	fixture := newFixture(t)
	fixture.policy.Epoch = 2
	fixture.writePolicy(t)
	if result := fixture.assess(t); result.Predicates[0].Status != StatusPass {
		t.Fatalf("epoch 2 result = %#v", result)
	}
	fixture.policy.Epoch = 1
	fixture.writePolicy(t)
	if result := fixture.assess(t); result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != "policy_epoch_rollback" {
		t.Fatalf("rollback result = %#v", result)
	}

	fixture = newFixture(t)
	if result := fixture.assess(t); result.Predicates[0].Status != StatusPass {
		t.Fatalf("first result = %#v", result)
	}
	fixture.policyKey(t, "buyer-requirement").AuthorityID = "changed-but-signed"
	fixture.writePolicy(t)
	if result := fixture.assess(t); result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != "policy_epoch_equivocation" {
		t.Fatalf("equivocation result = %#v", result)
	}
}

func TestAssessCheckpointCorruptionAndBusyLockAreUnverifiable(t *testing.T) {
	t.Run("corrupt-content", func(t *testing.T) {
		fixture := newFixture(t)
		if result := fixture.assess(t); result.Predicates[0].Status != StatusPass {
			t.Fatalf("initial result = %#v", result)
		}
		checkpointPath := filepath.Join(fixture.state, checkpointStem(fixture.policy.PolicyID)+".json")
		if err := os.WriteFile(checkpointPath, []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		result := fixture.assess(t)
		if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_invalid" {
			t.Fatalf("corrupt result = %#v", result)
		}
	})
	t.Run("busy-lock", func(t *testing.T) {
		fixture := newFixture(t)
		lockPath := filepath.Join(fixture.state, checkpointStem(fixture.policy.PolicyID)+".lock")
		if err := os.Mkdir(lockPath, 0o700); err != nil {
			t.Fatal(err)
		}
		result := fixture.assess(t)
		if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_busy" {
			t.Fatalf("busy result = %#v", result)
		}
	})
}

func TestAssessRejectsPolicyInsidePackage(t *testing.T) {
	fixture := newFixture(t)
	packagePolicy := filepath.Join(fixture.pkg, "policy.dsse.json")
	data, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePolicy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	result := Assess(testOptions(fixture.pkg, packagePolicy, fixture.contextPath, fixture.state))
	if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "policy_not_external" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAssessRejectsSubstitutePolicyRoot(t *testing.T) {
	fixture := newFixture(t)
	raw := signed(t, fixture.rogue, policyType, fixture.policy)
	if err := os.WriteFile(fixture.policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	contextRaw, err := os.ReadFile(fixture.contextPath)
	if err != nil {
		t.Fatal(err)
	}
	var context authContext
	if err := json.Unmarshal(contextRaw, &context); err != nil {
		t.Fatal(err)
	}
	context.PolicySHA256 = digest(raw)
	contextRaw, _ = json.Marshal(context)
	if err := os.WriteFile(fixture.contextPath, contextRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	result := fixture.assess(t)
	if result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != "policy_bootstrap_mismatch" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAssessRejectsFutureIssuedPolicy(t *testing.T) {
	fixture := newFixture(t)
	fixture.policy.IssuedAt = "2030-01-01T00:00:00Z"
	fixture.policy.NextUpdate = "2031-01-01T00:00:00Z"
	fixture.writePolicy(t)
	result := fixture.assess(t)
	if result.Predicates[0].Status != StatusFail || result.Predicates[0].Reason != "policy_time_invalid" {
		t.Fatalf("result = %#v, want future-policy FAIL", result)
	}
}

func TestAssessRejectsPackageOwnedCheckpoint(t *testing.T) {
	fixture := newFixture(t)
	state := filepath.Join(fixture.pkg, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	result := Assess(testOptions(fixture.pkg, fixture.policyPath, fixture.contextPath, state))
	if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_not_external" {
		t.Fatalf("result = %#v", result)
	}
}

func TestAssessRejectsPhysicalContainmentThroughSymlinkedParent(t *testing.T) {
	fixture := newFixture(t)
	packagePolicy := filepath.Join(fixture.pkg, "external-policy.dsse.json")
	data, err := os.ReadFile(fixture.policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePolicy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "outside-looking")
	if err := os.Symlink(fixture.pkg, alias); err != nil {
		t.Fatal(err)
	}
	result := Assess(testOptions(fixture.pkg, filepath.Join(alias, "external-policy.dsse.json"), fixture.contextPath, fixture.state))
	if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "policy_not_external" {
		t.Fatalf("policy result = %#v", result)
	}

	packageState := filepath.Join(fixture.pkg, "checkpoint")
	if err := os.Mkdir(packageState, 0o700); err != nil {
		t.Fatal(err)
	}
	result = Assess(testOptions(fixture.pkg, fixture.policyPath, fixture.contextPath, filepath.Join(alias, "checkpoint")))
	if result.Predicates[0].Status != StatusUnverifiable || result.Predicates[0].Reason != "checkpoint_not_external" {
		t.Fatalf("checkpoint result = %#v", result)
	}
}

func TestConcurrentSameEpochPoliciesCannotBothPass(t *testing.T) {
	fixture := newFixture(t)
	firstPolicy := signed(t, fixture.root, policyType, fixture.policy)
	second := fixture.policy
	second.IssuedAt = "2026-01-02T00:00:00Z"
	secondPolicy := signed(t, fixture.root, policyType, second)

	writeInputs := func(name string, raw []byte) (string, string) {
		dir := t.TempDir()
		policyPath := filepath.Join(dir, name+".dsse.json")
		contextPath := filepath.Join(dir, name+"-context.json")
		if err := os.WriteFile(policyPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		ctx := authContext{Profile: contextProfile, AssessmentTime: "2026-08-03T12:00:00Z", PolicyID: "test-policy", PolicySHA256: digest(raw), BootstrapKeyID: fixture.root.ID, BootstrapPublicKey: fixture.root.ID, EnvelopePayloadSHA256: fixture.envelopeDigest}
		ctxRaw, err := json.Marshal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(contextPath, ctxRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		return policyPath, contextPath
	}
	p1, c1 := writeInputs("first", firstPolicy)
	p2, c2 := writeInputs("second", secondPolicy)
	start := make(chan struct{})
	results := make(chan Result, 2)
	for _, pair := range [][2]string{{p1, c1}, {p2, c2}} {
		pair := pair
		go func() {
			<-start
			results <- Assess(testOptions(fixture.pkg, pair[0], pair[1], fixture.state))
		}()
	}
	close(start)
	r1, r2 := <-results, <-results
	if r1.Predicates[0].Status == StatusPass && r2.Predicates[0].Status == StatusPass {
		t.Fatalf("both conflicting policies passed: %#v %#v", r1, r2)
	}
	sequential := []Result{
		Assess(testOptions(fixture.pkg, p1, c1, fixture.state)),
		Assess(testOptions(fixture.pkg, p2, c2, fixture.state)),
	}
	passes := 0
	for _, result := range sequential {
		if result.Predicates[0].Status == StatusPass {
			passes++
		}
	}
	if passes != 1 {
		t.Fatalf("sequential convergence = %#v, want exactly one PASS", sequential)
	}
}

func TestUnverifiableAssessmentOmitsUnknownBindings(t *testing.T) {
	result := Assess(testOptions("", "", filepath.Join(t.TempDir(), "missing"), ""))
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"assessment_time", "evidence", "external_state"} {
		if _, ok := fields[forbidden]; ok {
			t.Fatalf("unknown binding %q was emitted in %s", forbidden, raw)
		}
	}
}

func TestPackageAdmissionLimitsFailClosed(t *testing.T) {
	t.Run("member-count", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i <= maxPackageMembers; i++ {
			name := filepath.Join(root, fmt.Sprintf("member-%03d.json", i))
			if err := os.WriteFile(name, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := loadPackage(root); err == nil {
			t.Fatal("oversized member set was accepted")
		}
	})

	t.Run("member-bytes", func(t *testing.T) {
		root := t.TempDir()
		path := filepath.Join(root, "oversized.bin")
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxPackageMember + 1); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPackage(root); err == nil {
			t.Fatal("oversized member was accepted")
		}
	})
}

func TestAssessmentResultsValidateAgainstPublicSchema(t *testing.T) {
	schemaPath := filepath.Join("..", "..", "..", "schemas", "control-evidence-assessment-v1.schema.json")
	schemaRaw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("assessment.json", doc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("assessment.json")
	if err != nil {
		t.Fatal(err)
	}

	passFixture := newFixture(t)
	pass := passFixture.assess(t)
	failFixture := newFixture(t)
	failFixture.policy.IssuedAt = "2030-01-01T00:00:00Z"
	failFixture.policy.NextUpdate = "2031-01-01T00:00:00Z"
	failFixture.writePolicy(t)
	fail := failFixture.assess(t)
	unverifiable := Assess(testOptions("", "", filepath.Join(t.TempDir(), "missing"), ""))
	invalidVerifierOptions := testOptions("", "", filepath.Join(t.TempDir(), "missing"), "")
	invalidVerifierOptions.VerifierSHA256 = "not-a-digest"
	invalidVerifier := Assess(invalidVerifierOptions)
	if invalidVerifier.Verifier.SHA256 != "" || invalidVerifier.Predicates[0].Reason != "verifier_identity_invalid" {
		t.Fatalf("invalid verifier result = %#v", invalidVerifier)
	}
	for name, result := range map[string]Result{"pass": pass, "fail": fail, "unverifiable": unverifiable, "invalid-verifier": invalidVerifier} {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(value); err != nil {
				t.Fatalf("assessment does not validate: %v\n%s", err, raw)
			}
		})
	}
}

type testKey struct {
	ID      string
	Private ed25519.PrivateKey
}

func newTestKey(label string) testKey {
	s := sha256.Sum256([]byte(label))
	p := ed25519.NewKeyFromSeed(s[:])
	return testKey{hex.EncodeToString(p.Public().(ed25519.PublicKey)), p}
}

func testOptions(packageDir, policyPath, contextPath, checkpointDir string) Options {
	return Options{
		PackageDir:      packageDir,
		PolicyPath:      policyPath,
		ContextPath:     contextPath,
		CheckpointDir:   checkpointDir,
		VerifierName:    "test",
		VerifierVersion: "1",
		VerifierSHA256:  hex.EncodeToString(make([]byte, 32)),
	}
}

type testFixture struct {
	t                                                   *testing.T
	pkg, state, policyPath, contextPath, envelopeDigest string
	root, buyer, runner, observer, clock, rogue         testKey
	policy                                              policy
	signerFor                                           map[string]testKey
}

var observerWrapperNames = []string{"observer-following.dsse.json", "observer-preceding.dsse.json", "observer-target.dsse.json"}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	root := newTestKey(t.Name() + "root")
	buyer := newTestKey(t.Name() + "buyer")
	runner := newTestKey(t.Name() + "runner")
	observer := newTestKey(t.Name() + "observer")
	clock := newTestKey(t.Name() + "clock")
	f := &testFixture{t: t, pkg: filepath.Join(t.TempDir(), "package"), state: filepath.Join(t.TempDir(), "state"), policyPath: filepath.Join(t.TempDir(), "policy.dsse.json"), contextPath: filepath.Join(t.TempDir(), "context.json"), root: root, buyer: buyer, runner: runner, observer: observer, clock: clock, rogue: newTestKey(t.Name() + "rogue")}
	if err := os.MkdirAll(f.pkg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.state, 0o700); err != nil {
		t.Fatal(err)
	}
	f.policy = policy{Profile: policyProfile, PolicyID: "test-policy", Epoch: 1, IssuedAt: "2026-01-01T00:00:00Z", NextUpdate: "2027-01-01T00:00:00Z", Keys: []policyKey{f.key(buyer, "buyer-requirement", typeRequirement, "buyer"), f.key(runner, "run-envelope", typeEnvelope, "runner"), f.key(observer, "observer-evidence", typeObserver, "observer"), f.key(clock, "completion-clock", typeClock, "clock")}}
	f.signerFor = map[string]testKey{"requirement.dsse.json": buyer, "envelope.dsse.json": runner, "clock.dsse.json": clock}
	for _, name := range observerWrapperNames {
		f.signerFor[name] = observer
	}
	f.writePackage(t)
	f.writePolicy(t)
	return f
}

func (f *testFixture) key(k testKey, role, purpose, authority string) policyKey {
	return policyKey{KeyID: k.ID, PublicKey: k.ID, AuthorityID: authority, Role: role, Purpose: purpose, NotBefore: "2025-01-01T00:00:00Z", ExpiresAt: "2027-01-01T00:00:00Z"}
}

func (f *testFixture) policyKey(t *testing.T, role string) *policyKey {
	t.Helper()
	for i := range f.policy.Keys {
		if f.policy.Keys[i].Role == role {
			return &f.policy.Keys[i]
		}
	}
	t.Fatalf("policy key for role %q not found", role)
	return nil
}

func (f *testFixture) writePackage(t *testing.T) {
	t.Helper()
	files := map[string][]byte{}
	files["requirement.dsse.json"] = signed(t, f.signerFor["requirement.dsse.json"], typeRequirement, map[string]any{"profile": "control-evidence-requirement/v0", "buyer_id": "buyer", "trust_policy_id": "test-policy", "trust_policy_sha256": "placeholder"})
	for _, name := range observerWrapperNames {
		files[name] = signed(t, f.signerFor[name], typeObserver, map[string]any{"profile": "control-evidence-observer-evidence/v0", "observer": map[string]any{"key_id": f.observer.ID, "protocol": "test", "version": "v1"}})
	}
	files["clock.dsse.json"] = signed(t, f.signerFor["clock.dsse.json"], typeClock, map[string]any{"profile": "control-evidence-clock-evidence/v0", "attestor": map[string]any{"authority_id": "clock"}})
	entries := []manifestEntry{}
	names := append([]string{"requirement.dsse.json"}, observerWrapperNames...)
	names = append(names, "clock.dsse.json")
	for _, name := range names {
		role := "observer-evidence"
		if name == "requirement.dsse.json" {
			role = "requirement"
		}
		if name == "clock.dsse.json" {
			role = "clock-evidence"
		}
		entries = append(entries, manifestEntry{Role: role, Path: name, SHA256: digest(files[name])})
	}
	manifest, _ := json.Marshal(struct {
		Entries []manifestEntry `json:"entries"`
	}{entries})
	files["manifest.json"] = manifest
	files["envelope.dsse.json"] = signed(t, f.signerFor["envelope.dsse.json"], typeEnvelope, map[string]any{"profile": "control-evidence-envelope/v0", "artifacts": map[string]any{"manifest_sha256": digest(manifest)}, "signer": map[string]any{"authority_id": "runner"}})
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(f.pkg, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, payload := decodeDSSE(t, files["envelope.dsse.json"])
	f.envelopeDigest = digest(payload)
	ctx := authContext{Profile: contextProfile, AssessmentTime: "2026-08-03T12:00:00Z", PolicyID: "test-policy", BootstrapKeyID: f.root.ID, BootstrapPublicKey: f.root.ID, EnvelopePayloadSHA256: f.envelopeDigest}
	// writePolicy must follow writePackage to bind this context to the signed policy.
	raw, _ := json.Marshal(ctx)
	if err := os.WriteFile(f.contextPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *testFixture) writePolicy(t *testing.T) {
	t.Helper()
	raw := signed(t, f.root, policyType, f.policy)
	if err := os.WriteFile(f.policyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctxRaw, err := os.ReadFile(f.contextPath)
	if err != nil {
		t.Fatal(err)
	}
	var ctx authContext
	if err := json.Unmarshal(ctxRaw, &ctx); err != nil {
		t.Fatal(err)
	}
	ctx.PolicySHA256 = digest(raw)
	ctxRaw, _ = json.Marshal(ctx)
	if err := os.WriteFile(f.contextPath, ctxRaw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *testFixture) assess(t *testing.T) Result {
	t.Helper()
	return Assess(testOptions(f.pkg, f.policyPath, f.contextPath, f.state))
}

func signed(t *testing.T, k testKey, typ string, payload any) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(k.Private, pae(typ, raw))
	out, err := json.Marshal(dsseEnvelope{PayloadType: typ, Payload: base64.StdEncoding.EncodeToString(raw), Signatures: []dsseSignature{{KeyID: k.ID, Sig: base64.StdEncoding.EncodeToString(sig)}}})
	if err != nil {
		t.Fatal(err)
	}
	out, err = canonicalize(out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeDSSE(t *testing.T, raw []byte) (dsseEnvelope, []byte) {
	t.Helper()
	var d dsseEnvelope
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(d.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return d, p
}
