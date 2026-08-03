// Package main deterministically generates the control-evidence v0 fixtures.
// It is deliberately not a verifier: expected outcomes are conformance claims
// for independently implemented verifiers.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	now          = "2026-08-02T12:00:00Z"
	typeReq      = "application/vnd.agent-egress-bench.control-evidence-requirement.v0+json"
	typeEnv      = "application/vnd.agent-egress-bench.control-evidence-envelope.v0+json"
	typeClock    = "application/vnd.agent-egress-bench.control-evidence-clock-evidence.v0+json"
	typeObserver = "application/vnd.agent-egress-bench.control-evidence-observer-evidence.v0+json"
)

type fixture struct {
	id, category, outcome, reason string
	mutate                        func(map[string]any, map[string]any, map[string]any)
}

func key(role string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("agent-egress-bench-control-evidence-" + role + "-test-key-v0"))
	return ed25519.NewKeyFromSeed(s[:])
}

func keyID(role string) string   { return hex.EncodeToString(key(role).Public().(ed25519.PublicKey)) }
func digest(b []byte) string     { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func textDigest(s string) string { return digest([]byte(s)) }
func tokenCommitment(requirementSHA, runID, caseID string, trial int, canaryID, transport, target, polarity, token string) string {
	parts := []string{"aeb-cee-v0/canary", requirementSHA, runID, caseID, fmt.Sprint(trial), canaryID, transport, target, polarity, token}
	h := sha256.New()
	for _, p := range parts {
		if uint64(len(p)) > uint64(^uint32(0)) {
			panic("canary field exceeds uint32")
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func healthCommitment(requirementSHA, runID, caseID string, trial int, canaryID, subjectToken, controlID, transport, target, controlToken string) string {
	parts := []string{"aeb-cee-v0/health-control", requirementSHA, runID, caseID, fmt.Sprint(trial), canaryID, subjectToken, controlID, transport, target, controlToken}
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func derivedHealthInput(profile, materialID, controlID, root string) string {
	parts := []string{"aeb-cee-conformance-health-input/v1", profile, materialID, controlID, root}
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func derivedToken(profile, materialID, root, canaryID string) string {
	parts := []string{"aeb-cee-conformance-token-input/v1", profile, materialID, canaryID, root}
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

const (
	packagedTokenProfile  = "aeb-cee-conformance-token-aesgcm/v1"
	packagedTokenID       = "synthetic-token-material"
	packagedHealthProfile = "aeb-cee-conformance-health-aesgcm/v1"
	packagedHealthID      = "synthetic-health-material"
	unknownTokenProfile   = "example-unknown-packaged-token/v9"
	unknownTokenID        = "unknown-token-material"
	unknownHealthProfile  = "example-unknown-packaged-health/v9"
	unknownHealthID       = "unknown-health-material"
)

func lengthPrefixedSHA256(parts ...string) []byte {
	h := sha256.New()
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(p))
	}
	return h.Sum(nil)
}

func packagedTokenKey(requirementID string) string {
	key := sha256.Sum256([]byte("agent-egress-bench-control-evidence-token-key-v0/" + requirementID))
	return base64.StdEncoding.EncodeToString(key[:])
}

func packagedTokenPlaintext() []byte {
	// All fields are ASCII and the value contains no non-integral numbers, so
	// encoding/json's sorted-key compact encoding is also RFC8785 JCS here.
	return compact(map[string]any{"profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "tokens": []any{
		map[string]any{"canary_id": "negative-1", "input": "packaged-negative-token-input"},
		map[string]any{"canary_id": "positive-1", "input": "packaged-positive-token-input"},
	}})
}

func packagedTokenMaterial(requirementID string) []byte {
	return packagedTokenMaterialWithPlaintext(requirementID, packagedTokenPlaintext())
}

func packagedTokenMaterialWithPlaintext(requirementID string, plaintext []byte) []byte {
	key, err := base64.StdEncoding.DecodeString(packagedTokenKey(requirementID))
	if err != nil || len(key) != 32 {
		panic("invalid deterministic packaged-token key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	// This v1 deterministic construction is conformance-only. Callers must use a
	// fresh AES key before encrypting different plaintext for the same tuple.
	nonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", requirementID, packagedTokenProfile, packagedTokenID, "token-material")[:gcm.NonceSize()]
	aad := append([]byte(nil), lengthPrefixedSHA256Input(packagedTokenProfile, packagedTokenID)...)
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, plaintext, aad)...)
}

func nonJCSPackagedTokenPlaintext() []byte {
	return []byte("{\n  \"tokens\": [{\"input\": \"packaged-negative-token-input\", \"canary_id\": \"negative-1\"}, {\"input\": \"packaged-positive-token-input\", \"canary_id\": \"positive-1\"}],\n  \"key_or_input_id\": \"synthetic-token-material\",\n  \"profile\": \"aeb-cee-conformance-token-aesgcm/v1\"\n}\n")
}

func packagedTokenPlaintextFor(fixtureID string) []byte {
	if fixtureID == "m35-token-duplicate-canary-id" {
		return compact(map[string]any{"profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "tokens": []any{
			map[string]any{"canary_id": "negative-1", "input": "packaged-negative-token-input"},
			map[string]any{"canary_id": "positive-1", "input": "packaged-positive-token-input"},
			map[string]any{"canary_id": "positive-1", "input": "different-positive-token-input"},
		}})
	}
	if fixtureID == "m27-token-extra-canary-id" {
		return compact(map[string]any{"profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "tokens": []any{
			map[string]any{"canary_id": "extra-1", "input": "packaged-extra-token-input"},
			map[string]any{"canary_id": "negative-1", "input": "packaged-negative-token-input"},
			map[string]any{"canary_id": "positive-1", "input": "packaged-positive-token-input"},
		}})
	}
	if fixtureID == "m28-token-missing-canary-id" {
		return compact(map[string]any{"profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "tokens": []any{
			map[string]any{"canary_id": "positive-1", "input": "packaged-positive-token-input"},
		}})
	}
	return packagedTokenPlaintext()
}

func packagedTokenStored(fixtureID, requirementID string) []byte {
	stored := packagedTokenMaterialWithPlaintext(requirementID, packagedTokenPlaintextFor(fixtureID))
	if fixtureID == "m24-token-aead-authentication-failure" {
		stored[len(stored)-1] ^= 1
	}
	if fixtureID == "m25-token-authenticated-non-jcs" {
		stored = packagedTokenMaterialWithPlaintext(requirementID, nonJCSPackagedTokenPlaintext())
	}
	if fixtureID == "m37-token-duplicate-json-key" {
		stored = packagedTokenMaterialWithPlaintext(requirementID, []byte(`{"profile":"aeb-cee-conformance-token-aesgcm/v1","profile":"aeb-cee-conformance-token-aesgcm/v1","key_or_input_id":"synthetic-token-material","tokens":[{"canary_id":"negative-1","input":"packaged-negative-token-input"},{"canary_id":"positive-1","input":"packaged-positive-token-input"}]}`))
	}
	return stored
}

func isPackagedTokenFixture(fixtureID string) bool {
	switch fixtureID {
	case "g03-token-packaged-material", "m09-post-hoc-token-material", "m23-token-artifact-digest-mismatch", "m24-token-aead-authentication-failure", "m25-token-authenticated-non-jcs", "m26-token-material-wrong-manifest-role", "m27-token-extra-canary-id", "m28-token-missing-canary-id", "m35-token-duplicate-canary-id", "m36-token-material-duplicate-manifest-role", "m37-token-duplicate-json-key":
		return true
	default:
		return false
	}
}

func lengthPrefixedSHA256Input(parts ...string) []byte {
	var out []byte
	for _, p := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(p)))
		out = append(out, n[:]...)
		out = append(out, p...)
	}
	return out
}

func tokenInput(fixtureID, canaryID string) string {
	if fixtureID == "m43-token-unsupported-packaged-profile" {
		if canaryID == "positive-1" {
			return "packaged-positive-token-input"
		}
		if canaryID == "negative-1" {
			return "packaged-negative-token-input"
		}
	}
	if isPackagedTokenFixture(fixtureID) {
		if canaryID == "positive-1" {
			return "packaged-positive-token-input"
		}
		if canaryID == "negative-1" {
			return "packaged-negative-token-input"
		}
		panic("unknown packaged canary")
	}
	return derivedToken("aeb-cee-conformance-token-derived/v1", "synthetic-token-input", "synthetic-token-root-"+fixtureID, canaryID)
}

func unknownTokenKey(requirementID string) string {
	key := sha256.Sum256([]byte("agent-egress-bench-control-evidence-unknown-token-key-v0/" + requirementID))
	return base64.StdEncoding.EncodeToString(key[:])
}

func unknownTokenMaterial(requirementID string) []byte {
	key, err := base64.StdEncoding.DecodeString(unknownTokenKey(requirementID))
	if err != nil || len(key) != 32 {
		panic("invalid unknown-token key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	plaintext := compact(map[string]any{"profile": unknownTokenProfile, "key_or_input_id": unknownTokenID, "tokens": []any{map[string]any{"canary_id": "negative-1", "input": "packaged-negative-token-input"}, map[string]any{"canary_id": "positive-1", "input": "packaged-positive-token-input"}}})
	nonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", requirementID, unknownTokenProfile, unknownTokenID, "token-material")[:gcm.NonceSize()]
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, plaintext, lengthPrefixedSHA256Input(unknownTokenProfile, unknownTokenID))...)
}

func packagedHealthKey(requirementID string) string {
	key := sha256.Sum256([]byte("agent-egress-bench-control-evidence-health-key-v0/" + requirementID))
	return base64.StdEncoding.EncodeToString(key[:])
}

func packagedHealthPlaintext() []byte {
	return compact(map[string]any{"profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "controls": []any{
		map[string]any{"control_id": "health-post", "input": "packaged-health-post-input"},
		map[string]any{"control_id": "health-pre", "input": "packaged-health-pre-input"},
	}})
}

func packagedHealthMaterial(requirementID string) []byte {
	return packagedHealthMaterialWithPlaintext(requirementID, packagedHealthPlaintext())
}

func packagedHealthMaterialWithPlaintext(requirementID string, plaintext []byte) []byte {
	key, err := base64.StdEncoding.DecodeString(packagedHealthKey(requirementID))
	if err != nil || len(key) != 32 {
		panic("invalid deterministic packaged-health key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", requirementID, packagedHealthProfile, packagedHealthID, "health-control-material")[:gcm.NonceSize()]
	aad := lengthPrefixedSHA256Input(packagedHealthProfile, packagedHealthID)
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, plaintext, aad)...)
}

func nonJCSPackagedHealthPlaintext() []byte {
	return []byte("{\n  \"controls\": [{\"input\": \"packaged-health-post-input\", \"control_id\": \"health-post\"}, {\"input\": \"packaged-health-pre-input\", \"control_id\": \"health-pre\"}],\n  \"key_or_input_id\": \"synthetic-health-material\",\n  \"profile\": \"aeb-cee-conformance-health-aesgcm/v1\"\n}\n")
}

func packagedHealthPlaintextFor(fixtureID string) []byte {
	if fixtureID == "m39-health-duplicate-control-id" {
		return compact(map[string]any{"profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "controls": []any{
			map[string]any{"control_id": "health-post", "input": "packaged-health-post-input"},
			map[string]any{"control_id": "health-pre", "input": "packaged-health-pre-input"},
			map[string]any{"control_id": "health-pre", "input": "different-health-pre-input"},
		}})
	}
	if fixtureID == "m33-health-extra-control-id" {
		return compact(map[string]any{"profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "controls": []any{
			map[string]any{"control_id": "health-extra", "input": "packaged-health-extra-input"},
			map[string]any{"control_id": "health-post", "input": "packaged-health-post-input"},
			map[string]any{"control_id": "health-pre", "input": "packaged-health-pre-input"},
		}})
	}
	if fixtureID == "m34-health-missing-post-control-id" {
		return compact(map[string]any{"profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "controls": []any{
			map[string]any{"control_id": "health-pre", "input": "packaged-health-pre-input"},
		}})
	}
	return packagedHealthPlaintext()
}

func packagedHealthStored(fixtureID, requirementID string) []byte {
	stored := packagedHealthMaterialWithPlaintext(requirementID, packagedHealthPlaintextFor(fixtureID))
	if fixtureID == "m30-health-aead-authentication-failure" {
		stored[len(stored)-1] ^= 1
	}
	if fixtureID == "m31-health-authenticated-non-jcs" {
		stored = packagedHealthMaterialWithPlaintext(requirementID, nonJCSPackagedHealthPlaintext())
	}
	return stored
}

func isPackagedHealthFixture(fixtureID string) bool {
	switch fixtureID {
	case "g04-health-packaged-material", "m18-missing-health-control-material", "m29-health-artifact-digest-mismatch", "m30-health-aead-authentication-failure", "m31-health-authenticated-non-jcs", "m32-health-material-wrong-manifest-role", "m33-health-extra-control-id", "m34-health-missing-post-control-id", "m39-health-duplicate-control-id", "m40-health-material-duplicate-manifest-role":
		return true
	default:
		return false
	}
}

func healthInput(fixtureID, controlID, root string) string {
	if fixtureID == "m44-health-unsupported-packaged-profile" {
		if controlID == "health-pre" {
			return "packaged-health-pre-input"
		}
		if controlID == "health-post" {
			return "packaged-health-post-input"
		}
	}
	if isPackagedHealthFixture(fixtureID) {
		if controlID == "health-pre" {
			return "packaged-health-pre-input"
		}
		if controlID == "health-post" {
			return "packaged-health-post-input"
		}
		panic("unknown packaged health control")
	}
	return derivedHealthInput("aeb-cee-conformance-health-derived/v1", "synthetic-health-input", controlID, root)
}

func unknownHealthKey(requirementID string) string {
	key := sha256.Sum256([]byte("agent-egress-bench-control-evidence-unknown-health-key-v0/" + requirementID))
	return base64.StdEncoding.EncodeToString(key[:])
}

func unknownHealthMaterial(requirementID string) []byte {
	key, err := base64.StdEncoding.DecodeString(unknownHealthKey(requirementID))
	if err != nil || len(key) != 32 {
		panic("invalid unknown-health key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	plaintext := compact(map[string]any{"profile": unknownHealthProfile, "key_or_input_id": unknownHealthID, "controls": []any{map[string]any{"control_id": "health-post", "input": "packaged-health-post-input"}, map[string]any{"control_id": "health-pre", "input": "packaged-health-pre-input"}}})
	nonce := lengthPrefixedSHA256("aeb-cee-conformance-nonce/v1", requirementID, unknownHealthProfile, unknownHealthID, "health-control-material")[:gcm.NonceSize()]
	return append(append([]byte(nil), nonce...), gcm.Seal(nil, nonce, plaintext, lengthPrefixedSHA256Input(unknownHealthProfile, unknownHealthID))...)
}

func pretty(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func compact(v any) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func compactGoHTML(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func pae(t string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(t), t, len(p), p))
}

func dsse(t string, payload any, signer ed25519.PrivateKey) map[string]any {
	return dssePayload(t, compact(payload), signer)
}

func dssePayload(t string, p []byte, signer ed25519.PrivateKey) map[string]any {
	sig := ed25519.Sign(signer, pae(t, p))
	pub := signer.Public().(ed25519.PublicKey)
	return map[string]any{"payloadType": t, "payload": base64.StdEncoding.EncodeToString(p), "signatures": []any{map[string]any{"keyid": hex.EncodeToString(pub), "sig": base64.StdEncoding.EncodeToString(sig)}}}
}

func baseRequirement(id string) map[string]any {
	vendor := keyID("vendor-runner")
	return map[string]any{
		"profile": "control-evidence-requirement/v0", "requirement_id": textDigest("req-" + id)[:32], "challenge_nonce": textDigest("nonce-" + id),
		"issued_at": "2026-08-02T11:00:00Z", "not_before": "2026-08-02T11:00:00Z", "expires_at": "2026-08-02T13:00:00Z",
		"buyer_id": "buyer-example", "deployment_archetype": "mcp-stdio-gateway", "required_transports": []any{"mcp_stdio"},
		"required_case_ids": []any{"mcp-input-synthetic-001"}, "required_case_expectations": []any{map[string]any{"case_id": "mcp-input-synthetic-001", "expected_verdict": "block"}}, "required_positive_canaries": []any{"positive-1"}, "required_negative_canaries": []any{"negative-1"},
		"enforcement_point":       map[string]any{"kind": "gateway", "note": "synthetic conformance gateway"},
		"approved_observer":       map[string]any{"protocol": "runner-owned", "version": "v1", "target_identity": "runner-target-example", "key_id": keyID("observer"), "maximum_health_control_interval_seconds": 60, "maximum_liveness_gap_seconds": 60},
		"token_material":          map[string]any{"mode": "buyer-derived", "profile": "aeb-cee-conformance-token-derived/v1", "key_or_input_id": "synthetic-token-input"},
		"health_control_material": map[string]any{"mode": "buyer-derived", "profile": "aeb-cee-conformance-health-derived/v1", "key_or_input_id": "synthetic-health-input"},
		"minimum_trials_per_case": 1, "maximum_errors": 0, "maximum_age_seconds": 3600, "allowed_future_skew_seconds": 60,
		"allowed_not_applicable": []any{}, "required_artifacts": []any{"policy", "adapter", "observer-evidence", "tool-profile"}, "trust_policy_id": "synthetic-trust-policy", "trust_policy_sha256": textDigest("trust-policy"),
		"approved_tool_identity": map[string]any{"kind": "binary", "expected": "tool-digest-example"},
		"approved_policy":        map[string]any{"sha256": digest(policyArtifact())},
		"required_signer_policy": map[string]any{"key_id": vendor, "authority_id": "example-runner-authority", "role": "vendor-runner"},
		"authorized_run_signers": []any{map[string]any{"key_id": vendor, "authority_id": "example-runner-authority", "role": "vendor-runner"}},
		"approved_runner":        map[string]any{"protocol": "gauntlet", "version": "0.4.0", "sha256": textDigest("runner")}, "approved_adapter": map[string]any{"protocol": "mcp-stdio", "version": "v1", "sha256": digest(adapterArtifact())},
	}
}

func policyArtifact() []byte {
	return pretty(map[string]any{"profile": "synthetic-policy/v1"})
}

func adapterArtifact() []byte {
	return pretty(map[string]any{"protocol": "mcp-stdio", "version": "v1"})
}

func observerIdentity(fixtureID string) map[string]any {
	if fixtureID == "m68-observer-authorized-runner-key" {
		return map[string]any{"protocol": "runner-owned", "version": "v1", "key_id": keyID("alternate-runner")}
	}
	if fixtureID == "m57-observer-identity-mismatch" {
		return map[string]any{"protocol": "alternate-runner-owned", "version": "v2", "key_id": keyID("substituted-observer")}
	}
	return map[string]any{"protocol": "runner-owned", "version": "v1", "key_id": keyID("observer")}
}

func observerSigner(fixtureID string) string {
	if fixtureID == "m68-observer-authorized-runner-key" {
		return "alternate-runner"
	}
	return "observer"
}

func toolProfileBytesForFixture(id string) []byte {
	supports := map[string]any{}
	for _, name := range []string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a", "tls_interception", "url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning", "response_prompt_injection_scanning", "mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning", "mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning", "mcp_tool_poison_scanning", "mcp_tool_baseline", "mcp_chain_memory", "mcp_cross_server_chain_memory", "mcp_data_class_labels", "a2a_dlp_scanning", "a2a_prompt_injection_scanning", "a2a_card_prompt_injection_scanning", "a2a_card_drift_scanning", "a2a_ssrf_scanning", "websocket_dlp_scanning", "websocket_prompt_injection_scanning", "ssrf_scanning", "ssrf_bypass_scanning", "domain_blocklist", "entropy_scanning", "encoding_evasion_scanning", "shell_analysis", "crypto_dlp_scanning", "hostname_exfil_scanning", "dns_rebinding_fixture", "budget_enforcement"} {
		supports[name] = false
	}
	supports["mcp_stdio"] = true
	supports["mcp_input_dlp_scanning"] = true
	supports["mcp_input_prompt_injection_scanning"] = true
	profile := map[string]any{"schema_version": 1, "tool": "example-tool", "tool_version": "v0", "runner_version": "0.4.0", "claims": []any{"mcp_input_scan"}, "supports": supports}
	if id == "m52-tool-profile-identity-mismatch" {
		profile["tool"] = "different-tool"
	}
	return pretty(profile)
}

func toolProfileBytes() []byte { return toolProfileBytesForFixture("") }

func baseOutcomes(id, requirementSHA, runID string) map[string]any {
	observer := observerIdentity(id)
	positive := tokenCommitment(requirementSHA, runID, "mcp-input-synthetic-001", 1, "positive-1", "mcp_stdio", "runner-target-example", "positive", tokenInput(id, "positive-1"))
	negative := tokenCommitment(requirementSHA, runID, "mcp-input-synthetic-001", 1, "negative-1", "mcp_stdio", "runner-target-example", "negative", tokenInput(id, "negative-1"))
	return map[string]any{
		"profile": "control-evidence-outcomes/v0", "requirement_sha256": requirementSHA, "run_id": runID, "rows": []any{map[string]any{
			"case_id": "mcp-input-synthetic-001", "trial_index": 1, "transport": "mcp_stdio", "expected_verdict": "block", "actual_verdict": "block",
			"outcome": "pass", "adapter_observation": "observed", "target_observation": "observed", "evidence_sha256": []any{textDigest("evidence-" + id)}, "scoring_facts": map[string]any{"budget_timing": "within_budget", "classification": "correct", "structured_evidence": "present"},
			"canaries": []any{
				map[string]any{"canary_id": "positive-1", "polarity": "positive", "expected_predicate": "allow-observed", "observer_protocol": observer["protocol"], "observer_version": observer["version"], "state": "observed", "canary_commitment_sha256": positive, "target_identity": "runner-target-example"},
				map[string]any{"canary_id": "negative-1", "polarity": "negative", "expected_predicate": "block-not-observed", "observer_protocol": observer["protocol"], "observer_version": observer["version"], "state": "not_observed", "canary_commitment_sha256": negative, "target_identity": "runner-target-example", "window_start": "2026-08-02T11:40:00Z", "window_end": "2026-08-02T11:41:00Z", "observer_key_id": observer["key_id"]},
			},
		}},
	}
}

func toolSupportFromProfile(profile []byte) map[string]any {
	var decoded map[string]any
	if err := json.Unmarshal(profile, &decoded); err != nil {
		panic(err)
	}
	supports := decoded["supports"].(map[string]any)
	unsupported := func(keys []string) []any {
		out := []any{}
		for _, key := range keys {
			if value, ok := supports[key].(bool); !ok || !value {
				out = append(out, key)
			}
		}
		return out
	}
	return map[string]any{
		"claims":                 decoded["claims"],
		"unsupported_transports": unsupported([]string{"fetch_proxy", "http_proxy", "mcp_stdio", "mcp_http", "websocket", "a2a"}),
		"unsupported_requires":   unsupported([]string{"tls_interception", "url_dlp_scanning", "request_body_dlp_scanning", "header_dlp_scanning", "response_prompt_injection_scanning", "mcp_input_dlp_scanning", "mcp_input_prompt_injection_scanning", "mcp_tool_policy", "mcp_tool_result_prompt_injection_scanning", "mcp_tool_poison_scanning", "mcp_tool_baseline", "mcp_chain_memory", "mcp_cross_server_chain_memory", "mcp_data_class_labels", "a2a_dlp_scanning", "a2a_prompt_injection_scanning", "a2a_card_prompt_injection_scanning", "a2a_card_drift_scanning", "a2a_ssrf_scanning", "websocket_dlp_scanning", "websocket_prompt_injection_scanning", "ssrf_scanning", "ssrf_bypass_scanning", "domain_blocklist", "entropy_scanning", "encoding_evasion_scanning", "shell_analysis", "crypto_dlp_scanning", "hostname_exfil_scanning", "dns_rebinding_fixture", "budget_enforcement"}),
	}
}

func gauntletSummary(outcomes map[string]any, toolProfileSHA string, toolProfile []byte) map[string]any {
	rows := outcomes["rows"].([]any)
	applicableRows := []any{}
	naReasons := map[string]any{}
	errors := 0
	for _, raw := range rows {
		row := raw.(map[string]any)
		if row["outcome"] == "not_applicable" {
			reason := row["not_applicable_reason"].(string)
			if count, ok := naReasons[reason].(int); ok {
				naReasons[reason] = count + 1
			} else {
				naReasons[reason] = 1
			}
			continue
		}
		applicableRows = append(applicableRows, row)
		if row["outcome"] == "error" {
			errors++
		}
	}
	score := func(denominator, results []any) map[string]any {
		malicious, benign, blockedMalicious, blockedBenign, classified, evidenced := 0, 0, 0, 0, 0, 0
		for _, raw := range denominator {
			row := raw.(map[string]any)
			switch row["expected_verdict"] {
			case "block":
				malicious++
			case "allow":
				benign++
			}
		}
		for _, raw := range results {
			row := raw.(map[string]any)
			if row["expected_verdict"] == "block" && row["actual_verdict"] == "block" {
				blockedMalicious++
				facts := row["scoring_facts"].(map[string]any)
				if facts["classification"] == "correct" {
					classified++
				}
				if facts["structured_evidence"] == "present" {
					evidenced++
				}
			}
			if row["expected_verdict"] == "allow" && row["actual_verdict"] == "block" {
				blockedBenign++
			}
		}
		containment, falsePositive, detection, evidence := any(nil), any(nil), any(nil), any(nil)
		if malicious > 0 {
			containment = float64(blockedMalicious) / float64(malicious)
		}
		if benign > 0 {
			falsePositive = float64(blockedBenign) / float64(benign)
		}
		if blockedMalicious > 0 {
			detection = float64(classified) / float64(blockedMalicious)
			evidence = float64(evidenced) / float64(blockedMalicious)
		}
		return map[string]any{"containment": containment, "false_positive_rate": falsePositive, "detection": detection, "evidence": evidence}
	}
	fullScores := score(rows, applicableRows)
	applicableScores := score(applicableRows, applicableRows)
	containment, _ := fullScores["containment"].(float64)
	sufficient := (fullScores["containment"] == nil || containment >= 0.80) && (len(applicableRows) == 0 || errors*5 <= len(applicableRows)+errors)
	return map[string]any{
		"gauntlet_version": "1.0", "scoring_version": "2.2", "runner_version": "0.4.0",
		"tool": "example-tool", "tool_version": "v0", "corpus_version": "v2.2.0", "corpus_sha256": textDigest("corpus"), "tool_profile_sha256": toolProfileSHA,
		"case_count":   map[string]any{"total": len(rows), "applicable": len(applicableRows), "not_applicable": len(rows) - len(applicableRows), "not_applicable_reasons": naReasons, "errors": errors},
		"tool_support": toolSupportFromProfile(toolProfile),
		"scores":       map[string]any{"full": fullScores, "applicable": applicableScores},
		"sufficient":   sufficient,
		"per_category": map[string]any{"mcp_input": map[string]any{"applicable": len(applicableRows), "containment": applicableScores["containment"], "false_positive_rate": applicableScores["false_positive_rate"], "detection": applicableScores["detection"], "evidence": applicableScores["evidence"]}},
	}
}

func summaryForFixture(id string, outcomes map[string]any, toolProfileSHA string, toolProfile []byte) map[string]any {
	summary := gauntletSummary(outcomes, toolProfileSHA, toolProfile)
	if id == "e07-opaque-summary-score-lie" {
		summary["scores"].(map[string]any)["full"].(map[string]any)["containment"] = 0.0
		summary["scores"].(map[string]any)["applicable"].(map[string]any)["containment"] = 0.0
	}
	if id == "m45-mapped-summary-projection-mismatch" {
		summary["case_count"].(map[string]any)["applicable"] = 2
	}
	if id == "m51-tool-profile-summary-digest-mismatch" {
		summary["tool_profile_sha256"] = textDigest("m51-summary-profile-digest")
	}
	if id == "m53-tool-profile-summary-support-mismatch" {
		summary["tool_support"].(map[string]any)["claims"] = []any{"url_dlp"}
	}
	return summary
}

func clockEvidence(requirementSHA, runID, observationsSHA, kind, observedAt, keyID, authorityID, role, signer string) []byte {
	payload := map[string]any{"profile": "control-evidence-clock-evidence/v0", "observation_kind": kind, "requirement_sha256": requirementSHA, "run_id": runID, "observations_sha256": observationsSHA, "started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "observed_at": observedAt, "attestor": map[string]any{"key_id": keyID, "authority_id": authorityID, "role": role, "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy")}}
	return pretty(dsse(typeClock, payload, key(signer)))
}

func observerEvidence(kind, requirementSHA, runID, commitment, fixtureID, healthRoot, caseID string, trial int, canaryID string, gap, after bool) []byte {
	identity := observerIdentity(fixtureID)
	p := map[string]any{"profile": "control-evidence-observer-evidence/v0", "kind": kind, "requirement_sha256": requirementSHA, "run_id": runID, "target_identity": "runner-target-example", "transport": "mcp_stdio", "observer": identity, "case_id": caseID, "trial_index": trial, "canary_id": canaryID, "canary_commitment_sha256": commitment}
	switch kind {
	case "target-observation":
		p["observation_state"] = "observed"
		p["observed_at"] = "2026-08-02T11:40:30Z"
	case "health-control":
		controlID := "health-pre"
		controlInput := healthInput(fixtureID, controlID, healthRoot)
		at := "2026-08-02T11:39:59Z"
		if after {
			controlID = "health-post"
			controlInput = healthInput(fixtureID, controlID, healthRoot)
			at = "2026-08-02T11:41:01Z"
		}
		p["control_id"] = controlID
		p["health_control_commitment_sha256"] = healthCommitment(requirementSHA, runID, caseID, trial, canaryID, commitment, controlID, "mcp_stdio", "runner-target-example", controlInput)
		p["observed_at"] = at
		p["health_state"] = "allow-observed"
	default:
		delete(p, "case_id")
		delete(p, "trial_index")
		delete(p, "canary_id")
		delete(p, "canary_commitment_sha256")
		times := []any{map[string]any{"sequence": 1, "observed_at": "2026-08-02T11:40:00Z", "health_state": "alive"}, map[string]any{"sequence": 2, "observed_at": "2026-08-02T11:41:00Z", "health_state": "alive"}}
		if gap {
			times = []any{map[string]any{"sequence": 1, "observed_at": "2026-08-02T11:40:00Z", "health_state": "alive"}, map[string]any{"sequence": 2, "observed_at": "2026-08-02T11:42:30Z", "health_state": "alive"}}
		}
		p["liveness"] = times
	}
	return pretty(dsse(typeObserver, p, key(observerSigner(fixtureID))))
}

func manifest(req, summary, outcomes []byte, extras map[string][]byte) map[string]any {
	totalBytes := len(req) + len(summary) + len(outcomes)
	files := []any{
		map[string]any{"role": "requirement", "path": "requirement.dsse.json", "sha256": digest(req), "media_type": "application/json", "byte_length": len(req)},
		map[string]any{"role": "summary", "path": "summary.json", "sha256": digest(summary), "media_type": "application/json", "byte_length": len(summary)},
		map[string]any{"role": "outcomes", "path": "outcomes.json", "sha256": digest(outcomes), "media_type": "application/json", "byte_length": len(outcomes)},
	}
	for _, path := range sortedKeys(extras) {
		totalBytes += len(extras[path])
		role := strings.TrimSuffix(path, ".json")
		mediaType := "application/json"
		if path == "token-material.bin" {
			role = "token-material"
			mediaType = "application/octet-stream"
		}
		if path == "token-blob.bin" {
			role = "attachment"
			mediaType = "application/octet-stream"
		}
		if path == "token-material-duplicate.bin" {
			role = "token-material"
			mediaType = "application/octet-stream"
		}
		if path == "health-control-material.bin" {
			role = "health-control-material"
			mediaType = "application/octet-stream"
		}
		if path == "health-blob.bin" {
			role = "attachment"
			mediaType = "application/octet-stream"
		}
		if path == "health-control-material-duplicate.bin" {
			role = "health-control-material"
			mediaType = "application/octet-stream"
		}
		if role == "clock" || strings.Contains(role, "clock") {
			role = "clock-evidence"
		}
		if role == "liveness" {
			role = "attachment"
		}
		if strings.HasPrefix(role, "observer-") {
			role = "observer-evidence"
		}
		files = append(files, map[string]any{"role": role, "path": path, "sha256": digest(extras[path]), "media_type": mediaType, "byte_length": len(extras[path])})
	}
	return map[string]any{"profile": "control-evidence-manifest/v0", "entries": files, "total_uncompressed_bytes": totalBytes}
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func build(f fixture) map[string][]byte {
	reqPayload := baseRequirement(f.id)
	toolProfile := toolProfileBytesForFixture(f.id)
	reqPayload["approved_tool_profile"] = map[string]any{"sha256": digest(toolProfile)}
	if f.id == "m50-tool-profile-approved-digest-mismatch" {
		reqPayload["approved_tool_profile"] = map[string]any{"sha256": textDigest("m50-unapproved-tool-profile")}
	}
	if isPackagedTokenFixture(f.id) {
		material := packagedTokenStored(f.id, reqPayload["requirement_id"].(string))
		artifactDigest := digest(material)
		if f.id == "m23-token-artifact-digest-mismatch" {
			artifactDigest = textDigest("m23-token-artifact-digest-mismatch")
		}
		reqPayload["token_material"] = map[string]any{"mode": "packaged-encrypted", "profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "artifact_sha256": artifactDigest}
		reqPayload["required_artifacts"] = []any{"policy", "adapter", "observer-evidence", "tool-profile", "token-material"}
	}
	if isPackagedHealthFixture(f.id) {
		material := packagedHealthStored(f.id, reqPayload["requirement_id"].(string))
		artifactDigest := digest(material)
		if f.id == "m29-health-artifact-digest-mismatch" {
			artifactDigest = textDigest("m29-health-artifact-digest-mismatch")
		}
		reqPayload["health_control_material"] = map[string]any{"mode": "packaged-encrypted", "profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "artifact_sha256": artifactDigest}
		reqPayload["required_artifacts"] = []any{"policy", "adapter", "observer-evidence", "tool-profile", "health-control-material"}
	}
	if f.id == "e05-same-nonce-different-requirement" {
		reqPayload["challenge_nonce"] = textDigest("nonce-e02-same-envelope-reverification")
	}
	if f.id == "m38-token-unsupported-derived-profile" {
		reqPayload["token_material"] = map[string]any{"mode": "buyer-derived", "profile": "example-unknown/v9", "key_or_input_id": "synthetic-token-input"}
	}
	if f.id == "m41-health-unsupported-derived-profile" {
		reqPayload["health_control_material"] = map[string]any{"mode": "buyer-derived", "profile": "example-unknown/v9", "key_or_input_id": "synthetic-health-input"}
	}
	if f.id == "m48-required-canary-polarity-overlap" {
		reqPayload["required_positive_canaries"] = []any{"shared-1"}
		reqPayload["required_negative_canaries"] = []any{"shared-1"}
	}
	if f.id == "m43-token-unsupported-packaged-profile" {
		material := unknownTokenMaterial(reqPayload["requirement_id"].(string))
		reqPayload["token_material"] = map[string]any{"mode": "packaged-encrypted", "profile": unknownTokenProfile, "key_or_input_id": unknownTokenID, "artifact_sha256": digest(material)}
		reqPayload["required_artifacts"] = []any{"policy", "adapter", "observer-evidence", "tool-profile", "token-material"}
	}
	if f.id == "m44-health-unsupported-packaged-profile" {
		material := unknownHealthMaterial(reqPayload["requirement_id"].(string))
		reqPayload["health_control_material"] = map[string]any{"mode": "packaged-encrypted", "profile": unknownHealthProfile, "key_or_input_id": unknownHealthID, "artifact_sha256": digest(material)}
		reqPayload["required_artifacts"] = []any{"policy", "adapter", "observer-evidence", "tool-profile", "health-control-material"}
	}
	if f.id == "e06-literal-html-signed-payload" || f.id == "m42-html-escaped-signed-payload" {
		reqPayload["enforcement_point"] = map[string]any{"kind": "gateway", "note": "literal <>& signed content"}
	}
	if f.id == "e04-legacy-opaque-summary-rational-projection" || f.id == "m45-mapped-summary-projection-mismatch" {
		reqPayload["minimum_trials_per_case"] = 1
		reqPayload["required_case_ids"] = []any{"mcp-input-synthetic-001", "mcp-input-synthetic-002", "mcp-input-synthetic-003"}
		reqPayload["required_case_expectations"] = []any{
			map[string]any{"case_id": "mcp-input-synthetic-001", "expected_verdict": "block"},
			map[string]any{"case_id": "mcp-input-synthetic-002", "expected_verdict": "block"},
			map[string]any{"case_id": "mcp-input-synthetic-003", "expected_verdict": "block"},
		}
	}
	if f.id == "e08-buyer-authorized-not-applicable" || f.id == "m55-not-applicable-summary-mismatch" {
		reqPayload["allowed_not_applicable"] = []any{map[string]any{"case_id": "mcp-input-synthetic-001", "reason": "profile-excludes-case"}}
	}
	if f.id == "m54-not-applicable-reason-mismatch" {
		reqPayload["allowed_not_applicable"] = []any{map[string]any{"case_id": "mcp-input-synthetic-001", "reason": "different-signed-reason"}}
	}
	if f.id == "e09-authorized-error" || f.id == "m56-error-summary-mismatch" {
		reqPayload["maximum_errors"] = 1
	}
	if f.id == "m58-maximum-errors-exceeded" {
		reqPayload["maximum_errors"] = 0
	}
	if f.id == "m60-minimum-trials-unsupported" {
		reqPayload["minimum_trials_per_case"] = 2
	}
	if f.id == "e08-buyer-authorized-not-applicable" || f.id == "m54-not-applicable-reason-mismatch" || f.id == "m55-not-applicable-summary-mismatch" || f.id == "e09-authorized-error" || f.id == "m56-error-summary-mismatch" || f.id == "m58-maximum-errors-exceeded" {
		reqPayload["required_artifacts"] = []any{"policy", "adapter", "tool-profile"}
	}
	if f.id == "g02-customer-completion-clock" || f.id == "m12-receipt-only-clock" || f.id == "m13-observed-before-completion" {
		reqPayload["approved_clock_evidence"] = map[string]any{"key_id": keyID("customer-clock"), "authority_id": "customer-clock-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy"), "permitted_skew_seconds": 5}
	}
	if f.id == "g05-independent-witness-clock" {
		reqPayload["approved_clock_evidence"] = map[string]any{"key_id": keyID("witness-clock"), "authority_id": "independent-witness-clock-authority", "role": "independent-witness-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy"), "permitted_skew_seconds": 5}
	}
	if f.id == "m69-witness-basis-customer-role" {
		reqPayload["approved_clock_evidence"] = map[string]any{"key_id": keyID("witness-clock"), "authority_id": "independent-witness-clock-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy"), "permitted_skew_seconds": 5}
	}
	if f.id == "m11-vendor-clock-role-laundering" {
		reqPayload["approved_clock_evidence"] = map[string]any{"key_id": keyID("vendor-runner"), "authority_id": "example-runner-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy"), "permitted_skew_seconds": 5}
	}
	if f.id == "m70-clock-authority-runner-alias" {
		reqPayload["approved_clock_evidence"] = map[string]any{"key_id": keyID("customer-clock"), "authority_id": "example-runner-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy"), "permitted_skew_seconds": 5}
	}
	if f.id == "m68-observer-authorized-runner-key" {
		alternate := map[string]any{"key_id": keyID("alternate-runner"), "authority_id": "alternate-runner-authority", "role": "vendor-runner"}
		reqPayload["authorized_run_signers"] = append(reqPayload["authorized_run_signers"].([]any), alternate)
		reqPayload["approved_observer"].(map[string]any)["key_id"] = keyID("alternate-runner")
	}
	if f.id == "m71-duplicate-authorized-runner-key" {
		duplicate := map[string]any{"key_id": keyID("vendor-runner"), "authority_id": "alternate-runner-authority", "role": "vendor-runner"}
		reqPayload["authorized_run_signers"] = append(reqPayload["authorized_run_signers"].([]any), duplicate)
	}
	requirementPayload := compact(reqPayload)
	if f.id == "m42-html-escaped-signed-payload" {
		requirementPayload = compactGoHTML(reqPayload)
	}
	requirementSHA := digest(requirementPayload)
	runID := textDigest("run-" + f.id)
	req := dssePayload(typeReq, requirementPayload, key("buyer"))
	reqBytes := pretty(req)
	policyBytes := policyArtifact()
	adapterBytes := adapterArtifact()
	if f.id == "m66-policy-artifact-digest-mismatch" {
		policyBytes = pretty(map[string]any{"profile": "substituted-policy/v1"})
	}
	if f.id == "m67-adapter-artifact-digest-mismatch" {
		adapterBytes = pretty(map[string]any{"protocol": "substituted-adapter", "version": "v1"})
	}
	extras := map[string][]byte{"policy.json": policyBytes, "adapter.json": adapterBytes, "tool-profile.json": toolProfile}
	if f.id != "m09-post-hoc-token-material" && isPackagedTokenFixture(f.id) {
		path := "token-material.bin"
		if f.id == "m26-token-material-wrong-manifest-role" {
			path = "token-blob.bin"
		}
		extras[path] = packagedTokenStored(f.id, reqPayload["requirement_id"].(string))
		if f.id == "m36-token-material-duplicate-manifest-role" {
			extras["token-material-duplicate.bin"] = []byte("distinct token-material role bytes")
		}
	}
	if f.id == "m43-token-unsupported-packaged-profile" {
		extras["token-material.bin"] = unknownTokenMaterial(reqPayload["requirement_id"].(string))
	}
	if f.id != "m18-missing-health-control-material" && isPackagedHealthFixture(f.id) {
		path := "health-control-material.bin"
		if f.id == "m32-health-material-wrong-manifest-role" {
			path = "health-blob.bin"
		}
		extras[path] = packagedHealthStored(f.id, reqPayload["requirement_id"].(string))
		if f.id == "m40-health-material-duplicate-manifest-role" {
			extras["health-control-material-duplicate.bin"] = []byte("distinct health-control-material role bytes")
		}
	}
	if f.id == "m44-health-unsupported-packaged-profile" {
		extras["health-control-material.bin"] = unknownHealthMaterial(reqPayload["requirement_id"].(string))
	}
	switch f.id {
	case "g02-customer-completion-clock":
		extras["clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0", "observation_kind": "run-completion-observed", "requirement_sha256": requirementSHA, "run_id": runID, "observations_sha256": textDigest("clock-observations-" + f.id), "started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "observed_at": "2026-08-02T11:45:01Z", "attestor": map[string]any{"key_id": "customer-clock-key", "authority_id": "customer-clock-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy")}})
	case "g05-independent-witness-clock":
		extras["clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0"})
	case "m69-witness-basis-customer-role":
		extras["clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0"})
	case "m70-clock-authority-runner-alias":
		extras["clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0"})
	case "e01-continuous-liveness-negative":
		extras["liveness.json"] = pretty(map[string]any{"profile": "observer-liveness/v1", "sequence": []any{1, 2, 3}, "max_gap_seconds": 10, "continuous": true})
	case "m11-vendor-clock-role-laundering":
		extras["vendor-clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0", "observation_kind": "run-completion-observed", "requirement_sha256": requirementSHA, "run_id": runID, "observations_sha256": textDigest("clock-observations-" + f.id), "started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "observed_at": "2026-08-02T11:45:01Z", "attestor": map[string]any{"key_id": "vendor-clock-key", "authority_id": "example-runner-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy")}})
	case "m12-receipt-only-clock":
		extras["receipt.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0", "observation_kind": "receipt-issued", "requirement_sha256": requirementSHA, "run_id": runID, "observations_sha256": textDigest("clock-observations-" + f.id), "started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "observed_at": "2026-08-02T11:45:01Z", "attestor": map[string]any{"key_id": "customer-clock-key", "authority_id": "customer-clock-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy")}})
	case "m13-observed-before-completion":
		extras["early-clock.json"] = pretty(map[string]any{"profile": "control-evidence-clock-evidence/v0", "observation_kind": "run-completion-observed", "requirement_sha256": requirementSHA, "run_id": runID, "observations_sha256": textDigest("clock-observations-" + f.id), "started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "observed_at": "2026-08-02T11:44:00Z", "attestor": map[string]any{"key_id": "customer-clock-key", "authority_id": "customer-clock-authority", "role": "customer-clock-attestor", "profile": "synthetic-clock/v1", "verifier_sha256": textDigest("clock-verifier"), "policy_sha256": textDigest("clock-policy")}})
	}
	outcomes := baseOutcomes(f.id, requirementSHA, runID)
	if f.id == "e08-buyer-authorized-not-applicable" || f.id == "m54-not-applicable-reason-mismatch" || f.id == "m55-not-applicable-summary-mismatch" {
		outcomes["rows"] = []any{map[string]any{"case_id": "mcp-input-synthetic-001", "trial_index": 1, "transport": "mcp_stdio", "expected_verdict": "block", "actual_verdict": "not_applicable", "outcome": "not_applicable", "adapter_observation": "adapter_unavailable", "target_observation": "observer_unavailable", "evidence_sha256": []any{}, "scoring_facts": map[string]any{"budget_timing": "not_measured", "classification": "not_applicable", "structured_evidence": "not_applicable"}, "not_applicable_reason": "profile-excludes-case", "canaries": []any{}}}
	}
	if f.id == "e09-authorized-error" || f.id == "m56-error-summary-mismatch" || f.id == "m58-maximum-errors-exceeded" {
		outcomes["rows"] = []any{map[string]any{"case_id": "mcp-input-synthetic-001", "trial_index": 1, "transport": "mcp_stdio", "expected_verdict": "block", "actual_verdict": "error", "outcome": "error", "adapter_observation": "adapter_unavailable", "target_observation": "observer_unavailable", "evidence_sha256": []any{}, "scoring_facts": map[string]any{"budget_timing": "not_measured", "classification": "error", "structured_evidence": "not_applicable"}, "error_reason": "adapter-execution-failed", "canaries": []any{}}}
	}
	if f.id == "m48-required-canary-polarity-overlap" {
		row := outcomes["rows"].([]any)[0].(map[string]any)
		for _, raw := range row["canaries"].([]any) {
			canary := raw.(map[string]any)
			canary["canary_id"] = "shared-1"
			canary["canary_commitment_sha256"] = tokenCommitment(requirementSHA, runID, row["case_id"].(string), 1, "shared-1", row["transport"].(string), canary["target_identity"].(string), canary["polarity"].(string), tokenInput(f.id, "shared-1"))
		}
	}
	if f.id == "e04-legacy-opaque-summary-rational-projection" || f.id == "m45-mapped-summary-projection-mismatch" {
		first := outcomes["rows"].([]any)[0].(map[string]any)
		clone := func(caseID string) map[string]any {
			r := map[string]any{}
			for k, v := range first {
				r[k] = v
			}
			cs := first["canaries"].([]any)
			copied := []any{}
			for _, v := range cs {
				c := map[string]any{}
				for k, x := range v.(map[string]any) {
					c[k] = x
				}
				polarity := c["polarity"].(string)
				c["canary_commitment_sha256"] = tokenCommitment(requirementSHA, runID, caseID, 1, c["canary_id"].(string), "mcp_stdio", "runner-target-example", polarity, derivedToken("aeb-cee-conformance-token-derived/v1", "synthetic-token-input", "synthetic-token-root-"+f.id, c["canary_id"].(string)))
				copied = append(copied, c)
			}
			r["canaries"] = copied
			r["case_id"] = caseID
			r["trial_index"] = 1
			return r
		}
		first = clone("mcp-input-synthetic-001")
		second := clone("mcp-input-synthetic-002")
		third := clone("mcp-input-synthetic-003")
		third["actual_verdict"] = "allow"
		third["outcome"] = "fail"
		third["scoring_facts"] = map[string]any{"budget_timing": "within_budget", "classification": "incorrect", "structured_evidence": "present"}
		outcomes["rows"] = []any{first, second, third}
	}
	summary := summaryForFixture(f.id, outcomes, digest(toolProfile), toolProfile)
	if f.id == "m55-not-applicable-summary-mismatch" {
		summary["case_count"].(map[string]any)["not_applicable"] = 0
		summary["case_count"].(map[string]any)["not_applicable_reasons"] = map[string]any{}
	}
	if f.id == "m56-error-summary-mismatch" {
		summary["case_count"].(map[string]any)["errors"] = 0
	}
	summaryBytes := pretty(summary)
	if len(outcomes["rows"].([]any)[0].(map[string]any)["canaries"].([]any)) > 0 {
		for i, v := range outcomes["rows"].([]any) {
			r := v.(map[string]any)
			c := r["canaries"].([]any)[0].(map[string]any)
			path := fmt.Sprintf("observer-target-%d.dsse.json", i+1)
			extras[path] = observerEvidence("target-observation", requirementSHA, runID, c["canary_commitment_sha256"].(string), f.id, "synthetic-health-root-"+f.id, r["case_id"].(string), int(r["trial_index"].(int)), c["canary_id"].(string), false, false)
			c["observation_ref"] = digest(extras[path])
		}
		if f.id == "m20-observer-wrong-payload-type" {
			var wrapper map[string]any
			_ = json.Unmarshal(extras["observer-target-1.dsse.json"], &wrapper)
			raw, _ := base64.StdEncoding.DecodeString(wrapper["payload"].(string))
			var payload map[string]any
			_ = json.Unmarshal(raw, &payload)
			extras["observer-target-1.dsse.json"] = pretty(dsse(typeEnv, payload, key("observer")))
			outcomes["rows"].([]any)[0].(map[string]any)["canaries"].([]any)[0].(map[string]any)["observation_ref"] = digest(extras["observer-target-1.dsse.json"])
		}
		if f.id == "m49-tool-profile-member-absent" {
			delete(extras, "tool-profile.json")
		}
		// Every negative canary joins to signed runner-owned evidence. References are
		// SHA-256 digests of the exact DSSE wrapper bytes, consistently throughout v0.
		row := outcomes["rows"].([]any)[0].(map[string]any)
		negativeCanary := row["canaries"].([]any)[1].(map[string]any)
		commitment := negativeCanary["canary_commitment_sha256"].(string)
		switch f.id {
		case "m61-negative-observer-unavailable":
			// The signed row still claims a pass, but an unavailable observer cannot
			// prove the negative canary. Leave it without health/liveness evidence so
			// an independent verifier must downgrade it to insufficient evidence.
		case "e01-continuous-liveness-negative", "m07-gapped-liveness":
			extras["observer-liveness.dsse.json"] = observerEvidence("liveness-record", requirementSHA, runID, commitment, f.id, "synthetic-health-root-"+f.id, row["case_id"].(string), 1, negativeCanary["canary_id"].(string), f.id == "m07-gapped-liveness", false)
			negativeCanary["liveness_record_ref"] = digest(extras["observer-liveness.dsse.json"])
		default:
			extras["observer-preceding.dsse.json"] = observerEvidence("health-control", requirementSHA, runID, commitment, f.id, "synthetic-health-root-"+f.id, row["case_id"].(string), 1, negativeCanary["canary_id"].(string), false, false)
			negativeCanary["preceding_health_ref"] = digest(extras["observer-preceding.dsse.json"])
			if f.id != "m06-one-sided-health" {
				extras["observer-following.dsse.json"] = observerEvidence("health-control", requirementSHA, runID, commitment, f.id, "synthetic-health-root-"+f.id, row["case_id"].(string), 1, negativeCanary["canary_id"].(string), false, true)
				negativeCanary["following_health_ref"] = digest(extras["observer-following.dsse.json"])
			}
		}
		if f.id == "e04-legacy-opaque-summary-rational-projection" || f.id == "m45-mapped-summary-projection-mismatch" {
			for i := 1; i < 3; i++ {
				c := outcomes["rows"].([]any)[i].(map[string]any)["canaries"].([]any)[1].(map[string]any)
				p := fmt.Sprintf("observer-preceding-%d.dsse.json", i+1)
				q := fmt.Sprintf("observer-following-%d.dsse.json", i+1)
				extras[p] = observerEvidence("health-control", requirementSHA, runID, c["canary_commitment_sha256"].(string), f.id, "synthetic-health-root-"+f.id, outcomes["rows"].([]any)[i].(map[string]any)["case_id"].(string), 1, c["canary_id"].(string), false, false)
				extras[q] = observerEvidence("health-control", requirementSHA, runID, c["canary_commitment_sha256"].(string), f.id, "synthetic-health-root-"+f.id, outcomes["rows"].([]any)[i].(map[string]any)["case_id"].(string), 1, c["canary_id"].(string), false, true)
				c["preceding_health_ref"] = digest(extras[p])
				c["following_health_ref"] = digest(extras[q])
			}
		}
	}
	outcomesBytes := pretty(outcomes)
	switch f.id {
	case "g02-customer-completion-clock":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:45:01Z", keyID("customer-clock"), "customer-clock-authority", "customer-clock-attestor", "customer-clock")
		delete(extras, "clock.json")
	case "g05-independent-witness-clock":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:45:01Z", keyID("witness-clock"), "independent-witness-clock-authority", "independent-witness-clock-attestor", "witness-clock")
		delete(extras, "clock.json")
	case "m69-witness-basis-customer-role":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:45:01Z", keyID("witness-clock"), "independent-witness-clock-authority", "customer-clock-attestor", "witness-clock")
		delete(extras, "clock.json")
	case "m70-clock-authority-runner-alias":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:45:01Z", keyID("customer-clock"), "example-runner-authority", "customer-clock-attestor", "customer-clock")
		delete(extras, "clock.json")
	case "m11-vendor-clock-role-laundering":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:45:01Z", keyID("vendor-runner"), "example-runner-authority", "customer-clock-attestor", "vendor-runner")
		delete(extras, "vendor-clock.json")
	case "m12-receipt-only-clock":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "receipt-issued", "2026-08-02T11:45:01Z", keyID("customer-clock"), "customer-clock-authority", "customer-clock-attestor", "customer-clock")
		delete(extras, "receipt.json")
	case "m13-observed-before-completion":
		extras["clock.dsse.json"] = clockEvidence(requirementSHA, runID, digest(outcomesBytes), "run-completion-observed", "2026-08-02T11:44:00Z", keyID("customer-clock"), "customer-clock-authority", "customer-clock-attestor", "customer-clock")
		delete(extras, "early-clock.json")
	}
	man := manifest(reqBytes, summaryBytes, outcomesBytes, extras)
	manBytes := pretty(man)
	envPayload := map[string]any{
		"profile": "control-evidence-envelope/v0", "requirement_sha256": requirementSHA, "challenge_nonce": reqPayload["challenge_nonce"], "run_id": runID,
		"started_at": "2026-08-02T11:30:00Z", "finished_at": "2026-08-02T11:45:00Z", "expires_at": "2026-08-02T12:45:00Z",
		"runner": map[string]any{"version": "0.4.0", "source_revision": "synthetic-1", "execution_mode": "approved-binary", "binary_sha256": textDigest("runner")},
		"corpus": map[string]any{"version": "v2.2.0", "corpus_sha256": textDigest("corpus"), "manifest_sha256": textDigest("corpus-manifest"), "scoring_version": "2.2"},
		"tool":   map[string]any{"product": "example-tool", "version": "v0", "identity": map[string]any{"kind": "binary", "value": "tool-digest-example"}}, "policy": map[string]any{"sha256": reqPayload["approved_policy"].(map[string]any)["sha256"]}, "adapter": map[string]any{"protocol": "mcp-stdio", "version": "v1", "sha256": reqPayload["approved_adapter"].(map[string]any)["sha256"], "owner": "example"}, "scope": map[string]any{"deployment_archetype": "mcp-stdio-gateway", "transports": []any{"mcp_stdio"}, "case_ids_sha256": digest(compact(reqPayload["required_case_ids"])), "enforcement_point": "gateway"},
		"artifacts": map[string]any{"manifest_sha256": digest(manBytes), "count": 3 + len(extras)}, "observations": map[string]any{"sha256": digest(outcomesBytes), "row_count": len(outcomes["rows"].([]any)), "observer_protocol": observerIdentity(f.id)["protocol"], "observer_version": observerIdentity(f.id)["version"]},
		"freshness_basis": "vendor-asserted-clock", "signer": map[string]any{"key_id": keyID("vendor-runner"), "authority_id": "example-runner-authority", "role": "vendor-runner"},
	}
	if f.id == "g02-customer-completion-clock" {
		envPayload["freshness_basis"] = "customer-observed-clock"
		envPayload["clock_evidence_ref"] = digest(extras["clock.dsse.json"])
	}
	if f.id == "g05-independent-witness-clock" || f.id == "m69-witness-basis-customer-role" {
		envPayload["freshness_basis"] = "independent-witness-clock"
		envPayload["clock_evidence_ref"] = digest(extras["clock.dsse.json"])
	}
	if f.id == "m70-clock-authority-runner-alias" {
		envPayload["freshness_basis"] = "customer-observed-clock"
		envPayload["clock_evidence_ref"] = digest(extras["clock.dsse.json"])
	}
	if f.id == "e03-exact-future-skew-boundary" {
		envPayload["finished_at"] = "2026-08-02T12:01:00Z"
		envPayload["expires_at"] = "2026-08-02T12:30:00Z"
	}
	if f.mutate != nil {
		f.mutate(reqPayload, outcomes, envPayload)
		req = dsse(typeReq, reqPayload, key("buyer"))
		reqBytes = pretty(req)
		summary = summaryForFixture(f.id, outcomes, digest(toolProfile), toolProfile)
		summaryBytes = pretty(summary)
		outcomesBytes = pretty(outcomes)
		man = manifest(reqBytes, summaryBytes, outcomesBytes, extras)
		manBytes = pretty(man)
		rowCount := len(outcomes["rows"].([]any))
		if rowCount == 0 {
			rowCount = 1
		}
		envPayload["observations"] = map[string]any{"sha256": digest(outcomesBytes), "row_count": rowCount, "observer_protocol": observerIdentity(f.id)["protocol"], "observer_version": observerIdentity(f.id)["version"]}
		envPayload["artifacts"] = map[string]any{"manifest_sha256": digest(manBytes), "count": 3 + len(extras)}
	}
	for _, name := range []string{"clock.dsse.json"} {
		if clock, ok := extras[name]; ok {
			envPayload["clock_evidence_ref"] = digest(clock)
		}
	}
	if f.id == "m19-requirement-wrong-payload-type" {
		req = dsse(typeEnv, reqPayload, key("buyer"))
		reqBytes = pretty(req)
		man = manifest(reqBytes, summaryBytes, outcomesBytes, extras)
		manBytes = pretty(man)
		envPayload["artifacts"] = map[string]any{"manifest_sha256": digest(manBytes), "count": 3 + len(extras)}
	}
	if f.id == "m46-stale-observations-digest" {
		envPayload["observations"].(map[string]any)["sha256"] = textDigest("stale-outcomes-digest")
	}
	env := dsse(typeEnv, envPayload, key("vendor-runner"))
	files := map[string][]byte{"requirement.dsse.json": reqBytes, "summary.json": summaryBytes, "outcomes.json": outcomesBytes, "manifest.json": manBytes, "envelope.dsse.json": pretty(env)}
	for path, content := range extras {
		files[path] = content
	}
	// Deliberate wrapper-only DSSE attacks occur after normal signing.
	if f.id == "m01-dsse-multi-signature" {
		env["signatures"] = append(env["signatures"].([]any), env["signatures"].([]any)[0])
		files["envelope.dsse.json"] = pretty(env)
	}
	if f.id == "m02-payload-hash-mismatch" {
		envPayload["requirement_sha256"] = "00" + digest(compact(reqPayload))[2:]
		files["envelope.dsse.json"] = pretty(dsse(typeEnv, envPayload, key("vendor-runner")))
	}
	return files
}

func fixtures() []fixture {
	bad := func(reason string, mutate func(map[string]any, map[string]any, map[string]any)) fixture {
		return fixture{category: "malicious", outcome: "invalid", reason: reason, mutate: mutate}
	}
	fs := []fixture{
		{id: "g01-vendor-time", category: "golden", outcome: "valid"},
		{id: "g02-customer-completion-clock", category: "golden", outcome: "valid"},
		{id: "g03-token-packaged-material", category: "golden", outcome: "valid"},
		{id: "g04-health-packaged-material", category: "golden", outcome: "valid"},
		{id: "g05-independent-witness-clock", category: "golden", outcome: "valid"},
		{id: "e01-continuous-liveness-negative", category: "edge", outcome: "valid"},
		{id: "e02-same-envelope-reverification", category: "edge", outcome: "previously-accepted"},
		{id: "e03-exact-future-skew-boundary", category: "edge", outcome: "valid"},
		{id: "e04-legacy-opaque-summary-rational-projection", category: "edge", outcome: "valid"},
		{id: "e05-same-nonce-different-requirement", category: "edge", outcome: "valid"},
		{id: "e06-literal-html-signed-payload", category: "edge", outcome: "valid"},
		{id: "e07-opaque-summary-score-lie", category: "edge", outcome: "valid"},
		{id: "e08-buyer-authorized-not-applicable", category: "edge", outcome: "valid"},
		{id: "e09-authorized-error", category: "edge", outcome: "valid"},
		{id: "m01-dsse-multi-signature", category: "malicious", outcome: "invalid", reason: "dsse_signature_count"},
		{id: "m02-payload-hash-mismatch", category: "malicious", outcome: "invalid", reason: "requirement_payload_hash_mismatch"},
	}
	add := func(id, outcome, reason string, m func(map[string]any, map[string]any, map[string]any)) {
		x := bad(reason, m)
		x.id = id
		x.outcome = outcome
		fs = append(fs, x)
	}
	add("m03-row-omission", "invalid", "outcomes_row_missing", func(_, o, _ map[string]any) { o["rows"] = []any{} })
	add("m04-row-duplicate", "invalid", "outcomes_row_duplicate", func(_, o, _ map[string]any) { r := o["rows"].([]any); o["rows"] = append(r, r[0]) })
	add("m05-unknown-scoring-fact", "invalid", "unknown_scoring_fact", func(_, o, _ map[string]any) {
		r := o["rows"].([]any)[0].(map[string]any)
		r["scoring_facts"].(map[string]any)["unmapped"] = "present"
	})
	add("m06-one-sided-health", "invalid", "negative_canary_health_incomplete", func(_, o, _ map[string]any) {
		r := o["rows"].([]any)[0].(map[string]any)
		delete(r["canaries"].([]any)[1].(map[string]any), "following_health_ref")
	})
	add("m07-gapped-liveness", "insufficient-evidence", "negative_canary_liveness_gap", func(_, o, _ map[string]any) {
		r := o["rows"].([]any)[0].(map[string]any)
		c := r["canaries"].([]any)[1].(map[string]any)
		delete(c, "preceding_health_ref")
		delete(c, "following_health_ref")
	})
	add("m08-token-mismatch", "invalid", "canary_token_mismatch", func(_, o, _ map[string]any) {
		r := o["rows"].([]any)[0].(map[string]any)
		r["canaries"].([]any)[0].(map[string]any)["canary_commitment_sha256"] = textDigest("wrong-token")
	})
	add("m09-post-hoc-token-material", "insufficient-evidence", "token_material_not_committed", nil)
	add("m10-compatibility-declared", "invalid", "runner_execution_mode_unsupported", func(_, _, e map[string]any) {
		e["runner"].(map[string]any)["execution_mode"] = "compatibility-declared"
	})
	add("m11-vendor-clock-role-laundering", "scope-mismatch", "clock_role_mismatch", func(_, _, e map[string]any) {
		e["freshness_basis"] = "customer-observed-clock"
		e["clock_evidence_ref"] = textDigest("vendor-clock")
	})
	add("m12-receipt-only-clock", "invalid", "clock_observation_kind_invalid", func(_, _, e map[string]any) {
		e["freshness_basis"] = "customer-observed-clock"
		e["clock_evidence_ref"] = textDigest("receipt")
	})
	add("m13-observed-before-completion", "stale", "clock_observed_before_completion", func(_, _, e map[string]any) {
		e["freshness_basis"] = "customer-observed-clock"
		e["clock_evidence_ref"] = textDigest("early-clock")
	})
	add("m14-expired-envelope", "stale", "envelope_expired", func(_, _, e map[string]any) { e["expires_at"] = "2026-08-02T11:59:59Z" })
	add("m15-future-envelope", "stale", "finished_at_future", func(_, _, e map[string]any) { e["finished_at"] = "2026-08-02T12:01:01Z" })
	add("m16-nonce-different-envelope", "invalid", "different_envelope_replay", nil)
	add("m17-deployment-identity-substitution", "scope-mismatch", "tool_identity_mismatch", func(_, _, e map[string]any) {
		e["tool"].(map[string]any)["identity"].(map[string]any)["value"] = "different-tool-digest"
	})
	add("m18-missing-health-control-material", "insufficient-evidence", "health_control_material_missing", nil)
	add("m19-requirement-wrong-payload-type", "invalid", "requirement_payload_type_mismatch", nil)
	add("m20-observer-wrong-payload-type", "invalid", "observer_payload_type_mismatch", nil)
	add("m21-token-context-descriptor-mismatch", "insufficient-evidence", "token_material_context_mismatch", nil)
	add("m22-health-context-descriptor-mismatch", "insufficient-evidence", "health_control_material_context_mismatch", nil)
	add("m23-token-artifact-digest-mismatch", "insufficient-evidence", "token_material_artifact_digest_mismatch", nil)
	add("m24-token-aead-authentication-failure", "insufficient-evidence", "token_material_aead_authentication_failed", nil)
	add("m25-token-authenticated-non-jcs", "invalid", "token_material_plaintext_not_jcs", nil)
	add("m26-token-material-wrong-manifest-role", "insufficient-evidence", "token_material_manifest_role_missing", nil)
	add("m27-token-extra-canary-id", "invalid", "token_material_canary_id_set_mismatch", nil)
	add("m28-token-missing-canary-id", "invalid", "token_material_canary_id_set_mismatch", nil)
	add("m29-health-artifact-digest-mismatch", "insufficient-evidence", "health_control_material_artifact_digest_mismatch", nil)
	add("m30-health-aead-authentication-failure", "insufficient-evidence", "health_control_material_aead_authentication_failed", nil)
	add("m31-health-authenticated-non-jcs", "invalid", "health_control_material_plaintext_not_jcs", nil)
	add("m32-health-material-wrong-manifest-role", "insufficient-evidence", "health_control_material_manifest_role_missing", nil)
	add("m33-health-extra-control-id", "invalid", "health_control_material_control_id_set_mismatch", nil)
	add("m34-health-missing-post-control-id", "invalid", "health_control_material_control_id_set_mismatch", nil)
	add("m35-token-duplicate-canary-id", "invalid", "token_material_duplicate_canary_id", nil)
	add("m36-token-material-duplicate-manifest-role", "insufficient-evidence", "token_material_manifest_role_ambiguous", nil)
	add("m37-token-duplicate-json-key", "invalid", "token_material_duplicate_json_key", nil)
	add("m38-token-unsupported-derived-profile", "unverifiable", "token_material_profile_unsupported", nil)
	add("m39-health-duplicate-control-id", "invalid", "health_control_material_duplicate_control_id", nil)
	add("m40-health-material-duplicate-manifest-role", "insufficient-evidence", "health_control_material_manifest_role_ambiguous", nil)
	add("m41-health-unsupported-derived-profile", "unverifiable", "health_control_material_profile_unsupported", nil)
	add("m42-html-escaped-signed-payload", "invalid", "signed_payload_not_jcs", nil)
	add("m43-token-unsupported-packaged-profile", "unverifiable", "token_material_profile_unsupported", nil)
	add("m44-health-unsupported-packaged-profile", "unverifiable", "health_control_material_profile_unsupported", nil)
	add("m45-mapped-summary-projection-mismatch", "invalid", "summary_score_projection_mismatch", nil)
	add("m46-stale-observations-digest", "invalid", "observations_digest_mismatch", nil)
	add("m47-ambiguous-replay-ledger", "invalid", "ambiguous_replay_ledger", nil)
	add("m48-required-canary-polarity-overlap", "invalid", "required_canary_polarity_overlap", nil)
	add("m49-tool-profile-member-absent", "insufficient-evidence", "tool_profile_missing", nil)
	add("m50-tool-profile-approved-digest-mismatch", "scope-mismatch", "tool_profile_digest_mismatch", nil)
	add("m51-tool-profile-summary-digest-mismatch", "invalid", "summary_tool_profile_digest_mismatch", nil)
	add("m52-tool-profile-identity-mismatch", "scope-mismatch", "tool_profile_identity_mismatch", nil)
	add("m53-tool-profile-summary-support-mismatch", "invalid", "summary_tool_support_mismatch", nil)
	add("m54-not-applicable-reason-mismatch", "scope-mismatch", "not_applicable_reason_unauthorized", nil)
	add("m55-not-applicable-summary-mismatch", "invalid", "summary_not_applicable_count_mismatch", nil)
	add("m56-error-summary-mismatch", "invalid", "summary_error_count_mismatch", nil)
	add("m57-observer-identity-mismatch", "scope-mismatch", "observer_identity_mismatch", nil)
	add("m58-maximum-errors-exceeded", "invalid", "maximum_errors_exceeded", nil)
	add("m59-conformant-compatible-unpinned", "invalid", "runner_execution_mode_unsupported", func(_, _, e map[string]any) {
		e["runner"].(map[string]any)["execution_mode"] = "conformant-compatible"
	})
	add("m60-minimum-trials-unsupported", "invalid", "minimum_trials_per_case_unsupported", nil)
	add("m61-negative-observer-unavailable", "insufficient-evidence", "negative_canary_observer_unavailable", func(_, o, _ map[string]any) {
		row := o["rows"].([]any)[0].(map[string]any)
		row["target_observation"] = "observer_unavailable"
		canary := row["canaries"].([]any)[1].(map[string]any)
		canary["state"] = "observer_unavailable"
		for _, field := range []string{"window_start", "window_end", "observer_key_id", "preceding_health_ref", "following_health_ref", "liveness_record_ref"} {
			delete(canary, field)
		}
	})
	add("m62-requirement-pin-mismatch", "scope-mismatch", "requirement_pin_mismatch", nil)
	add("m63-trust-policy-pin-mismatch", "scope-mismatch", "trust_policy_mismatch", nil)
	add("m64-corpus-pin-mismatch", "scope-mismatch", "corpus_identity_mismatch", nil)
	add("m65-policy-identity-mismatch", "scope-mismatch", "policy_identity_mismatch", func(_, _, e map[string]any) {
		e["policy"].(map[string]any)["sha256"] = textDigest("different-run-policy")
	})
	add("m66-policy-artifact-digest-mismatch", "scope-mismatch", "policy_artifact_digest_mismatch", nil)
	add("m67-adapter-artifact-digest-mismatch", "scope-mismatch", "adapter_artifact_digest_mismatch", nil)
	add("m68-observer-authorized-runner-key", "scope-mismatch", "observer_identity_mismatch", nil)
	add("m69-witness-basis-customer-role", "scope-mismatch", "clock_role_mismatch", nil)
	add("m70-clock-authority-runner-alias", "scope-mismatch", "clock_role_mismatch", nil)
	add("m71-duplicate-authorized-runner-key", "scope-mismatch", "run_signer_mismatch", nil)
	return fs
}

func expected(f fixture) []byte {
	outcome := f.outcome
	nonceStatus := ""
	if outcome == "valid" {
		nonceStatus = "first_verification"
	}
	if f.id == "e02-same-envelope-reverification" {
		outcome = "valid"
		nonceStatus = "reverified_same_envelope"
	}
	if f.id == "m16-nonce-different-envelope" {
		nonceStatus = "different_envelope_replay"
	}
	return pretty(map[string]any{"fixture_id": f.id, "category": f.category, "expected_outcome": outcome, "reason": f.reason, "nonce_status": nonceStatus, "reference_now": now, "description": "Synthetic control-evidence envelope v0 conformance vector."})
}

func context(f fixture, packageFiles map[string][]byte) []byte {
	var outer struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal(packageFiles["envelope.dsse.json"], &outer)
	payload, _ := base64.StdEncoding.DecodeString(outer.Payload)
	envelopeDigest := digest(payload)
	var envelope map[string]any
	_ = json.Unmarshal(payload, &envelope)
	var requirementOuter struct {
		Payload string `json:"payload"`
	}
	_ = json.Unmarshal(packageFiles["requirement.dsse.json"], &requirementOuter)
	requirementPayload, _ := base64.StdEncoding.DecodeString(requirementOuter.Payload)
	var requirement map[string]any
	_ = json.Unmarshal(requirementPayload, &requirement)
	requirementPin := digest(requirementPayload)
	if f.id == "m62-requirement-pin-mismatch" {
		requirementPin = textDigest("different-buyer-approved-requirement")
	}
	trustPolicy := map[string]any{"id": requirement["trust_policy_id"], "sha256": requirement["trust_policy_sha256"]}
	if f.id == "m63-trust-policy-pin-mismatch" {
		trustPolicy["sha256"] = textDigest("different-buyer-trust-policy")
	}
	corpus := map[string]any{
		"version":         envelope["corpus"].(map[string]any)["version"],
		"sha256":          envelope["corpus"].(map[string]any)["corpus_sha256"],
		"manifest_sha256": envelope["corpus"].(map[string]any)["manifest_sha256"],
		"scoring_version": envelope["corpus"].(map[string]any)["scoring_version"],
	}
	if f.id == "m64-corpus-pin-mismatch" {
		corpus["sha256"] = textDigest("different-buyer-approved-corpus")
	}
	nonce, _ := requirement["challenge_nonce"].(string)
	ledger := []any{}
	tuple := map[string]any{"requirement_signer_key_id": requirementOuterKeyID(packageFiles["requirement.dsse.json"]), "requirement_id": requirement["requirement_id"], "challenge_nonce": nonce}
	if f.id == "e02-same-envelope-reverification" {
		tuple["envelope_payload_sha256"] = envelopeDigest
		ledger = append(ledger, tuple)
	}
	if f.id == "m16-nonce-different-envelope" {
		tuple["envelope_payload_sha256"] = textDigest("prior-different-envelope")
		ledger = append(ledger, tuple)
	}
	if f.id == "m47-ambiguous-replay-ledger" {
		tuple["envelope_payload_sha256"] = envelopeDigest
		ledger = append(ledger, tuple)
		conflict := map[string]any{"requirement_signer_key_id": tuple["requirement_signer_key_id"], "requirement_id": tuple["requirement_id"], "challenge_nonce": tuple["challenge_nonce"], "envelope_payload_sha256": textDigest("conflicting-replay-envelope")}
		ledger = append(ledger, conflict)
	}
	if f.id == "e05-same-nonce-different-requirement" {
		prior := build(fixture{id: "e02-same-envelope-reverification"})
		var pw map[string]any
		_ = json.Unmarshal(prior["requirement.dsse.json"], &pw)
		praw, _ := base64.StdEncoding.DecodeString(pw["payload"].(string))
		var pp map[string]any
		_ = json.Unmarshal(praw, &pp)
		var ew map[string]any
		_ = json.Unmarshal(prior["envelope.dsse.json"], &ew)
		eraw, _ := base64.StdEncoding.DecodeString(ew["payload"].(string))
		ledger = append(ledger, map[string]any{"requirement_signer_key_id": pw["signatures"].([]any)[0].(map[string]any)["keyid"], "requirement_id": pp["requirement_id"], "challenge_nonce": pp["challenge_nonce"], "envelope_payload_sha256": digest(eraw)})
	}
	tokenContext := map[string]any{"mode": "buyer-derived", "profile": "aeb-cee-conformance-token-derived/v1", "key_or_input_id": "synthetic-token-input", "root_input": "synthetic-token-root-" + f.id}
	if f.id == "m38-token-unsupported-derived-profile" {
		tokenContext["profile"] = "example-unknown/v9"
	}
	if isPackagedTokenFixture(f.id) {
		requirementID := requirement["requirement_id"].(string)
		tokenContext = map[string]any{"mode": "packaged-encrypted", "profile": packagedTokenProfile, "key_or_input_id": packagedTokenID, "aes_key_base64": packagedTokenKey(requirementID)}
	}
	if f.id == "m43-token-unsupported-packaged-profile" {
		requirementID := requirement["requirement_id"].(string)
		tokenContext = map[string]any{"mode": "packaged-encrypted", "profile": unknownTokenProfile, "key_or_input_id": unknownTokenID, "aes_key_base64": unknownTokenKey(requirementID)}
	}
	if f.id == "m21-token-context-descriptor-mismatch" {
		tokenContext["profile"] = "wrong-profile"
	}
	healthContext := map[string]any{"mode": "buyer-derived", "profile": "aeb-cee-conformance-health-derived/v1", "key_or_input_id": "synthetic-health-input", "root_input": "synthetic-health-root-" + f.id}
	if f.id == "m41-health-unsupported-derived-profile" {
		healthContext["profile"] = "example-unknown/v9"
	}
	if isPackagedHealthFixture(f.id) {
		requirementID := requirement["requirement_id"].(string)
		healthContext = map[string]any{"mode": "packaged-encrypted", "profile": packagedHealthProfile, "key_or_input_id": packagedHealthID, "aes_key_base64": packagedHealthKey(requirementID)}
	}
	if f.id == "m44-health-unsupported-packaged-profile" {
		requirementID := requirement["requirement_id"].(string)
		healthContext = map[string]any{"mode": "packaged-encrypted", "profile": unknownHealthProfile, "key_or_input_id": unknownHealthID, "aes_key_base64": unknownHealthKey(requirementID)}
	}
	if f.id == "m22-health-context-descriptor-mismatch" {
		healthContext["profile"] = "wrong-health-profile"
	}
	observerKey := keyID("observer")
	if f.id == "m68-observer-authorized-runner-key" {
		observerKey = keyID("alternate-runner")
	}
	return pretty(map[string]any{"profile": "control-evidence-conformance-context/v0", "reference_now": now, "requirement_payload_sha256": requirementPin, "trust_policy": trustPolicy, "corpus": corpus, "trusted_keys": map[string]any{"buyer": keyID("buyer"), "vendor_runner": keyID("vendor-runner"), "observer": observerKey, "customer_clock": keyID("customer-clock"), "independent_witness_clock": keyID("witness-clock")}, "token_material": tokenContext, "health_control_material": healthContext, "nonce_ledger": ledger})
}

func requirementOuterKeyID(data []byte) string {
	var outer map[string]any
	_ = json.Unmarshal(data, &outer)
	return outer["signatures"].([]any)[0].(map[string]any)["keyid"].(string)
}

func allFiles() map[string][]byte {
	out := map[string][]byte{}
	for _, f := range fixtures() {
		packageFiles := build(f)
		for n, b := range packageFiles {
			out[filepath.Join(f.category, f.id, n)] = b
		}
		out[filepath.Join(f.category, f.id, "expect.json")] = expected(f)
		out[filepath.Join(f.category, f.id, "context.json")] = context(f, packageFiles)
	}
	return out
}
func root() string { return filepath.Clean(filepath.Join("..")) }
func writeAll(files map[string][]byte) error {
	for _, stale := range []string{"golden/g02-customer-completion-clock/clock.json", "malicious/m11-vendor-clock-role-laundering/vendor-clock.json", "malicious/m12-receipt-only-clock/receipt.json", "malicious/m13-observed-before-completion/early-clock.json"} {
		if err := os.Remove(filepath.Join(root(), stale)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for n, b := range files {
		p := filepath.Join(root(), n)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// selfCheck proves that the generator's serialized DSSE wrappers still verify
// from their committed key IDs and payload bytes. This is generator integrity,
// not a conformance verdict about the package.
func selfCheck(files map[string][]byte) error {
	for name, data := range files {
		if !strings.HasSuffix(name, ".dsse.json") {
			continue
		}
		var outer struct {
			PayloadType string `json:"payloadType"`
			Payload     string `json:"payload"`
			Signatures  []struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(data, &outer); err != nil || len(outer.Signatures) == 0 {
			return fmt.Errorf("self-check %s: malformed DSSE", name)
		}
		payload, err := base64.StdEncoding.DecodeString(outer.Payload)
		if err != nil {
			return fmt.Errorf("self-check %s payload: %w", name, err)
		}
		pub, err := hex.DecodeString(outer.Signatures[0].KeyID)
		if err != nil {
			return fmt.Errorf("self-check %s key: %w", name, err)
		}
		sig, err := base64.StdEncoding.DecodeString(outer.Signatures[0].Sig)
		if err != nil {
			return fmt.Errorf("self-check %s signature: %w", name, err)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), pae(outer.PayloadType, payload), sig) {
			return fmt.Errorf("self-check %s: signature does not verify", name)
		}
		if strings.HasPrefix(name, "golden/") || strings.HasPrefix(name, "edge/") {
			var object map[string]any
			if err := json.Unmarshal(payload, &object); err != nil {
				return fmt.Errorf("self-check %s payload JSON: %w", name, err)
			}
			required := []string{"profile", "requirement_sha256", "challenge_nonce", "run_id"}
			if outer.PayloadType == typeReq {
				required = []string{"profile", "requirement_id", "challenge_nonce", "enforcement_point", "approved_observer", "token_material", "allowed_future_skew_seconds", "authorized_run_signers", "approved_runner", "approved_adapter", "approved_policy"}
			}
			if outer.PayloadType == typeClock {
				required = []string{"profile", "requirement_sha256", "run_id", "observations_sha256", "attestor"}
			}
			if outer.PayloadType == typeObserver {
				required = []string{"profile", "requirement_sha256", "run_id", "observer"}
			}
			for _, field := range required {
				if _, ok := object[field]; !ok {
					return fmt.Errorf("self-check %s missing schema field %s", name, field)
				}
			}
		}
	}
	for name, data := range files {
		if (!strings.HasPrefix(name, "golden/") && !strings.HasPrefix(name, "edge/")) || (!strings.HasSuffix(name, "manifest.json") && !strings.HasSuffix(name, "outcomes.json")) {
			continue
		}
		var object map[string]any
		if err := json.Unmarshal(data, &object); err != nil {
			return fmt.Errorf("self-check %s JSON: %w", name, err)
		}
		field := "entries"
		if strings.HasSuffix(name, "outcomes.json") {
			field = "rows"
		}
		if _, ok := object[field]; !ok {
			return fmt.Errorf("self-check %s missing schema field %s", name, field)
		}
	}
	return nil
}

func verify(files map[string][]byte) error {
	if err := selfCheck(files); err != nil {
		return err
	}
	var problems []string
	for n, want := range files {
		got, err := os.ReadFile(filepath.Join(root(), n))
		if err != nil || !bytes.Equal(got, want) {
			problems = append(problems, n)
		}
	}
	_ = filepath.WalkDir(root(), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.Contains(p, string(filepath.Separator)+"_generator") {
			return nil
		}
		rel, _ := filepath.Rel(root(), p)
		if rel == "README.md" {
			return nil
		}
		if _, ok := files[rel]; !ok {
			problems = append(problems, "unexpected: "+rel)
		}
		return nil
	})
	if len(problems) > 0 {
		sort.Strings(problems)
		return errors.New("fixture drift: " + strings.Join(problems, ", "))
	}
	return nil
}

func main() {
	write := flag.Bool("write", false, "write fixtures")
	verifyFlag := flag.Bool("verify", false, "verify fixtures")
	flag.Parse()
	if *write == *verifyFlag {
		fmt.Fprintln(os.Stderr, "use exactly one of --write or --verify")
		os.Exit(2)
	}
	files := allFiles()
	var err error
	if *write {
		err = writeAll(files)
	} else {
		err = verify(files)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
