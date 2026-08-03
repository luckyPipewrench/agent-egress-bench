package verifier

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

const (
	derivedTokenProfile   = "aeb-cee-conformance-token-derived/v1"
	derivedHealthProfile  = "aeb-cee-conformance-health-derived/v1"
	packagedTokenProfile  = "aeb-cee-conformance-token-aesgcm/v1"
	packagedHealthProfile = "aeb-cee-conformance-health-aesgcm/v1"
)

type materialInputs struct {
	tokens   map[string]string
	controls map[string]string
}

func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, part := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		out = append(out, n[:]...)
		out = append(out, part...)
	}
	return out
}

func lengthPrefixedDigest(parts ...string) string {
	sum := sha256.Sum256(lengthPrefixed(parts...))
	return hex.EncodeToString(sum[:])
}

func deriveInput(domain, profile, id, element, root string) string {
	return lengthPrefixedDigest(domain, profile, id, element, root)
}

func tokenCommitment(requirementSHA, runID, caseID string, trial int, c canary, input string) string {
	return lengthPrefixedDigest("aeb-cee-v0/canary", requirementSHA, runID, caseID, fmt.Sprint(trial), c.CanaryID, "mcp_stdio", c.TargetIdentity, c.Polarity, input)
}

func healthCommitment(requirementSHA, runID string, row outcomeRow, c canary, controlID, input string) string {
	return lengthPrefixedDigest("aeb-cee-v0/health-control", requirementSHA, runID, row.CaseID, fmt.Sprint(row.TrialIndex), c.CanaryID, c.CanaryCommitmentSHA256, controlID, row.Transport, c.TargetIdentity, input)
}

func decryptMaterial(stored []byte, keyB64, requirementID, profile, materialID, role string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid AES-256 key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(stored) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("encrypted material is truncated")
	}
	nonce := stored[:gcm.NonceSize()]
	expectedNonce := sha256.Sum256(lengthPrefixed("aeb-cee-conformance-nonce/v1", requirementID, profile, materialID, role))
	if !bytes.Equal(nonce, expectedNonce[:gcm.NonceSize()]) {
		return nil, errors.New("encrypted material nonce mismatch")
	}
	aad := lengthPrefixed(profile, materialID)
	return gcm.Open(nil, nonce, stored[gcm.NonceSize():], aad)
}

func resolveMaterials(req requirement, ctx verifierContext, entries map[string][]manifestEntry, files map[string][]byte, schemas *schemaSet) (materialInputs, *Result) {
	out := materialInputs{tokens: map[string]string{}, controls: map[string]string{}}
	if req.TokenMaterial.Mode != ctx.TokenMaterial.Mode || req.TokenMaterial.Profile != ctx.TokenMaterial.Profile || req.TokenMaterial.KeyOrInputID != ctx.TokenMaterial.KeyOrInputID {
		return out, failure(outcomeInsufficientEvidence, "token_material_context_mismatch")
	}
	if req.HealthMaterial.Mode != ctx.HealthMaterial.Mode || req.HealthMaterial.Profile != ctx.HealthMaterial.Profile || req.HealthMaterial.KeyOrInputID != ctx.HealthMaterial.KeyOrInputID {
		return out, failure(outcomeInsufficientEvidence, "health_control_material_context_mismatch")
	}

	switch req.TokenMaterial.Mode {
	case "buyer-derived":
		if req.TokenMaterial.Profile != derivedTokenProfile {
			return out, failure(outcomeUnverifiable, "token_material_profile_unsupported")
		}
		for _, id := range append(append([]string{}, req.RequiredPositiveCanaries...), req.RequiredNegativeCanaries...) {
			out.tokens[id] = deriveInput("aeb-cee-conformance-token-input/v1", req.TokenMaterial.Profile, req.TokenMaterial.KeyOrInputID, id, ctx.TokenMaterial.RootInput)
		}
	case "packaged-encrypted":
		if req.TokenMaterial.Profile != packagedTokenProfile {
			return out, failure(outcomeUnverifiable, "token_material_profile_unsupported")
		}
		roleEntries := entries["token-material"]
		if len(roleEntries) == 0 {
			reason := "token_material_manifest_role_missing"
			if req.TokenMaterial.ArtifactSHA256 != "" && requiredRole(req.RequiredArtifacts, "token-material") {
				reason = "token_material_not_committed"
				for _, data := range files {
					if digestBytes(data) == req.TokenMaterial.ArtifactSHA256 {
						reason = "token_material_manifest_role_missing"
						break
					}
				}
			}
			return out, failure(outcomeInsufficientEvidence, reason)
		}
		if len(roleEntries) != 1 {
			return out, failure(outcomeInsufficientEvidence, "token_material_manifest_role_ambiguous")
		}
		entry := roleEntries[0]
		if entry.SHA256 != req.TokenMaterial.ArtifactSHA256 {
			return out, failure(outcomeInsufficientEvidence, "token_material_artifact_digest_mismatch")
		}
		plain, err := decryptMaterial(files[entry.Path], ctx.TokenMaterial.AESKeyBase64, req.RequirementID, req.TokenMaterial.Profile, req.TokenMaterial.KeyOrInputID, "token-material")
		if err != nil {
			return out, failure(outcomeInsufficientEvidence, "token_material_aead_authentication_failed")
		}
		var decoded decodedMaterial
		value, err := strictJSON(plain, &decoded)
		if err != nil {
			if bytes.Contains([]byte(err.Error()), []byte("duplicate object key")) {
				return out, failure(outcomeInvalid, "token_material_duplicate_json_key")
			}
			return out, failure(outcomeInvalid, "token_material_plaintext_invalid")
		}
		if err := canonicalJSON(plain); err != nil {
			return out, failure(outcomeInvalid, "token_material_plaintext_not_jcs")
		}
		if err := validateSchema(schemas.tokenMaterial, value); err != nil {
			return out, failure(outcomeInvalid, "token_material_plaintext_invalid")
		}
		if decoded.Profile != req.TokenMaterial.Profile || decoded.KeyOrInputID != req.TokenMaterial.KeyOrInputID {
			return out, failure(outcomeInvalid, "token_material_plaintext_binding_mismatch")
		}
		seen := map[string]bool{}
		for _, token := range decoded.Tokens {
			if seen[token.CanaryID] {
				return out, failure(outcomeInvalid, "token_material_duplicate_canary_id")
			}
			seen[token.CanaryID] = true
			out.tokens[token.CanaryID] = token.Input
		}
		if !sameStringSet(keys(out.tokens), append(append([]string{}, req.RequiredPositiveCanaries...), req.RequiredNegativeCanaries...)) {
			return out, failure(outcomeInvalid, "token_material_canary_id_set_mismatch")
		}
	default:
		return out, failure(outcomeUnverifiable, "token_material_profile_unsupported")
	}

	switch req.HealthMaterial.Mode {
	case "buyer-derived":
		if req.HealthMaterial.Profile != derivedHealthProfile {
			return out, failure(outcomeUnverifiable, "health_control_material_profile_unsupported")
		}
	case "packaged-encrypted":
		if req.HealthMaterial.Profile != packagedHealthProfile {
			return out, failure(outcomeUnverifiable, "health_control_material_profile_unsupported")
		}
		roleEntries := entries["health-control-material"]
		if len(roleEntries) == 0 {
			reason := "health_control_material_missing"
			for _, data := range files {
				if digestBytes(data) == req.HealthMaterial.ArtifactSHA256 {
					reason = "health_control_material_manifest_role_missing"
					break
				}
			}
			return out, failure(outcomeInsufficientEvidence, reason)
		}
		if len(roleEntries) != 1 {
			return out, failure(outcomeInsufficientEvidence, "health_control_material_manifest_role_ambiguous")
		}
		entry := roleEntries[0]
		if entry.SHA256 != req.HealthMaterial.ArtifactSHA256 {
			return out, failure(outcomeInsufficientEvidence, "health_control_material_artifact_digest_mismatch")
		}
		plain, err := decryptMaterial(files[entry.Path], ctx.HealthMaterial.AESKeyBase64, req.RequirementID, req.HealthMaterial.Profile, req.HealthMaterial.KeyOrInputID, "health-control-material")
		if err != nil {
			return out, failure(outcomeInsufficientEvidence, "health_control_material_aead_authentication_failed")
		}
		var decoded decodedMaterial
		value, err := strictJSON(plain, &decoded)
		if err != nil {
			if bytes.Contains([]byte(err.Error()), []byte("duplicate object key")) {
				return out, failure(outcomeInvalid, "health_control_material_duplicate_json_key")
			}
			return out, failure(outcomeInvalid, "health_control_material_plaintext_invalid")
		}
		if err := canonicalJSON(plain); err != nil {
			return out, failure(outcomeInvalid, "health_control_material_plaintext_not_jcs")
		}
		if err := validateSchema(schemas.healthMaterial, value); err != nil {
			return out, failure(outcomeInvalid, "health_control_material_plaintext_invalid")
		}
		if decoded.Profile != req.HealthMaterial.Profile || decoded.KeyOrInputID != req.HealthMaterial.KeyOrInputID {
			return out, failure(outcomeInvalid, "health_control_material_plaintext_binding_mismatch")
		}
		seen := map[string]bool{}
		for _, control := range decoded.Controls {
			if seen[control.ControlID] {
				return out, failure(outcomeInvalid, "health_control_material_duplicate_control_id")
			}
			seen[control.ControlID] = true
			out.controls[control.ControlID] = control.Input
		}
	default:
		return out, failure(outcomeUnverifiable, "health_control_material_profile_unsupported")
	}
	return out, nil
}

func (m materialInputs) healthInput(req requirement, ctx verifierContext, controlID string) (string, bool) {
	if req.HealthMaterial.Mode == "buyer-derived" {
		return deriveInput("aeb-cee-conformance-health-input/v1", req.HealthMaterial.Profile, req.HealthMaterial.KeyOrInputID, controlID, ctx.HealthMaterial.RootInput), true
	}
	input, ok := m.controls[controlID]
	return input, ok
}

func requiredRole(roles []string, wanted string) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa, bb := append([]string{}, a...), append([]string{}, b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
