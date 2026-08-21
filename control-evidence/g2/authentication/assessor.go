// Package authentication assesses the single G2 authenticated-at(T) predicate.
package authentication

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
)

const (
	StatusPass         = "PASS"
	StatusFail         = "FAIL"
	StatusUnverifiable = "UNVERIFIABLE"
	policyProfile      = "control-evidence-trust-policy/v1"
	contextProfile     = "control-evidence-authentication-context/v1"
	assessmentProfile  = "control-evidence-assessment/v1"
	policyType         = "application/vnd.agent-egress-bench.control-evidence-trust-policy.v1+json"
	typeRequirement    = "application/vnd.agent-egress-bench.control-evidence-requirement.v0+json"
	typeEnvelope       = "application/vnd.agent-egress-bench.control-evidence-envelope.v0+json"
	typeClock          = "application/vnd.agent-egress-bench.control-evidence-clock-evidence.v0+json"
	typeObserver       = "application/vnd.agent-egress-bench.control-evidence-observer-evidence.v0+json"
	maxPackageMembers  = 258
	maxPackageMember   = int64(64 << 20)
	maxPackageBytes    = int64(256 << 20)
	maxExternalJSON    = int64(1 << 20)
)

type (
	Options   struct{ PackageDir, PolicyPath, ContextPath, CheckpointDir, VerifierName, VerifierVersion, VerifierSHA256 string }
	Predicate struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
)

type EvidenceState struct {
	EnvelopePayloadSHA256 string `json:"envelope_payload_sha256"`
}
type ExternalState struct {
	PolicyID                    string `json:"policy_id"`
	PolicyEpoch                 int    `json:"policy_epoch"`
	PolicySHA256                string `json:"policy_sha256"`
	AuthenticationContextSHA256 string `json:"authentication_context_sha256"`
	BootstrapKeyID              string `json:"bootstrap_key_id"`
	CheckpointSHA256            string `json:"checkpoint_sha256,omitempty"`
}
type Result struct {
	Profile        string `json:"profile"`
	AssessmentTime string `json:"assessment_time,omitempty"`
	Verifier       struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	} `json:"verifier"`
	Evidence      *EvidenceState `json:"evidence,omitempty"`
	ExternalState *ExternalState `json:"external_state,omitempty"`
	Predicates    []Predicate    `json:"predicates"`
}
type authContext struct {
	Profile               string `json:"profile"`
	AssessmentTime        string `json:"assessment_time"`
	PolicyID              string `json:"policy_id"`
	PolicySHA256          string `json:"policy_sha256"`
	BootstrapKeyID        string `json:"bootstrap_key_id"`
	BootstrapPublicKey    string `json:"bootstrap_public_key"`
	EnvelopePayloadSHA256 string `json:"envelope_payload_sha256"`
}
type policy struct {
	Profile     string       `json:"profile"`
	PolicyID    string       `json:"policy_id"`
	Epoch       int          `json:"epoch"`
	IssuedAt    string       `json:"issued_at"`
	NextUpdate  string       `json:"next_update"`
	Keys        []policyKey  `json:"keys"`
	Revocations []revocation `json:"revocations"`
}
type policyKey struct {
	KeyID       string `json:"key_id"`
	PublicKey   string `json:"public_key"`
	AuthorityID string `json:"authority_id"`
	Role        string `json:"role"`
	Purpose     string `json:"purpose"`
	NotBefore   string `json:"not_before"`
	ExpiresAt   string `json:"expires_at"`
}
type revocation struct {
	KeyID       string `json:"key_id"`
	EffectiveAt string `json:"effective_at"`
	Reason      string `json:"reason"`
}
type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}
type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}
type manifest struct {
	Profile                string          `json:"profile"`
	Entries                []manifestEntry `json:"entries"`
	TotalUncompressedBytes int64           `json:"total_uncompressed_bytes"`
}
type manifestEntry struct {
	Role       string `json:"role"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	MediaType  string `json:"media_type"`
	ByteLength int64  `json:"byte_length"`
}
type signedArtifact struct{ path, role, expectedType, authority, signer string }

func baseResult(o Options) Result {
	r := Result{Profile: assessmentProfile}
	r.Verifier.Name = o.VerifierName
	r.Verifier.Version = o.VerifierVersion
	if lowerHex64(o.VerifierSHA256) {
		r.Verifier.SHA256 = o.VerifierSHA256
	}
	return r
}

func resultWith(r Result, status, reason string) Result {
	r.Predicates = []Predicate{{Name: "authenticated-at(T)", Status: status, Reason: reason}}
	return r
}

// Assess never treats data inside the submitted package as a policy or checkpoint.
func Assess(o Options) Result {
	r := baseResult(o)
	if strings.TrimSpace(o.VerifierName) == "" || strings.TrimSpace(o.VerifierVersion) == "" || !lowerHex64(o.VerifierSHA256) {
		return resultWith(r, StatusUnverifiable, "verifier_identity_invalid")
	}
	ctxBytes, err := readRegularBounded(o.ContextPath, maxExternalJSON)
	if err != nil {
		return resultWith(r, StatusUnverifiable, "context_unavailable")
	}
	var ctx authContext
	if err := strictJSON(ctxBytes, &ctx); err != nil || !validContext(ctx) {
		return resultWith(r, StatusUnverifiable, "context_invalid")
	}
	now, err := time.Parse(time.RFC3339, ctx.AssessmentTime)
	if err != nil {
		return resultWith(r, StatusUnverifiable, "context_invalid")
	}
	r.AssessmentTime = ctx.AssessmentTime
	if !externalToPackage(o.PackageDir, o.PolicyPath) || !externalToPackage(o.PackageDir, o.ContextPath) {
		return resultWith(r, StatusUnverifiable, "policy_not_external")
	}
	if !externalToPackage(o.PackageDir, o.CheckpointDir) {
		return resultWith(r, StatusUnverifiable, "checkpoint_not_external")
	}
	policyBytes, err := readRegularBounded(o.PolicyPath, maxExternalJSON)
	if err != nil {
		return resultWith(r, StatusUnverifiable, "policy_unavailable")
	}
	if digest(policyBytes) != ctx.PolicySHA256 {
		return resultWith(r, StatusFail, "policy_digest_mismatch")
	}
	p, reason := verifyPolicy(policyBytes, ctx)
	if reason != "" {
		return resultWith(r, StatusFail, reason)
	}
	r.ExternalState = &ExternalState{
		PolicyID:                    p.PolicyID,
		PolicyEpoch:                 p.Epoch,
		PolicySHA256:                digest(policyBytes),
		AuthenticationContextSHA256: digest(ctxBytes),
		BootstrapKeyID:              ctx.BootstrapKeyID,
	}
	if p.PolicyID != ctx.PolicyID {
		return resultWith(r, StatusFail, "policy_id_mismatch")
	}
	next, err := time.Parse(time.RFC3339, p.NextUpdate)
	if err != nil || !next.After(now) {
		return resultWith(r, StatusUnverifiable, "policy_stale")
	}
	issued, err := time.Parse(time.RFC3339, p.IssuedAt)
	if err != nil || issued.After(now) || !issued.Before(next) {
		return resultWith(r, StatusFail, "policy_time_invalid")
	}
	checkpoint, reason := advanceCheckpoint(o.CheckpointDir, p.PolicyID, p.Epoch, digest(policyBytes))
	if reason != "" {
		if reason == "policy_epoch_rollback" || reason == "policy_epoch_equivocation" {
			return resultWith(r, StatusFail, reason)
		}
		return resultWith(r, StatusUnverifiable, reason)
	}
	r.ExternalState.CheckpointSHA256 = checkpoint
	files, err := loadPackage(o.PackageDir)
	if err != nil {
		return resultWith(r, StatusUnverifiable, "package_structure_unverifiable")
	}
	artifacts, envDigest, reason := requiredArtifacts(files)
	if reason != "" {
		return resultWith(r, StatusUnverifiable, reason)
	}
	r.Evidence = &EvidenceState{EnvelopePayloadSHA256: envDigest}
	if envDigest != ctx.EnvelopePayloadSHA256 {
		return resultWith(r, StatusFail, "envelope_digest_mismatch")
	}
	for _, a := range artifacts {
		if reason := authorizeArtifact(a, p, now); reason != "" {
			return resultWith(r, StatusFail, reason)
		}
	}
	return resultWith(r, StatusPass, "all_required_signatures_authorized")
}

func verifyPolicy(raw []byte, ctx authContext) (policy, string) {
	if err := canonical(raw); err != nil {
		return policy{}, "policy_wrapper_not_jcs"
	}
	var d dsseEnvelope
	if err := strictJSON(raw, &d); err != nil || d.PayloadType != policyType || len(d.Signatures) != 1 {
		return policy{}, "policy_wrapper_invalid"
	}
	if d.Signatures[0].KeyID != ctx.BootstrapKeyID || ctx.BootstrapKeyID != ctx.BootstrapPublicKey {
		return policy{}, "policy_bootstrap_mismatch"
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(d.Payload)
	if err != nil {
		return policy{}, "policy_wrapper_invalid"
	}
	if err := canonical(payload); err != nil {
		return policy{}, "policy_payload_not_jcs"
	}
	pub, err := decodeKey(ctx.BootstrapPublicKey)
	if err != nil {
		return policy{}, "policy_bootstrap_invalid"
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(d.Signatures[0].Sig)
	if err != nil || !ed25519.Verify(pub, pae(d.PayloadType, payload), sig) {
		return policy{}, "policy_signature_invalid"
	}
	var p policy
	if err := strictJSON(payload, &p); err != nil || p.Profile != policyProfile || p.PolicyID == "" || p.Epoch < 1 {
		return policy{}, "policy_payload_invalid"
	}
	issued, issuedErr := parseUTC(p.IssuedAt)
	next, nextErr := parseUTC(p.NextUpdate)
	if !validOpaqueID(p.PolicyID) || issuedErr != nil || nextErr != nil || !issued.Before(next) || len(p.Keys) < 1 || len(p.Keys) > 128 || len(p.Revocations) > 128 {
		return policy{}, "policy_payload_invalid"
	}
	seen := map[string]bool{}
	for _, k := range p.Keys {
		notBefore, notBeforeErr := parseUTC(k.NotBefore)
		expiresAt, expiresAtErr := parseUTC(k.ExpiresAt)
		if k.KeyID == "" || k.KeyID != k.PublicKey || seen[k.KeyID] || !validOpaqueID(k.AuthorityID) ||
			expectedPurpose(k.Role) != k.Purpose || notBeforeErr != nil || expiresAtErr != nil || !notBefore.Before(expiresAt) {
			return policy{}, "policy_payload_invalid"
		}
		seen[k.KeyID] = true
		if _, err := decodeKey(k.PublicKey); err != nil {
			return policy{}, "policy_payload_invalid"
		}
	}
	seenRevocations := map[string]bool{}
	for _, rv := range p.Revocations {
		if !seen[rv.KeyID] || seenRevocations[rv.KeyID] || strings.TrimSpace(rv.Reason) == "" || len(rv.Reason) > 256 {
			return policy{}, "policy_payload_invalid"
		}
		if _, err := parseUTC(rv.EffectiveAt); err != nil {
			return policy{}, "policy_payload_invalid"
		}
		seenRevocations[rv.KeyID] = true
	}
	return p, ""
}

func expectedPurpose(role string) string {
	switch role {
	case "buyer-requirement":
		return typeRequirement
	case "run-envelope":
		return typeEnvelope
	case "observer-evidence":
		return typeObserver
	case "completion-clock":
		return typeClock
	default:
		return ""
	}
}

func authorizeArtifact(a signedArtifact, p policy, at time.Time) string {
	for _, k := range p.Keys {
		if k.KeyID != a.signer {
			continue
		}
		if k.Role != a.role || k.Purpose != a.expectedType || (a.authority != "" && k.AuthorityID != a.authority) {
			return "signer_role_or_authority_mismatch"
		}
		nb, e1 := time.Parse(time.RFC3339, k.NotBefore)
		ex, e2 := time.Parse(time.RFC3339, k.ExpiresAt)
		if e1 != nil || e2 != nil || at.Before(nb) || !at.Before(ex) {
			return "signer_key_not_valid_at_assessment"
		}
		for _, rv := range p.Revocations {
			if rv.KeyID == k.KeyID {
				effective, e := time.Parse(time.RFC3339, rv.EffectiveAt)
				if e != nil {
					return "policy_payload_invalid"
				}
				if !at.Before(effective) {
					return "signer_key_revoked"
				}
			}
		}
		return ""
	}
	return "signer_key_untrusted"
}

type checkpoint struct {
	Profile      string `json:"profile"`
	PolicyID     string `json:"policy_id"`
	Epoch        int    `json:"epoch"`
	PolicySHA256 string `json:"policy_sha256"`
}

func advanceCheckpoint(root, id string, epoch int, policySHA string) (string, string) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return "", "checkpoint_unavailable"
	}
	stem := checkpointStem(id)
	lockPath := filepath.Join(root, stem+".lock")
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		return "", "checkpoint_busy"
	}
	defer func() { _ = os.Remove(lockPath) }()
	path := filepath.Join(root, stem+".json")
	if raw, err := readRegularBounded(path, 4096); err == nil {
		var old checkpoint
		oldInfo, statErr := os.Lstat(path)
		if statErr != nil || oldInfo.Mode().Perm() != 0o600 || oldInfo.Size() > 4096 || strictJSON(raw, &old) != nil ||
			old.Profile != "control-evidence-policy-checkpoint/v1" || old.PolicyID != id || old.Epoch < 1 || !lowerHex64(old.PolicySHA256) {
			return "", "checkpoint_invalid"
		}
		if epoch < old.Epoch {
			return "", "policy_epoch_rollback"
		}
		if epoch == old.Epoch && old.PolicySHA256 != policySHA {
			return "", "policy_epoch_equivocation"
		}
		if epoch == old.Epoch {
			if err := syncDirectory(root); err != nil {
				return "", "checkpoint_unavailable"
			}
			return digest(raw), ""
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", "checkpoint_invalid"
	}
	record := checkpoint{Profile: "control-evidence-policy-checkpoint/v1", PolicyID: id, Epoch: epoch, PolicySHA256: policySHA}
	raw, err := json.Marshal(record)
	if err != nil {
		return "", "checkpoint_unavailable"
	}
	tmp, err := os.CreateTemp(root, ".checkpoint-")
	if err != nil {
		return "", "checkpoint_unavailable"
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		return "", "checkpoint_unavailable"
	}
	if _, err := tmp.Write(raw); err != nil {
		return "", "checkpoint_unavailable"
	}
	if err := tmp.Sync(); err != nil {
		return "", "checkpoint_unavailable"
	}
	if err := tmp.Close(); err != nil {
		return "", "checkpoint_unavailable"
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", "checkpoint_unavailable"
	}
	if err := syncDirectory(root); err != nil {
		return "", "checkpoint_unavailable"
	}
	return digest(raw), ""
}

func checkpointStem(policyID string) string {
	sum := sha256.Sum256([]byte(policyID))
	return hex.EncodeToString(sum[:])
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	return errors.Join(syncErr, closeErr)
}

func requiredArtifacts(files map[string][]byte) ([]signedArtifact, string, string) {
	mraw, ok := files["manifest.json"]
	if !ok {
		return nil, "", "manifest_missing"
	}
	var m manifest
	if err := strictJSON(mraw, &m); err != nil {
		return nil, "", "manifest_invalid"
	}
	entries := map[string]manifestEntry{}
	for _, e := range m.Entries {
		if !safePath(e.Path) || entries[e.Path].Path != "" || digest(files[e.Path]) != e.SHA256 {
			return nil, "", "manifest_invalid"
		}
		entries[e.Path] = e
	}
	req, ok := entries["requirement.dsse.json"]
	if !ok || req.Role != "requirement" {
		return nil, "", "required_wrapper_missing"
	}
	envelopeRaw, ok := files["envelope.dsse.json"]
	if !ok {
		return nil, "", "required_wrapper_missing"
	}
	_, envelopePayload, err := parseDSSE(envelopeRaw, typeEnvelope)
	if err != nil {
		return nil, "", "required_wrapper_invalid"
	}
	var envelopeBinding struct {
		Artifacts struct {
			ManifestSHA256 string `json:"manifest_sha256"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(envelopePayload, &envelopeBinding) != nil || envelopeBinding.Artifacts.ManifestSHA256 != digest(mraw) {
		return nil, "", "manifest_binding_mismatch"
	}
	items := []struct{ path, role, typ string }{{"requirement.dsse.json", "buyer-requirement", typeRequirement}, {"envelope.dsse.json", "run-envelope", typeEnvelope}}
	for _, e := range entries {
		switch e.Role {
		case "observer-evidence":
			items = append(items, struct{ path, role, typ string }{e.Path, "observer-evidence", typeObserver})
		case "clock-evidence":
			items = append(items, struct{ path, role, typ string }{e.Path, "completion-clock", typeClock})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].path < items[j].path })
	out := make([]signedArtifact, 0, len(items))
	envDigest := ""
	for _, item := range items {
		d, p, err := parseDSSE(files[item.path], item.typ)
		if err != nil {
			return nil, "", "required_wrapper_invalid"
		}
		a := signedArtifact{path: item.path, role: item.role, expectedType: item.typ, authority: authorityFor(item.role, p), signer: d.Signatures[0].KeyID}
		out = append(out, a)
		if item.path == "envelope.dsse.json" {
			envDigest = digest(p)
		}
	}
	return out, envDigest, ""
}

func authorityFor(role string, p []byte) string {
	var v struct {
		BuyerID     string `json:"buyer_id"`
		AuthorityID string `json:"authority_id"`
		Signer      struct {
			AuthorityID string `json:"authority_id"`
		} `json:"signer"`
		Attestor struct {
			AuthorityID string `json:"authority_id"`
		} `json:"attestor"`
	}
	if json.Unmarshal(p, &v) != nil {
		return ""
	}
	switch role {
	case "buyer-requirement":
		return v.BuyerID
	case "run-envelope":
		return v.Signer.AuthorityID
	case "completion-clock":
		return v.Attestor.AuthorityID
	default:
		return v.AuthorityID
	}
}

func parseDSSE(raw []byte, want string) (dsseEnvelope, []byte, error) {
	var d dsseEnvelope
	if err := strictJSON(raw, &d); err != nil {
		return d, nil, err
	}
	if d.PayloadType != want || len(d.Signatures) != 1 {
		return d, nil, errors.New("wrong DSSE")
	}
	p, err := base64.StdEncoding.Strict().DecodeString(d.Payload)
	if err != nil || canonical(p) != nil {
		return d, nil, errors.New("invalid payload")
	}
	pub, err := decodeKey(d.Signatures[0].KeyID)
	if err != nil {
		return d, nil, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(d.Signatures[0].Sig)
	if err != nil || !ed25519.Verify(pub, pae(d.PayloadType, p), sig) {
		return d, nil, errors.New("signature")
	}
	return d, p, nil
}

func loadPackage(root string) (map[string][]byte, error) {
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("bad root")
	}
	out := map[string][]byte{}
	members := 0
	var total int64
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() || !safePath(filepath.ToSlash(rel)) {
			return errors.New("unsafe member")
		}
		members++
		if members > maxPackageMembers {
			return errors.New("package member limit exceeded")
		}
		if rel == "context.json" || rel == "expect.json" {
			return nil
		}
		data, err := readRegularBounded(path, maxPackageMember)
		if err != nil {
			return err
		}
		total += int64(len(data))
		if total > maxPackageBytes {
			return errors.New("package byte limit exceeded")
		}
		out[filepath.ToSlash(rel)] = data
		return nil
	})
	return out, err
}

func safePath(p string) bool {
	return p != "" && p == filepath.ToSlash(filepath.Clean(p)) && !filepath.IsAbs(p) && !strings.HasPrefix(p, "../") && !strings.Contains(p, "\\")
}

func externalToPackage(root, path string) bool {
	a, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	b, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	a, err = filepath.Abs(a)
	if err != nil {
		return false
	}
	b, err = filepath.Abs(b)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(a, b)
	return err == nil && rel != "." && (rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

func readRegularBounded(path string, maxBytes int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxBytes {
		return nil, errors.New("not regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("input changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return nil, errors.New("input unavailable or too large")
	}
	return data, nil
}

func validContext(ctx authContext) bool {
	if ctx.Profile != contextProfile || !validOpaqueID(ctx.PolicyID) || !lowerHex64(ctx.PolicySHA256) ||
		!lowerHex64(ctx.BootstrapKeyID) || !lowerHex64(ctx.BootstrapPublicKey) || !lowerHex64(ctx.EnvelopePayloadSHA256) {
		return false
	}
	_, err := parseUTC(ctx.AssessmentTime)
	return err == nil
}

func parseUTC(value string) (time.Time, error) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, errors.New("timestamp must use UTC Z form")
	}
	return time.Parse(time.RFC3339, value)
}

func lowerHex64(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validOpaqueID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || (i > 0 && strings.ContainsRune("._:-", r)) {
			continue
		}
		return false
	}
	return true
}

func decodeKey(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("bad key")
	}
	return ed25519.PublicKey(b), nil
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func SHA256(b []byte) string { return digest(b) }
func pae(t string, p []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(t), t, len(p), p))
}

func canonical(raw []byte) error {
	c, err := jsoncanonicalizer.Transform(raw)
	if err != nil || !bytes.Equal(c, raw) {
		return errors.New("not JCS")
	}
	return nil
}
func canonicalize(raw []byte) ([]byte, error) { return jsoncanonicalizer.Transform(raw) }
func strictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if _, err := strictValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	if dst != nil {
		dec = json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(dst)
	}
	return nil
}

func strictValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("depth")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch x := tok.(type) {
	case json.Delim:
		if x == '{' {
			m := map[string]bool{}
			for dec.More() {
				k, e := dec.Token()
				if e != nil {
					return nil, e
				}
				ks, ok := k.(string)
				if !ok || m[ks] {
					return nil, errors.New("duplicate key")
				}
				m[ks] = true
				if _, e := strictValue(dec, depth+1); e != nil {
					return nil, e
				}
			}
			_, e := dec.Token()
			return nil, e
		}
		if x == '[' {
			for dec.More() {
				if _, e := strictValue(dec, depth+1); e != nil {
					return nil, e
				}
			}
			_, e := dec.Token()
			return nil, e
		}
	}
	return tok, nil
}
