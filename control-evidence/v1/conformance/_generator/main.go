// Package main deterministically builds payload-bearing Control Evidence v1
// conformance packages from the frozen v0 golden package. It changes every
// versioned payload, re-signs it, and rebinds the complete manifest; the v1
// verifier remains independent and never imports this generator.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	typeRequirement = "application/vnd.agent-egress-bench.control-evidence-requirement.v1+json"
	typeEnvelope    = "application/vnd.agent-egress-bench.control-evidence-envelope.v1+json"
	typeObserver    = "application/vnd.agent-egress-bench.control-evidence-observer-evidence.v1+json"
)

type vector struct {
	category, id, description string
	mode, outcome, reason     string
	reverify                  bool
}

var vectors = []vector{
	{"golden", "g01-valid-registry-bound", "A complete v1 package binds every active artifact to one raw registry snapshot.", "persistent", "valid", "", false},
	{"malicious", "m01-summary-registry-mismatch", "A manifest-bound summary naming another registry revision fails before outcome evaluation.", "persistent", "scope-mismatch", "capability_registry_summary_mismatch", false},
	{"malicious", "m02-registry-snapshot-missing", "A package without the referenced raw registry snapshot cannot support a score.", "persistent", "insufficient-evidence", "capability_registry_snapshot_missing", false},
	{"malicious", "m03-outcomes-profile-invalid", "A manifest-bound outcomes payload with the wrong profile fails schema validation.", "persistent", "invalid", "outcomes_invalid", false},
	{"edge", "e01-expired-requirement", "An otherwise complete package fails when the buyer reference time is after requirement expiry.", "persistent", "stale", "requirement_expired", false},
	{"edge", "e02-replay-ledger-required", "An otherwise valid package is unverifiable without buyer-controlled durable replay state.", "stateless", "unverifiable", "replay_ledger_required", false},
	{"edge", "e03-same-envelope-reverification", "Rechecking the exact same envelope remains valid and reports the retained nonce state.", "persistent", "valid", "", true},
}

func main() {
	verify := flag.Bool("verify", false, "verify committed vectors instead of rewriting them")
	write := flag.Bool("write", false, "rewrite committed vectors")
	flag.Parse()
	if *verify == *write {
		fmt.Fprintln(os.Stderr, "choose exactly one of --verify or --write")
		os.Exit(2)
	}
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	if filepath.Base(cwd) != "_generator" {
		panic("run from control-evidence/v1/conformance/_generator")
	}
	root := filepath.Clean(filepath.Join(".."))
	contexts := make(map[string][]byte, len(vectors))
	expectations := make(map[string][]byte, len(vectors))
	for _, item := range vectors {
		files := build(item)
		contexts[item.id+".json"] = files["context.json"]
		expectations[item.id+".json"] = files["expect.json"]
		delete(files, "context.json")
		delete(files, "expect.json")
		dir := filepath.Join(root, item.category, item.id)
		if *verify {
			verifyFiles(dir, files)
			continue
		}
		replaceFiles(root, dir, files)
	}
	if *verify {
		verifyFiles(filepath.Join(root, "contexts"), contexts)
		verifyFiles(filepath.Join(root, "expectations"), expectations)
		return
	}
	replaceFiles(root, filepath.Join(root, "contexts"), contexts)
	replaceFiles(root, filepath.Join(root, "expectations"), expectations)
}

func replaceFiles(root, dir string, files map[string][]byte) {
	root = mustAbs(root)
	dir = mustAbs(dir)
	if !generatedTarget(root, dir) {
		panic(fmt.Sprintf("refusing to replace non-generated directory %s", dir))
	}
	rootReal, err := filepath.EvalSymlinks(root)
	if err != nil {
		panic(err)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		panic(err)
	}
	if !within(rootReal, parent) {
		panic(fmt.Sprintf("generated directory parent escapes conformance root: %s", parent))
	}
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			panic(fmt.Sprintf("generated target is not a real directory: %s", dir))
		}
	} else if !os.IsNotExist(err) {
		panic(err)
	}

	staged, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".new-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(staged) }()
	if err := os.Chmod(staged, 0o750); err != nil {
		panic(err)
	}
	for name, data := range files {
		if name == "." || filepath.Base(name) != name {
			panic(fmt.Sprintf("invalid generated filename %q", name))
		}
		if err := os.WriteFile(filepath.Join(staged, name), data, 0o600); err != nil {
			panic(err)
		}
	}
	verifyFiles(staged, files)

	backup, err := os.MkdirTemp(parent, "."+filepath.Base(dir)+".old-")
	if err != nil {
		panic(err)
	}
	if err := os.Remove(backup); err != nil {
		panic(err)
	}
	hadOld := false
	if err := os.Rename(dir, backup); err == nil {
		hadOld = true
	} else if !os.IsNotExist(err) {
		panic(err)
	}
	if err := os.Rename(staged, dir); err != nil {
		if hadOld {
			_ = os.Rename(backup, dir)
		}
		panic(err)
	}
	staged = ""
	if hadOld {
		if err := os.RemoveAll(backup); err != nil {
			panic(err)
		}
	}
}

func mustAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return filepath.Clean(abs)
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func generatedTarget(root, dir string) bool {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	if rel == "contexts" || rel == "expectations" {
		return true
	}
	for _, item := range vectors {
		if rel == filepath.Join(item.category, item.id) {
			return true
		}
	}
	return false
}

func verifyFiles(dir string, wanted map[string][]byte) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		panic(err)
	}
	if len(entries) != len(wanted) {
		panic(fmt.Sprintf("%s contains %d files, want %d", dir, len(entries), len(wanted)))
	}
	for _, entry := range entries {
		if entry.IsDir() {
			panic(fmt.Sprintf("unexpected directory %s", filepath.Join(dir, entry.Name())))
		}
		expected, ok := wanted[entry.Name()]
		if !ok {
			panic(fmt.Sprintf("unexpected vector file %s", filepath.Join(dir, entry.Name())))
		}
		actual := mustRead(filepath.Join(dir, entry.Name()))
		if !bytes.Equal(actual, expected) {
			panic(fmt.Sprintf("generated bytes differ: %s", filepath.Join(dir, entry.Name())))
		}
	}
}

func build(item vector) map[string][]byte {
	base := filepath.Join("..", "..", "..", "v0", "conformance", "golden", "g01-vendor-time")
	registry := mustRead(filepath.Join("..", "..", "..", "..", "capability-registry", "aeb.core-capabilities", "format-1", "revision-1.json"))
	registryRef := map[string]any{"id": "aeb.core-capabilities", "format": 1, "revision": 1, "sha256": digest(registry)}

	adapter := mustRead(filepath.Join(base, "adapter.json"))
	policy := mustRead(filepath.Join(base, "policy.json"))
	profile := map[string]any{
		"schema_version": 4, "tool": "example-tool", "tool_version": "v1", "runner_version": "0.4.2",
		"claims": []any{"mcp_input_scan"}, "capability_registry": clone(registryRef),
	}
	profileBytes := pretty(profile)

	requirement := payload(mustRead(filepath.Join(base, "requirement.dsse.json")))
	requirement["profile"] = "control-evidence-requirement/v1"
	requirement["capability_registry"] = clone(registryRef)
	requirement["approved_tool_profile"] = map[string]any{"sha256": digest(profileBytes)}
	requirement["required_artifacts"] = append(requirement["required_artifacts"].([]any), "capability-registry")
	requirementBytes, requirementPayload := signed(typeRequirement, requirement, key("buyer"))
	requirementSHA := digest(requirementPayload)

	context := object(mustRead(filepath.Join(base, "context.json")))
	context["profile"] = "control-evidence-conformance-context/v1"
	context["requirement_payload_sha256"] = requirementSHA
	if item.id == "e01-expired-requirement" {
		context["reference_now"] = "2026-08-02T14:00:00Z"
	}

	outcomes := object(mustRead(filepath.Join(base, "outcomes.json")))
	outcomes["profile"] = "control-evidence-outcomes/v1"
	outcomes["capability_registry"] = clone(registryRef)
	outcomes["requirement_sha256"] = requirementSHA
	if item.id == "m03-outcomes-profile-invalid" {
		outcomes["profile"] = "control-evidence-outcomes/v0"
	}
	row := outcomes["rows"].([]any)[0].(map[string]any)
	canaries := row["canaries"].([]any)
	positive := canaries[0].(map[string]any)
	negative := canaries[1].(map[string]any)
	positiveInput := derivedInput("aeb-cee-conformance-token-input/v1", "aeb-cee-conformance-token-derived/v1", "synthetic-token-input", "positive-1", "synthetic-token-root-g01-vendor-time")
	negativeInput := derivedInput("aeb-cee-conformance-token-input/v1", "aeb-cee-conformance-token-derived/v1", "synthetic-token-input", "negative-1", "synthetic-token-root-g01-vendor-time")
	positive["canary_commitment_sha256"] = tokenCommitment(requirementSHA, outcomes["run_id"].(string), row, positive, positiveInput)
	negative["canary_commitment_sha256"] = tokenCommitment(requirementSHA, outcomes["run_id"].(string), row, negative, negativeInput)

	files := map[string][]byte{
		"adapter.json":          adapter,
		"policy.json":           policy,
		"requirement.dsse.json": requirementBytes,
		"tool-profile.json":     profileBytes,
	}
	observerNames := []string{"observer-preceding.dsse.json", "observer-target-1.dsse.json", "observer-following.dsse.json"}
	for _, name := range observerNames {
		observer := payload(mustRead(filepath.Join(base, name)))
		observer["profile"] = "control-evidence-observer-evidence/v1"
		observer["requirement_sha256"] = requirementSHA
		canary := positive
		if observer["canary_id"] == "negative-1" {
			canary = negative
		}
		observer["canary_commitment_sha256"] = canary["canary_commitment_sha256"]
		if controlID, ok := observer["control_id"].(string); ok {
			input := derivedInput("aeb-cee-conformance-health-input/v1", "aeb-cee-conformance-health-derived/v1", "synthetic-health-input", controlID, "synthetic-health-root-g01-vendor-time")
			observer["health_control_commitment_sha256"] = healthCommitment(requirementSHA, outcomes["run_id"].(string), row, negative, controlID, input)
		}
		wrapper, _ := signed(typeObserver, observer, key("observer"))
		files[name] = wrapper
	}
	positive["observation_ref"] = digest(files["observer-target-1.dsse.json"])
	negative["preceding_health_ref"] = digest(files["observer-preceding.dsse.json"])
	negative["following_health_ref"] = digest(files["observer-following.dsse.json"])
	outcomesBytes := pretty(outcomes)
	files["outcomes.json"] = outcomesBytes

	summaryRef := clone(registryRef).(map[string]any)
	if item.id == "m01-summary-registry-mismatch" {
		summaryRef["revision"] = 2
	}
	summary := map[string]any{
		"gauntlet_version": "1.0", "scoring_version": "2.4", "runner_version": "0.4.2",
		"tool": "example-tool", "tool_version": "v1", "corpus_version": "v2.3.0",
		"corpus_sha256": context["corpus"].(map[string]any)["sha256"], "tool_profile_sha256": digest(profileBytes),
		"capability_registry": summaryRef, "reported_claims": []any{"mcp_input_scan"},
		"case_count":   map[string]any{"total": 1, "applicable": 1, "not_applicable": 0, "not_applicable_reasons": map[string]any{}, "errors": 0},
		"exercised":    map[string]any{"capability_tags": []any{"mcp_input_scan"}},
		"per_category": map[string]any{"mcp_input": map[string]any{"applicable": 1}},
	}
	files["summary.json"] = pretty(summary)
	if item.id != "m02-registry-snapshot-missing" {
		files["capability-registry.json"] = registry
	}

	roles := map[string]string{
		"adapter.json": "adapter", "policy.json": "policy", "requirement.dsse.json": "requirement",
		"tool-profile.json": "tool-profile", "outcomes.json": "outcomes", "summary.json": "summary",
		"observer-preceding.dsse.json": "observer-evidence", "observer-target-1.dsse.json": "observer-evidence",
		"observer-following.dsse.json": "observer-evidence", "capability-registry.json": "capability-registry",
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]any, 0, len(names))
	total := 0
	for _, name := range names {
		data := files[name]
		total += len(data)
		entries = append(entries, map[string]any{"path": name, "role": roles[name], "media_type": "application/json", "sha256": digest(data), "byte_length": len(data)})
	}
	manifest := map[string]any{"profile": "control-evidence-manifest/v1", "entries": entries, "total_uncompressed_bytes": total}
	manifestBytes := pretty(manifest)
	files["manifest.json"] = manifestBytes

	envelope := payload(mustRead(filepath.Join(base, "envelope.dsse.json")))
	envelope["profile"] = "control-evidence-envelope/v1"
	envelope["capability_registry"] = clone(registryRef)
	envelope["requirement_sha256"] = requirementSHA
	envelope["tool"].(map[string]any)["version"] = "v1"
	envelope["observations"].(map[string]any)["sha256"] = digest(outcomesBytes)
	envelope["artifacts"] = map[string]any{"count": len(entries), "manifest_sha256": digest(manifestBytes)}
	files["envelope.dsse.json"], _ = signed(typeEnvelope, envelope, key("vendor-runner"))
	files["context.json"] = pretty(context)

	runs := []any{map[string]any{"mode": item.mode, "expected_outcome": item.outcome, "reason": item.reason}}
	if item.reverify {
		runs = append(runs, map[string]any{"mode": "persistent", "expected_outcome": "valid", "reason": "", "nonce_status": "reverified_same_envelope"})
	}
	files["expect.json"] = pretty(map[string]any{"description": item.description, "runs": runs})
	return files
}

func key(role string) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte("agent-egress-bench-control-evidence-" + role + "-test-key-v0"))
	return ed25519.NewKeyFromSeed(sum[:])
}

func signed(payloadType string, value map[string]any, signer ed25519.PrivateKey) ([]byte, []byte) {
	payload := compact(value)
	signature := ed25519.Sign(signer, pae(payloadType, payload))
	keyID := hex.EncodeToString(signer.Public().(ed25519.PublicKey))
	wrapper := map[string]any{"payloadType": payloadType, "payload": base64.StdEncoding.EncodeToString(payload), "signatures": []any{map[string]any{"keyid": keyID, "sig": base64.StdEncoding.EncodeToString(signature)}}}
	return pretty(wrapper), payload
}

func payload(data []byte) map[string]any {
	wrapper := object(data)
	raw, err := base64.StdEncoding.DecodeString(wrapper["payload"].(string))
	if err != nil {
		panic(err)
	}
	return object(raw)
}

func object(data []byte) map[string]any {
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		panic(err)
	}
	return value
}

func clone(value any) any {
	return object(compact(value))
}

func compact(value any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
}

func pretty(value any) []byte {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}

func mustRead(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return data
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func lengthPrefixed(parts ...string) []byte {
	var out []byte
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		out = append(out, size[:]...)
		out = append(out, part...)
	}
	return out
}

func derivedInput(domain, profile, id, element, root string) string {
	return digest(lengthPrefixed(domain, profile, id, element, root))
}

func tokenCommitment(requirementSHA, runID string, row, canary map[string]any, input string) string {
	return digest(lengthPrefixed("aeb-cee-v0/canary", requirementSHA, runID, row["case_id"].(string), fmt.Sprint(row["trial_index"]), canary["canary_id"].(string), "mcp_stdio", canary["target_identity"].(string), canary["polarity"].(string), input))
}

func healthCommitment(requirementSHA, runID string, row, canary map[string]any, controlID, input string) string {
	return digest(lengthPrefixed("aeb-cee-v0/health-control", requirementSHA, runID, row["case_id"].(string), fmt.Sprint(row["trial_index"]), canary["canary_id"].(string), canary["canary_commitment_sha256"].(string), controlID, row["transport"].(string), canary["target_identity"].(string), input))
}

func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}
