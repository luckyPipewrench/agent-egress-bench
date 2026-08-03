package verifier

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestNegativeEvidenceWindowMustBeInsideSignedRun(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)

	preceding := resignObserverTime(t, filepath.Join(destination, "observer-preceding.dsse.json"), "2026-08-02T10:59:30Z")
	following := resignObserverTime(t, filepath.Join(destination, "observer-following.dsse.json"), "2026-08-02T11:01:30Z")
	outcomesPath := filepath.Join(destination, "outcomes.json")
	outcomes := readObject(t, outcomesPath)
	rows := outcomes["rows"].([]any)
	canaries := rows[0].(map[string]any)["canaries"].([]any)
	negative := canaries[1].(map[string]any)
	negative["window_start"] = "2026-08-02T11:00:00Z"
	negative["window_end"] = "2026-08-02T11:01:00Z"
	negative["preceding_health_ref"] = preceding
	negative["following_health_ref"] = following
	writePrettyJSON(t, outcomesPath, outcomes)
	resealPackage(t, destination)

	result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "negative_canary_window_outside_run" {
		t.Fatalf("Verify() = %#v, want invalid negative_canary_window_outside_run", result)
	}
}

func TestExplicitlyRequiredArtifactCannotDisappear(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	if err := os.Remove(filepath.Join(destination, "policy.json")); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(destination, "manifest.json")
	manifest := readObject(t, manifestPath)
	entries := manifest["entries"].([]any)
	kept := make([]any, 0, len(entries)-1)
	for _, raw := range entries {
		if raw.(map[string]any)["role"] != "policy" {
			kept = append(kept, raw)
		}
	}
	manifest["entries"] = kept
	writePrettyJSON(t, manifestPath, manifest)
	resealPackage(t, destination)

	result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInsufficientEvidence || result.Reason != "required_artifact_missing" {
		t.Fatalf("Verify() = %#v, want insufficient-evidence required_artifact_missing", result)
	}
}

func TestLivenessNegativeWindowCannotBeReversed(t *testing.T) {
	source := filepath.Join("..", "conformance", "edge", "e01-continuous-liveness-negative")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	outcomesPath := filepath.Join(destination, "outcomes.json")
	outcomes := readObject(t, outcomesPath)
	canaries := outcomes["rows"].([]any)[0].(map[string]any)["canaries"].([]any)
	negative := canaries[1].(map[string]any)
	negative["window_start"] = "2026-08-02T11:41:00Z"
	negative["window_end"] = "2026-08-02T11:40:00Z"
	writePrettyJSON(t, outcomesPath, outcomes)
	resealPackage(t, destination)

	result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "negative_canary_window_invalid" {
		t.Fatalf("Verify() = %#v, want invalid negative_canary_window_invalid", result)
	}
}

func TestVendorCannotRelabelBuyerExpectedVerdict(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	destination := filepath.Join(t.TempDir(), "package")
	copyTree(t, source, destination)
	outcomesPath := filepath.Join(destination, "outcomes.json")
	outcomes := readObject(t, outcomesPath)
	row := outcomes["rows"].([]any)[0].(map[string]any)
	row["expected_verdict"] = "allow"
	row["actual_verdict"] = "allow"
	writePrettyJSON(t, outcomesPath, outcomes)
	resealPackage(t, destination)

	result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
	if result.Outcome != outcomeInvalid || result.Reason != "outcomes_expected_verdict_mismatch" {
		t.Fatalf("Verify() = %#v, want invalid outcomes_expected_verdict_mismatch", result)
	}
}

func TestOutcomeAndClassificationMustAgree(t *testing.T) {
	source := filepath.Join("..", "conformance", "golden", "g01-vendor-time")
	for _, test := range []struct {
		name           string
		outcome        string
		actual         string
		classification string
	}{
		{name: "pass_with_mismatched_actual", outcome: "pass", actual: "allow", classification: "correct"},
		{name: "pass_with_incorrect_classification", outcome: "pass", actual: "block", classification: "incorrect"},
		{name: "fail_with_matching_actual", outcome: "fail", actual: "block", classification: "incorrect"},
		{name: "fail_with_correct_classification", outcome: "fail", actual: "allow", classification: "correct"},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "package")
			copyTree(t, source, destination)
			outcomesPath := filepath.Join(destination, "outcomes.json")
			outcomes := readObject(t, outcomesPath)
			row := outcomes["rows"].([]any)[0].(map[string]any)
			row["outcome"] = test.outcome
			row["actual_verdict"] = test.actual
			row["scoring_facts"].(map[string]any)["classification"] = test.classification
			writePrettyJSON(t, outcomesPath, outcomes)
			resealPackage(t, destination)

			result := verifyPersistent(t, destination, filepath.Join(destination, "context.json"))
			if result.Outcome != outcomeInvalid || result.Reason != "outcomes_scoring_facts_mismatch" {
				t.Fatalf("Verify() = %#v, want invalid outcomes_scoring_facts_mismatch", result)
			}
		})
	}
}

func resignObserverTime(t *testing.T, path, observedAt string) string {
	t.Helper()
	wrapper := readObject(t, path)
	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(wrapper["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	payload["observed_at"] = observedAt
	resignTestWrapper(t, wrapper, payload, "observer")
	writePrettyJSON(t, path, wrapper)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digestBytes(data)
}

func resealPackage(t *testing.T, root string) {
	t.Helper()
	manifestPath := filepath.Join(root, "manifest.json")
	manifest := readObject(t, manifestPath)
	var total int64
	for _, raw := range manifest["entries"].([]any) {
		entry := raw.(map[string]any)
		data, err := os.ReadFile(filepath.Join(root, entry["path"].(string)))
		if err != nil {
			t.Fatal(err)
		}
		entry["sha256"] = digestBytes(data)
		entry["byte_length"] = len(data)
		total += int64(len(data))
	}
	manifest["total_uncompressed_bytes"] = total
	writePrettyJSON(t, manifestPath, manifest)
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}

	envelopePath := filepath.Join(root, "envelope.dsse.json")
	wrapper := readObject(t, envelopePath)
	payloadBytes, err := base64.StdEncoding.Strict().DecodeString(wrapper["payload"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	outcomesBytes, err := os.ReadFile(filepath.Join(root, "outcomes.json"))
	if err != nil {
		t.Fatal(err)
	}
	payload["artifacts"].(map[string]any)["manifest_sha256"] = digestBytes(manifestBytes)
	payload["artifacts"].(map[string]any)["count"] = len(manifest["entries"].([]any))
	payload["observations"].(map[string]any)["sha256"] = digestBytes(outcomesBytes)
	resignTestWrapper(t, wrapper, payload, "vendor-runner")
	writePrettyJSON(t, envelopePath, wrapper)
}

func resignTestWrapper(t *testing.T, wrapper, payload map[string]any, role string) {
	t.Helper()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("agent-egress-bench-control-evidence-" + role + "-test-key-v0"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	payloadType := wrapper["payloadType"].(string)
	wrapper["payload"] = base64.StdEncoding.EncodeToString(payloadBytes)
	wrapper["signatures"] = []any{map[string]any{
		"keyid": hex.EncodeToString(publicKey),
		"sig":   base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payloadBytes), payloadBytes)))),
	}}
}

func readObject(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func writePrettyJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
