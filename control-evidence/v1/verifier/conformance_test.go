package verifier

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type v1Expectation struct {
	Description string `json:"description"`
	Runs        []struct {
		Mode            string `json:"mode"`
		ExpectedOutcome string `json:"expected_outcome"`
		Reason          string `json:"reason"`
		NonceStatus     string `json:"nonce_status"`
	} `json:"runs"`
}

func TestV1ConformanceCorpus(t *testing.T) {
	root := filepath.Join("..", "conformance")
	distribution := map[string]int{}
	packages := 0
	runs := 0
	for _, category := range []string{"golden", "edge", "malicious"} {
		entries, err := os.ReadDir(filepath.Join(root, category))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			packages++
			packageDir := filepath.Join(root, category, entry.Name())
			t.Run(entry.Name(), func(t *testing.T) {
				expectation := readV1Expectation(t, filepath.Join(root, "expectations", entry.Name()+".json"))
				contextPath := filepath.Join(root, "contexts", entry.Name()+".json")
				if expectation.Description == "" || len(expectation.Runs) == 0 {
					t.Fatal("expectation requires a description and at least one run")
				}
				ledger := filepath.Join(t.TempDir(), "replay")
				if err := os.Mkdir(ledger, 0o700); err != nil {
					t.Fatal(err)
				}
				for index, run := range expectation.Runs {
					var result Result
					switch run.Mode {
					case "persistent":
						result = VerifyWithOptions(packageDir, VerifyOptions{ContextPath: contextPath, ReplayLedgerDir: ledger})
					case "stateless":
						result = Verify(packageDir, contextPath)
					default:
						t.Fatalf("run %d has unknown mode %q", index, run.Mode)
					}
					wantNonce := run.NonceStatus
					if run.ExpectedOutcome == OutcomeValid && run.Mode == "persistent" && wantNonce == "" {
						wantNonce = "first_verification"
					}
					if result.Outcome != run.ExpectedOutcome || result.Reason != run.Reason || result.NonceStatus != wantNonce {
						t.Fatalf("run %d: Verify() = %#v, want outcome=%q reason=%q nonce_status=%q", index, result, run.ExpectedOutcome, run.Reason, wantNonce)
					}
					distribution[result.Outcome]++
					runs++
				}
			})
		}
	}
	if packages != 7 || runs != 8 {
		t.Fatalf("tested %d packages and %d runs, want 7 packages and 8 runs", packages, runs)
	}
	want := map[string]int{OutcomeValid: 3, outcomeInvalid: 1, outcomeStale: 1, outcomeScopeMismatch: 1, outcomeInsufficientEvidence: 1, outcomeUnverifiable: 1}
	if !equalJSON(distribution, want) {
		t.Fatalf("outcome distribution = %#v, want %#v", distribution, want)
	}
}

func TestV1VerifierRejectsPackageSidecars(t *testing.T) {
	root := filepath.Join("..", "conformance")
	source := filepath.Join(root, "golden", "g01-valid-registry-bound")
	contextPath := filepath.Join(root, "contexts", "g01-valid-registry-bound.json")

	t.Run("context must be external", func(t *testing.T) {
		packageDir := filepath.Join(t.TempDir(), "package")
		if err := os.CopyFS(packageDir, os.DirFS(source)); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(contextPath)
		if err != nil {
			t.Fatal(err)
		}
		inside := filepath.Join(packageDir, "context.json")
		if err := os.WriteFile(inside, data, 0o600); err != nil {
			t.Fatal(err)
		}
		result := Verify(packageDir, inside)
		if result.Outcome != outcomeUnverifiable || result.Reason != "context_not_external" {
			t.Fatalf("Verify() = %#v, want unverifiable/context_not_external", result)
		}
	})

	t.Run("undeclared expectation is rejected", func(t *testing.T) {
		packageDir := filepath.Join(t.TempDir(), "package")
		if err := os.CopyFS(packageDir, os.DirFS(source)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(packageDir, "expect.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		result := Verify(packageDir, contextPath)
		if result.Outcome != outcomeInvalid || result.Reason != "manifest_member_uncommitted" {
			t.Fatalf("Verify() = %#v, want invalid/manifest_member_uncommitted", result)
		}
	})
}

func readV1Expectation(t *testing.T, path string) v1Expectation {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var expectation v1Expectation
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&expectation); err != nil {
		t.Fatal(err)
	}
	return expectation
}
