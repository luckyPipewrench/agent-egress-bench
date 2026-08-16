package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestCalibrationOutputSatisfiesTheResultContract drives each calibration
// adapter over the real corpus and validates the rows against the real cases.
//
// This is the guard that was missing. The validator was exercised only against
// hand-written fixtures, and the harness ran it without the cases directory, so
// every case-bound rule sat idle. The first time the two were put together, the
// built-in dryrun adapter was claiming a denial-of-wallet block without the
// timing evidence those cases require, and had been for as long as both existed.
//
// A fixture cannot catch that, because a fixture is written by whoever wrote the
// code and agrees with it by construction. Only the real emitter against the
// real corpus does.
func TestCalibrationOutputSatisfiesTheResultContract(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the runner and validator over the whole corpus")
	}
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	cases := filepath.Join(repo, "cases")
	profile := filepath.Join(repo, "examples/runner-template/tool-profile-template.json")

	for _, adapter := range []string{"dryrun", "blockall", "null"} {
		t.Run(adapter, func(t *testing.T) {
			dir := t.TempDir()
			results := filepath.Join(dir, "results.jsonl")
			handle, err := os.Create(results)
			if err != nil {
				t.Fatal(err)
			}
			run := exec.Command("go", "run", ".",
				"--cases", cases,
				"--profile", profile,
				"--adapter", adapter,
				"--output", filepath.Join(dir, "summary.json"),
			)
			run.Dir = filepath.Join(repo, "runner")
			run.Stdout = handle
			runErr := run.Run()
			if closeErr := handle.Close(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if runErr != nil {
				t.Fatalf("%s run: %v", adapter, runErr)
			}

			// The cases directory is the argument that enables the case-bound
			// rules. Omitting it is what made this check pass while proving
			// nothing, so it is supplied deliberately here.
			validate := exec.Command("go", "run", ".", "results", results, cases)
			validate.Dir = filepath.Join(repo, "validate")
			validate.Env = append(os.Environ(), "AEB_CAPABILITY_REGISTRY="+filepath.Join(repo, "capability-registry"))
			if out, err := validate.CombinedOutput(); err != nil {
				t.Fatalf("%s output failed the result contract: %v\n%s", adapter, err, out)
			}
		})
	}
}

// TestCalibrationCannotEmitAReceiptProfile pins the other way a calibration run
// could make a claim it never earned.
//
// The receipt profile is read as a statement that a tool blocked things, and
// its renderer maps an expected block plus an actual block to blocked: yes
// without consulting the evidence behind the row. Measured on the unmodified
// runner: a dryrun run emitted a profile reporting 174 blocked malicious cases
// for a tool that was never contacted, and the profile schema carries no field
// that would let a reader tell it from a measured one.
func TestCalibrationCannotEmitAReceiptProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("drives the runner over the whole corpus")
	}
	repo, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range []string{"dryrun", "blockall", "null"} {
		t.Run(adapter, func(t *testing.T) {
			dir := t.TempDir()
			profile := filepath.Join(dir, "receipt-profile.json")
			run := exec.Command("go", "run", ".",
				"--cases", filepath.Join(repo, "cases"),
				"--profile", filepath.Join(repo, "examples/runner-template/tool-profile-template.json"),
				"--adapter", adapter,
				"--output", filepath.Join(dir, "summary.json"),
				"--emit-receipt-profile", profile,
			)
			run.Dir = filepath.Join(repo, "runner")
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("%s emitted a receipt profile from a calibration run", adapter)
			}
			if !strings.Contains(string(out), "refusing to write a receipt profile") {
				t.Fatalf("%s failed for the wrong reason: %s", adapter, out)
			}
			if _, statErr := os.Stat(profile); !os.IsNotExist(statErr) {
				t.Errorf("%s wrote a receipt profile despite refusing", adapter)
			}
		})
	}
}

func TestReceiptProfileRefusalFailsClosedOnMissingProvenance(t *testing.T) {
	// The first version of this guard asked the synthetic question in its own
	// words instead of using the rule that already decides measurement_status,
	// and the copy diverged at once: a row whose evidence was nil was skipped,
	// so an adapter returning a verdict and no evidence could emit a receipt
	// profile. The comment above it claimed the opposite, which is worse than
	// the hole, because it told the next reader the check was stricter than it
	// was.
	cases := []struct {
		name string
		rows []CaseResult
		want bool
	}{
		{name: "nil evidence", rows: []CaseResult{{CaseID: "x", Evidence: nil}}, want: true},
		{name: "empty evidence", rows: []CaseResult{{CaseID: "x", Evidence: map[string]interface{}{}}}, want: true},
		{name: "declared synthetic", rows: []CaseResult{{CaseID: "x", Evidence: map[string]interface{}{"synthetic": true}}}, want: true},
		{name: "malformed marker", rows: []CaseResult{{CaseID: "x", Evidence: map[string]interface{}{"synthetic": "calibration"}}}, want: true},
		{name: "honest negative", rows: []CaseResult{{CaseID: "x", Evidence: map[string]interface{}{"synthetic": false, "proof": "observed"}}}, want: false},
		{name: "real row with no marker", rows: []CaseResult{{CaseID: "x", Evidence: map[string]interface{}{"proof": "observed"}}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			refused := receiptProfileRefusal(tc.rows, nil) != ""
			if refused != tc.want {
				t.Errorf("refused = %v, want %v", refused, tc.want)
			}
			// An unreachable row reaches the profile too, so the same rule has
			// to hold when the row arrives through that list instead.
			if refusedUnreachable := receiptProfileRefusal(nil, tc.rows) != ""; refusedUnreachable != tc.want {
				t.Errorf("unreachable refused = %v, want %v", refusedUnreachable, tc.want)
			}
		})
	}
}
