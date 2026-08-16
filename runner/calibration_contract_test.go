package main

import (
	"os"
	"os/exec"
	"path/filepath"
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
