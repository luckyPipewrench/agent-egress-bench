package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	verifier "github.com/luckyPipewrench/agent-egress-bench/control-evidence/v1/verifier"
)

func main() {
	packageDir := flag.String("package", "", "Control Evidence v1 package directory")
	flag.Parse()
	if *packageDir == "" {
		fmt.Fprintln(os.Stderr, "--package is required")
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve verifier executable:", err)
		os.Exit(2)
	}
	binary, err := os.ReadFile(self)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read verifier executable:", err)
		os.Exit(2)
	}
	result := verifier.AssessSchema(verifier.SchemaOptions{
		PackageDir:      *packageDir,
		VerifierName:    "aeb-ce-schema-valid",
		VerifierVersion: "v1",
		VerifierSHA256:  fmt.Sprintf("%x", sha256.Sum256(binary)),
		AssessmentTime:  time.Now(),
	})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(2)
	}
	if result.Predicates[0].Status != "PASS" {
		os.Exit(1)
	}
}
