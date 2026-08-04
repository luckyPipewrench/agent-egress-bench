package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	verifier "github.com/luckyPipewrench/agent-egress-bench/control-evidence/v0/verifier"
)

func main() {
	packageDir := flag.String("package", "", "source Control Evidence v0 package directory")
	statementPath := flag.String("statement", "", "external buyer reproduction DSSE statement")
	transcriptPath := flag.String("transcript", "", "external normalized reproduction transcript")
	flag.Parse()
	if *packageDir == "" || *statementPath == "" || *transcriptPath == "" {
		fmt.Fprintln(os.Stderr, "--package, --statement, and --transcript are required")
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
	result := verifier.AssessBuyerReproduced(verifier.BuyerReproducedOptions{
		PackageDir: *packageDir, StatementPath: *statementPath, TranscriptPath: *transcriptPath,
		VerifierName: "aeb-ce-buyer-reproduced", VerifierVersion: "v1",
		VerifierSHA256: fmt.Sprintf("%x", sha256.Sum256(binary)), AssessmentTime: time.Now(),
	})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(2)
	}
	if result.Predicates[0].Status != "PASS" {
		os.Exit(1)
	}
}
