package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/luckyPipewrench/agent-egress-bench/control-evidence/g2/authentication"
)

func main() {
	packageDir := flag.String("package", "", "Control Evidence v0 package directory")
	policy := flag.String("policy", "", "externally supplied signed trust policy")
	context := flag.String("context", "", "verifier-trusted authentication context (never producer supplied)")
	checkpoint := flag.String("policy-checkpoint", "", "private durable policy checkpoint directory")
	flag.Parse()
	if *packageDir == "" || *policy == "" || *context == "" || *checkpoint == "" {
		fmt.Fprintln(os.Stderr, "--package, --policy, --context, and --policy-checkpoint are required")
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
	result := authentication.Assess(authentication.Options{PackageDir: *packageDir, PolicyPath: *policy, ContextPath: *context, CheckpointDir: *checkpoint, VerifierName: "aeb-ce-authenticate", VerifierVersion: "v1", VerifierSHA256: authentication.SHA256(binary)})
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(2)
	}
	if result.Predicates[0].Status != authentication.StatusPass {
		os.Exit(1)
	}
}
