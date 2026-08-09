package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	verifier "github.com/luckyPipewrench/agent-egress-bench/control-evidence/v1/verifier"
)

func main() {
	packageDir := flag.String("package", "", "control-evidence package directory")
	contextPath := flag.String("context", "", "independent verifier context JSON")
	replayLedgerDir := flag.String("replay-ledger", "", "buyer-controlled private replay-ledger directory")
	flag.Parse()
	if *packageDir == "" || *contextPath == "" {
		fmt.Fprintln(os.Stderr, "--package and --context are required")
		os.Exit(2)
	}
	result := verifier.VerifyWithOptions(*packageDir, verifier.VerifyOptions{
		ContextPath:     *contextPath,
		ReplayLedgerDir: *replayLedgerDir,
	})
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if result.Outcome != verifier.OutcomeValid {
		os.Exit(1)
	}
}
