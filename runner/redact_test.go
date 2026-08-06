package main

import (
	"strings"
	"testing"
)

// The retained command is the highest-value line in a published report and the
// one most likely to carry a credential, because a real invocation passes
// --scan-token and proxy URLs on the command line.
//
// EVERY credential-shaped value below is assembled at run time from parts.
// Written out whole they are real secret patterns committed to a public
// repository, and secret scanners are right to flag them: an earlier revision
// of this file split only some of them and a scanner caught the one left
// intact. There is no such thing as a fake secret that only looks fake to the
// scanner you happened to run, so the rule here is all of them or none.
func secretish(parts ...string) string { return strings.Join(parts, "") }

func TestRedactReportCommand(t *testing.T) {
	var (
		apiToken       = secretish("sk", "-live-", "abc123")
		awsLikeKey     = secretish("AKIA", "IOSFODNN7", "EXAMPLE")
		envTokenVar    = secretish("AEB_SCAN_", "TOKEN")
		envPasswordVar = secretish("PROXY_PASS", "WORD")
		envTokenValue  = secretish("hunt", "er2")
		envPasswdValue = secretish("sword", "fish")
		urlPassword    = secretish("s3c", "r3t")
		bearerToken    = secretish("abc.", "def.", "ghi")
		bearerValue    = secretish("Bear", "er ") + bearerToken
	)

	tests := []struct {
		name     string
		command  string
		mustHide []string
		mustKeep []string
	}{
		{
			name:     "spaced credential flag",
			command:  "./runner --adapter proxy --scan-token " + apiToken + " --cases ./cases",
			mustHide: []string{apiToken},
			mustKeep: []string{"--scan-token", "--adapter", "proxy", "./cases"},
		},
		{
			name:     "assigned credential flag",
			command:  "./runner --api-key=" + awsLikeKey + " --cases ./cases",
			mustHide: []string{awsLikeKey},
			mustKeep: []string{"--api-key=", "./cases"},
		},
		{
			name:     "inline environment secret",
			command:  envTokenVar + "=" + envTokenValue + " " + envPasswordVar + "=" + envPasswdValue + " ./runner --cases ./cases",
			mustHide: []string{envTokenValue, envPasswdValue},
			mustKeep: []string{envTokenVar + "=", envPasswordVar + "=", "./runner"},
		},
		{
			name:     "url userinfo",
			command:  "./runner --mcp-http-url https://alice:" + urlPassword + "@mcp.internal:8443/rpc",
			mustHide: []string{urlPassword, "alice:"},
			mustKeep: []string{"https://", "mcp.internal:8443/rpc"},
		},
		{
			// Assert the token itself is gone, not just the whole quoted value.
			// A redaction that stopped at the first space satisfied the
			// whole-value check while leaving the token in the report.
			name:     "quoted bearer authorization flag",
			command:  "./runner --authorization '" + bearerValue + "' --cases ./cases",
			mustHide: []string{bearerValue, bearerToken},
			mustKeep: []string{"--authorization", "./cases"},
		},
		{
			name:     "quoted environment secret",
			command:  envTokenVar + `="` + envTokenValue + ` trailing" ./runner --cases ./cases`,
			mustHide: []string{envTokenValue, "trailing"},
			mustKeep: []string{envTokenVar + "=", "./runner"},
		},
		{
			name:     "nothing to redact is left alone",
			command:  "./runner --adapter dryrun --cases ./cases --profile ./profile.json",
			mustKeep: []string{"--adapter dryrun", "--cases ./cases", "--profile ./profile.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactReportCommand(tt.command)
			for _, secret := range tt.mustHide {
				if strings.Contains(got, secret) {
					t.Errorf("redacted command still contains %q:\n%s", secret, got)
				}
			}
			for _, keep := range tt.mustKeep {
				if !strings.Contains(got, keep) {
					t.Errorf("redacted command lost %q, which a reader needs to reproduce the run:\n%s", keep, got)
				}
			}
		})
	}
}

func TestRedactReportCommandEmpty(t *testing.T) {
	if got := redactReportCommand(""); got != "" {
		t.Errorf("redactReportCommand(\"\") = %q, want empty", got)
	}
}

// The report only warns about a manual read when there is something local left
// to read, so the warning stays meaningful instead of decorating every run.
func TestReportCommandContainsLocalDetail(t *testing.T) {
	tests := []struct {
		command string
		want    bool
	}{
		{"./runner --cases ./cases", false},
		{"./runner --profile /home/operator/private/profile.json", true},
		{"./runner --mcp-http-url https://mcp.internal:8443/rpc", true},
		{"./runner --cases ~/corpus", true},
		{"", false},
	}
	for _, tt := range tests {
		if got := reportCommandContainsLocalDetail(tt.command); got != tt.want {
			t.Errorf("reportCommandContainsLocalDetail(%q) = %v, want %v", tt.command, got, tt.want)
		}
	}
}
