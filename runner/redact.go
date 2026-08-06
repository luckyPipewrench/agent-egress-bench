package main

import (
	"regexp"
	"strings"
)

// The buyer report is built to be published. The runner command it retains is
// the most useful thing in it for reproduction and the most dangerous, because
// a real invocation carries --scan-token, proxy URLs with userinfo, and inline
// environment assignments. Rendering it verbatim copies whatever the operator
// typed into a document meant for outsiders.
//
// Redaction here is deliberately conservative about what it claims: it removes
// credential-shaped values with confidence, and the report says plainly that
// local paths and hostnames may remain, so a publisher still reads the command
// before posting it. A denylist cannot promise more than that, and promising
// more is how a leak ships.

var (
	// A credential value may be single-quoted, double-quoted, or bare. The
	// quoted alternatives come first: matching \S+ alone stops at the first
	// space, which redacts up to the quote and leaves the rest of the secret
	// sitting in the report.
	credentialValue = `(?:'[^']*'|"[^"]*"|\S+)`

	credentialFlagName = `--[A-Za-z0-9._-]*(?:token|secret|password|passwd|credential|apikey|api-key|auth|bearer)[A-Za-z0-9._-]*`

	// Flag values whose name suggests a credential, in --flag=value and
	// --flag value form.
	redactFlagAssign = regexp.MustCompile(`(?i)(` + credentialFlagName + `=)(` + credentialValue + `)`)
	redactFlagSpaced = regexp.MustCompile(`(?i)(` + credentialFlagName + `\s+)(` + credentialValue + `)`)

	// Inline environment assignments, VAR=value, with a credential-shaped name.
	redactEnvAssign = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|API_KEY|AUTH|BEARER)[A-Z0-9_]*=)(` + credentialValue + `)`)

	// Userinfo in a URL: scheme://user:pass@host.
	redactURLUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s:@]+(?::[^/\s@]*)?@`)
)

const redactedValue = "REDACTED"

// redactReportCommand removes credential-shaped values from a retained command
// line. It preserves the structure so the reader can still see which flags ran.
func redactReportCommand(command string) string {
	if command == "" {
		return command
	}
	out := redactFlagAssign.ReplaceAllString(command, "${1}"+redactedValue)
	out = redactFlagSpaced.ReplaceAllString(out, "${1}"+redactedValue)
	out = redactEnvAssign.ReplaceAllString(out, "${1}"+redactedValue)
	out = redactURLUserinfo.ReplaceAllString(out, "${1}"+redactedValue+"@")
	return out
}

// reportCommandContainsLocalDetail reports whether a redacted command still
// carries an absolute path or a host-looking token. The report uses this to
// tell the publisher when a manual read is genuinely warranted rather than
// printing the same warning on every run.
func reportCommandContainsLocalDetail(command string) bool {
	for _, field := range strings.Fields(command) {
		if strings.HasPrefix(field, "/") || strings.HasPrefix(field, "~/") {
			return true
		}
		if strings.Contains(field, "://") {
			return true
		}
	}
	return false
}
