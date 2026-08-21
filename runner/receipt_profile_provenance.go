package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	corpusGitStatusClean                = "clean"
	corpusGitStatusDirty                = "dirty"
	corpusGitStatusNotGitCheckout       = "not_git_checkout"
	corpusGitStatusMultipleSources      = "multiple_sources"
	corpusGitStatusUnavailable          = "unavailable"
	corpusGitStatusChangedDuringCapture = "changed_during_capture"

	toolVersionStatusObserved       = "observed"
	toolVersionStatusNotRequested   = "not_requested"
	toolVersionStatusInvalidCommand = "invalid_command"
	toolVersionStatusCommandFailed  = "command_failed"
	toolVersionStatusTimedOut       = "timed_out"
	toolVersionStatusEmptyOutput    = "empty_output"
	toolVersionStatusOutputTooLarge = "output_too_large"
)

const (
	gitObservationTimeout       = 10 * time.Second
	toolVersionTimeout          = 10 * time.Second
	maxToolVersionCommandBytes  = 16 << 10
	maxToolVersionArguments     = 32
	maxToolVersionArgumentBytes = 4 << 10
	maxObservedVersionBytes     = 4 << 10
)

var gitSHA1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// CorpusGitProvenance records whether one Git revision can identify every
// source directory used for the captured corpus snapshot. SHA is set only for
// a clean, stable single checkout. Every other state uses nil rather than a
// head revision that could be mistaken for the exact bytes that ran.
type CorpusGitProvenance struct {
	SHA    *string
	Status string
}

// ToolVersionObservation preserves the tool's own version output without
// conflating it with the tool_version label declared in the runner profile.
// Value is nil whenever the runner did not obtain a bounded non-empty stdout
// value from the supplied argv command.
type ToolVersionObservation struct {
	Status string  `json:"status"`
	Value  *string `json:"value"`
}

type observedGitCheckout struct {
	root   string
	sha    string
	status string
}

func observeCorpusGitProvenance(sourceRoots []string) CorpusGitProvenance {
	if len(sourceRoots) == 0 {
		return CorpusGitProvenance{Status: corpusGitStatusUnavailable}
	}

	checkouts := make(map[string]observedGitCheckout, len(sourceRoots))
	for _, sourceRoot := range sourceRoots {
		checkout := observeGitCheckout(sourceRoot)
		key := checkout.root
		if key == "" {
			key = checkout.status + ":" + filepath.Clean(sourceRoot)
		}
		if previous, exists := checkouts[key]; exists {
			checkouts[key] = mergeObservedGitCheckouts(previous, checkout)
		} else {
			checkouts[key] = checkout
		}
	}

	if len(checkouts) != 1 {
		return CorpusGitProvenance{Status: corpusGitStatusMultipleSources}
	}
	for _, checkout := range checkouts {
		switch checkout.status {
		case corpusGitStatusClean:
			sha := checkout.sha
			return CorpusGitProvenance{SHA: &sha, Status: corpusGitStatusClean}
		case corpusGitStatusDirty:
			return CorpusGitProvenance{Status: corpusGitStatusDirty}
		case corpusGitStatusNotGitCheckout:
			return CorpusGitProvenance{Status: corpusGitStatusNotGitCheckout}
		default:
			return CorpusGitProvenance{Status: corpusGitStatusUnavailable}
		}
	}
	return CorpusGitProvenance{Status: corpusGitStatusUnavailable}
}

func mergeObservedGitCheckouts(left, right observedGitCheckout) observedGitCheckout {
	if left.status == corpusGitStatusDirty || right.status == corpusGitStatusDirty {
		return observedGitCheckout{root: left.root, status: corpusGitStatusDirty}
	}
	if left.status != right.status {
		return observedGitCheckout{root: left.root, status: corpusGitStatusUnavailable}
	}
	if left.root != right.root || left.sha != right.sha {
		return observedGitCheckout{root: left.root, status: corpusGitStatusUnavailable}
	}
	return left
}

func stableCorpusGitProvenance(before, after CorpusGitProvenance) CorpusGitProvenance {
	if before.Status != after.Status || gitSHAValue(before.SHA) != gitSHAValue(after.SHA) {
		return CorpusGitProvenance{Status: corpusGitStatusChangedDuringCapture}
	}
	return after
}

func gitSHAValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func observeGitCheckout(sourceRoot string) observedGitCheckout {
	resolvedSource, err := filepath.EvalSymlinks(sourceRoot)
	if err != nil {
		return observedGitCheckout{status: corpusGitStatusUnavailable}
	}
	rootOut, rootErr, err := runGit(resolvedSource, "rev-parse", "--show-toplevel")
	if err != nil {
		if strings.Contains(strings.ToLower(rootErr), "not a git repository") {
			return observedGitCheckout{status: corpusGitStatusNotGitCheckout}
		}
		return observedGitCheckout{status: corpusGitStatusUnavailable}
	}
	root, err := filepath.EvalSymlinks(strings.TrimSpace(rootOut))
	if err != nil || root == "" {
		return observedGitCheckout{status: corpusGitStatusUnavailable}
	}
	relativeSource, err := filepath.Rel(root, resolvedSource)
	if err != nil || relativeSource == ".." || strings.HasPrefix(relativeSource, ".."+string(filepath.Separator)) {
		return observedGitCheckout{root: root, status: corpusGitStatusUnavailable}
	}

	status, _, err := runGit(root, "status", "--porcelain", "--untracked-files=all", "--", relativeSource)
	if err != nil {
		return observedGitCheckout{root: root, status: corpusGitStatusUnavailable}
	}
	if status != "" {
		return observedGitCheckout{root: root, status: corpusGitStatusDirty}
	}

	sha, _, err := runGit(root, "rev-parse", "HEAD")
	sha = strings.TrimSpace(sha)
	if err != nil || !gitSHA1Pattern.MatchString(sha) {
		return observedGitCheckout{root: root, status: corpusGitStatusUnavailable}
	}
	return observedGitCheckout{root: root, sha: sha, status: corpusGitStatusClean}
}

func runGit(dir string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitObservationTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	command.WaitDelay = time.Second
	command.Env = append(filteredGitEnvironment(), "LC_ALL=C", "LANG=C")
	var stderrBuffer bytes.Buffer
	command.Stderr = &stderrBuffer
	output, err := command.Output()
	return string(output), stderrBuffer.String(), err
}

func filteredGitEnvironment() []string {
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		// Git exposes repository, object, config, namespace, and executable
		// overrides through GIT_* variables. Observation must describe the
		// supplied source path, not a repository selected by inherited process
		// state, so none of those variables cross this boundary.
		if !strings.HasPrefix(key, "GIT_") {
			environment = append(environment, entry)
		}
	}
	return environment
}

// observeToolVersion executes a JSON-encoded argv array without a shell. A
// command failure, timeout, empty output, or oversized output is represented
// by a status and nil value instead of borrowing the declared tool_version.
func observeToolVersion(commandJSON string) ToolVersionObservation {
	if commandJSON == "" {
		return ToolVersionObservation{Status: toolVersionStatusNotRequested}
	}
	if len(commandJSON) > maxToolVersionCommandBytes {
		return ToolVersionObservation{Status: toolVersionStatusInvalidCommand}
	}

	var argv []string
	if err := json.Unmarshal([]byte(commandJSON), &argv); err != nil || len(argv) == 0 || len(argv) > maxToolVersionArguments {
		return ToolVersionObservation{Status: toolVersionStatusInvalidCommand}
	}
	for _, argument := range argv {
		if strings.TrimSpace(argument) == "" || len(argument) > maxToolVersionArgumentBytes {
			return ToolVersionObservation{Status: toolVersionStatusInvalidCommand}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), toolVersionTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Bound Wait as well as command execution. A version command can exit after
	// spawning a child that keeps stdout open; without WaitDelay the runner can
	// hang after the parent process has already exited.
	command.WaitDelay = time.Second
	command.Stderr = io.Discard
	var output boundedVersionBuffer
	command.Stdout = &output
	if err := command.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return ToolVersionObservation{Status: toolVersionStatusTimedOut}
		}
		return ToolVersionObservation{Status: toolVersionStatusCommandFailed}
	}
	if output.exceeded {
		return ToolVersionObservation{Status: toolVersionStatusOutputTooLarge}
	}
	value := strings.TrimSpace(output.String())
	if value == "" {
		return ToolVersionObservation{Status: toolVersionStatusEmptyOutput}
	}
	return ToolVersionObservation{Status: toolVersionStatusObserved, Value: &value}
}

type boundedVersionBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (buffer *boundedVersionBuffer) Write(value []byte) (int, error) {
	remaining := maxObservedVersionBytes - buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = buffer.Buffer.Write(value[:remaining])
		buffer.exceeded = true
		return len(value), nil
	}
	return buffer.Buffer.Write(value)
}
