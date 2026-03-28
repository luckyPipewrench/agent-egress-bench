package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Case represents a single benchmark case loaded from JSON.
type Case struct {
	SchemaVersion   int                    `json:"schema_version"`
	ID              string                 `json:"id"`
	Category        string                 `json:"category"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	InputType       string                 `json:"input_type"`
	Transport       string                 `json:"transport"`
	Payload         map[string]interface{} `json:"payload"`
	ExpectedVerdict string                 `json:"expected_verdict"`
	Severity        string                 `json:"severity"`
	CapabilityTags  []string               `json:"capability_tags"`
	Requires        []string               `json:"requires"`
	FPRisk          string                 `json:"false_positive_risk"`
	WhyExpected     string                 `json:"why_expected"`
	SafeExample     *bool                  `json:"safe_example,omitempty"`
	Notes           string                 `json:"notes"`
	Source          string                 `json:"source"`
}

// Profile represents a tool profile JSON file.
type Profile struct {
	SchemaVersion int              `json:"schema_version"`
	Tool          string           `json:"tool"`
	ToolVersion   string           `json:"tool_version"`
	RunnerVersion string           `json:"runner_version"`
	Claims        []string         `json:"claims"`
	Supports      map[string]bool  `json:"supports"`
}

// NAKind describes why a case is not applicable.
type NAKind string

const (
	NAMissingCapability    NAKind = "missing_capability"
	NAMissingRequires      NAKind = "missing_requires"
	NAUnsupportedTransport NAKind = "unsupported_transport"
)

// loadCases walks a directory recursively and loads all .json files as Cases.
func loadCases(dir string) ([]Case, error) {
	var cases []Case

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", path, readErr)
		}

		var c Case
		if jsonErr := json.Unmarshal(data, &c); jsonErr != nil {
			return fmt.Errorf("parsing %s: %w", path, jsonErr)
		}

		cases = append(cases, c)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(cases) == 0 {
		return nil, fmt.Errorf("no case files found in %s", dir)
	}

	return cases, nil
}

// loadProfile reads and parses a tool profile JSON file.
func loadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("reading profile: %w", err)
	}

	var p Profile
	if jsonErr := json.Unmarshal(data, &p); jsonErr != nil {
		return Profile{}, fmt.Errorf("parsing profile: %w", jsonErr)
	}

	return p, nil
}

// checkApplicability determines if a case is applicable given a profile.
// Returns ("", true) if applicable, or (reason, false) if not.
// Checks are ordered: capability_tags first, then requires, then transport.
func checkApplicability(c Case, p Profile) (NAKind, bool) {
	claimsSet := make(map[string]bool, len(p.Claims))
	for _, claim := range p.Claims {
		claimsSet[claim] = true
	}

	// 1. Any capability_tag not in tool's claims
	for _, tag := range c.CapabilityTags {
		if !claimsSet[tag] {
			return NAMissingCapability, false
		}
	}

	// 2. Any requires value where supports.<value> is false
	for _, req := range c.Requires {
		if supported, exists := p.Supports[req]; !exists || !supported {
			return NAMissingRequires, false
		}
	}

	// 3. Transport not supported
	if supported, exists := p.Supports[c.Transport]; !exists || !supported {
		return NAUnsupportedTransport, false
	}

	return "", true
}
