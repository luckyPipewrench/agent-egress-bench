package main

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

// runSetup records which declared case prerequisites this run can actually
// satisfy. A missing entry is unsatisfied setup, not a detection miss.
type runSetup struct {
	seededBlocklist map[string]struct{}
	routableSinks   map[string]struct{}
}

func newRunSetup(seededBlocklist []string, routableSinks []string) runSetup {
	setup := runSetup{
		seededBlocklist: make(map[string]struct{}, len(seededBlocklist)),
		routableSinks:   make(map[string]struct{}, len(routableSinks)),
	}
	for _, domain := range seededBlocklist {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		setup.seededBlocklist[domain] = struct{}{}
	}
	for _, host := range routableSinks {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		setup.routableSinks[host] = struct{}{}
	}
	return setup
}

// stringList is a repeatable CLI flag value.
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value must be non-empty")
	}
	*s = append(*s, value)
	return nil
}

func proxyRoutableSinks(fixturesStarted bool) []string {
	if !fixturesStarted {
		return nil
	}
	return []string{adapter.WSUntrustedSinkHostname, adapter.A2AUntrustedSinkHostname}
}

// casePayloadHost returns the host of the case payload URL.
func casePayloadHost(c Case) string {
	for _, key := range []string{"url", "target_url"} {
		raw, ok := c.Payload[key].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		return strings.ToLower(parsed.Hostname())
	}
	return ""
}

// derivedPrerequisites returns setup a case needs without having to declare it.
// Case bytes are fixed once a case ships, so a declared copy cannot be added to
// exactly the cases that carry this defect. The action is already machine
// readable in requires, and the value is the host in the case's own payload, so
// the runner derives it instead of demanding a second copy.
func derivedPrerequisites(c Case) []Prerequisite {
	host := casePayloadHost(c)
	if host == "" {
		return nil
	}
	var derived []Prerequisite
	for _, req := range c.Requires {
		if req == "domain_blocklist" {
			derived = append(derived, Prerequisite{Kind: "blocklist_domain", Value: host})
		}
	}
	if host == adapter.WSUntrustedSinkHostname || host == adapter.A2AUntrustedSinkHostname {
		derived = append(derived, Prerequisite{Kind: "reserved_sink_route", Value: host})
	}
	return derived
}

// effectivePrerequisites prefers what the case declares. A declared entry is
// bound to the payload host by the validator, so the two agree wherever both
// exist, and a future case whose required domain is not its payload host can
// still state it explicitly.
func effectivePrerequisites(c Case) []Prerequisite {
	if len(c.Prerequisites) > 0 {
		return c.Prerequisites
	}
	return derivedPrerequisites(c)
}

func (s runSetup) unsatisfied(c Case) string {
	for _, prereq := range effectivePrerequisites(c) {
		kind := strings.TrimSpace(prereq.Kind)
		value := strings.ToLower(strings.TrimSpace(prereq.Value))
		switch kind {
		case "blocklist_domain":
			if _, ok := s.seededBlocklist[value]; !ok {
				return fmt.Sprintf("unsatisfied prerequisite blocklist_domain=%q: pass --seeded-blocklist-domain %s after seeding that domain in the tool blocklist", prereq.Value, prereq.Value)
			}
		case "reserved_sink_route":
			if _, ok := s.routableSinks[value]; !ok {
				return fmt.Sprintf("unsatisfied prerequisite reserved_sink_route=%q: enable --fixtures so the runner can route this reserved sink without treating the hostname as trusted", prereq.Value)
			}
		default:
			return fmt.Sprintf("unsatisfied prerequisite kind=%q value=%q: runner has no satisfaction path for this kind", prereq.Kind, prereq.Value)
		}
	}
	return ""
}
