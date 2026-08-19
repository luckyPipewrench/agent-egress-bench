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

// casePayloadHosts returns every endpoint host a case payload names.
//
// It returns all of them rather than the first. Taking only the first meant a
// payload carrying both url and target_url derived from url, while the A2A
// adapter delivers to target_url: a seeded decoy url satisfied setup and the
// real target was never required to be seeded, so the run scored an observation
// it had not earned. Requiring every named endpoint makes an extra field add a
// requirement instead of hiding one.
func casePayloadHosts(c Case) []string {
	var hosts []string
	seen := make(map[string]struct{}, 2)
	for _, key := range []string{"url", "target_url"} {
		raw, ok := c.Payload[key].(string)
		if !ok || strings.TrimSpace(raw) == "" {
			continue
		}
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

// derivedPrerequisites returns setup a case needs without having to declare it.
// Case bytes are fixed once a case ships, so a declared copy cannot be added to
// exactly the cases that carry this defect. The action is already machine
// readable in requires, and the value is the host in the case's own payload, so
// the runner derives it instead of demanding a second copy.
func derivedPrerequisites(c Case) []Prerequisite {
	hosts := casePayloadHosts(c)
	if len(hosts) == 0 {
		return nil
	}
	var derived []Prerequisite
	for _, host := range hosts {
		for _, req := range c.Requires {
			if req == "domain_blocklist" {
				derived = append(derived, Prerequisite{Kind: "blocklist_domain", Value: host})
			}
		}
		if host == adapter.WSUntrustedSinkHostname || host == adapter.A2AUntrustedSinkHostname {
			derived = append(derived, Prerequisite{Kind: "reserved_sink_route", Value: host})
		}
	}
	return derived
}

// effectivePrerequisites is the UNION of what a case declares and what its
// payload implies, deduplicated.
//
// It is deliberately not "declared wins". Preferring declarations wholesale let
// an unrelated declared entry suppress a derived one, so a case declaring a sink
// route while requiring a blocklist would run with no blocklist seeded and score
// a detection result it never earned. A union cannot do that: adding a
// declaration can only ever add setup.
//
// The two agree where they overlap rather than competing, because the validator
// requires a declared value to equal the payload host, which is the same value
// derivation produces.
func effectivePrerequisites(c Case) []Prerequisite {
	derived := derivedPrerequisites(c)
	if len(c.Prerequisites) == 0 {
		return derived
	}
	seen := make(map[string]struct{}, len(c.Prerequisites)+len(derived))
	effective := make([]Prerequisite, 0, len(c.Prerequisites)+len(derived))
	add := func(prereq Prerequisite) {
		key := strings.ToLower(strings.TrimSpace(prereq.Kind)) + "\x00" + strings.ToLower(strings.TrimSpace(prereq.Value))
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		effective = append(effective, prereq)
	}
	for _, prereq := range c.Prerequisites {
		add(prereq)
	}
	for _, prereq := range derived {
		add(prereq)
	}
	return effective
}

// assertedFor returns the setup values this case relied on that the runner took
// on the operator's word rather than verifying.
//
// A reserved sink route is excluded because the runner proves that one: it holds
// the fixture route itself. A seeded blocklist domain cannot be proven from here,
// since the runner cannot read the target's configuration, so any case scored
// because of one carries the claim in its own evidence.
func (s runSetup) assertedFor(c Case) []string {
	var asserted []string
	seen := make(map[string]struct{})
	for _, prereq := range effectivePrerequisites(c) {
		if strings.TrimSpace(prereq.Kind) != "blocklist_domain" {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(prereq.Value))
		if _, ok := s.seededBlocklist[value]; !ok {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		asserted = append(asserted, value)
	}
	return asserted
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
