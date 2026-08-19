package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/agent-egress-bench/runner/adapter"
)

func TestUnsatisfiedBlocklistPrerequisiteIsErrorNotMiss(t *testing.T) {
	c := stateTestCase()
	c.ExpectedVerdict = "block"
	c.Prerequisites = []Prerequisite{{Kind: "blocklist_domain", Value: "exfil-collector.example.net"}}
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "allow", DeliveryProven: true, VerdictObserved: true},
	}

	var output bytes.Buffer
	results, _, unreachable, _, err := runCases([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if adapt.calls != 0 {
		t.Fatalf("adapter Run calls = %d, want 0 when setup is unsatisfied", adapt.calls)
	}
	if len(unreachable) != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one error row", len(results), len(unreachable))
	}
	got := results[0]
	if got.ActualVerdict != "error" || got.Score != "error" || got.Evidence["result_state"] != string(ResultStateAdapterError) {
		t.Fatalf("result = %+v, want adapter_error rather than an observed miss", got)
	}
	if got.Notes == "" || !strings.Contains(got.Notes, "blocklist_domain") {
		t.Fatalf("notes = %q, want the unsatisfied blocklist_domain reason", got.Notes)
	}

	var emitted CaseResult
	if err := json.Unmarshal(output.Bytes(), &emitted); err != nil {
		t.Fatalf("decode emitted result: %v", err)
	}
	if emitted.Score != "error" {
		t.Fatalf("emitted score = %q, want error so an unsatisfied setup cannot read as a miss", emitted.Score)
	}
}

func TestSatisfiedBlocklistPrerequisiteRunsAdapter(t *testing.T) {
	c := stateTestCase()
	c.ExpectedVerdict = "block"
	c.Prerequisites = []Prerequisite{{Kind: "blocklist_domain", Value: "exfil-collector.example.net"}}
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "allow", DeliveryProven: true, VerdictObserved: true},
	}
	setup := newRunSetup([]string{"exfil-collector.example.net"}, nil)
	var output bytes.Buffer
	results, _, unreachable, _, err := runCasesWithSetup([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output, setup)
	if err != nil {
		t.Fatalf("runCasesWithSetup: %v", err)
	}
	if adapt.calls != 1 {
		t.Fatalf("adapter Run calls = %d, want 1 after the blocklist domain is declared seeded", adapt.calls)
	}
	if len(unreachable) != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one observed row", len(results), len(unreachable))
	}
	got := results[0]
	if got.ActualVerdict != "allow" || got.Score != "fail" || got.Evidence["result_state"] != string(ResultStateObserved) {
		t.Fatalf("result = %+v, want an observed miss once setup is proven", got)
	}
}

func TestUnsatisfiedReservedSinkPrerequisiteIsErrorNotMiss(t *testing.T) {
	c := stateTestCase()
	c.Transport = "websocket"
	c.InputType = "websocket_frame"
	c.ExpectedVerdict = "block"
	c.Prerequisites = []Prerequisite{{Kind: "reserved_sink_route", Value: adapter.WSUntrustedSinkHostname}}
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "allow", DeliveryProven: true, VerdictObserved: true},
	}
	var output bytes.Buffer
	results, _, unreachable, _, err := runCases([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output)
	if err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if adapt.calls != 0 {
		t.Fatalf("adapter Run calls = %d, want 0 when the reserved sink is not routable", adapt.calls)
	}
	if len(unreachable) != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one error row", len(results), len(unreachable))
	}
	got := results[0]
	if got.ActualVerdict != "error" || got.Score != "error" || got.Evidence["result_state"] != string(ResultStateAdapterError) {
		t.Fatalf("result = %+v, want adapter_error rather than an observed miss", got)
	}
}

func TestSatisfiedReservedSinkPrerequisiteRunsAdapter(t *testing.T) {
	c := stateTestCase()
	c.Transport = "websocket"
	c.InputType = "websocket_frame"
	c.ExpectedVerdict = "block"
	c.Prerequisites = []Prerequisite{{Kind: "reserved_sink_route", Value: adapter.WSUntrustedSinkHostname}}
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "block", DeliveryProven: true, VerdictObserved: true},
	}
	setup := newRunSetup(nil, proxyRoutableSinks(true))
	var output bytes.Buffer
	results, _, unreachable, _, err := runCasesWithSetup([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output, setup)
	if err != nil {
		t.Fatalf("runCasesWithSetup: %v", err)
	}
	if adapt.calls != 1 {
		t.Fatalf("adapter Run calls = %d, want 1 after the reserved sink is routable", adapt.calls)
	}
	if len(unreachable) != 0 || len(results) != 1 {
		t.Fatalf("results=%d unreachable=%d, want one observed row", len(results), len(unreachable))
	}
	got := results[0]
	if got.ActualVerdict != "block" || got.Score != "pass" {
		t.Fatalf("result = %+v, want observed pass once the sink is routable", got)
	}
}

// The three corpus cases needing external setup declare nothing, because their
// bytes are fixed. What the runner acts on is the effective prerequisite, so
// this asserts the derived path produces the same requirement a declaration
// would have. If it stops matching, an unseeded or unrouted runner scores those
// cases as detection misses.
func TestCorpusSetupCasesResolveTheirPrerequisites(t *testing.T) {
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	want := map[string]Prerequisite{
		"url-domain-blocklist-001":   {Kind: "blocklist_domain", Value: "exfil-collector.example.net"},
		"ws-dlp-opaque-binary-010":   {Kind: "reserved_sink_route", Value: adapter.WSUntrustedSinkHostname},
		"a2a-msg-opaque-entropy-013": {Kind: "reserved_sink_route", Value: adapter.A2AUntrustedSinkHostname},
	}
	seen := make(map[string]bool, len(want))
	for _, c := range cases {
		expected, ok := want[c.ID]
		if !ok {
			continue
		}
		seen[c.ID] = true
		effective := effectivePrerequisites(c)
		if len(effective) != 1 || effective[0].Kind != expected.Kind || effective[0].Value != expected.Value {
			t.Errorf("case %s effective prerequisites = %#v, want %#v", c.ID, effective, expected)
		}
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("missing case %s while checking prerequisite consumption", id)
		}
	}
}

// An unrelated declared prerequisite must not suppress the derived one. Before
// this was a union, a case declaring a sink route while requiring a blocklist
// ran with nothing seeded and scored a detection result it never earned.
func TestPartialDeclarationDoesNotSuppressDerived(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{"url": "https://exfil-collector.example.net/beacon"}
	c.Requires = []string{"domain_blocklist"}
	c.Prerequisites = []Prerequisite{{Kind: "reserved_sink_route", Value: adapter.WSUntrustedSinkHostname}}

	setup := newRunSetup(nil, []string{adapter.WSUntrustedSinkHostname})
	if reason := setup.unsatisfied(c); reason == "" {
		t.Fatal("unrelated declaration suppressed the derived blocklist requirement; the case would score without setup")
	}
}

// Declaring the same requirement derivation produces must not double it. The
// validator binds a declared value to the payload host, so the two describe one
// requirement rather than two.
func TestDeclaredAndDerivedPrerequisitesDeduplicate(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{"url": "https://exfil-collector.example.net/beacon"}
	c.Requires = []string{"domain_blocklist"}
	c.Prerequisites = []Prerequisite{{Kind: "blocklist_domain", Value: "exfil-collector.example.net"}}

	if effective := effectivePrerequisites(c); len(effective) != 1 {
		t.Fatalf("effective = %#v, want one deduplicated requirement", effective)
	}
}

// The real corpus case declares no prerequisites and its bytes cannot change,
// so derivation is the only path that reaches it. If this stops firing, an
// unseeded runner scores that case as a detection miss again.
func TestFrozenBlocklistCaseDerivesItsPrerequisite(t *testing.T) {
	cases, err := loadCases("../cases")
	if err != nil {
		t.Fatalf("loadCases: %v", err)
	}
	var target *Case
	for i := range cases {
		if cases[i].ID == "url-domain-blocklist-001" {
			target = &cases[i]
			break
		}
	}
	if target == nil {
		t.Fatal("url-domain-blocklist-001 not found in the corpus")
	}
	if len(target.Prerequisites) != 0 {
		t.Fatalf("case declares %d prerequisites; this test covers the derived path", len(target.Prerequisites))
	}

	derived := derivedPrerequisites(*target)
	if len(derived) != 1 || derived[0].Kind != "blocklist_domain" || derived[0].Value != "exfil-collector.example.net" {
		t.Fatalf("derived = %+v, want the payload host as a blocklist_domain prerequisite", derived)
	}

	empty := newRunSetup(nil, nil)
	if reason := empty.unsatisfied(*target); reason == "" {
		t.Fatal("unseeded runner reported satisfied setup; the case would score as a miss")
	}
	seeded := newRunSetup([]string{"exfil-collector.example.net"}, nil)
	if reason := seeded.unsatisfied(*target); reason != "" {
		t.Fatalf("seeded runner still unsatisfied: %s", reason)
	}
}
