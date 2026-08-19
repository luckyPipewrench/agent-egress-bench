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

// A case naming two endpoints must require setup for both. Deriving from the
// first field let a seeded decoy url stand in while the A2A adapter delivered to
// an unseeded target_url, and the run scored an observation it had not earned.
func TestDerivationCoversEveryPayloadEndpoint(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{
		"url":        "https://seeded-decoy.example.net/ignored",
		"target_url": "https://unseeded-real-target.example.net/message:send",
	}
	c.Requires = []string{"domain_blocklist"}

	setup := newRunSetup([]string{"seeded-decoy.example.net"}, nil)
	if reason := setup.unsatisfied(c); reason == "" {
		t.Fatal("a seeded decoy satisfied setup while the delivered endpoint went unseeded")
	}
	both := newRunSetup([]string{"seeded-decoy.example.net", "unseeded-real-target.example.net"}, nil)
	if reason := both.unsatisfied(c); reason != "" {
		t.Fatalf("both endpoints seeded but still unsatisfied: %s", reason)
	}
}

// A row scored because an operator said a domain was seeded must carry that
// claim, since the runner cannot read the target configuration to check it.
func TestOperatorAssertedSetupIsRecorded(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{"url": "https://exfil-collector.example.net/beacon"}
	c.Requires = []string{"domain_blocklist"}

	setup := newRunSetup([]string{"exfil-collector.example.net"}, nil)
	asserted := setup.assertedFor(c)
	if len(asserted) != 1 || asserted[0] != "exfil-collector.example.net" {
		t.Fatalf("asserted = %#v, want the operator-claimed seeded domain", asserted)
	}

	// A reserved sink is proven by the runner holding the route, so it is not a claim.
	sink := stateTestCase()
	sink.Payload = map[string]interface{}{"url": "wss://" + adapter.WSUntrustedSinkHostname + "/live"}
	if got := newRunSetup(nil, proxyRoutableSinks(true)).assertedFor(sink); len(got) != 0 {
		t.Fatalf("asserted = %#v, want nothing for setup the runner proves itself", got)
	}
}

// A reserved sink in one endpoint field must not vouch for an attacker host in
// the other. Derivation only produces a requirement for a host that is itself a
// reserved sink or that a domain_blocklist require covers, so without this the
// sink's own prerequisite was the only one, it was satisfied, and the case
// scored while nothing was ever required of the endpoint beside it.
func TestReservedSinkDoesNotVouchForItsSiblingEndpoint(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{
		"url":        "https://" + adapter.A2AUntrustedSinkHostname + "/decoy",
		"target_url": "https://unseeded-real-target.example.net/message:send",
	}
	c.Requires = nil
	c.Prerequisites = []Prerequisite{{Kind: "reserved_sink_route", Value: adapter.A2AUntrustedSinkHostname}}

	setup := newRunSetup(nil, []string{adapter.A2AUntrustedSinkHostname})
	reason := setup.unsatisfied(c)
	if reason == "" {
		t.Fatal("a covered reserved sink satisfied setup while the sibling endpoint went uncovered")
	}
	if !strings.Contains(reason, "unseeded-real-target.example.net") {
		t.Fatalf("refusal did not name the uncovered endpoint: %s", reason)
	}

	c.Prerequisites = append(c.Prerequisites, Prerequisite{Kind: "blocklist_domain", Value: "unseeded-real-target.example.net"})
	covered := newRunSetup([]string{"unseeded-real-target.example.net"}, []string{adapter.A2AUntrustedSinkHostname})
	if reason := covered.unsatisfied(c); reason != "" {
		t.Fatalf("every endpoint covered but still unsatisfied: %s", reason)
	}
}

// A case that covers no endpoint at all is making no claim about a destination,
// so completeness has nothing to be complete about. Refusing here would fail the
// availability direction: it would turn ordinary two-endpoint cases that need no
// external setup into errors no operator can clear.
func TestCaseCoveringNoEndpointIsNotRefusedForCompleteness(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{
		"url":        "https://first.example.net/a",
		"target_url": "https://second.example.net/b",
	}
	c.Requires = nil
	c.Prerequisites = nil
	if reason := newRunSetup(nil, nil).unsatisfied(c); reason != "" {
		t.Fatalf("case needing no endpoint setup was refused: %s", reason)
	}
}

// One endpoint cannot trip completeness against itself.
func TestSingleEndpointCaseIsUnaffected(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{"url": "https://exfil-collector.example.net/beacon"}
	c.Requires = []string{"domain_blocklist"}
	c.Prerequisites = nil
	if reason := newRunSetup([]string{"exfil-collector.example.net"}, nil).unsatisfied(c); reason != "" {
		t.Fatalf("single-endpoint case was refused: %s", reason)
	}
}

// The list of asserted domains being computed correctly proves nothing about the
// artifact: a value that never reaches a result row cannot explain a score to
// anyone reading it later. This drives the real run path and reads the row.
func TestOperatorAssertedSetupReachesTheResultRow(t *testing.T) {
	c := stateTestCase()
	c.Payload = map[string]interface{}{"url": "https://exfil-collector.example.net/beacon"}
	c.Requires = []string{"domain_blocklist"}
	c.ExpectedVerdict = "block"
	adapt := &stateTestAdapter{
		routes: []adapter.DeliveryTuple{adapter.TupleForCase(adapter.Case{Transport: c.Transport, InputType: c.InputType})},
		result: adapter.Result{Verdict: "block", DeliveryProven: true, VerdictObserved: true},
	}

	// The EMITTED row is what a reader inspects later, and an in-memory struct can
	// carry a field the serialized row drops. Reading only results[0] would repeat
	// the exact mistake this test exists to close.
	var output bytes.Buffer
	setup := newRunSetup([]string{"exfil-collector.example.net"}, nil)
	if _, _, _, _, err := runCasesWithSetup([]Case{c}, stateTestProfile(), adapt, time.Second, false, &output, setup); err != nil {
		t.Fatalf("runCases: %v", err)
	}
	asserted, ok := emittedEvidence(t, output.String())["setup_asserted_by_operator"]
	if !ok {
		t.Fatalf("emitted row carries no operator assertion: %s", output.String())
	}
	values, ok := asserted.([]interface{})
	if !ok || len(values) != 1 || values[0] != "exfil-collector.example.net" {
		t.Fatalf("asserted = %#v, want the seeded domain the score depended on", asserted)
	}

	// A case the operator asserted nothing for must not gain an empty claim, or
	// every row would carry the key and the key would stop meaning anything. The
	// buffer is reset so this assertion cannot read the previous run's row.
	clean := stateTestCase()
	clean.Payload = map[string]interface{}{"url": "https://echo.fixture.example.com/ok"}
	clean.Requires = nil
	clean.ExpectedVerdict = "block"
	output.Reset()
	if _, _, _, _, err := runCasesWithSetup([]Case{clean}, stateTestProfile(), adapt, time.Second, false, &output, newRunSetup(nil, nil)); err != nil {
		t.Fatalf("runCases: %v", err)
	}
	if _, present := emittedEvidence(t, output.String())["setup_asserted_by_operator"]; present {
		t.Fatalf("a case with no asserted setup carried the key: %s", output.String())
	}
}

// emittedEvidence decodes the evidence of the single result row written to the
// run output, so a test reads what a consumer reads.
func emittedEvidence(t *testing.T, emitted string) map[string]interface{} {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(emitted), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("want exactly one emitted row, got %d: %s", len(lines), emitted)
	}
	var row struct {
		Evidence map[string]interface{} `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatalf("decode emitted row: %v (%s)", err, lines[0])
	}
	return row.Evidence
}
