// Generator for the agent-egress-bench receipt verifier conformance corpus.
// Stdlib-only by design — vendors should be able to read this file and
// implement an equivalent verifier in any language.
//
// Usage:
//
//	go run . --write    # regenerate all fixtures under ../{golden,malicious,edge}
//	go run . --verify   # re-derive fixtures in memory, diff against committed files
//
// The receipt schema and signing protocol are defined inline here so the
// corpus remains readable and reproducible without depending on any product
// implementation.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Receipt schema under test.
// ---------------------------------------------------------------------------

const (
	receiptVersion       = 1
	actionRecordVersion  = 1
	signaturePrefix      = "ed25519:"
	genesisHash          = "genesis"
	testSeedPhrase       = "agent-egress-bench-receipt-conformance-test-key-v1"
	conformanceSessionID = "conformance-session"
)

// ActionRecord covers every field a v0 verifier may consult. The field set,
// declaration order, and omitempty semantics MIRROR THE GO STRUCT EXACTLY at
// github.com/luckyPipewrench/pipelock/internal/receipt/action.go. The v1
// signing input is SHA-256(json.Marshal(ActionRecord)) in struct-declaration
// order (NOT JCS), so any field a verifier omits or reorders recomputes a
// different canonical byte string and fails signature verification. Keeping
// this struct a faithful mirror lets the generator emit fixtures that exercise
// every field, which is what locks the four reference verifiers against drift.
type ActionRecord struct {
	Version int `json:"version"`

	ActionID       string    `json:"action_id"`
	ParentActionID string    `json:"parent_action_id,omitempty"`
	ActionType     string    `json:"action_type"`
	Timestamp      time.Time `json:"timestamp"`

	Principal       string   `json:"principal"`
	Actor           string   `json:"actor"`
	DelegationChain []string `json:"delegation_chain"`

	Target string `json:"target"`

	Intent         string   `json:"intent,omitempty"`
	DataClassesIn  []string `json:"data_classes_in,omitempty"`
	DataClassesOut []string `json:"data_classes_out,omitempty"`

	SideEffectClass string `json:"side_effect_class"`
	Reversibility   string `json:"reversibility"`

	PolicyHash string `json:"policy_hash"`
	Verdict    string `json:"verdict"`

	// Taint-aware policy escalation context.
	SessionTaintLevel   string           `json:"session_taint_level,omitempty"`
	SessionContaminated bool             `json:"session_contaminated,omitempty"`
	RecentTaintSources  []TaintSourceRef `json:"recent_taint_sources,omitempty"`
	SessionTaskID       string           `json:"session_task_id,omitempty"`
	SessionTaskLabel    string           `json:"session_task_label,omitempty"`
	AuthorityKind       string           `json:"authority_kind,omitempty"`
	TaintDecision       string           `json:"taint_decision,omitempty"`
	TaintDecisionReason string           `json:"taint_decision_reason,omitempty"`
	TaskOverrideApplied bool             `json:"task_override_applied,omitempty"`

	// Contract context, populated when live lock evaluates this action.
	ContractWinningSource string   `json:"contract_winning_source,omitempty"`
	ContractLiveVerdict   string   `json:"contract_live_verdict,omitempty"`
	ContractPolicySources []string `json:"contract_policy_sources,omitempty"`
	ContractRuleID        string   `json:"contract_rule_id,omitempty"`
	ActiveManifestHash    string   `json:"active_manifest_hash,omitempty"`
	ContractHash          string   `json:"contract_hash,omitempty"`
	ContractSelectorID    string   `json:"contract_selector_id,omitempty"`
	ContractGeneration    uint64   `json:"contract_generation,omitempty"`

	Transport string            `json:"transport"`
	Method    string            `json:"method,omitempty"`
	Layer     string            `json:"layer,omitempty"`
	Pattern   string            `json:"pattern,omitempty"`
	Severity  string            `json:"severity,omitempty"`
	Redaction *RedactionSummary `json:"redaction,omitempty"`
	Shield    *ShieldSummary    `json:"shield,omitempty"`
	RequestID string            `json:"request_id,omitempty"`

	ChainPrevHash string `json:"chain_prev_hash"`
	ChainSeq      uint64 `json:"chain_seq"`

	// Jurisdictional fields - present in schema for forward compatibility.
	Venue              string   `json:"venue,omitempty"`
	Jurisdiction       string   `json:"jurisdiction,omitempty"`
	RulebookID         string   `json:"rulebook_id,omitempty"`
	RemedyClass        string   `json:"remedy_class,omitempty"`
	ContestationWindow string   `json:"contestation_window,omitempty"`
	PrecedentRefs      []string `json:"precedent_refs,omitempty"`
}

// TaintSourceRef mirrors session.TaintSourceRef. Field order and omitempty
// match the Go source so recent_taint_sources entries canonicalize identically.
// Level mirrors session.TaintLevel (a uint8 with no custom JSON marshaller), so
// it serializes as a NUMBER, not a string. The top-level ActionRecord
// session_taint_level is a separate string field — do not conflate the two.
type TaintSourceRef struct {
	URL         string    `json:"url"`
	Kind        string    `json:"kind"`
	Level       uint8     `json:"level"`
	Timestamp   time.Time `json:"timestamp"`
	ReceiptID   string    `json:"receipt_id,omitempty"`
	MatchReason string    `json:"match_reason,omitempty"`
}

// RedactionSummary mirrors receipt.RedactionSummary.
type RedactionSummary struct {
	Profile           string         `json:"profile,omitempty"`
	Provider          string         `json:"provider,omitempty"`
	Parser            string         `json:"parser,omitempty"`
	TotalRedactions   int            `json:"total_redactions,omitempty"`
	ByClass           map[string]int `json:"by_class,omitempty"`
	CacheBoundaryKept bool           `json:"cache_boundary_kept,omitempty"`
}

// ShieldSummary mirrors receipt.ShieldSummary.
type ShieldSummary struct {
	Pipeline                 string `json:"pipeline,omitempty"`
	TotalRewrites            int    `json:"total_rewrites,omitempty"`
	ExtensionProbes          int    `json:"extension_probes,omitempty"`
	TrackingBeacons          int    `json:"tracking_beacons,omitempty"`
	AgentTraps               int    `json:"agent_traps,omitempty"`
	FingerprintShimInjected  bool   `json:"fingerprint_shim_injected,omitempty"`
	SVGForeignObjects        int    `json:"svg_foreign_objects,omitempty"`
	SVGEventHandlers         int    `json:"svg_event_handlers,omitempty"`
	SVGExternalReferences    int    `json:"svg_external_references,omitempty"`
	SVGHiddenText            int    `json:"svg_hidden_text,omitempty"`
	SVGAnimationInjections   int    `json:"svg_animation_injections,omitempty"`
	BodyBytes                int    `json:"body_bytes,omitempty"`
	ScannedBytes             int    `json:"scanned_bytes,omitempty"`
	Partial                  bool   `json:"partial,omitempty"`
	AdaptiveSignalsRecorded  int    `json:"adaptive_signals_recorded,omitempty"`
	AdaptiveSignalMaxPerBody int    `json:"adaptive_signal_max_per_body,omitempty"`
}

// Receipt is the v0 signed envelope around an ActionRecord.
type Receipt struct {
	Version      int          `json:"version"`
	ActionRecord ActionRecord `json:"action_record"`
	Signature    string       `json:"signature"`
	SignerKey    string       `json:"signer_key"`
}

// canonical marshals the action record in the deterministic shape the signer
// uses. The generator relies on encoding/json's field-tag order, which is stable.
func (ar ActionRecord) canonical() ([]byte, error) {
	return json.Marshal(ar)
}

// signReceipt produces a v0 receipt for ar using priv.
func signReceipt(ar ActionRecord, priv ed25519.PrivateKey) (Receipt, error) {
	data, err := ar.canonical()
	if err != nil {
		return Receipt{}, fmt.Errorf("canonical: %w", err)
	}
	sum := sha256.Sum256(data)
	sig := ed25519.Sign(priv, sum[:])
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return Receipt{}, fmt.Errorf("unexpected public key type %T", priv.Public())
	}
	return Receipt{
		Version:      receiptVersion,
		ActionRecord: ar,
		Signature:    signaturePrefix + hex.EncodeToString(sig),
		SignerKey:    hex.EncodeToString(pub),
	}, nil
}

// receiptHash returns the hex SHA-256 of a receipt's canonical JSON. Used as
// the next receipt's chain_prev_hash.
func receiptHash(r Receipt) (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Expect-output schema.
// ---------------------------------------------------------------------------

// Expect is the verifier-output specification a correct verifier must match.
type Expect struct {
	FixtureID           string `json:"fixture_id"`
	Category            string `json:"category"`
	InputFormat         string `json:"input_format"`
	Verdict             string `json:"verdict"`
	RejectReason        string `json:"reject_reason,omitempty"`
	Description         string `json:"description"`
	ExpectedChainLength int    `json:"expected_chain_length,omitempty"`
	ExpectedSignerKey   string `json:"expected_signer_key,omitempty"`
	ExpectedRootHash    string `json:"expected_root_hash,omitempty"`
	Notes               string `json:"notes,omitempty"`
}

// ---------------------------------------------------------------------------
// Fixture-builder helpers.
// ---------------------------------------------------------------------------

// baseTime fixes the timestamp floor for golden receipts.
var baseTime = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)

// agedTime sits well inside the corpus max_age window (1 year).
var freshTime = time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)

// expiredTime sits outside the corpus max_age window (older than 1 year vs the
// frozen "now" used by golden fixtures).
var expiredTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// edgeTime sits exactly on the max_age boundary minus one second — still
// fresh but vendors must round correctly.
var edgeTime = time.Date(2025, 4, 15, 12, 0, 1, 0, time.UTC)

// futureTime is for the "exact-edge timestamp" edge case where the receipt is
// timestamped slightly in the future (small clock skew). Verifiers MUST
// accept up to a few minutes of skew.
var skewTime = time.Date(2026, 4, 15, 12, 0, 30, 0, time.UTC)

// kp returns the deterministic Ed25519 test keypair.
func kp() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte(testSeedPhrase))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// foreignKP returns a different deterministic keypair used to produce signatures
// that are mathematically valid but unpinned — exercising signer_key_untrusted.
func foreignKP() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("agent-egress-bench-receipt-conformance-foreign-key-v1"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub, _ := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

// sideEffectFromMethod mirrors pipelock's internal/receipt/classify.go.
// Keep this in sync with the canonical mapping: GET/HEAD/OPTIONS/TRACE/CONNECT
// are external_read, POST/PUT/PATCH/DELETE are external_write.
func sideEffectFromMethod(method string) string {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return "external_read"
	case "POST", "PUT", "PATCH", "DELETE":
		return "external_write"
	default:
		return "none"
	}
}

// reversibilityFromMethod mirrors pipelock's internal/receipt/classify.go.
// DELETE is irreversible, POST/PUT/PATCH are compensatable, reads are full.
func reversibilityFromMethod(method string) string {
	switch method {
	case "GET", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return "full"
	case "DELETE":
		return "irreversible"
	case "POST", "PUT", "PATCH":
		return "compensatable"
	default:
		return "unknown"
	}
}

// baseRecord returns an action record with the common fields filled in. The
// side_effect_class and reversibility defaults are method-derived to match
// what pipelock's classify.go emits in production. Test authors override the
// verdict-specific fields per fixture and may override side_effect_class or
// reversibility when the fixture intentionally models a non-canonical policy
// classification.
func baseRecord(seq uint64, prev string, ts time.Time, actionType, verdict, target, transport, method string) ActionRecord {
	return ActionRecord{
		Version:         actionRecordVersion,
		ActionID:        fmt.Sprintf("conformance-%05d", seq),
		ActionType:      actionType,
		Timestamp:       ts,
		Principal:       "org:conformance-test",
		Actor:           "agent:conformance-runner",
		DelegationChain: []string{"test-policy-v1", "test-grant"},
		Target:          target,
		SideEffectClass: sideEffectFromMethod(method),
		Reversibility:   reversibilityFromMethod(method),
		PolicyHash:      "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Verdict:         verdict,
		Transport:       transport,
		Method:          method,
		ChainPrevHash:   prev,
		ChainSeq:        seq,
	}
}

// chainOf signs n receipts linked into a valid hash chain starting at the
// genesis hash. Returns the final receipt's hash for downstream reference.
func chainOf(priv ed25519.PrivateKey, build func(seq uint64, prev string) ActionRecord, n int) ([]Receipt, string, error) {
	out := make([]Receipt, 0, n)
	prev := genesisHash
	for i := 0; i < n; i++ {
		r, err := signReceipt(build(uint64(i), prev), priv)
		if err != nil {
			return nil, "", err
		}
		h, err := receiptHash(r)
		if err != nil {
			return nil, "", err
		}
		out = append(out, r)
		prev = h
	}
	return out, prev, nil
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

func main() {
	var (
		writeFlag  = flag.Bool("write", false, "write fixtures to disk")
		verifyFlag = flag.Bool("verify", false, "verify on-disk fixtures match generator output")
		outDir     = flag.String("out", "..", "output directory (defaults to ..)")
	)
	flag.Parse()

	if !*writeFlag && !*verifyFlag {
		fmt.Fprintln(os.Stderr, "usage: go run . --write | --verify")
		os.Exit(2)
	}

	all, err := buildAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n", err)
		os.Exit(1)
	}

	if *writeFlag {
		if err := writeAll(*outDir, all); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %d fixtures under %s\n", len(all), *outDir)
		return
	}

	// --verify
	if err := verifyAll(*outDir, all); err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("verified %d fixtures under %s\n", len(all), *outDir)
}

// fixture is a single conformance file pair to write.
type fixture struct {
	Category string // golden | malicious | edge
	Name     string // base filename (no extension)
	Payload  []byte // raw bytes to write to <name>.json
	Expect   Expect
}

func buildAll() ([]fixture, error) {
	var out []fixture

	g, err := buildGolden()
	if err != nil {
		return nil, fmt.Errorf("golden: %w", err)
	}
	out = append(out, g...)

	m, err := buildMalicious()
	if err != nil {
		return nil, fmt.Errorf("malicious: %w", err)
	}
	out = append(out, m...)

	e, err := buildEdge()
	if err != nil {
		return nil, fmt.Errorf("edge: %w", err)
	}
	out = append(out, e...)

	// Stable order so output is reproducible.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})

	return out, nil
}

// ---------------------------------------------------------------------------
// Golden fixtures.
// ---------------------------------------------------------------------------

func buildGolden() ([]fixture, error) {
	_, priv := kp()
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	var out []fixture

	// 1. allow + clean GET — vanilla allow path.
	if f, err := makeSingle("01-allow-clean-get", "golden", priv, pubHex,
		baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET"),
		"Plain allow on a benign HTTPS GET to an explicitly allowed host.",
		"Smoke test: clean outcome with no DLP layer activity. Verifier MUST accept and surface signer_key.",
	); err != nil {
		return nil, err
	} else {
		out = append(out, f)
	}

	// 2. allow + suppressed-allowlist — verdict is allow but layer was DLP.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/upload", "https", "POST")
		ar.Layer = "dlp"
		ar.Pattern = "api_key_aws"
		ar.Severity = "high"
		ar.Intent = "upload-build-artifact"
		if f, err := makeSingle("02-allow-suppressed-allowlist", "golden", priv, pubHex, ar,
			"Allow on a destination that matched DLP but is on the suppression allowlist.",
			"Verifier MUST accept and MUST NOT collapse the layer/pattern fields — they are evidence the operator made a deliberate exception.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 3. block + DLP — AWS key in URL query.
	{
		// GET with secrets in the query string is still ActionRead under
		// pipelock's ClassifyHTTP. The exfiltration nature is captured by
		// verdict=block + layer=dlp + pattern=api_key_aws, not by
		// reclassifying the method.
		ar := baseRecord(0, genesisHash, freshTime, "read", "block",
			"https://attacker.example.net/exfil?key=AKIA...REDACTED", "https", "GET")
		ar.Layer = "dlp"
		ar.Pattern = "api_key_aws"
		ar.Severity = "critical"
		if f, err := makeSingle("03-block-dlp-aws-key", "golden", priv, pubHex, ar,
			"Block on AWS access key detected in URL query string.",
			"Verifier MUST accept the signed receipt. The verdict is block, not allow, but the receipt itself is well-formed evidence of the block decision.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 4. block + injection — prompt injection in fetched response.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "block",
			"https://compromised-blog.example/post/123", "https", "GET")
		ar.Layer = "response_injection"
		ar.Pattern = "ignore_previous_instructions"
		ar.Severity = "high"
		if f, err := makeSingle("04-block-injection-fetch", "golden", priv, pubHex, ar,
			"Block on prompt injection detected in a fetched web page.",
			"Demonstrates a response-side layer firing on inbound content. Verifier MUST accept the receipt and surface layer=response_injection.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 5. ask + HITL approve — chain of two receipts (ask, then allow).
	{
		_, priv := kp()
		askAR := baseRecord(0, genesisHash, freshTime, "write", "ask",
			"https://prod.example.com/v1/deploy", "https", "POST")
		askAR.Layer = "tool_policy"
		askAR.Severity = "medium"

		askR, err := signReceipt(askAR, priv)
		if err != nil {
			return nil, err
		}
		askHash, err := receiptHash(askR)
		if err != nil {
			return nil, err
		}
		allowAR := baseRecord(1, askHash, freshTime.Add(2*time.Second), "write", "allow",
			"https://prod.example.com/v1/deploy", "https", "POST")
		allowAR.Layer = "hitl"
		allowAR.Intent = "operator_approved"
		allowR, err := signReceipt(allowAR, priv)
		if err != nil {
			return nil, err
		}

		// Compute the root hash of the chain so the expect file pins it.
		finalHash, err := receiptHash(allowR)
		if err != nil {
			return nil, err
		}
		f, err := makeChain("05-ask-hitl-approve", "golden", []Receipt{askR, allowR}, pubHex, finalHash,
			"Two-receipt chain: ASK verdict followed by HITL operator approval (allow).",
			"Verifier MUST accept both receipts and treat them as a single coherent decision sequence linked by chain_prev_hash.",
		)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	// 6. ask + HITL deny — chain of two receipts (ask, then block).
	{
		_, priv := kp()
		askAR := baseRecord(0, genesisHash, freshTime, "write", "ask",
			"https://prod.example.com/v1/payments", "https", "POST")
		askAR.Layer = "tool_policy"
		askAR.Severity = "high"
		askR, err := signReceipt(askAR, priv)
		if err != nil {
			return nil, err
		}
		askHash, err := receiptHash(askR)
		if err != nil {
			return nil, err
		}
		blockAR := baseRecord(1, askHash, freshTime.Add(2*time.Second), "write", "block",
			"https://prod.example.com/v1/payments", "https", "POST")
		blockAR.Layer = "hitl"
		blockAR.Intent = "operator_denied"
		blockR, err := signReceipt(blockAR, priv)
		if err != nil {
			return nil, err
		}
		finalHash, err := receiptHash(blockR)
		if err != nil {
			return nil, err
		}
		f, err := makeChain("06-ask-hitl-deny", "golden", []Receipt{askR, blockR}, pubHex, finalHash,
			"Two-receipt chain: ASK verdict followed by HITL operator denial (block).",
			"Verifier MUST accept the chain. This proves an operator was offered a decision and chose to block — a procurement-relevant artifact.",
		)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}

	// 7. redirect + audited handler.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "redirect",
			"https://wallet.example.com/v1/transfer", "https", "POST")
		ar.Layer = "tool_policy"
		ar.Intent = "redirected_to_audited_handler"
		ar.Pattern = "wallet_transfer_redirect"
		ar.Severity = "high"
		if f, err := makeSingle("07-redirect-audited-handler", "golden", priv, pubHex, ar,
			"Redirect verdict: tool policy diverted the call to an audited handler program.",
			"Verifier MUST accept. Redirect is a non-block, non-allow third-state vendors often forget — fixture exists so they implement it.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 8. warn + observe mode.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "warn",
			"https://newsletter.example.com/track?u=user-123", "https", "GET")
		ar.Layer = "tracking_detection"
		ar.Pattern = "marketing_pixel"
		ar.Severity = "low"
		if f, err := makeSingle("08-warn-observe-mode", "golden", priv, pubHex, ar,
			"Warn verdict in observe-mode: action allowed but flagged for review.",
			"Verifier MUST accept and MUST NOT degrade to allow — the warn signal is the whole point of observe mode.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 9. allow + Browser Shield summary — exercises the nested `shield` object.
	// Historically the TS and Rust canonical field lists OMITTED `shield`
	// entirely, so a shield-bearing receipt recomputed a DIFFERENT canonical
	// byte string in those verifiers and the signature failed to verify. This
	// fixture is the regression that locks `shield` into every verifier's
	// canonical field list, in the correct position (after redaction, before
	// request_id).
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://news.example.com/article/42", "https", "GET")
		ar.Layer = "browser_shield"
		ar.Severity = "low"
		ar.Shield = &ShieldSummary{
			Pipeline:                "browser_shield_v1",
			TotalRewrites:           7,
			TrackingBeacons:         3,
			AgentTraps:              1,
			FingerprintShimInjected: true,
			BodyBytes:               20480,
			ScannedBytes:            20480,
		}
		if f, err := makeSingle("09-allow-shield-summary", "golden", priv, pubHex, ar,
			"Allow on a fetched page where Browser Shield rewrote tracking beacons and an agent trap.",
			"Verifier MUST accept. The nested shield object MUST be included in the canonical field list (after redaction, before request_id); a verifier that drops it recomputes a different signing hash and wrongly reports signature_invalid.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// 10. full-field differential — populates one representative field from
	// every block that the non-Go verifiers historically dropped:
	// parent_action_id, the taint block (scalars + a nested recent_taint_sources
	// entry), the contract block, redaction (nested), and shield (nested). A
	// verifier whose canonical field list is missing ANY of these recomputes a
	// different signing hash and fails. This is the four-language differential:
	// the Go signer includes all of them, so only a verifier that mirrors the
	// full Go struct verifies it.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/agents/spawn", "https", "POST")
		ar.ParentActionID = "conformance-parent-00000"
		ar.Intent = "delegated-subagent-write"
		ar.Layer = "tool_policy"
		ar.Severity = "medium"
		ar.SessionTaintLevel = "suspected"
		ar.SessionContaminated = true
		ar.RecentTaintSources = []TaintSourceRef{
			{
				URL:  "https://compromised-blog.example/post/9",
				Kind: "response_injection",
				// session.TaintExternalUntrusted (4); serializes as a number.
				Level:       4,
				Timestamp:   freshTime,
				MatchReason: "ignore_previous_instructions",
			},
		}
		ar.SessionTaskID = "task-abc123"
		ar.SessionTaskLabel = "research-and-summarize"
		ar.AuthorityKind = "delegated"
		ar.TaintDecision = "allow_with_constraints"
		ar.TaintDecisionReason = "task_scope_permits_write"
		ar.ContractWinningSource = "operator_policy"
		ar.ContractLiveVerdict = "allow"
		ar.ContractPolicySources = []string{"operator_policy", "org_default"}
		ar.ContractRuleID = "rule-write-allow-7"
		ar.ActiveManifestHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		ar.ContractHash = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		ar.ContractSelectorID = "selector-9"
		ar.ContractGeneration = 4
		ar.Redaction = &RedactionSummary{
			Profile:         "strict",
			Provider:        "provider.example",
			Parser:          "json",
			TotalRedactions: 2,
			ByClass:         map[string]int{"api_key": 1, "email": 1},
		}
		ar.Shield = &ShieldSummary{
			Pipeline:      "browser_shield_v1",
			TotalRewrites: 1,
			AgentTraps:    1,
		}
		ar.RequestID = "req-7f3a"
		if f, err := makeSingle("10-full-field-differential", "golden", priv, pubHex, ar,
			"Allow on a delegated sub-agent write carrying parent_action_id, taint context (scalars + a nested recent_taint_sources entry), contract context, redaction, and shield. Every block here was missing from at least one reference verifier's canonical field list.",
			"Verifier MUST accept. This is the cross-language drift sentinel: a verifier MUST mirror the full Go ActionRecord field set, declaration order, and omitempty semantics — including nested object key order for recent_taint_sources, redaction, and shield. Any omitted or reordered field recomputes a different signing hash and wrongly reports signature_invalid.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	return out, nil
}

func makeSingle(name, category string, priv ed25519.PrivateKey, pubHex string, ar ActionRecord, desc, notes string) (fixture, error) {
	r, err := signReceipt(ar, priv)
	if err != nil {
		return fixture{}, err
	}
	payload, err := marshalPretty(r)
	if err != nil {
		return fixture{}, err
	}
	hash, err := receiptHash(r)
	if err != nil {
		return fixture{}, err
	}
	return fixture{
		Category: category,
		Name:     name,
		Payload:  payload,
		Expect: Expect{
			FixtureID:           name,
			Category:            category,
			InputFormat:         "receipt",
			Verdict:             "accept",
			Description:         desc,
			ExpectedChainLength: 1,
			ExpectedSignerKey:   pubHex,
			ExpectedRootHash:    hash,
			Notes:               notes,
		},
	}, nil
}

func makeChain(name, category string, chain []Receipt, pubHex, rootHash, desc, notes string) (fixture, error) {
	payload, err := marshalChainJSONL(chain)
	if err != nil {
		return fixture{}, err
	}
	return fixture{
		Category: category,
		Name:     name,
		Payload:  payload,
		Expect: Expect{
			FixtureID:           name,
			Category:            category,
			InputFormat:         "chain",
			Verdict:             "accept",
			Description:         desc,
			ExpectedChainLength: len(chain),
			ExpectedSignerKey:   pubHex,
			ExpectedRootHash:    rootHash,
			Notes:               notes,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Malicious fixtures.
// ---------------------------------------------------------------------------

func buildMalicious() ([]fixture, error) {
	_, priv := kp()
	_, foreignPriv := foreignKP()
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))
	foreignPubHex := hex.EncodeToString(foreignPriv.Public().(ed25519.PublicKey))

	var out []fixture

	// M1. Forged signature — right format, wrong key.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://attacker.example.net/sneak", "https", "POST")
		r, err := signReceipt(ar, foreignPriv)
		if err != nil {
			return nil, err
		}
		// Force-rewrite the signer_key field to the pinned-key hex so the
		// signature is internally consistent w.r.t. the wrong signer_key
		// claim — this is the realistic forge pattern.
		r.SignerKey = pubHex
		payload, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m01-forged-signature-wrong-key",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m01-forged-signature-wrong-key",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "signature_invalid",
				Description:  "Signature is well-formed Ed25519 but was produced with a foreign key. signer_key was rewritten to claim the pinned key.",
				Notes:        "Verifier MUST recompute SHA-256(canonical(action_record)) and run ed25519.Verify against the embedded signer_key. The forge fails because the foreign signature does not verify against the pinned public key.",
			},
		})
		_ = foreignPubHex // referenced for documentation; unused at runtime
	}

	// M2. Untrusted but valid signature — math is fine, key is not pinned.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		r, err := signReceipt(ar, foreignPriv)
		if err != nil {
			return nil, err
		}
		payload, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m02-signer-key-untrusted",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m02-signer-key-untrusted",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "signer_key_untrusted",
				Description:  "Receipt is signed correctly by a different key. The signature math is valid but the key is not on the verifier's pinned list.",
				Notes:        "Verifier MUST distinguish 'signature math broken' (signature_invalid) from 'signature math fine, key unknown' (signer_key_untrusted). Conflating them loses evidence.",
			},
		})
	}

	// M3. Expired timestamp.
	{
		ar := baseRecord(0, genesisHash, expiredTime, "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		payload, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m03-expired-timestamp",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m03-expired-timestamp",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "expired",
				Description:  "Receipt timestamp is 2024-01-01, well beyond the corpus max_age window of 1 year.",
				Notes:        "Verifier MUST treat the timestamp as the proof's freshness anchor. Long-lived receipts must be replayed via flight-recorder archival, not re-presented as fresh.",
			},
		})
	}

	// M4. Replay — duplicate action_id in a chain.
	{
		ar0 := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		r0, err := signReceipt(ar0, priv)
		if err != nil {
			return nil, err
		}
		h0, err := receiptHash(r0)
		if err != nil {
			return nil, err
		}
		ar1 := baseRecord(1, h0, freshTime.Add(1*time.Second), "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		ar1.ActionID = ar0.ActionID // duplicate action_id
		r1, err := signReceipt(ar1, priv)
		if err != nil {
			return nil, err
		}
		payload, err := marshalChainJSONL([]Receipt{r0, r1})
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m04-replay-duplicate-action-id",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m04-replay-duplicate-action-id",
				Category:     "malicious",
				InputFormat:  "chain",
				Verdict:      "reject",
				RejectReason: "replay_detected",
				Description:  "Two receipts in the chain share the same action_id — a replay or attempted re-presentation of an earlier decision.",
				Notes:        "Verifier MUST detect duplicate action_id within the same session. action_id is UUIDv7 in production; collision implies forgery or replay.",
			},
		})
	}

	// M5. Malformed JSON — trailing junk after a valid receipt.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		good, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		bad := append(good, []byte("\n}EXTRA\n")...)
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m05-malformed-json-trailing-junk",
			Payload:  bad,
			Expect: Expect{
				FixtureID:    "m05-malformed-json-trailing-junk",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "malformed_json",
				Description:  "Receipt JSON is followed by garbage bytes. A strict parser must reject; a forgiving parser may silently consume the prefix and trust an unauthenticated trailer.",
				Notes:        "Verifier MUST consume the entire input as a single JSON value (use json.Decoder + EOF check). Loose parsers create a smuggling vector for unsigned content.",
			},
		})
	}

	// M6. Missing required field — drop verdict.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		// Marshal then surgically remove the verdict field.
		buf, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		stripped := bytes.ReplaceAll(buf, []byte("\"verdict\": \"allow\",\n    "), []byte(""))
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m06-missing-required-verdict",
			Payload:  stripped,
			Expect: Expect{
				FixtureID:    "m06-missing-required-verdict",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "missing_required_field",
				Description:  "Required action_record.verdict field has been removed. Even if signature math worked over an empty-verdict record, the receipt is not well-formed.",
				Notes:        "Verifier MUST enforce a schema-required field set before falling through to signature verification. A field-by-field absent-string treated as 'allow' would create an existence-based bypass.",
			},
		})
	}

	// M7. Padding attack — wrap the receipt in a JSONL line that declares a
	// length that does not match the body length.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		body, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		wrapped := map[string]any{
			"declared_length": 9999, // lies about body size
			"body":            json.RawMessage(body),
		}
		payload, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m07-padding-length-mismatch",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m07-padding-length-mismatch",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "padding_attack",
				Description:  "Receipt is wrapped in a transport envelope that claims declared_length=9999 but the body is much smaller. Verifiers that trust the declared length without re-measuring create a smuggling primitive.",
				Notes:        "Verifier MUST measure body length itself rather than trusting envelope-declared length. Length-vs-body divergence is a classic protocol-layer attack.",
			},
		})
	}

	// M8. Tampered chain — prev_hash of receipt[3] does not match hash of
	// receipt[2].
	{
		chain, _, err := chainOf(priv, func(seq uint64, prev string) ActionRecord {
			return baseRecord(seq, prev, freshTime.Add(time.Duration(seq)*time.Second),
				"write", "allow", "https://api.example.com/v1/data", "https", "POST")
		}, 5)
		if err != nil {
			return nil, err
		}
		// Tamper receipt[3]'s chain_prev_hash.
		brokenAR := chain[3].ActionRecord
		brokenAR.ChainPrevHash = "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
		brokenR, err := signReceipt(brokenAR, priv)
		if err != nil {
			return nil, err
		}
		chain[3] = brokenR
		payload, err := marshalChainJSONL(chain)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m08-tampered-chain-prev-hash",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m08-tampered-chain-prev-hash",
				Category:     "malicious",
				InputFormat:  "chain",
				Verdict:      "reject",
				RejectReason: "chain_break",
				Description:  "Every receipt signature is individually valid, but receipt[3]'s chain_prev_hash does not match the SHA-256 of receipt[2]. Indicates an insert or removal in the chain.",
				Notes:        "Verifier MUST walk the chain in order, recompute SHA-256(canonical(receipt[N])), and compare against receipt[N+1].action_record.chain_prev_hash.",
			},
		})
	}

	// M9. Verdict vs chain mismatch — last receipt claims allow but a prior
	// receipt in the chain blocks the same target. A semantic-aware verifier
	// (one that follows the audit packet spec) MUST surface the inconsistency.
	{
		_, priv := kp()
		ar0 := baseRecord(0, genesisHash, freshTime, "write", "block",
			"https://prod.example.com/v1/data", "https", "POST")
		ar0.Layer = "dlp"
		ar0.Pattern = "api_key_aws"
		ar0.Severity = "critical"
		r0, err := signReceipt(ar0, priv)
		if err != nil {
			return nil, err
		}
		h0, err := receiptHash(r0)
		if err != nil {
			return nil, err
		}
		ar1 := baseRecord(1, h0, freshTime.Add(1*time.Second), "write", "allow",
			"https://prod.example.com/v1/data", "https", "POST")
		// Same target, immediate allow, no policy_hash change — no plausible
		// policy update could justify this in <1s.
		ar1.PolicyHash = ar0.PolicyHash
		r1, err := signReceipt(ar1, priv)
		if err != nil {
			return nil, err
		}
		payload, err := marshalChainJSONL([]Receipt{r0, r1})
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m09-verdict-chain-mismatch",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m09-verdict-chain-mismatch",
				Category:     "malicious",
				InputFormat:  "chain",
				Verdict:      "reject",
				RejectReason: "verdict_chain_mismatch",
				Description:  "Same target blocked then immediately allowed under identical policy_hash. A semantic verifier MUST flag this as a chain-internal contradiction.",
				Notes:        "A purely-syntactic verifier (one that only checks signatures and chain_prev_hash) will accept this. Vendors implementing semantic checks must reject. The audit-packet schema's verifier.verdict surfaces this distinction.",
			},
		})
	}

	// M10. Receipt count mismatch — wrapper claims 5 but payload has 4.
	{
		chain, _, err := chainOf(priv, func(seq uint64, prev string) ActionRecord {
			return baseRecord(seq, prev, freshTime.Add(time.Duration(seq)*time.Second),
				"read", "allow", "https://api.example.com/v1/data", "https", "GET")
		}, 4) // build 4, claim 5
		if err != nil {
			return nil, err
		}
		// Wrap in an envelope.
		var lines []json.RawMessage
		for _, r := range chain {
			b, err := json.Marshal(r)
			if err != nil {
				return nil, err
			}
			lines = append(lines, b)
		}
		wrapped := map[string]any{
			"declared_receipt_count": 5, // lies
			"receipts":               lines,
		}
		payload, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m10-receipt-count-mismatch",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m10-receipt-count-mismatch",
				Category:     "malicious",
				InputFormat:  "chain",
				Verdict:      "reject",
				RejectReason: "receipt_count_mismatch",
				Description:  "Wrapper envelope claims declared_receipt_count=5 but only 4 receipts are present in the body.",
				Notes:        "Mirrors the audit-packet schema's summary.receipt_count vs verifier.receipt_count divergence check. Vendors MUST flag the gap rather than silently using whichever count is smaller.",
			},
		})
	}

	// M11. Signature over altered body — sign one record, ship a different
	// record bytes but the original signature.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		// Tamper the target after signing.
		r.ActionRecord.Target = "https://attacker.example.net/exfil"
		payload, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m11-body-tampered-after-sign",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m11-body-tampered-after-sign",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "body_tampered",
				Description:  "Signature was valid for the original target, but action_record.target has been rewritten post-signing. SHA-256(canonical(action_record)) no longer matches.",
				Notes:        "Verifier MUST recompute the canonical-JSON hash from the current action_record bytes. Caching the hash from an envelope field or trusting the signer is an exploitable shortcut.",
			},
		})
	}

	// M12. Header injection — embedded NUL in agent identifier (principal).
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		ar.Principal = "agent:legit\x00; agent:attacker"
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		payload, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m12-header-injection-null-byte",
			Payload:  payload,
			Expect: Expect{
				FixtureID:    "m12-header-injection-null-byte",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "header_injection",
				Description:  "principal field contains a NUL byte followed by a second agent identifier. Downstream consumers that string-split on common delimiters could be tricked into trusting the second identifier.",
				Notes:        "Verifier MUST reject control bytes (0x00-0x1F except whitespace) in identifier fields. This is a transport-level integrity check, not a signature check.",
			},
		})
	}

	// M13. Duplicate object key — verdict smuggling via parser differential.
	// The receipt is signed normally with verdict="block". The raw bytes are
	// then rewritten to carry a SECOND, EARLIER verdict key with value "allow":
	//   "verdict":"allow", ... "verdict":"block"
	// This is valid JSON (RFC 8259 permits duplicate names but says behaviour
	// is unpredictable). Go/JS/Rust-serde/Python json all resolve last-wins, so
	// a verifier WITHOUT duplicate-key rejection parses verdict="block",
	// recomputes the canonical form, and the signature VERIFIES — it silently
	// ACCEPTS the receipt while a naive display or log layer that reads the
	// first occurrence shows "allow". That display-vs-reality divergence is the
	// attack. A correct verifier MUST reject any duplicate object key (at any
	// nesting depth) at parse time, before signature verification.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "block",
			"https://attacker.example.net/exfil", "https", "POST")
		ar.Layer = "tool_policy"
		ar.Severity = "high"
		r, err := signReceipt(ar, priv)
		if err != nil {
			return nil, err
		}
		good, err := marshalPretty(r)
		if err != nil {
			return nil, err
		}
		// Inject a duplicate `verdict` key inside the action_record, before the
		// real (signed) one. marshalPretty indents action_record fields by four
		// spaces. There is exactly one `verdict` key in the document (the
		// Receipt envelope has none), so a single targeted replacement is safe.
		marker := []byte("\"verdict\": \"block\"")
		dup := []byte("\"verdict\": \"allow\",\n    \"verdict\": \"block\"")
		if !bytes.Contains(good, marker) {
			return nil, fmt.Errorf("m13: verdict marker not found in payload")
		}
		bad := bytes.Replace(good, marker, dup, 1)
		out = append(out, fixture{
			Category: "malicious",
			Name:     "m13-duplicate-key-verdict",
			Payload:  bad,
			Expect: Expect{
				FixtureID:    "m13-duplicate-key-verdict",
				Category:     "malicious",
				InputFormat:  "receipt",
				Verdict:      "reject",
				RejectReason: "duplicate_key",
				Description:  "action_record carries two verdict keys (\"allow\" then the signed \"block\"). Valid JSON, last-wins parsing makes the signature verify, so a verifier without duplicate-key rejection silently accepts while a first-occurrence display layer shows the opposite verdict.",
				Notes:        "Verifier MUST reject duplicate object keys at parse time, at any nesting depth, before signature verification. Use a raw token/pair scan (Go json.Decoder token loop, JS reviver/pair check, serde_json with reject_duplicate, Python object_pairs_hook) — last-wins map insertion hides the duplicate.",
			},
		})
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Edge fixtures.
// ---------------------------------------------------------------------------

func buildEdge() ([]fixture, error) {
	_, priv := kp()
	pubHex := hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	var out []fixture

	// E1. Unicode in agent identifier — accepted, preserved byte-for-byte.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		ar.Principal = "agent:研究員-α"
		ar.Actor = "agent:研究員-α"
		if f, err := makeSingle("e01-unicode-agent-identifier", "edge", priv, pubHex, ar,
			"Unicode (CJK + Greek) in principal and actor fields.",
			"Verifier MUST accept and preserve the bytes. Canonical JSON encodes non-ASCII differently across implementations; either escaped or raw UTF-8 forms are acceptable provided the canonical form is stable.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E2. Maximum argument array — long delegation chain.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		chain := make([]string, 64)
		for i := range chain {
			chain[i] = fmt.Sprintf("policy-rule-%03d", i)
		}
		ar.DelegationChain = chain
		if f, err := makeSingle("e02-maximum-delegation-chain", "edge", priv, pubHex, ar,
			"DelegationChain with 64 entries — exercises canonical-JSON encoder on a long array.",
			"Verifier MUST accept. The cap is enforced at policy-write time, not verification time.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E3. Empty delegation chain — legal.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		ar.DelegationChain = []string{}
		if f, err := makeSingle("e03-empty-delegation-chain", "edge", priv, pubHex, ar,
			"DelegationChain is an empty array — legal at the schema layer (root-policy direct action).",
			"Verifier MUST accept. Empty array MUST encode as [], NOT null. A verifier that demands at least one delegation entry would reject all root-authority actions.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E4. Exact-edge timestamp — receipt at the freshness boundary minus 1s.
	{
		ar := baseRecord(0, genesisHash, edgeTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		if f, err := makeSingle("e04-edge-of-freshness-window", "edge", priv, pubHex, ar,
			"Timestamp sits 1 second inside the corpus max_age window of 1 year.",
			"Verifier MUST accept. Vendors who use an open-interval (>) comparison instead of inclusive (>=) will fire spurious expired rejects on this fixture.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E5. Multi-byte UTF-8 in policy_hash representation — accepted as-is.
	// We emulate this by putting the multi-byte content in pattern (a free-form
	// optional field) since policy_hash remains hex-shaped in this corpus.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "block",
			"https://api.example.com/v1/data", "https", "GET")
		ar.Layer = "dlp"
		ar.Pattern = "patrón-α-€" // multi-byte UTF-8 in the pattern label
		ar.Severity = "medium"
		if f, err := makeSingle("e05-multibyte-utf8-pattern", "edge", priv, pubHex, ar,
			"Multi-byte UTF-8 in the pattern label (free-form field).",
			"Verifier MUST accept. Pattern labels are operator-defined — non-ASCII is legal. Verifiers that try to ASCII-normalize on read will corrupt the canonical bytes and break signature verification on re-serialization.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E6. Nested JSON-RPC in intent — long structured intent string.
	{
		ar := baseRecord(0, genesisHash, freshTime, "write", "allow",
			"https://api.example.com/v1/data", "https", "POST")
		ar.Intent = `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search","arguments":{"query":"weather in San Francisco"}},"id":1}`
		if f, err := makeSingle("e06-nested-jsonrpc-intent", "edge", priv, pubHex, ar,
			"Intent field carries a JSON-RPC envelope as a string (not nested JSON).",
			"Verifier MUST accept. The receipt itself is JSON; the intent value is a string. Verifiers that try to parse intent as nested JSON will violate the type contract — intent is opaque to verification.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E7. Binary blob in pattern via base64 — exercises non-ASCII-but-not-bytes path.
	{
		ar := baseRecord(0, genesisHash, freshTime, "read", "block",
			"https://api.example.com/v1/data", "https", "GET")
		ar.Layer = "dlp"
		// Base64 of 32 random-looking bytes (deterministic content for reproducibility).
		ar.Pattern = "binary:KMjmBnUOzh0Zs9rfd5W8gFNgC1k7vEQowqK/CkjeWvI="
		ar.Severity = "high"
		if f, err := makeSingle("e07-binary-base64-pattern", "edge", priv, pubHex, ar,
			"Pattern carries base64-encoded binary content (e.g., entropy fingerprint).",
			"Verifier MUST accept. Base64 sits inside a string field — the verifier is not required to decode it. Vendors who try to decode-and-revalidate will produce false negatives.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	// E8. Slight future-skew timestamp — within typical clock-skew tolerance.
	{
		ar := baseRecord(0, genesisHash, skewTime, "read", "allow",
			"https://api.example.com/v1/data", "https", "GET")
		if f, err := makeSingle("e08-clock-skew-future-timestamp", "edge", priv, pubHex, ar,
			"Timestamp is 30 seconds in the future relative to the corpus base time.",
			"Verifier MUST accept up to a few minutes of forward skew. Hard-future-rejects break under common NTP drift.",
		); err != nil {
			return nil, err
		} else {
			out = append(out, f)
		}
	}

	return out, nil
}

// ---------------------------------------------------------------------------
// Marshal / write helpers.
// ---------------------------------------------------------------------------

// marshalPretty serializes a receipt as 2-space-indented JSON with a trailing newline.
// The pretty form is for human review; verifier behaviour MUST be agnostic to
// whitespace.
func marshalPretty(r Receipt) ([]byte, error) {
	buf, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(buf, '\n'), nil
}

// marshalChainJSONL serializes a slice of receipts as one compact JSON object
// per line. This corpus uses the raw form so verifiers in non-Go languages do
// not need to model any product-specific recorder envelope.
func marshalChainJSONL(rs []Receipt) ([]byte, error) {
	var buf bytes.Buffer
	for _, r := range rs {
		b, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// writeAll writes every fixture under outDir/{category}/{name}.json and
// outDir/{category}/{name}.expect.json. Files are written with 0o600 perms.
func writeAll(outDir string, fixtures []fixture) error {
	for _, f := range fixtures {
		dir := filepath.Join(outDir, f.Category)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		extJSON := ".json"
		if f.Expect.InputFormat == "chain" {
			extJSON = ".jsonl"
		}
		payloadPath := filepath.Join(dir, f.Name+extJSON)
		if err := os.WriteFile(payloadPath, f.Payload, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", payloadPath, err)
		}
		expectPath := filepath.Join(dir, f.Name+".expect.json")
		expectBuf, err := json.MarshalIndent(f.Expect, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal expect %s: %w", f.Name, err)
		}
		expectBuf = append(expectBuf, '\n')
		if err := os.WriteFile(expectPath, expectBuf, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", expectPath, err)
		}
	}
	return nil
}

// verifyAll re-derives fixture bytes in memory and diffs against committed
// files. Used in CI to catch accidental hand-edits.
func verifyAll(outDir string, fixtures []fixture) error {
	var drift []string
	for _, f := range fixtures {
		dir := filepath.Join(outDir, f.Category)
		extJSON := ".json"
		if f.Expect.InputFormat == "chain" {
			extJSON = ".jsonl"
		}
		payloadPath := filepath.Join(dir, f.Name+extJSON)
		got, err := os.ReadFile(filepath.Clean(payloadPath))
		if err != nil {
			drift = append(drift, fmt.Sprintf("%s: %v", payloadPath, err))
			continue
		}
		if !bytes.Equal(got, f.Payload) {
			drift = append(drift, fmt.Sprintf("%s: payload bytes differ", payloadPath))
		}
		expectPath := filepath.Join(dir, f.Name+".expect.json")
		gotExpect, err := os.ReadFile(filepath.Clean(expectPath))
		if err != nil {
			drift = append(drift, fmt.Sprintf("%s: %v", expectPath, err))
			continue
		}
		wantExpect, err := json.MarshalIndent(f.Expect, "", "  ")
		if err != nil {
			return err
		}
		wantExpect = append(wantExpect, '\n')
		if !bytes.Equal(gotExpect, wantExpect) {
			drift = append(drift, fmt.Sprintf("%s: expect bytes differ", expectPath))
		}
	}
	if len(drift) > 0 {
		return fmt.Errorf("drift detected:\n%s", strings.Join(drift, "\n"))
	}
	return nil
}
