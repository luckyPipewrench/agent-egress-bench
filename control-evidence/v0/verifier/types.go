package verifier

const (
	OutcomeValid                = "valid"
	OutcomeInvalid              = "invalid"
	OutcomeStale                = "stale"
	OutcomeScopeMismatch        = "scope-mismatch"
	OutcomeInsufficientEvidence = "insufficient-evidence"
	OutcomeUnverifiable         = "unverifiable"

	outcomeInvalid              = OutcomeInvalid
	outcomeStale                = OutcomeStale
	outcomeScopeMismatch        = OutcomeScopeMismatch
	outcomeInsufficientEvidence = OutcomeInsufficientEvidence
	outcomeUnverifiable         = OutcomeUnverifiable

	typeRequirement = "application/vnd.agent-egress-bench.control-evidence-requirement.v0+json"
	typeEnvelope    = "application/vnd.agent-egress-bench.control-evidence-envelope.v0+json"
	typeClock       = "application/vnd.agent-egress-bench.control-evidence-clock-evidence.v0+json"
	typeObserver    = "application/vnd.agent-egress-bench.control-evidence-observer-evidence.v0+json"
)

type Result struct {
	Profile           string `json:"profile"`
	Outcome           string `json:"outcome"`
	Reason            string `json:"reason,omitempty"`
	NonceStatus       string `json:"nonce_status"`
	RequirementSHA256 string `json:"requirement_sha256,omitempty"`
	RunID             string `json:"run_id,omitempty"`
}

type verifierContext struct {
	Profile                  string `json:"profile"`
	ReferenceNow             string `json:"reference_now"`
	RequirementPayloadSHA256 string `json:"requirement_payload_sha256"`
	TrustPolicy              struct {
		ID     string `json:"id"`
		SHA256 string `json:"sha256"`
	} `json:"trust_policy"`
	Corpus struct {
		Version        string `json:"version"`
		SHA256         string `json:"sha256"`
		ManifestSHA256 string `json:"manifest_sha256"`
		ScoringVersion string `json:"scoring_version"`
	} `json:"corpus"`
	TrustedKeys struct {
		Buyer                   string `json:"buyer"`
		VendorRunner            string `json:"vendor_runner"`
		Observer                string `json:"observer"`
		CustomerClock           string `json:"customer_clock"`
		IndependentWitnessClock string `json:"independent_witness_clock"`
	} `json:"trusted_keys"`
	TokenMaterial  contextMaterial `json:"token_material"`
	HealthMaterial contextMaterial `json:"health_control_material"`
	NonceLedger    []nonceEntry    `json:"nonce_ledger"`
}

type contextMaterial struct {
	Mode         string `json:"mode"`
	Profile      string `json:"profile"`
	KeyOrInputID string `json:"key_or_input_id"`
	RootInput    string `json:"root_input"`
	AESKeyBase64 string `json:"aes_key_base64"`
}

type nonceEntry struct {
	RequirementSignerKeyID string `json:"requirement_signer_key_id"`
	RequirementID          string `json:"requirement_id"`
	ChallengeNonce         string `json:"challenge_nonce"`
	EnvelopePayloadSHA256  string `json:"envelope_payload_sha256"`
}

type dsseEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []dsseSignature `json:"signatures"`
}

type dsseSignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type requirement struct {
	Profile                  string               `json:"profile"`
	RequirementID            string               `json:"requirement_id"`
	ChallengeNonce           string               `json:"challenge_nonce"`
	IssuedAt                 string               `json:"issued_at"`
	NotBefore                string               `json:"not_before"`
	ExpiresAt                string               `json:"expires_at"`
	BuyerID                  string               `json:"buyer_id"`
	DeploymentArchetype      string               `json:"deployment_archetype"`
	EnforcementPoint         enforcementPoint     `json:"enforcement_point"`
	RequiredTransports       []string             `json:"required_transports"`
	RequiredCaseIDs          []string             `json:"required_case_ids"`
	RequiredPositiveCanaries []string             `json:"required_positive_canaries"`
	RequiredNegativeCanaries []string             `json:"required_negative_canaries"`
	ApprovedObserver         approvedObserver     `json:"approved_observer"`
	ApprovedToolProfile      digestRef            `json:"approved_tool_profile"`
	ApprovedPolicy           digestRef            `json:"approved_policy"`
	TokenMaterial            materialRequirement  `json:"token_material"`
	HealthMaterial           materialRequirement  `json:"health_control_material"`
	MinimumTrialsPerCase     int                  `json:"minimum_trials_per_case"`
	AllowedNotApplicable     []allowedNA          `json:"allowed_not_applicable"`
	MaximumErrors            int                  `json:"maximum_errors"`
	MaximumAgeSeconds        int                  `json:"maximum_age_seconds"`
	AllowedFutureSkewSeconds int                  `json:"allowed_future_skew_seconds"`
	RequiredArtifacts        []string             `json:"required_artifacts"`
	TrustPolicyID            string               `json:"trust_policy_id"`
	TrustPolicySHA256        string               `json:"trust_policy_sha256"`
	RequiredSignerPolicy     signerIdentity       `json:"required_signer_policy"`
	AuthorizedRunSigners     []signerIdentity     `json:"authorized_run_signers"`
	ApprovedRunner           approvedRunner       `json:"approved_runner"`
	ApprovedAdapter          approvedAdapter      `json:"approved_adapter"`
	ApprovedToolIdentity     approvedToolIdentity `json:"approved_tool_identity"`
	ApprovedClockEvidence    *approvedClock       `json:"approved_clock_evidence,omitempty"`
}

type enforcementPoint struct {
	Kind string `json:"kind"`
	Note string `json:"note"`
}

type digestRef struct {
	SHA256 string `json:"sha256"`
}

type approvedObserver struct {
	Protocol                            string `json:"protocol"`
	Version                             string `json:"version"`
	TargetIdentity                      string `json:"target_identity"`
	KeyID                               string `json:"key_id"`
	MaximumHealthControlIntervalSeconds int    `json:"maximum_health_control_interval_seconds"`
	MaximumLivenessGapSeconds           int    `json:"maximum_liveness_gap_seconds"`
}

type materialRequirement struct {
	Mode           string `json:"mode"`
	Profile        string `json:"profile"`
	KeyOrInputID   string `json:"key_or_input_id"`
	ArtifactSHA256 string `json:"artifact_sha256,omitempty"`
}

type allowedNA struct {
	CaseID string `json:"case_id"`
	Reason string `json:"reason"`
}

type signerIdentity struct {
	KeyID       string `json:"key_id"`
	AuthorityID string `json:"authority_id"`
	Role        string `json:"role"`
}

type approvedRunner struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
}

type approvedAdapter struct {
	Protocol string `json:"protocol"`
	Version  string `json:"version"`
	SHA256   string `json:"sha256"`
}

type approvedToolIdentity struct {
	Kind     string `json:"kind"`
	Expected string `json:"expected"`
}

type approvedClock struct {
	KeyID                string `json:"key_id"`
	AuthorityID          string `json:"authority_id"`
	Role                 string `json:"role"`
	Profile              string `json:"profile"`
	VerifierSHA256       string `json:"verifier_sha256"`
	PolicySHA256         string `json:"policy_sha256"`
	PermittedSkewSeconds int    `json:"permitted_skew_seconds"`
}

type runEnvelope struct {
	Profile           string `json:"profile"`
	RequirementSHA256 string `json:"requirement_sha256"`
	ChallengeNonce    string `json:"challenge_nonce"`
	RunID             string `json:"run_id"`
	StartedAt         string `json:"started_at"`
	FinishedAt        string `json:"finished_at"`
	ExpiresAt         string `json:"expires_at"`
	Runner            struct {
		Version        string `json:"version"`
		SourceRevision string `json:"source_revision"`
		ExecutionMode  string `json:"execution_mode"`
		BinarySHA256   string `json:"binary_sha256"`
	} `json:"runner"`
	Corpus struct {
		Version        string `json:"version"`
		CorpusSHA256   string `json:"corpus_sha256"`
		ManifestSHA256 string `json:"manifest_sha256"`
		ScoringVersion string `json:"scoring_version"`
	} `json:"corpus"`
	Tool struct {
		Product  string `json:"product"`
		Version  string `json:"version"`
		Identity struct {
			Kind  string `json:"kind"`
			Value string `json:"value"`
		} `json:"identity"`
	} `json:"tool"`
	Policy struct {
		SHA256 string `json:"sha256"`
	} `json:"policy"`
	Adapter struct {
		Protocol string `json:"protocol"`
		Version  string `json:"version"`
		SHA256   string `json:"sha256"`
		Owner    string `json:"owner"`
	} `json:"adapter"`
	Scope struct {
		DeploymentArchetype string   `json:"deployment_archetype"`
		Transports          []string `json:"transports"`
		CaseIDsSHA256       string   `json:"case_ids_sha256"`
		EnforcementPoint    string   `json:"enforcement_point"`
	} `json:"scope"`
	Artifacts struct {
		ManifestSHA256 string `json:"manifest_sha256"`
		Count          int    `json:"count"`
	} `json:"artifacts"`
	Observations struct {
		SHA256           string `json:"sha256"`
		RowCount         int    `json:"row_count"`
		ObserverProtocol string `json:"observer_protocol"`
		ObserverVersion  string `json:"observer_version"`
	} `json:"observations"`
	FreshnessBasis   string         `json:"freshness_basis"`
	ClockEvidenceRef string         `json:"clock_evidence_ref,omitempty"`
	Signer           signerIdentity `json:"signer"`
}

type manifest struct {
	Profile                string          `json:"profile"`
	Entries                []manifestEntry `json:"entries"`
	TotalUncompressedBytes int64           `json:"total_uncompressed_bytes"`
}

type manifestEntry struct {
	Role       string `json:"role"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	MediaType  string `json:"media_type"`
	ByteLength int64  `json:"byte_length"`
}

type outcomes struct {
	Profile           string       `json:"profile"`
	RequirementSHA256 string       `json:"requirement_sha256"`
	RunID             string       `json:"run_id"`
	Rows              []outcomeRow `json:"rows"`
}

type outcomeRow struct {
	CaseID              string       `json:"case_id"`
	TrialIndex          int          `json:"trial_index"`
	Transport           string       `json:"transport"`
	ExpectedVerdict     string       `json:"expected_verdict"`
	ActualVerdict       string       `json:"actual_verdict"`
	Outcome             string       `json:"outcome"`
	AdapterObservation  string       `json:"adapter_observation"`
	TargetObservation   string       `json:"target_observation"`
	EvidenceSHA256      []string     `json:"evidence_sha256"`
	ScoringFacts        scoringFacts `json:"scoring_facts"`
	NotApplicableReason string       `json:"not_applicable_reason,omitempty"`
	ErrorReason         string       `json:"error_reason,omitempty"`
	Canaries            []canary     `json:"canaries"`
}

type scoringFacts struct {
	BudgetTiming       string `json:"budget_timing"`
	Classification     string `json:"classification"`
	StructuredEvidence string `json:"structured_evidence"`
}

type canary struct {
	CanaryID               string `json:"canary_id"`
	Polarity               string `json:"polarity"`
	CanaryCommitmentSHA256 string `json:"canary_commitment_sha256"`
	ExpectedPredicate      string `json:"expected_predicate"`
	ObserverProtocol       string `json:"observer_protocol"`
	ObserverVersion        string `json:"observer_version"`
	TargetIdentity         string `json:"target_identity"`
	State                  string `json:"state"`
	ObservationRef         string `json:"observation_ref,omitempty"`
	WindowStart            string `json:"window_start,omitempty"`
	WindowEnd              string `json:"window_end,omitempty"`
	ObserverKeyID          string `json:"observer_key_id,omitempty"`
	PrecedingHealthRef     string `json:"preceding_health_ref,omitempty"`
	FollowingHealthRef     string `json:"following_health_ref,omitempty"`
	LivenessRecordRef      string `json:"liveness_record_ref,omitempty"`
}

type clockEvidence struct {
	Profile            string        `json:"profile"`
	ObservationKind    string        `json:"observation_kind"`
	RequirementSHA256  string        `json:"requirement_sha256"`
	RunID              string        `json:"run_id"`
	ObservationsSHA256 string        `json:"observations_sha256"`
	StartedAt          string        `json:"started_at"`
	FinishedAt         string        `json:"finished_at"`
	ObservedAt         string        `json:"observed_at"`
	Attestor           clockAttestor `json:"attestor"`
}

type clockAttestor struct {
	KeyID          string `json:"key_id"`
	AuthorityID    string `json:"authority_id"`
	Role           string `json:"role"`
	Profile        string `json:"profile"`
	VerifierSHA256 string `json:"verifier_sha256"`
	PolicySHA256   string `json:"policy_sha256"`
}

type observerEvidence struct {
	Profile                string `json:"profile"`
	Kind                   string `json:"kind"`
	RequirementSHA256      string `json:"requirement_sha256"`
	RunID                  string `json:"run_id"`
	CaseID                 string `json:"case_id"`
	TrialIndex             int    `json:"trial_index"`
	CanaryID               string `json:"canary_id"`
	CanaryCommitmentSHA256 string `json:"canary_commitment_sha256"`
	Transport              string `json:"transport"`
	TargetIdentity         string `json:"target_identity"`
	Observer               struct {
		Protocol string `json:"protocol"`
		Version  string `json:"version"`
		KeyID    string `json:"key_id"`
	} `json:"observer"`
	ObservedAt                    string `json:"observed_at,omitempty"`
	ControlID                     string `json:"control_id,omitempty"`
	HealthControlCommitmentSHA256 string `json:"health_control_commitment_sha256,omitempty"`
	HealthState                   string `json:"health_state,omitempty"`
	ObservationState              string `json:"observation_state,omitempty"`
	Liveness                      []struct {
		Sequence    int    `json:"sequence"`
		ObservedAt  string `json:"observed_at"`
		HealthState string `json:"health_state"`
	} `json:"liveness,omitempty"`
}

type decodedMaterial struct {
	Profile      string `json:"profile"`
	KeyOrInputID string `json:"key_or_input_id"`
	Tokens       []struct {
		CanaryID string `json:"canary_id"`
		Input    string `json:"input"`
	} `json:"tokens,omitempty"`
	Controls []struct {
		ControlID string `json:"control_id"`
		Input     string `json:"input"`
	} `json:"controls,omitempty"`
}
