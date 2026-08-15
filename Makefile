.PHONY: preflight check-case-immutability check-frozen-schema-immutability check-schema-catalog check-schema-copies check-docs check-contracts check-public-contracts check-claim-language check-readme-categories check-capability-registry-history check-scorecard-workflow test-label-boundary test-runner-parity stats stats-update check-stats cases-manifest check-gauntlet-site test-capability-registry test-validate test-runner test-receipt-generator test-control-evidence-vectors test-control-evidence-verifier test-control-evidence-v1-verifier test-control-evidence-g2-authentication test-pipelock-example test-release-build test-release-workflow test-release-snapshot release-snapshot validate-cases validate

TMPDIR := $(HOME)/.cache/pipelock-tmp
GOCACHE := $(HOME)/.cache/go-build
export TMPDIR GOCACHE

# Default fixture for local validator/renderer contract tests. A workflow that
# generates a real artifact must override this with that exact output path.
GAUNTLET_SCOPE_ARTIFACT ?= gauntlet-site/testdata/complete-provenance-artifact.json
AEB_IMMUTABILITY_BASE ?= origin/main

# Pre-push gate. Race coverage remains here because the Go modules exercised
# below complete comfortably inside the edit-to-push budget and it catches real
# shared-state defects that ordinary go test would miss. It requires the Go
# toolchain needed by runner/go.mod (currently Go 1.25 or newer).
preflight: check-contracts check-schema-catalog check-public-contracts check-case-immutability check-frozen-schema-immutability check-schema-copies check-docs test-capability-registry check-capability-registry-history check-scorecard-workflow test-label-boundary test-runner-parity test-validate validate-cases test-runner test-receipt-generator test-control-evidence-vectors test-control-evidence-verifier test-control-evidence-v1-verifier test-control-evidence-g2-authentication test-pipelock-example test-release-build test-release-workflow check-stats check-gauntlet-site check-claim-language check-readme-categories

check-scorecard-workflow:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/scorecard_workflow_test.py
# Keep the machine-readable compatibility inventory tied to the schemas,
# source constants, and frozen public records it describes. The checker
# rejects missing and empty inputs before it compares any values, so a failed
# producer or an empty record tree cannot turn this into a false green.
check-contracts:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_contracts_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_contracts.py

# The discovery document is generated from the canonical schema files. It pins
# every versioned schema's resolving identifier and current bytes without
# making a second hand-maintained schema inventory.
check-schema-catalog:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_schema_catalog_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_schema_catalog.py

# Keep the human tables, machine-readable cross-field contracts, JSON Schemas,
# scorer, and validator on one active definition.
check-public-contracts:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_public_contracts_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public_contracts.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts.build_gauntlet_provenance_test.ProvenanceBuilderTest.test_active_result_score_enforces_budget_timing
	@cd validate && go test -count=1 -run '^TestPublic' .
	@cd runner && go test -count=1 -run '^TestPublic' .

# Case bytes are immutable once their ID reaches the merge base. New IDs and
# their MANIFEST.txt / STATS.md updates remain allowed. A documented maintainer
# repair may set AEB_CASE_IMMUTABILITY_REPAIR and
# AEB_CASE_IMMUTABILITY_REASON; the gate prints OVERRIDE ACTIVE when it uses
# that escape hatch so CI logs make the exceptional rewrite reviewable.
check-case-immutability:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_case_immutability_test.py
	@base="$$(git merge-base "$(AEB_IMMUTABILITY_BASE)" HEAD 2>/dev/null)"; \
	if [ -z "$$base" ]; then \
		echo "check-case-immutability: FAIL - cannot resolve a merge base with $(AEB_IMMUTABILITY_BASE); fetch that ref first" >&2; \
		exit 1; \
	fi; \
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_case_immutability.py --base "$$base"

# Frozen schemas are immutable, byte for byte, with no permitted transition.
# A reformat or key reorder that leaves the parsed document identical still
# fails, because a consumer pinning a digest sees a different document.
# Changing a frozen contract means publishing a new version.
check-frozen-schema-immutability:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_frozen_schema_immutability_test.py
	@base="$$(git merge-base "$(AEB_IMMUTABILITY_BASE)" HEAD 2>/dev/null)"; \
	if [ -z "$$base" ]; then \
		echo "check-frozen-schema-immutability: FAIL - cannot resolve a merge base with $(AEB_IMMUTABILITY_BASE); fetch that ref first" >&2; \
		exit 1; \
	fi; \
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_frozen_schema_immutability.py --base "$$base"

# Keep contract ownership links live and prevent deleted scoring documents from
# becoming shadow authorities again. Missing and empty inputs fail the scan.
check-docs:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_docs_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_docs.py

# Independent verifier modules embed governed schema copies. Missing, empty,
# extra, symlinked, or byte-different copies fail before verifier tests.
check-schema-copies:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_schema_copies_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_schema_copies.py

test-capability-registry:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd capability-registry && go test -race -count=1 ./...

check-capability-registry-history:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/validate_capability_registry_history_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_capability_registry_history.py --base "$$(git merge-base origin/main HEAD)"

test-label-boundary:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd runner && go test -count=1 -run '^(TestLabelBoundary|TestClaimsDoNotChangeMeasurement)' .

test-runner-parity:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/runner_parity_test.py

# Reject documentation that makes a claim the method cannot support, and keep
# docs/RESULTS-USE.md defining the assurance labels and the adverse-result
# permission it grants.
check-claim-language:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_claim_language_test.py
	@python3 scripts/check_claim_language.py

check-readme-categories:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_readme_categories_test.py
	@python3 scripts/check_readme_categories.py --repo-root .

test-validate:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd validate && go test -race -count=1 ./...

# `validate` is an alias for validate-cases. It must stay .PHONY: a directory
# named validate/ holds the validator source, so without the .PHONY entry Make
# considers the target already satisfied and exits 0 having run nothing. A gate
# that always passes is worse than no gate, because callers trust it.
validate: validate-cases

validate-cases:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@bin="$(TMPDIR)/aeb-validate"; trap 'rm -f "$$bin"' EXIT; \
	(cd validate && go build -o "$$bin" .); \
	"$$bin" cases cases

test-runner:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd runner && go test -race -count=1 ./...

test-receipt-generator:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd receipts/v0/conformance/_generator && go test -race -count=1 ./...

test-control-evidence-vectors:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd control-evidence/v0/conformance/_generator && go test -race -count=1 ./... && go run . --verify

test-control-evidence-verifier:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd control-evidence/v0/verifier && go test -race -count=1 ./...

test-control-evidence-v1-verifier:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd control-evidence/v1/conformance/_generator && go test -race -count=1 ./... && go run . --verify
	@cd control-evidence/v1/verifier && go test -race -count=1 ./...

test-control-evidence-g2-authentication:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd control-evidence/g2/authentication && go test -race -count=1 ./...

test-pipelock-example:
	@sh examples/pipelock/mcp-stdio-upstream-bridge_test.sh

# Regenerate cases/MANIFEST.txt after adding or removing a case. The manifest
# pins the logical corpus so a case cannot leave it without a visible diff;
# runner/corpus_manifest_test.go asserts the two agree in both directions.
cases-manifest:
	cd runner && go test . -run 'TestCorpus' -update-manifest

# Print canonical statistics from the runner's loaded corpus. Unlike the
# manifest, this reports category and verdict metadata from each loaded case.
stats:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd runner && go run . --stats --cases ../cases

# Refresh the committed, reader-facing stats snapshot from the runner loaders.
# Generate into a temporary file and replace the snapshot only after the runner
# succeeds with output. Redirecting straight into cases/STATS.md truncates it
# when the shell opens it, so a runner that then failed left an EMPTY snapshot.
stats-update:
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	if ! (cd runner && go run . --stats --cases ../cases) > "$$tmp"; then \
		echo "stats-update: FAIL - the runner could not load the corpus"; \
		echo "  cases/STATS.md is unchanged; repair the corpus, then run 'make stats-update'"; \
		exit 1; \
	fi; \
	if ! test -s "$$tmp"; then \
		echo "stats-update: FAIL - the runner produced no output"; \
		echo "  cases/STATS.md is unchanged"; \
		exit 1; \
	fi; \
	cp "$$tmp" cases/STATS.md; \
	echo "stats-update: OK (cases/STATS.md refreshed from the runner-loaded corpus)"

# Fail when the reader-facing stats snapshot no longer matches the corpus that
# the runner actually loads. This compares the whole generated report, not a
# wording-dependent claim embedded in prose.
#
# The runner's exit status is checked BEFORE the comparison. Piping it straight
# into cmp reported the pipeline's last status, so a failing runner produced no
# output, and an empty snapshot compared equal to it and passed.
check-stats: check-gauntlet-site
	@test -f cases/STATS.md || { echo "check-stats: FAIL - missing cases/STATS.md; run 'make stats-update'"; exit 1; }
	@test -s cases/STATS.md || { echo "check-stats: FAIL - cases/STATS.md is empty; run 'make stats-update'"; exit 1; }
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	if ! (cd runner && go run . --stats --cases ../cases) > "$$tmp"; then \
		echo "check-stats: FAIL - the runner could not load the corpus"; \
		echo "  fix: repair the corpus, then run 'make stats-update'"; \
		exit 1; \
	fi; \
	if ! test -s "$$tmp"; then \
		echo "check-stats: FAIL - the runner produced no output"; \
		exit 1; \
	fi; \
	if ! cmp -s "$$tmp" cases/STATS.md; then \
		echo "check-stats: FAIL - cases/STATS.md is stale or malformed"; \
		echo "  fix: run 'make stats-update', review cases/STATS.md, then run 'make check-stats'"; \
		exit 1; \
	fi; \
	echo "check-stats: OK (cases/STATS.md matches the runner-loaded corpus)"

# Exercise provenance-artifact validation and the renderer contract. The
# fixture is the local-test default; callers can and must pass the generated
# artifact path when validating an actual scoring run.
check-gauntlet-site:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/capability_registry_publication_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/validate_gauntlet_scope_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/evaluate_gauntlet_candidate_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/build_gauntlet_provenance_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/continuous_gauntlet_workflow_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/render_gauntlet_run_summary_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/promote_gauntlet_candidate_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/promote_gauntlet_workflow_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/gauntlet_site_index_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/validate_gauntlet_records_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_gauntlet_records.py
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/validate_pipelock_result_inventory_test.py
	@PYTHONDONTWRITEBYTECODE=1 python3 scripts/validate_pipelock_result_inventory.py
	@node gauntlet-site/scope-render_test.js
	@node gauntlet-site/latest-result_test.js
	@test -f "$(GAUNTLET_SCOPE_ARTIFACT)" || { echo "check-gauntlet-site: FAIL - missing provenance artifact: $(GAUNTLET_SCOPE_ARTIFACT)"; exit 1; }
	@python3 scripts/validate_gauntlet_scope.py "$(GAUNTLET_SCOPE_ARTIFACT)"

# The release contract tests break source declarations and downloaded artifacts
# on purpose. They prove the release guards stop an inconsistent package.
test-release-build:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/release_build_test.py

test-release-workflow:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/release_workflow_test.py scripts/release_publish_test.py

# This integration test is deliberately separate from preflight because it
# requires the pinned GoReleaser binary installed by the validation workflow.
test-release-snapshot:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/release_snapshot_test.py

# Snapshot mode builds the exact archive layout without creating a tag or a
# GitHub release. Release assets are written to dist/release. goreleaser must
# already be installed and pinned by the caller.
release-snapshot:
	@./scripts/release-build.sh --tag snapshot --commit "$$(git rev-parse HEAD)" --snapshot
