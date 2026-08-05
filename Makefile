.PHONY: preflight check-claim-language stats stats-update check-stats cases-manifest check-gauntlet-site test-validate test-runner test-receipt-generator test-control-evidence-vectors test-control-evidence-verifier test-control-evidence-g2-authentication test-pipelock-example validate-cases

TMPDIR := $(HOME)/.cache/pipelock-tmp
GOCACHE := $(HOME)/.cache/go-build
export TMPDIR GOCACHE

# Default fixture for local validator/renderer contract tests. A workflow that
# generates a real artifact must override this with that exact output path.
GAUNTLET_SCOPE_ARTIFACT ?= gauntlet-site/testdata/complete-provenance-artifact.json

# Pre-push gate. Race coverage remains here because the Go modules exercised
# below complete comfortably inside the edit-to-push budget and it catches real
# shared-state defects that ordinary go test would miss. It requires the Go
# toolchain needed by runner/go.mod (currently Go 1.25 or newer).
preflight: test-validate validate-cases test-runner test-receipt-generator test-control-evidence-vectors test-control-evidence-verifier test-control-evidence-g2-authentication test-pipelock-example check-stats check-gauntlet-site check-claim-language

# Reject documentation that makes a claim the method cannot support, and keep
# docs/RESULTS-USE.md defining the assurance labels and the adverse-result
# permission it grants.
check-claim-language:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest scripts/check_claim_language_test.py
	@python3 scripts/check_claim_language.py

test-validate:
	@mkdir -p "$(TMPDIR)" "$(GOCACHE)"
	@cd validate && go test -race -count=1 ./...

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
	@node gauntlet-site/scope-render_test.js
	@node gauntlet-site/latest-result_test.js
	@test -f "$(GAUNTLET_SCOPE_ARTIFACT)" || { echo "check-gauntlet-site: FAIL - missing provenance artifact: $(GAUNTLET_SCOPE_ARTIFACT)"; exit 1; }
	@python3 scripts/validate_gauntlet_scope.py "$(GAUNTLET_SCOPE_ARTIFACT)"
