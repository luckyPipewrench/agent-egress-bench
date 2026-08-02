.PHONY: stats stats-update check-stats cases-manifest

# Regenerate cases/MANIFEST.txt after adding or removing a case. The manifest
# pins the logical corpus so a case cannot leave it without a visible diff;
# runner/corpus_manifest_test.go asserts the two agree in both directions.
cases-manifest:
	cd runner && go test . -run 'TestCorpus' -update-manifest

# Print canonical statistics from the runner's loaded corpus. Unlike the
# manifest, this reports category and verdict metadata from each loaded case.
stats:
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
check-stats:
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
