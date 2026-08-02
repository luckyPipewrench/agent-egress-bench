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
stats-update:
	@cd runner && go run . --stats --cases ../cases > ../cases/STATS.md

# Fail when the reader-facing stats snapshot no longer matches the corpus that
# the runner actually loads. This compares the whole generated report, not a
# wording-dependent claim embedded in prose.
check-stats:
	@test -f cases/STATS.md || { echo "check-stats: FAIL - missing cases/STATS.md; run 'make stats-update'"; exit 1; }
	@if ! (cd runner && go run . --stats --cases ../cases | cmp -s - ../cases/STATS.md); then \
		echo "check-stats: FAIL - cases/STATS.md is stale or malformed"; \
		echo "  fix: run 'make stats-update', review cases/STATS.md, then run 'make check-stats'"; \
		exit 1; \
	fi; \
	echo "check-stats: OK (cases/STATS.md matches the runner-loaded corpus)"
