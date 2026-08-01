.PHONY: stats check-stats

# Print canonical stats from test cases.
# Counts are LOGICAL cases: single-file JSON cases plus each multi-file
# mcp-drift directory as one case. Verdicts include the mcp-drift case.yaml.
stats:
	@echo "# agent-egress-bench stats"
	@single=$$(find cases -name '*.json' -not -path 'cases/mcp-drift/*' | wc -l); \
	drift=$$(find cases/mcp-drift -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l); \
	echo "cases_total: $$((single + drift))"
	@echo "categories: $$(find cases -mindepth 1 -maxdepth 1 -type d | wc -l)"
	@jblk=$$(find cases -name '*.json' -not -path 'cases/mcp-drift/*' -exec grep -l '"expected_verdict"[[:space:]]*:[[:space:]]*"block"' {} \; | wc -l); \
	dblk=$$(grep -lE 'expected_verdict:[[:space:]]*block' cases/mcp-drift/*/case.yaml 2>/dev/null | wc -l); \
	echo "block: $$((jblk + dblk))"
	@jaln=$$(find cases -name '*.json' -not -path 'cases/mcp-drift/*' -exec grep -l '"expected_verdict"[[:space:]]*:[[:space:]]*"allow"' {} \; | wc -l); \
	daln=$$(grep -lE 'expected_verdict:[[:space:]]*allow' cases/mcp-drift/*/case.yaml 2>/dev/null | wc -l); \
	echo "allow: $$((jaln + daln))"
	@echo "warn: $$(grep -lE 'expected_verdict:[[:space:]]*warn' cases/mcp-drift/*/case.yaml 2>/dev/null | wc -l)"
	@set -- cases/*/; \
	if [ "$$1" = 'cases/*/' ]; then exit 0; fi; \
	for dir in "$$@"; do \
		name=$$(basename "$$dir"); \
		if [ "$$name" = "mcp-drift" ]; then \
			count=$$(find "$$dir" -mindepth 1 -maxdepth 1 -type d | wc -l); \
		else \
			count=$$(find "$$dir" -name '*.json' | wc -l); \
		fi; \
		echo "  $$name: $$count"; \
	done

# Fail when README.md's advertised case count no longer matches the corpus.
# The count is LOGICAL: one JSON outside cases/mcp-drift, or one
# cases/mcp-drift/<dir>. Counting files instead inflates it, which is how the
# advertised number has drifted before.
check-stats:
	@single=$$(find cases -name '*.json' -not -path 'cases/mcp-drift/*' | wc -l); \
	drift=$$(find cases/mcp-drift -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l); \
	actual=$$((single + drift)); \
	stated=$$(grep -oE '[0-9]+ logical cases' README.md | head -1 | grep -oE '^[0-9]+'); \
	if [ -z "$$stated" ]; then \
		echo "check-stats: FAIL - no 'N logical cases' phrase found in README.md"; \
		exit 1; \
	fi; \
	if [ "$$stated" != "$$actual" ]; then \
		echo "check-stats: FAIL - README.md advertises $$stated logical cases, corpus has $$actual"; \
		echo "  a case = one JSON outside cases/mcp-drift, or one cases/mcp-drift/<dir>"; \
		echo "  fix: change README.md to $$actual, or run 'make stats' to see the breakdown"; \
		exit 1; \
	fi; \
	echo "check-stats: OK ($$actual logical cases, README agrees)"
