.PHONY: stats

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
	echo "malicious: $$((jblk + dblk))"
	@jaln=$$(find cases -name '*.json' -not -path 'cases/mcp-drift/*' -exec grep -l '"expected_verdict"[[:space:]]*:[[:space:]]*"allow"' {} \; | wc -l); \
	daln=$$(grep -lE 'expected_verdict:[[:space:]]*allow' cases/mcp-drift/*/case.yaml 2>/dev/null | wc -l); \
	echo "benign: $$((jaln + daln))"
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
