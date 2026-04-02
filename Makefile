.PHONY: stats

# Print canonical stats from test cases
stats:
	@echo "# agent-egress-bench stats"
	@echo "cases_total: $$(find cases -name '*.json' | wc -l)"
	@echo "categories: $$(find cases -mindepth 1 -maxdepth 1 -type d | wc -l)"
	@echo "malicious: $$(find cases -name '*.json' -exec grep -l '"expected_verdict"[[:space:]]*:[[:space:]]*"block"' {} \; | wc -l)"
	@echo "benign: $$(find cases -name '*.json' -exec grep -l '"expected_verdict"[[:space:]]*:[[:space:]]*"allow"' {} \; | wc -l)"
	@set -- cases/*/; \
	if [ "$$1" = 'cases/*/' ]; then exit 0; fi; \
	for dir in "$$@"; do \
		name=$$(basename "$$dir"); \
		count=$$(find "$$dir" -name '*.json' | wc -l); \
		echo "  $$name: $$count"; \
	done
