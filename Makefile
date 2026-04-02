.PHONY: stats

# Print canonical stats from test cases
stats:
	@echo "# agent-egress-bench stats"
	@echo "cases_total: $$(find cases -name '*.json' | wc -l)"
	@echo "categories: $$(find cases -mindepth 1 -maxdepth 1 -type d | wc -l)"
	@echo "malicious: $$(find cases -name '*.json' -exec grep -l '"expect": "block"' {} \; | wc -l)"
	@echo "benign: $$(find cases -name '*.json' -exec grep -l '"expect": "allow"' {} \; | wc -l)"
	@for dir in cases/*/; do \
		name=$$(basename "$$dir"); \
		count=$$(find "$$dir" -name '*.json' | wc -l); \
		echo "  $$name: $$count"; \
	done
