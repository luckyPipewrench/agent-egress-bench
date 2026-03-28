# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Gauntlet scoring program:** four independent metrics (containment, false positive rate, detection, evidence) with an 80% containment gate. See `docs/gauntlet.md`.
- **Gauntlet runner CLI** (`runner/`): Go binary that runs all cases against a tool profile, computes scores, and outputs a machine-readable summary. Dry-run mode for v1. Zero external dependencies.
- **AI PR review workflow** (`/review` and `/review deep`): slash-command triggered code review via GitHub Actions.
- 70 new test cases across 8 new categories: a2a-message (10), a2a-agent-card (7), websocket-dlp (8), ssrf-bypass (9), encoding-evasion (9), shell-obfuscation (7), crypto-financial (8), false-positive (12)
- New input types: `a2a_message`, `a2a_agent_card`, `websocket_frame`
- New transport: `a2a`
- New capability tags: `a2a_scan`, `a2a_card_poison`, `websocket_dlp`, `ssrf_bypass`, `shell_obfuscation`, `crypto_dlp`
- New requires values: `websocket_frame_scanning`, `a2a_scanning`, `shell_analysis`, `dns_rebinding_fixture`
- OWASP mapping for ASI05 (partial, shell obfuscation) and ASI07 (A2A inter-agent communication)
- Source provenance enforcement for new categories (validator rule)

### Changed

- Corpus expanded from 73 to 143 cases (106 malicious, 37 benign)
- Pipelock reference profile updated with new capability claims
- Runner template profile updated with new supports fields
- Tool profile schema: 5 new supports fields (a2a, websocket_frame_scanning, a2a_scanning, shell_analysis, dns_rebinding_fixture)

## [1.0.0] - 2026-03-08

### Added

- 73 test cases across 8 categories: url, request-body, headers, response-fetch, response-mitm, mcp-input, mcp-tool, mcp-chain
- 57 malicious cases (expected: block) and 16 benign cases (expected: allow)
- Case spec v1 with payload, expected verdict, capability tags, and requirements
- Go validator with subcommands: `cases`, `results`, `profile` (stdlib only, no external deps)
- Reference Pipelock runner in `examples/pipelock/`
- Runner template skeleton in `examples/runner-template/` for building new runners
- JSON Schema files for cases, tool profiles, and result lines (`schemas/`)
- CI pipeline with CodeQL, dependency review, corpus validation, and Pipelock scan
- OpenSSF Scorecard integration
- OWASP Agentic Top 10 mapping for all 8 case categories
- MITRE ATT&CK technique mapping (T1041, T1567, T1048, T1071.001)
- Scoring model documentation (pass/fail/not_applicable/error)
- Runner output contract and verdict mapping spec
- Adoption guide for vendors (`docs/ADOPTION.md`)
- Glossary of key terms (`docs/GLOSSARY.md`)
- Governance policy covering neutrality, immutability, and contributions (`docs/GOVERNANCE.md`)
- CONTRIBUTING.md with case authoring guidelines
- SECURITY.md with vulnerability reporting policy
- CITATION.cff for academic citation
- GitHub issue templates (new case, new runner, bug report)
- Pull request template with validation checklist
- Source provenance for all 73 case files

### Fixed

- Harness config path and counter logic in Pipelock runner
- Pipelock runner README: corrected `error` to `not_applicable` for unsupported transports
- Runner template jq validation command (variadic `has()` replaced with chained `and`)
- Lint-clean validator (errcheck issues resolved)
