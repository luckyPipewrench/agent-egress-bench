# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
