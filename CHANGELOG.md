# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Multi-file MCP-drift case runner support:** new `--multifile-cases <dir>` flag on the gauntlet runner loads each `cases/mcp-drift/<id>/` directory, converts the `before.json` / `after.json` snapshot pair into a four-message JSON-RPC sequence, and replays the sequence through a single MCP session against the running tool. The verdict on the second `tools/list` response is what scores. Closes the coverage gap previously called out in `profiles/README.md`.
- **Receipt-scoring corpus hash covers multi-file cases.** `computeCorpusSHA256` includes `case.yaml` plus the three JSON snapshots per multi-file case when the multi-file flag is set, so `corpus_sha256` in the emitted profile pins the full case surface the runner exercised.
- **Pipelock receipt profile regenerated against the full corpus.** `profiles/pipelock.json` records Pipelock 3.1.0 against the current 197-case corpus surface (193 single-file JSON cases plus 4 multi-file MCP-drift fixtures). The profile keeps unsupported or not-applicable rows explicit so receipt-evidence claims do not get inflated into scanner-containment claims.
- **Gauntlet scoring program:** four independent metrics (containment, false positive rate, detection, evidence) with an 80% containment gate. See `docs/gauntlet.md`.
- **Gauntlet runner CLI** (`runner/`): Go binary that runs all cases against a tool profile, computes scores, and outputs a machine-readable summary. Dry-run mode for v1.
- **AI PR review workflow** (`/review` and `/review deep`): slash-command triggered code review via GitHub Actions.
- 70 new test cases across 8 new categories: a2a-message (10), a2a-agent-card (7), websocket-dlp (8), ssrf-bypass (9), encoding-evasion (9), shell-obfuscation (7), crypto-financial (8), false-positive (12)
- New input types: `a2a_message`, `a2a_agent_card`, `websocket_frame`
- New transport: `a2a`
- New capability tags: `a2a_scan`, `a2a_card_poison`, `websocket_dlp`, `ssrf_bypass`, `shell_obfuscation`, `crypto_dlp`
- New requires values: `websocket_frame_scanning`, `a2a_scanning`, `shell_analysis`, `dns_rebinding_fixture`
- OWASP mapping for ASI05 (partial, shell obfuscation) and ASI07 (A2A inter-agent communication)
- Source provenance enforcement for new categories (validator rule)

### Changed

- **Applicability now gates on observability (scoring 2.5, corpus v2.4.0).** `requires` lists only delivery, fixture, and base-observation prerequisites. Attack-difficulty and evasion-resistance flags (`encoding_evasion_scanning`, `ssrf_bypass_scanning`) no longer gate applicability: they moved to `capability_tags` on the 32 affected cases, so a tool can no longer render a hard variant `not_applicable` by declining a difficulty claim for a surface it already inspects. The validator rejects difficulty flags in `requires` for both single-file and multi-file cases. Full-corpus malicious containment stays comparable across this change, because a not-applicable malicious case already counted as unblocked. Full-corpus false-positive rates, and any composite score incorporating them, are not strictly comparable where a benign control changed applicability. Applicable-only scores from before 2.5 are not comparable to those after it at all.
- **Enforcement claims no longer gate applicability either.** The three denial-of-wallet cases gated on `budget_enforcement`, the feature under test, so any tool declining that claim removed the whole family from its run -- including `mcp-chain-dow-under-budget-011`, the benign control that measures over-blocking. The two malicious cases now gate on `mcp_chain_memory`, matching the nine malicious `mcp_chain` siblings, and the benign control gates on nothing, matching the category's other benign control. Three opaque-payload cases (`a2a-msg-opaque-entropy-013`, `body-entropy-opaque-json-014`, `ws-dlp-opaque-binary-010`) likewise drop their redundant base-surface gate and keep `entropy_scanning`.
- The Pipelock reference profile declines `budget_enforcement`, so this regate moves three cases from `not_applicable` to applicable for it. Full-corpus containment is unaffected, because a not-applicable malicious case already counted as unblocked. Its applicable-only diagnostic containment falls, and the benign within-budget control now contributes to its false-positive rate, so the full-corpus false-positive component is not strictly comparable across this boundary even though containment is. See methodology.md for which component is comparable and which is not.
- Corpus expanded from 73 to 197 logical cases: 193 single-file JSON cases plus 4 multi-file MCP-drift fixtures across 18 categories
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
