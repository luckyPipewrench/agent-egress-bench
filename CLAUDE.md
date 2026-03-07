# CLAUDE.md: agent-egress-bench Development Guide

Tool-neutral attack corpus for evaluating AI agent egress security tools. JSON case files, Go validator, spec docs, reference runners.

## Quick Reference

| Item | Value |
|------|-------|
| Repo | `luckyPipewrench/agent-egress-bench` |
| License | Apache 2.0 |
| Spec | `docs/SPEC.md` (source of truth for case format) |
| Scoring | `docs/SCORING.md` |
| Runner contract | `docs/RUNNER.md` |
| OWASP mapping | `docs/OWASP-MAPPING.md` |

## Build and Validate

```bash
cd validate && go test -race -count=1 ./... && go build -o /tmp/aeb-validate . && /tmp/aeb-validate ../cases
```

The validator is stdlib-only Go. No external dependencies.

## Project Structure

```
cases/
  url/              URL-based exfiltration (DLP, entropy, encoding evasion)
  request-body/     Request body exfiltration
  headers/          Header-based secret leaks
  response-fetch/   Response content injection (fetched pages)
  response-mitm/    Response injection via TLS interception
  mcp-input/        MCP tool call argument scanning
  mcp-tool/         MCP tool description poisoning
  mcp-chain/        Multi-step MCP tool call sequences
validate/           Go validator (stdlib-only)
examples/           Reference runner implementations
docs/               Spec, scoring, runner contract, OWASP mapping
```

## Adding a Case

1. Pick category and directory (see table in `docs/SPEC.md`)
2. Name: `{category}-{subcategory}-{NNN}.json`. Filename must match `id` field.
3. Use an existing case in the same directory as a template
4. Benign cases (`expected_verdict: allow`) MUST have `"safe_example": true`
5. Validate: `cd validate && go build -o /tmp/aeb-validate . && /tmp/aeb-validate ../cases`

## Fake Secrets

Cases contain intentionally fake secrets. GitHub Push Protection flags patterns like `AKIA`, `ghp_`, `xoxb-`.

Rules:
- Use obviously synthetic values (e.g., `AKIAIOSFODNN7EXAMPLE`)
- Split at pattern boundary if push is blocked: `"AKIA" + "IOSFODNN7EXAMPLE"`
- Never use real secrets, even expired ones

## Governance

1. Case IDs are immutable. Never rename.
2. Existing case semantics don't change. Semantic changes = new case.
3. Corpus versions are additive.
4. No cross-tool leaderboard in this repo. Tool-neutral.

## CI

Validate CI runs on every push/PR to `main`:
- Go tests for the validator
- Full case validation against corpus
- Case count check (must be > 0)

Branch protection requires passing CI + 1 approving review.

## Neutrality

This repo is tool-neutral. The pipelock reference runner in `examples/pipelock/` is an example, not a privileged position. Any security tool can add a runner following `docs/RUNNER.md`.
