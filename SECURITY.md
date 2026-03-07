# Security Policy

## Scope

This repository contains **intentionally fake test data** designed to evaluate AI agent egress security tools. All credentials, API keys, and secrets in the `cases/` directory are synthetic and non-functional.

## Reporting Issues

If you find a real security issue in this repository (e.g., an accidentally committed real credential, a vulnerability in the validator, or a case that could cause harm when used), please report it via [GitHub Security Advisories](https://github.com/luckyPipewrench/agent-egress-bench/security/advisories).

Do not open a public issue for security vulnerabilities.

## What Is NOT a Security Issue

- Fake API keys, tokens, or credentials in `cases/` directory (these are intentional test data)
- Attack patterns described in case files (these are the purpose of the project)
- Prompt injection payloads in response content cases (these test detection capabilities)
