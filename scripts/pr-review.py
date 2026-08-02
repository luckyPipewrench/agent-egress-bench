#!/usr/bin/env python3
"""AI-powered PR review for agent-egress-bench.

Triggered by /review or /review deep comments on PRs.
Sends the PR diff to an LLM and posts the review as a single PR comment.

Requires environment variables:
  GITHUB_TOKEN       - GitHub token (provided by Actions)
  REPO               - owner/repo
  PR_NUMBER          - PR number
  REVIEW_MODE        - "default" or "deep"

LLM configuration (one of):
  LITELLM_BASE_URL + LITELLM_API_KEY  - LiteLLM proxy
  OPENAI_API_KEY                       - Direct OpenAI API

Model selection:
  PR_REVIEW_MODEL_FAST  - Model for /review (default: gpt-5.6-luna)
  PR_REVIEW_MODEL_DEEP  - Model for /review deep (default: gpt-5.6-terra)

The PR_REVIEW_MODEL_FAST env var keeps its name for backwards compatibility
with existing environment overrides.
"""

import json
import os
import sys

import requests

# --- Constants ---

MAX_DIFF_CHARS = 100_000  # ~25k tokens, keeps costs reasonable
DEFAULT_MODEL_FAST = "gpt-5.6-luna"
DEFAULT_MODEL_DEEP = "gpt-5.6-terra"
DEFAULT_TEMPERATURE = 0.2
DEFAULT_MAX_COMPLETION_TOKENS = 8192
DEEP_MAX_COMPLETION_TOKENS = 25000
DEFAULT_LLM_TIMEOUT_SECONDS = 120
DEEP_LLM_TIMEOUT_SECONDS = 300
FAST_REASONING_EFFORT = "low"
DEEP_REASONING_EFFORT = "medium"


class LLMReviewError(RuntimeError):
    """Raised when the LLM call completed but did not produce a usable review."""

SYSTEM_PROMPT = """You are reviewing a pull request for agent-egress-bench, an open test corpus for evaluating AI agent egress security tools. The repo contains JSON test cases, a Go validator (stdlib-only), a Gauntlet scoring runner (stdlib-only), and documentation.

Focus on issues that materially affect correctness, corpus integrity, scoring accuracy, or governance compliance.

Flag:
- test cases with incorrect expected verdicts or missing required fields
- cases that leak private infrastructure details, real credentials, or tool-specific implementation details
- validator logic that would accept invalid cases or reject valid ones
- scoring math errors or incorrect N/A handling in the runner
- schema changes that break backwards compatibility without a version bump
- cases that violate the governance policy (immutable IDs, tool neutrality)
- documentation that contradicts the spec, scoring methodology, or runner contract
- Go code with race conditions, missing error handling, or external dependencies

Do not waste time on style nits, JSON formatting, or trivial suggestions.
Be direct and specific.
For each finding, include:
1. severity: high, medium, or low
2. file and function or section
3. why it matters
4. a concrete fix

If there are no material issues, say exactly: No material issues found in this diff."""


def get_pr_diff(repo: str, pr_number: str, token: str) -> str:
    """Fetch the PR diff from GitHub."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.text


def truncate_diff(diff: str, max_chars: int = MAX_DIFF_CHARS) -> str:
    """Truncate diff to stay within token limits."""
    if len(diff) <= max_chars:
        return diff
    truncated = diff[:max_chars]
    return truncated + f"\n\n... (diff truncated at {max_chars} chars, {len(diff)} total)"


def model_supports_custom_temperature(model: str) -> bool:
    """Return whether chat completions should send a non-default temperature."""
    normalized = model.strip().lower()
    model_name = normalized.rsplit("/", 1)[-1]
    return not model_name.startswith(("gpt-5", "o1", "o3", "o4"))


def model_supports_reasoning_effort(model: str) -> bool:
    """Return whether chat completions should pin reasoning effort."""
    normalized = model.strip().lower()
    model_name = normalized.rsplit("/", 1)[-1]
    return model_name.startswith(("gpt-5", "o1", "o3", "o4"))


def build_llm_payload(
    model: str,
    diff: str,
    *,
    max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS,
    reasoning_effort: str = FAST_REASONING_EFFORT,
) -> dict:
    """Build a chat-completions payload compatible with the selected model."""
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Review this pull request diff:\n\n```diff\n{diff}\n```",
            },
        ],
        "max_completion_tokens": max_completion_tokens,
    }
    if model_supports_custom_temperature(model):
        payload["temperature"] = DEFAULT_TEMPERATURE
    if model_supports_reasoning_effort(model):
        payload["reasoning_effort"] = reasoning_effort
    return payload


def summarize_usage(data: dict) -> str:
    """Return compact token usage details for operator-visible errors."""
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return "usage unavailable"
    details = usage.get("completion_tokens_details") or {}
    parts = [
        f"prompt={usage.get('prompt_tokens', 'unknown')}",
        f"completion={usage.get('completion_tokens', 'unknown')}",
        f"total={usage.get('total_tokens', 'unknown')}",
    ]
    if isinstance(details, dict) and "reasoning_tokens" in details:
        parts.append(f"reasoning={details['reasoning_tokens']}")
    return ", ".join(parts)


def extract_chat_content(data: dict) -> str:
    """Extract visible text from a chat-completions response."""
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        raise LLMReviewError("LLM returned no choices.")

    choice = choices[0] if isinstance(choices[0], dict) else {}
    message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
    content = message.get("content", "")
    if isinstance(content, list):
        content = "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    if isinstance(content, str) and content.strip():
        if choice.get("finish_reason") == "length":
            content += (
                "\n\n> **Warning:** Review output was truncated by the model "
                f"completion limit ({summarize_usage(data)}). Treat this as an "
                "incomplete review and rerun with a narrower diff if needed."
            )
        return content

    finish_reason = choice.get("finish_reason", "unknown")
    raise LLMReviewError(
        "LLM returned empty content "
        f"(finish_reason={finish_reason}; {summarize_usage(data)})."
    )


def model_for_mode(mode: str) -> str:
    """Return the configured model for a review mode, with Python defaults."""
    if mode == "deep":
        return os.environ.get("PR_REVIEW_MODEL_DEEP") or DEFAULT_MODEL_DEEP
    return os.environ.get("PR_REVIEW_MODEL_FAST") or DEFAULT_MODEL_FAST


def call_llm(diff: str, mode: str) -> str:
    """Send the diff to the LLM and return the review."""
    litellm_url = os.environ.get("LITELLM_BASE_URL", "")
    litellm_key = os.environ.get("LITELLM_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")

    model = model_for_mode(mode)

    # Prefer LiteLLM if configured, fall back to OpenAI.
    if litellm_url and litellm_key:
        api_url = litellm_url.rstrip("/") + "/chat/completions"
        api_key = litellm_key
    elif openai_key:
        api_url = "https://api.openai.com/v1/chat/completions"
        api_key = openai_key
    else:
        raise LLMReviewError(
            "No LLM API configured. Set LITELLM_BASE_URL + LITELLM_API_KEY "
            "or OPENAI_API_KEY in repo secrets."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    is_deep = mode == "deep"
    payload = build_llm_payload(
        model,
        diff,
        max_completion_tokens=(
            DEEP_MAX_COMPLETION_TOKENS if is_deep else DEFAULT_MAX_COMPLETION_TOKENS
        ),
        reasoning_effort=(
            DEEP_REASONING_EFFORT if is_deep else FAST_REASONING_EFFORT
        ),
    )

    timeout = DEEP_LLM_TIMEOUT_SECONDS if is_deep else DEFAULT_LLM_TIMEOUT_SECONDS
    resp = requests.post(api_url, headers=headers, json=payload, timeout=timeout)
    if resp.status_code != 200:
        raise LLMReviewError(f"LLM API returned {resp.status_code} for model `{model}`.")
    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError) as exc:
        raise LLMReviewError("LLM returned invalid JSON.") from exc
    return extract_chat_content(data)


def post_comment(repo: str, pr_number: str, token: str, body: str) -> None:
    """Post a comment on the PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    resp = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    resp.raise_for_status()


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    mode = os.environ.get("REVIEW_MODE", "default")

    if not all([token, repo, pr_number]):
        print("Missing required environment variables", file=sys.stderr)
        sys.exit(1)

    print(f"Reviewing PR #{pr_number} in {repo} (mode: {mode})")

    # Fetch diff.
    try:
        diff = get_pr_diff(repo, pr_number, token)
    except requests.RequestException as e:
        post_comment(repo, pr_number, token, f"**AI Review Error:** Failed to fetch PR diff: {e}")
        sys.exit(1)

    if not diff.strip():
        post_comment(repo, pr_number, token, "**AI Review:** No diff found for this PR.")
        return

    diff = truncate_diff(diff)
    print(f"Diff size: {len(diff)} chars")

    # Call LLM.
    try:
        review = call_llm(diff, mode)
    except (requests.RequestException, LLMReviewError) as e:
        post_comment(repo, pr_number, token, f"**AI Review Error:** LLM API call failed: {e}")
        sys.exit(1)

    # Post review.
    model_name = model_for_mode(mode)
    command = "/review" if mode == "default" else f"/review {mode}"
    header = f"## AI Security Review (`{command}`)\n\n**Model:** `{model_name}`\n\n---\n\n"
    post_comment(repo, pr_number, token, header + review)
    print("Review posted.")


if __name__ == "__main__":
    main()
