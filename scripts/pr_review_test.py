#!/usr/bin/env python3
"""Focused unit tests for the PR review runner and workflow contract."""

import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-review.py")
WORKFLOW_PATH = SCRIPT_PATH.parents[1] / ".github" / "workflows" / "pr-review.yaml"
SPEC = importlib.util.spec_from_file_location("pr_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_review)


class FakeResponse:
    def __init__(self, data: dict, status_code: int = 200, text: str = "") -> None:
        self._data = data
        self.status_code = status_code
        self.text = text

    def json(self) -> dict:
        return self._data


class InvalidJSONResponse(FakeResponse):
    def json(self) -> dict:
        raise ValueError("not JSON")


class PayloadTest(unittest.TestCase):
    def test_gpt5_payload_uses_reasoning_effort_without_temperature(self) -> None:
        payload = pr_review.build_llm_payload("gpt-5.6-luna", "diff")
        self.assertNotIn("temperature", payload)
        self.assertEqual(payload["reasoning_effort"], "low")
        self.assertEqual(
            payload["max_completion_tokens"], pr_review.DEFAULT_MAX_COMPLETION_TOKENS
        )

    def test_deep_payload_uses_medium_reasoning_effort(self) -> None:
        payload = pr_review.build_llm_payload(
            "gpt-5.6-terra",
            "diff",
            max_completion_tokens=pr_review.DEEP_MAX_COMPLETION_TOKENS,
            reasoning_effort=pr_review.DEEP_REASONING_EFFORT,
        )
        self.assertEqual(payload["reasoning_effort"], "medium")
        self.assertEqual(
            payload["max_completion_tokens"], pr_review.DEEP_MAX_COMPLETION_TOKENS
        )

    def test_legacy_model_keeps_temperature_without_reasoning_effort(self) -> None:
        payload = pr_review.build_llm_payload("gpt-4.1", "diff")
        self.assertEqual(payload["temperature"], pr_review.DEFAULT_TEMPERATURE)
        self.assertNotIn("reasoning_effort", payload)


class ModelRoutingTest(unittest.TestCase):
    def test_python_constants_are_the_model_default_source(self) -> None:
        self.assertEqual(pr_review.DEFAULT_MODEL_FAST, "gpt-5.6-luna")
        self.assertEqual(pr_review.DEFAULT_MODEL_DEEP, "gpt-5.6-terra")

    def test_workflow_delegates_defaults_to_runner(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "PR_REVIEW_MODEL_FAST: ${{ vars.PR_REVIEW_MODEL_FAST }}", workflow
        )
        self.assertIn(
            "PR_REVIEW_MODEL_DEEP: ${{ vars.PR_REVIEW_MODEL_DEEP }}", workflow
        )
        self.assertNotRegex(workflow, r"PR_REVIEW_MODEL_(?:FAST|DEEP): gpt-")

    def test_workflow_requires_owner_and_uses_trusted_runner_checkout(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("github.event.comment.user.login == 'luckyPipewrench'", workflow)
        self.assertIn("github.event.comment.author_association == 'OWNER'", workflow)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("group: pr-review-${{ github.repository }}-${{ github.event.issue.number }}", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python -m unittest scripts/pr_review_test.py", workflow)
        self.assertNotIn("'/review fast'", workflow)

    def test_workflow_keeps_credentials_in_secrets(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("LITELLM_BASE_URL: ${{ secrets.LITELLM_BASE_URL }}", workflow)
        self.assertIn("LITELLM_API_KEY: ${{ secrets.LITELLM_API_KEY }}", workflow)
        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", workflow)

    def test_default_and_deep_modes_cannot_swap_model_routes(self) -> None:
        response = FakeResponse({"choices": [{"message": {"content": "review"}}]})
        with mock.patch.dict(
            pr_review.os.environ, {"OPENAI_API_KEY": "test-key"}, clear=True
        ), mock.patch.object(pr_review.requests, "post", return_value=response) as post:
            pr_review.call_llm("diff", "default")
            default_payload = post.call_args.kwargs["json"]
            pr_review.call_llm("diff", "deep")
            deep_payload = post.call_args.kwargs["json"]

        self.assertEqual(default_payload["model"], pr_review.DEFAULT_MODEL_FAST)
        self.assertEqual(default_payload["reasoning_effort"], "low")
        self.assertEqual(deep_payload["model"], pr_review.DEFAULT_MODEL_DEEP)
        self.assertEqual(deep_payload["reasoning_effort"], "medium")

    def test_empty_overrides_fall_back_to_python_defaults(self) -> None:
        with mock.patch.dict(
            pr_review.os.environ,
            {"PR_REVIEW_MODEL_FAST": "", "PR_REVIEW_MODEL_DEEP": ""},
            clear=True,
        ):
            self.assertEqual(pr_review.model_for_mode("default"), "gpt-5.6-luna")
            self.assertEqual(pr_review.model_for_mode("deep"), "gpt-5.6-terra")


class ResponseParsingTest(unittest.TestCase):
    def test_shape_errors_are_generic_and_fail_closed(self) -> None:
        with self.assertRaises(pr_review.LLMReviewError) as ctx:
            pr_review.extract_chat_content(
                {"choices": [], "private": "provider detail"}
            )
        self.assertIn("no choices", str(ctx.exception))
        self.assertNotIn("provider detail", str(ctx.exception))

        with self.assertRaisesRegex(pr_review.LLMReviewError, "empty content"):
            pr_review.extract_chat_content({"choices": [None]})

    def test_extract_chat_content_accepts_content_parts(self) -> None:
        data = {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": "review "},
                            {"type": "text", "text": "body"},
                        ]
                    }
                }
            ]
        }
        self.assertEqual(pr_review.extract_chat_content(data), "review body")

    def test_extract_chat_content_rejects_empty_response(self) -> None:
        data = {
            "choices": [{"finish_reason": "length", "message": {"content": ""}}],
            "usage": {"completion_tokens_details": {"reasoning_tokens": 4096}},
        }
        with self.assertRaisesRegex(pr_review.LLMReviewError, "finish_reason=length"):
            pr_review.extract_chat_content(data)

    def test_extract_chat_content_marks_truncated_review_incomplete(self) -> None:
        data = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": "partial review"},
                }
            ],
            "usage": {"completion_tokens_details": {"reasoning_tokens": 22000}},
        }
        content = pr_review.extract_chat_content(data)
        self.assertIn("partial review", content)
        self.assertIn("incomplete review", content)
        self.assertIn("reasoning=22000", content)

    def test_call_llm_raises_on_non_200_response(self) -> None:
        response = FakeResponse({}, status_code=500, text="boom")
        with mock.patch.dict(
            pr_review.os.environ, {"OPENAI_API_KEY": "test-key"}, clear=True
        ), mock.patch.object(pr_review.requests, "post", return_value=response):
            with self.assertRaises(pr_review.LLMReviewError) as ctx:
                pr_review.call_llm("diff", "default")
        self.assertIn("returned 500", str(ctx.exception))
        self.assertNotIn("boom", str(ctx.exception))

    def test_call_llm_rejects_invalid_json_response(self) -> None:
        response = InvalidJSONResponse({})
        with mock.patch.dict(
            pr_review.os.environ, {"OPENAI_API_KEY": "test-key"}, clear=True
        ), mock.patch.object(pr_review.requests, "post", return_value=response):
            with self.assertRaisesRegex(pr_review.LLMReviewError, "invalid JSON"):
                pr_review.call_llm("diff", "default")


if __name__ == "__main__":
    unittest.main()
