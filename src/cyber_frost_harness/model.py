from __future__ import annotations

import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import ModelConfig


CONTEXT_LENGTH_RE = re.compile(
    r"maximum context length of (?P<context>\d+) tokens.*?"
    r"(?P<prompt>\d+) tokens from the input messages and "
    r"(?P<completion>\d+) tokens for the completion",
    re.IGNORECASE | re.DOTALL,
)


class ContextLengthError(RuntimeError):
    def __init__(
        self,
        detail: str,
        *,
        context_limit: int | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ):
        super().__init__(detail)
        self.context_limit = context_limit
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens


def estimate_json_tokens(value: Any, chars_per_token: float = 3.0) -> int:
    """Conservatively estimate tokens without requiring a model-specific tokenizer."""
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return max(1, math.ceil(len(serialized) / chars_per_token))


@dataclass(frozen=True)
class ModelReply:
    response_id: str
    model: str
    message: dict[str, Any]
    finish_reason: str | None
    usage: dict[str, Any]
    raw: dict[str, Any]


class OpenAICompatibleClient:
    def __init__(self, config: ModelConfig):
        self.config = config

    def _request(self, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        request = urllib.request.Request(url, data=body, headers=headers)
        try:
            with urllib.request.urlopen(
                request, timeout=self.config.request_timeout_seconds
            ) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")
            if exc.code == 400:
                match = CONTEXT_LENGTH_RE.search(detail)
                if match:
                    raise ContextLengthError(
                        detail,
                        context_limit=int(match.group("context")),
                        prompt_tokens=int(match.group("prompt")),
                        completion_tokens=int(match.group("completion")),
                    ) from exc
            raise RuntimeError(f"model API HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"model API connection failed: {exc}") from exc

    def models(self) -> dict[str, Any]:
        return self._request("/models")

    @property
    def preferred_prompt_tokens(self) -> int:
        return (
            self.config.context_window_tokens
            - self.config.context_safety_tokens
            - self.config.max_completion_tokens
        )

    def estimate_prompt_tokens(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> int:
        # The fixed allowance covers chat-template framing and tokenizer variance.
        return 1024 + estimate_json_tokens(
            {"messages": messages, "tools": tools},
            self.config.estimated_chars_per_token,
        )

    def completion_budget(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
    ) -> int:
        prompt_tokens = self.estimate_prompt_tokens(messages, tools)
        available = (
            self.config.context_window_tokens
            - self.config.context_safety_tokens
            - prompt_tokens
        )
        return max(0, min(self.config.max_completion_tokens, available))

    def complete(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        max_tokens: int | None = None,
    ) -> ModelReply:
        requested_max_tokens = (
            self.completion_budget(messages, tools) if max_tokens is None else int(max_tokens)
        )
        if requested_max_tokens <= 0:
            raise ContextLengthError(
                "estimated prompt leaves no safe completion budget",
                context_limit=self.config.context_window_tokens,
                prompt_tokens=self.estimate_prompt_tokens(messages, tools),
                completion_tokens=requested_max_tokens,
            )
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": requested_max_tokens,
            "seed": self.config.seed,
            "presence_penalty": 0.0,
            "top_k": 20,
            "min_p": 0.0,
            "repetition_penalty": 1.0,
            "reasoning_effort": self.config.reasoning_effort,
            "chat_template_kwargs": {
                "enable_thinking": True,
                "preserve_thinking": True,
            },
        }
        raw = self._request("/chat/completions", payload)
        choices = raw.get("choices") or []
        if not choices:
            raise RuntimeError(f"model returned no choices: {raw}")
        choice = choices[0]
        message = choice.get("message") or {}
        return ModelReply(
            response_id=str(raw.get("id", "")),
            model=str(raw.get("model", self.config.model)),
            message=message,
            finish_reason=choice.get("finish_reason"),
            usage=raw.get("usage") or {},
            raw=raw,
        )
