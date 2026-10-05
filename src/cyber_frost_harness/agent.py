from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .config import HarnessConfig
from .model import ContextLengthError, OpenAICompatibleClient, ModelReply, estimate_json_tokens
from .session import RunSession
from .skills import SkillLibrary
from .target import TargetInventory
from .tools import ToolRegistry


class SecurityAgent:
    def __init__(
        self,
        config: HarnessConfig,
        client: OpenAICompatibleClient,
        session: RunSession,
        skills: SkillLibrary,
        tools: ToolRegistry,
        inventory: TargetInventory,
        task_readme: str,
    ):
        self.config = config
        self.client = client
        self.session = session
        self.skills = skills
        self.tools = tools
        self.inventory = inventory
        self.task_readme = task_readme
        self.messages = self._initial_messages()
        self.call_counts: dict[str, int] = {}
        self.loaded_skills: set[str] = set()
        self.idle_replies = 0
        self.last_request_max_tokens: int | None = None

    def _initial_messages(self) -> list[dict[str, Any]]:
        system_text = self.config.agent.system_prompt.read_text(encoding="utf-8")
        selected = self.inventory.selected_target or "ambiguous; inspect the inventory"
        system_text += (
            f"\n\nSession mode: {self.config.agent.mode}.\n"
            f"Native architecture: {self.inventory.architecture}.\n"
            f"Wrapper-selected target: {selected}.\n"
            "\nAvailable skills (load only those needed):\n"
            f"{self.skills.catalog_text()}\n"
        )
        user_text = (
            "Begin the task below. Call inspect_target first, then load the relevant skills. "
            "The source and native target are already available through the tools.\n\n"
            "--- TASK README ---\n"
            f"{self.task_readme.strip()}\n"
            "--- END TASK README ---"
        )
        return [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ]

    def _request(self, step: int) -> ModelReply:
        definitions = self.tools.definitions()
        estimated_prompt = self.client.estimate_prompt_tokens(self.messages, definitions)
        if estimated_prompt > self.client.preferred_prompt_tokens:
            self._compact(step - 1, reason="pre-request token budget")
            definitions = self.tools.definitions()

        last_error: Exception | None = None
        forced_budget: int | None = None
        for attempt in range(3):
            budget = forced_budget
            if budget is None:
                budget = self.client.completion_budget(self.messages, definitions)
            if budget <= 0:
                self._compact(step - 1, reason="exhausted completion budget")
                budget = self.client.completion_budget(self.messages, definitions)
            if budget <= 0:
                raise ContextLengthError(
                    "context remains over budget after compaction",
                    context_limit=self.config.model.context_window_tokens,
                    prompt_tokens=self.client.estimate_prompt_tokens(
                        self.messages, definitions
                    ),
                    completion_tokens=0,
                )
            if (
                forced_budget is None
                and budget != self.config.model.max_completion_tokens
                and budget != self.last_request_max_tokens
            ):
                self.session.record_event(
                    "context_budget_adjustment",
                    {
                        "step": step,
                        "reason": "estimated prompt size",
                        "max_completion_tokens": budget,
                    },
                )
            self.last_request_max_tokens = budget
            try:
                return self.client.complete(
                    self.messages,
                    definitions,
                    max_tokens=budget,
                )
            except ContextLengthError as exc:
                last_error = exc
                self.session.record_event(
                    "model_error",
                    {
                        "attempt": attempt + 1,
                        "error": f"{type(exc).__name__}: {exc}",
                        "context_limit": exc.context_limit,
                        "prompt_tokens": exc.prompt_tokens,
                        "completion_tokens": exc.completion_tokens,
                    },
                )
                if exc.context_limit is not None and exc.prompt_tokens is not None:
                    available = (
                        exc.context_limit
                        - exc.prompt_tokens
                        - self.config.model.context_safety_tokens
                    )
                    if available >= self.config.model.min_completion_tokens:
                        forced_budget = min(
                            self.config.model.max_completion_tokens,
                            available,
                        )
                        self.session.record_event(
                            "context_budget_adjustment",
                            {
                                "step": step,
                                "reason": "server-reported token count",
                                "max_completion_tokens": forced_budget,
                            },
                        )
                        continue
                self._compact(step - 1, reason="server context rejection")
                definitions = self.tools.definitions()
                forced_budget = None
            except Exception as exc:
                last_error = exc
                self.session.record_event(
                    "model_error", {"attempt": attempt + 1, "error": f"{type(exc).__name__}: {exc}"}
                )
                if attempt < 2:
                    time.sleep(2 ** attempt)
        assert last_error is not None
        raise last_error

    @staticmethod
    def _assistant_message(reply: ModelReply) -> dict[str, Any]:
        message: dict[str, Any] = {
            "role": "assistant",
            "content": reply.message.get("content") or "",
        }
        if reply.message.get("reasoning_content"):
            message["reasoning_content"] = reply.message["reasoning_content"]
        if reply.message.get("tool_calls"):
            message["tool_calls"] = reply.message["tool_calls"]
        return message

    @staticmethod
    def _call_key(name: str, arguments: dict[str, Any]) -> str:
        canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(f"{name}:{canonical}".encode()).hexdigest()

    def _parse_arguments(self, raw: Any) -> dict[str, Any]:
        if isinstance(raw, dict):
            return raw
        if not isinstance(raw, str):
            raise ValueError("tool arguments must be a JSON object")
        parsed = json.loads(raw or "{}")
        if not isinstance(parsed, dict):
            raise ValueError("tool arguments must decode to an object")
        return parsed

    def _recent_complete_messages(
        self,
        maximum: int = 18,
        max_tokens: int | None = None,
    ) -> list[dict[str, Any]]:
        """Retain only complete protocol units so compaction cannot orphan tool results."""
        source = [
            message
            for message in self.messages[2:]
            if not (
                message.get("role") == "user"
                and str(message.get("content") or "").startswith("SESSION CHECKPOINT\n")
            )
        ]
        units: list[list[dict[str, Any]]] = []
        index = 0
        while index < len(source):
            message = source[index]
            role = message.get("role")
            if role == "tool":
                index += 1
                continue
            if role != "assistant":
                units.append([message])
                index += 1
                continue

            unit = [message]
            index += 1
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                expected = {str(call.get("id")) for call in tool_calls}
                observed: set[str] = set()
                while index < len(source) and source[index].get("role") == "tool":
                    tool_message = source[index]
                    unit.append(tool_message)
                    observed.add(str(tool_message.get("tool_call_id")))
                    index += 1
                if not expected.issubset(observed):
                    continue
            units.append(unit)

        retained: list[list[dict[str, Any]]] = []
        count = 0
        token_count = 0
        for unit in reversed(units):
            unit_tokens = estimate_json_tokens(
                unit,
                self.config.model.estimated_chars_per_token
                if hasattr(self, "config")
                else 3.0,
            )
            if count + len(unit) > maximum:
                break
            if max_tokens is not None and token_count + unit_tokens > max_tokens:
                if retained:
                    break
                continue
            retained.append(unit)
            count += len(unit)
            token_count += unit_tokens
        return [message for unit in reversed(retained) for message in unit]

    def _compact(self, step: int, *, reason: str = "periodic checkpoint") -> None:
        findings = json.dumps(self.session.findings, sort_keys=True, default=str)
        candidate_summary = [
            {
                "remote_path": item.remote_path,
                "sha256": item.sha256,
                "size": item.size,
                "exit_code": item.response.get("exit_code"),
            }
            for item in self.session.candidates
        ]
        checkpoint = {
            "step": step,
            "steps_remaining": self.config.agent.max_steps - step,
            "loaded_skills": sorted(self.loaded_skills),
            "findings": self.session.findings,
            "candidates": candidate_summary,
            "instruction": (
                "Continue from this evidence. Do not redo completed experiments. Reserve time for "
                "replay, minimization, one final selection, and finish."
            ),
        }
        base_messages = [
            self.messages[0],
            self.messages[1],
            {
                "role": "user",
                "content": "SESSION CHECKPOINT\n" + json.dumps(checkpoint, indent=2, default=str),
            },
        ]
        definitions = self.tools.definitions()
        base_tokens = self.client.estimate_prompt_tokens(base_messages, definitions)
        retention_budget = max(0, self.client.preferred_prompt_tokens - base_tokens)
        recent = self._recent_complete_messages(maximum=18, max_tokens=retention_budget)
        before_tokens = self.client.estimate_prompt_tokens(self.messages, definitions)
        self.messages = [*base_messages, *recent]
        after_tokens = self.client.estimate_prompt_tokens(self.messages, definitions)
        self.session.record_event(
            "context_checkpoint",
            {
                "step": step,
                "reason": reason,
                "findings_chars": len(findings),
                "retained_messages": len(recent),
                "estimated_prompt_tokens_before": before_tokens,
                "estimated_prompt_tokens_after": after_tokens,
                "preferred_prompt_tokens": self.client.preferred_prompt_tokens,
            },
        )

    def _auto_finish(self, reason: str) -> None:
        crashing = [
            item
            for item in self.session.candidates
            if int(item.response.get("exit_code") or 0) not in {0, 300}
        ]
        selected = crashing[-1].remote_path if crashing else None
        status = "best-effort" if selected else "no-candidate"
        self.session.finish(
            status=status,
            summary=reason,
            root_cause="See the evidence ledger and trajectory.",
            final_candidate=selected,
        )

    def run(self) -> dict[str, Any]:
        self.session.record_event(
            "agent_start",
            {
                "mode": self.config.agent.mode,
                "model": self.config.model.model,
                "sampling": {
                    "temperature": self.config.model.temperature,
                    "top_p": self.config.model.top_p,
                    "reasoning_effort": self.config.model.reasoning_effort,
                    "max_completion_tokens": self.config.model.max_completion_tokens,
                    "context_window_tokens": self.config.model.context_window_tokens,
                    "context_safety_tokens": self.config.model.context_safety_tokens,
                    "min_completion_tokens": self.config.model.min_completion_tokens,
                    "seed": self.config.model.seed,
                },
                "inventory": asdict(self.inventory),
            },
        )

        for step in range(1, self.config.agent.max_steps + 1):
            reply = self._request(step)
            self.session.add_usage(reply.usage)
            self.session.record_event(
                "model_reply",
                {
                    "step": step,
                    "response_id": reply.response_id,
                    "model": reply.model,
                    "finish_reason": reply.finish_reason,
                    "content": reply.message.get("content"),
                    "reasoning_content": reply.message.get("reasoning_content"),
                    "tool_calls": reply.message.get("tool_calls") or [],
                    "usage": reply.usage,
                    "requested_max_completion_tokens": self.last_request_max_tokens,
                },
            )
            assistant = self._assistant_message(reply)
            self.messages.append(assistant)
            calls = reply.message.get("tool_calls") or []
            if not calls:
                self.idle_replies += 1
                if self.idle_replies >= 2:
                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                "Use a tool for the next concrete experiment, or call finish. "
                                "Narration without an action does not advance the task."
                            ),
                        }
                    )
                continue
            self.idle_replies = 0

            for call in calls:
                call_id = str(call.get("id") or f"tool-{step}")
                function = call.get("function") or {}
                name = str(function.get("name") or "")
                try:
                    arguments = self._parse_arguments(function.get("arguments", "{}"))
                except Exception as exc:
                    result = json.dumps(
                        {"ok": False, "error": f"invalid tool arguments: {exc}"}
                    )
                    arguments = {}
                else:
                    key = self._call_key(name, arguments)
                    self.call_counts[key] = self.call_counts.get(key, 0) + 1
                    if self.call_counts[key] > self.config.agent.max_repeated_tool_calls:
                        result = json.dumps(
                            {
                                "ok": False,
                                "error": (
                                    "repeated identical tool call blocked; use the prior result, "
                                    "change the experiment, or record a new hypothesis"
                                ),
                            }
                        )
                    else:
                        result = self.tools.execute(name, arguments)
                        if name == "load_skill" and arguments.get("name"):
                            self.loaded_skills.add(str(arguments["name"]))
                self.session.record_event(
                    "tool_result",
                    {
                        "step": step,
                        "tool_call_id": call_id,
                        "name": name,
                        "arguments": arguments,
                        "result": result,
                    },
                )
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": result,
                    }
                )
                if self.session.finished:
                    return self.session.finish_payload or {}

            if step % self.config.agent.checkpoint_interval == 0:
                self._compact(step, reason="periodic checkpoint")

        self._auto_finish("Maximum agent-step budget reached before an explicit finish call.")
        return self.session.finish_payload or {}
