import unittest
from types import SimpleNamespace

from cyber_frost_harness.agent import SecurityAgent
from cyber_frost_harness.model import ContextLengthError, ModelReply


class RecordingSession:
    def __init__(self):
        self.events = []

    def record_event(self, kind, payload):
        self.events.append((kind, payload))


class ContextRetryClient:
    preferred_prompt_tokens = 126976

    def __init__(self):
        self.budgets = []

    def estimate_prompt_tokens(self, _messages, _tools):
        return 1000

    def completion_budget(self, _messages, _tools):
        return 131072

    def complete(self, _messages, _tools, *, max_tokens=None):
        self.budgets.append(max_tokens)
        if len(self.budgets) == 1:
            raise ContextLengthError(
                "server context rejection",
                context_limit=262144,
                prompt_tokens=206772,
                completion_tokens=131072,
            )
        return ModelReply("id", "model", {"content": "ok"}, "stop", {}, {})


class AgentCompactionTests(unittest.TestCase):
    def test_assistant_message_preserves_separate_reasoning_stream(self):
        reply = ModelReply(
            response_id="id",
            model="model",
            message={
                "content": "",
                "reasoning_content": "private working state",
                "tool_calls": [{"id": "x", "function": {"name": "probe", "arguments": "{}"}}],
            },
            finish_reason="tool_calls",
            usage={},
            raw={},
        )
        message = SecurityAgent._assistant_message(reply)
        self.assertEqual(message["reasoning_content"], "private working state")
        self.assertEqual(message["tool_calls"][0]["id"], "x")

    def test_retains_complete_tool_call_units_and_drops_old_checkpoints(self):
        agent = object.__new__(SecurityAgent)
        agent.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task"},
            {"role": "user", "content": "SESSION CHECKPOINT\nold"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"id": "a", "function": {"name": "x", "arguments": "{}"}},
                    {"id": "b", "function": {"name": "y", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "a", "content": "one"},
            {"role": "tool", "tool_call_id": "b", "content": "two"},
            {"role": "assistant", "content": "next"},
        ]
        recent = agent._recent_complete_messages(maximum=3)
        self.assertEqual([item["role"] for item in recent], ["assistant"])
        self.assertEqual(recent[0]["content"], "next")
        recent = agent._recent_complete_messages(maximum=4)
        self.assertEqual(
            [item.get("tool_call_id") for item in recent[1:3]], ["a", "b"]
        )
        self.assertFalse(
            any(str(item.get("content", "")).startswith("SESSION CHECKPOINT") for item in recent)
        )

    def test_drops_incomplete_assistant_tool_unit(self):
        agent = object.__new__(SecurityAgent)
        agent.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task"},
            {
                "role": "assistant",
                "tool_calls": [
                    {"id": "a", "function": {"name": "x", "arguments": "{}"}},
                    {"id": "b", "function": {"name": "y", "arguments": "{}"}},
                ],
            },
            {"role": "tool", "tool_call_id": "a", "content": "one"},
        ]
        self.assertEqual(agent._recent_complete_messages(), [])

    def test_token_budget_skips_oversized_complete_unit(self):
        agent = object.__new__(SecurityAgent)
        agent.config = SimpleNamespace(
            model=SimpleNamespace(estimated_chars_per_token=3.0)
        )
        agent.messages = [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "task"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "huge",
                        "function": {
                            "name": "write_workspace_file",
                            "arguments": "x" * 30000,
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "huge", "content": "done"},
            {"role": "assistant", "content": "small recent conclusion"},
        ]
        recent = agent._recent_complete_messages(maximum=18, max_tokens=100)
        self.assertEqual(recent, [{"role": "assistant", "content": "small recent conclusion"}])

    def test_server_context_error_retries_with_exact_safe_budget(self):
        agent = object.__new__(SecurityAgent)
        agent.config = SimpleNamespace(
            model=SimpleNamespace(
                max_completion_tokens=131072,
                min_completion_tokens=16384,
                context_window_tokens=262144,
                context_safety_tokens=4096,
            )
        )
        agent.client = ContextRetryClient()
        agent.tools = SimpleNamespace(definitions=lambda: [])
        agent.messages = [{"role": "user", "content": "task"}]
        agent.session = RecordingSession()
        agent.last_request_max_tokens = None

        reply = agent._request(step=33)

        self.assertEqual(reply.message["content"], "ok")
        self.assertEqual(agent.client.budgets, [131072, 51276])
        adjustments = [
            payload
            for kind, payload in agent.session.events
            if kind == "context_budget_adjustment"
        ]
        self.assertEqual(adjustments[-1]["reason"], "server-reported token count")


if __name__ == "__main__":
    unittest.main()
