import io
import urllib.error
import unittest
from unittest.mock import patch

from cyber_frost_harness.config import ModelConfig
from cyber_frost_harness.model import ContextLengthError, OpenAICompatibleClient


class CapturingClient(OpenAICompatibleClient):
    def __init__(self, config):
        super().__init__(config)
        self.payload = None

    def _request(self, path, payload=None):
        self.payload = payload
        return {
            "id": "reply",
            "model": self.config.model,
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {},
        }


class ModelContextBudgetTests(unittest.TestCase):
    def setUp(self):
        self.config = ModelConfig(base_url="http://model/v1", model="test")

    def test_completion_budget_shrinks_for_large_prompt(self):
        client = OpenAICompatibleClient(self.config)
        messages = [{"role": "user", "content": "x" * 450000}]
        budget = client.completion_budget(messages, [])
        self.assertGreater(budget, 0)
        self.assertLess(budget, self.config.max_completion_tokens)

    def test_explicit_completion_budget_is_sent(self):
        client = CapturingClient(self.config)
        client.complete([{"role": "user", "content": "hello"}], [], max_tokens=32768)
        self.assertEqual(client.payload["max_tokens"], 32768)

    def test_parses_server_context_error(self):
        client = OpenAICompatibleClient(self.config)
        detail = (
            '{"message":"Requested token count exceeds the model\'s maximum context '
            'length of 262144 tokens. You requested a total of 337844 tokens: '
            '206772 tokens from the input messages and 131072 tokens for the completion."}'
        )
        error = urllib.error.HTTPError(
            "http://model/v1/models",
            400,
            "Bad Request",
            {},
            io.BytesIO(detail.encode()),
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(ContextLengthError) as raised:
                client.models()
        self.assertEqual(raised.exception.context_limit, 262144)
        self.assertEqual(raised.exception.prompt_tokens, 206772)
        self.assertEqual(raised.exception.completion_tokens, 131072)


if __name__ == "__main__":
    unittest.main()
