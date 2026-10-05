import json
import unittest
from types import SimpleNamespace

from cyber_frost_harness.tools import ToolRegistry, _function_tool
from cyber_frost_harness.transport import CommandResult


class ToolSchemaTests(unittest.TestCase):
    def test_function_schema_disallows_extra_fields(self):
        schema = _function_tool(
            "x", "test", {"value": {"type": "string"}}, ["value"]
        )
        parameters = schema["function"]["parameters"]
        self.assertFalse(parameters["additionalProperties"])
        self.assertEqual(parameters["required"], ["value"])

    def test_bounded_tool_output_remains_valid_json(self):
        registry = object.__new__(ToolRegistry)
        registry.config = SimpleNamespace(max_tool_output_chars=3000)
        payload = {
            "ok": True,
            "result": {
                "artifact_dir": "/artifacts/fuzz-a",
                "returncode": 0,
                "stdout": "x" * 20000,
            },
        }
        bounded = json.loads(registry._bounded(payload))
        self.assertTrue(bounded["ok"])
        self.assertEqual(bounded["result"]["artifact_dir"], "/artifacts/fuzz-a")
        self.assertEqual(bounded["result"]["returncode"], 0)
        self.assertIn("output_truncation", bounded)

    def test_classifies_asan_before_generic_signal(self):
        result = CommandResult(
            command="target input",
            returncode=134,
            stdout="",
            stderr=(
                "ERROR: AddressSanitizer: heap-use-after-free\n"
                "SUMMARY: AddressSanitizer: heap-use-after-free source.c:9 in parse\n"
            ),
            duration_seconds=1.0,
        )
        classification = ToolRegistry._classify_result(result)
        self.assertEqual(classification["kind"], "address-sanitizer")
        self.assertEqual(classification["signal"], 6)
        self.assertIn("heap-use-after-free", classification["summary"])

    def test_rejects_oversized_finding_ledger_entries(self):
        registry = object.__new__(ToolRegistry)
        registry.session = SimpleNamespace(record_finding=lambda *_args: {})
        with self.assertRaisesRegex(ValueError, "12,000-character"):
            registry._record_finding(
                {"key": "oversized", "value": "x" * 13000, "evidence": ""}
            )


if __name__ == "__main__":
    unittest.main()
