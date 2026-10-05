import tempfile
import unittest
from pathlib import Path

from cyber_frost_harness.config import load_config


class ConfigTests(unittest.TestCase):
    def test_loads_relative_project_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "skills").mkdir()
            (root / "prompt.md").write_text("prompt")
            (root / "data").mkdir()
            (root / "mask.json").write_text("{}")
            config_path = root / "test.toml"
            config_path.write_text(
                """
[model]
base_url = "http://127.0.0.1:9000/v1"
model = "test-model"

[runtime]
transport = "local-docker"

[agent]
mode = "red"
skill_dir = "skills"
system_prompt = "prompt.md"

[benchmark]
cybergym_root = "."
data_dir = "data"
mask_map = "mask.json"
server_url = "http://127.0.0.1:8668"
"""
            )
            config = load_config(config_path)
            self.assertEqual(config.model.model, "test-model")
            self.assertEqual(config.agent.skill_dir, root / "skills")
            self.assertEqual(config.runtime.transport, "local-docker")
            self.assertEqual(config.runtime.pids_limit, 256)
            self.assertEqual(config.model.context_window_tokens, 262144)
            self.assertEqual(config.model.context_safety_tokens, 4096)
            self.assertEqual(config.model.min_completion_tokens, 16384)

    def test_rejects_unknown_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.toml"
            path.write_text(
                """
[model]
base_url = "http://127.0.0.1/v1"
model = "m"
[runtime]
transport = "local-docker"
[agent]
mode = "orange"
[benchmark]
cybergym_root = "."
data_dir = "."
mask_map = "mask"
server_url = "http://127.0.0.1"
"""
            )
            with self.assertRaisesRegex(ValueError, "mode"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
