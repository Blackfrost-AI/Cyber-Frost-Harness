import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from scripts.run_manifest import ManifestRunner, summarize_task_entries


class ManifestScoringTests(unittest.TestCase):
    def test_summary_counts_model_misses_and_all_usage(self):
        entries = [
            {
                "status": "complete",
                "score": {"final_success": True},
                "usage": {"total_tokens": 10, "model_requests": 1},
            },
            {
                "status": "complete",
                "score": {"final_success": False},
                "usage": {"total_tokens": 20, "model_requests": 2},
            },
            {
                "status": "infrastructure_error",
                "usage": {"total_tokens": 30, "model_requests": 3},
            },
        ]
        summary = summarize_task_entries(entries)
        self.assertEqual(summary["score_so_far"], "1/2")
        self.assertEqual(summary["tasks_failed_model"], 1)
        self.assertEqual(summary["tasks_failed_infrastructure"], 1)
        self.assertEqual(summary["usage"]["total_tokens"], 60)
        self.assertEqual(summary["usage"]["model_requests"], 6)

    def test_no_candidate_without_submissions_skips_hidden_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_dir = root / "tasks" / "arvo_1"
            agent_dir = root / "agents" / "arvo_1"
            task_dir.mkdir(parents=True)
            agent_dir.mkdir(parents=True)

            runner = object.__new__(ManifestRunner)
            runner.tasks_dir = root / "tasks"
            runner.agents_dir = root / "agents"
            runner.logs_dir = root / "logs"
            runner.state = {"tasks": {"arvo:1": {"status": "pending"}}}
            runner.generate_task = lambda _task_id: task_dir
            runner.task_agent_id = lambda _task_dir: "agent-id"
            runner.launch_harness = lambda *_args: 0
            runner.verify_agent = Mock(side_effect=AssertionError("must not verify"))
            runner.score_agent = lambda *_args: {
                "submissions": 0,
                "verified_submissions": 0,
                "any_success": False,
                "final_sha256": None,
                "final_record_found": False,
                "final_vulnerable_exit_code": None,
                "final_fixed_exit_code": None,
                "final_success": False,
            }
            runner.load_usage = lambda _agent_dir: {}

            def update_task(task_id, **values):
                runner.state["tasks"][task_id].update(values)

            runner.update_task = update_task
            (agent_dir / "result.json").write_text(
                json.dumps({"status": "no-candidate", "summary": "step budget reached"})
            )

            runner.run_task("arvo:1")

            task = runner.state["tasks"]["arvo:1"]
            self.assertEqual(task["status"], "complete")
            self.assertEqual(task["outcome"], "model_failure")
            self.assertEqual(task["verification"]["status"], "skipped")
            runner.verify_agent.assert_not_called()


if __name__ == "__main__":
    unittest.main()
