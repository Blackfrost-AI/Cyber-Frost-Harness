import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from cyber_frost_harness.failure_analysis import analyze_run


class FailureAnalysisTests(unittest.TestCase):
    def test_classifies_build_sink_and_clean_submission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs = root / "openhands-logs" / "task-agent"
            logs.mkdir(parents=True)
            trajectory = []
            for index in range(12):
                trajectory.append(
                    {
                        "source": "agent",
                        "action": "run",
                        "args": {"command": f"make target{index}"},
                    }
                )
            trajectory.append(
                {
                    "source": "agent",
                    "action": "run",
                    "args": {"command": "bash submit.sh poc"},
                    "message": "Agent reached maximum iteration",
                }
            )
            trajectory_path = logs / "trajectory"
            trajectory_path.write_text(json.dumps(trajectory))
            state = {
                "model": "test",
                "sampling": {},
                "benchmark": "test",
                "selection": {"tasks": ["arvo:1"]},
                "tasks": {
                    "arvo:1": {
                        "status": "complete",
                        "agent_id": "agent",
                        "trajectory_path": str(trajectory_path),
                        "agent_actions": 13,
                        "score": {"final_success": False},
                        "usage": {"prompt_tokens": 100, "completion_tokens": 10},
                    }
                },
            }
            (root / "driver-state.json").write_text(json.dumps(state))
            database_dir = root / "server-poc"
            database_dir.mkdir()
            connection = sqlite3.connect(database_dir / "poc.db")
            connection.execute(
                "create table poc_records (id integer, agent_id text, task_id text, "
                "poc_id text, poc_hash text, poc_length integer, vul_exit_code integer, "
                "fix_exit_code integer, created_at text, updated_at text)"
            )
            connection.execute(
                "insert into poc_records values (1,'agent','arvo:1','p','h',4,0,null,'','')"
            )
            connection.commit()
            connection.close()

            report = analyze_run(root)
            modes = report["tasks"][0]["failure_modes"]
            self.assertIn("build_sink", modes)
            self.assertIn("all_candidates_exited_cleanly", modes)
            self.assertEqual(report["summary"]["score"], "0/1")


if __name__ == "__main__":
    unittest.main()
