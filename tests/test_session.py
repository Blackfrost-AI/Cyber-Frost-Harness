import json
import os
import tempfile
import unittest
from pathlib import Path

from cyber_frost_harness.session import Candidate, RunSession


class FinalSelectionTests(unittest.TestCase):
    def test_parses_large_json_response_with_escaped_sanitizer_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = root / "task"
            task.mkdir()
            session = RunSession(root / "run", "arvo:1", task, object(), "container", 3)
            sanitizer = "==1==ERROR: AddressSanitizer: crash\\n" * 10000
            payload = {"exit_code": 1, "output": sanitizer, "poc_id": "abc123"}
            self.assertEqual(session._parse_submission_response(json.dumps(payload)), payload)

    def test_curl_progress_on_stderr_does_not_corrupt_submission_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = root / "task"
            task.mkdir()
            (task / "submit.sh").write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '{\"exit_code\":1,\"poc_id\":\"abc123\"}'\n"
                "printf '%s\\n' '100 6881  100 6881' >&2\n"
            )
            os.chmod(task / "submit.sh", 0o755)
            session = RunSession(root / "run", "arvo:1", task, object(), "container", 3)
            candidate = session._submit_bytes("/artifacts/poc", b"poc", "test", final=False)
            self.assertEqual(candidate.response["exit_code"], 1)
            self.assertIn("100 6881", candidate.response["_client"]["stderr_tail"])

    def test_marks_exactly_one_existing_candidate_final(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = root / "task"
            task.mkdir()
            session = RunSession(root / "run", "arvo:1", task, object(), "container", 5)
            first_path = root / "first.bin"
            second_path = root / "second.bin"
            first_path.write_bytes(b"first")
            second_path.write_bytes(b"second")
            session.candidates = [
                Candidate(1, "/artifacts/first", str(first_path), "a", 5, "", "now", {}, True),
                Candidate(2, "/artifacts/second", str(second_path), "b", 6, "", "now", {}, False),
            ]
            selected = session._set_final(session.candidates[1])
            self.assertTrue(selected.final)
            self.assertEqual([item.final for item in session.candidates], [False, True])
            payload = json.loads((session.final_dir / "selection.json").read_text())
            self.assertTrue(payload["final"])
            self.assertEqual((session.final_dir / "poc.bin").read_bytes(), b"second")

    def test_resubmits_preserved_bytes_when_earlier_candidate_is_final(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            task = root / "task"
            task.mkdir()
            (task / "submit.sh").write_text("#!/bin/sh\nprintf '{\"exit_code\": 134}\\n'\n")
            session = RunSession(root / "run", "arvo:1", task, object(), "container", 3)
            first_path = root / "first.bin"
            second_path = root / "second.bin"
            first_path.write_bytes(b"first")
            second_path.write_bytes(b"second")
            session.candidates = [
                Candidate(1, "/artifacts/first", str(first_path), "a", 5, "", "now", {}, False),
                Candidate(2, "/artifacts/second", str(second_path), "b", 6, "", "now", {}, False),
            ]
            result = session.finish("solved", "summary", "cause", "/artifacts/first")
            self.assertEqual(len(session.candidates), 3)
            self.assertEqual([item.final for item in session.candidates], [False, False, True])
            self.assertEqual(session.candidates[-1].sequence, 3)
            self.assertEqual(session.candidates[-1].remote_path, "/artifacts/first")
            self.assertEqual(Path(session.candidates[-1].local_path).read_bytes(), b"first")
            self.assertEqual((session.final_dir / "poc.bin").read_bytes(), b"first")
            self.assertTrue(result["final_candidate"]["final"])


if __name__ == "__main__":
    unittest.main()
