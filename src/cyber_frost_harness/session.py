from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .transport import DockerTransport


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


@dataclass(frozen=True)
class Candidate:
    sequence: int
    remote_path: str
    local_path: str
    sha256: str
    size: int
    rationale: str
    submitted_at: str
    response: dict[str, Any]
    final: bool


class RunSession:
    def __init__(
        self,
        run_dir: Path,
        task_id: str,
        task_dir: Path,
        transport: DockerTransport,
        container: str,
        max_submissions: int,
    ):
        self.run_dir = run_dir.resolve()
        self.task_id = task_id
        self.task_dir = task_dir.resolve()
        self.transport = transport
        self.container = container
        self.max_submissions = max_submissions
        self.events_path = self.run_dir / "trajectory.jsonl"
        self.findings_path = self.run_dir / "findings.json"
        self.candidates_dir = self.run_dir / "candidates"
        self.final_dir = self.run_dir / "final"
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.candidates_dir.mkdir(exist_ok=True)
        self.final_dir.mkdir(exist_ok=True)
        self.findings: dict[str, Any] = {}
        self.candidates: list[Candidate] = []
        self.finished = False
        self.finish_payload: dict[str, Any] | None = None
        self.usage = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "reasoning_tokens": 0,
            "total_tokens": 0,
            "model_requests": 0,
        }

    def record_event(self, kind: str, payload: dict[str, Any]) -> None:
        event = {"timestamp": utc_now(), "kind": kind, **payload}
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    def record_finding(self, key: str, value: Any, evidence: str = "") -> dict[str, Any]:
        self.findings[key] = {
            "value": value,
            "evidence": evidence,
            "updated_at": utc_now(),
        }
        _atomic_json(self.findings_path, self.findings)
        return self.findings[key]

    def add_usage(self, usage: dict[str, Any]) -> None:
        prompt = int(usage.get("prompt_tokens") or 0)
        completion = int(usage.get("completion_tokens") or 0)
        details = usage.get("completion_tokens_details") or {}
        reasoning = int(
            usage.get("reasoning_tokens")
            or details.get("reasoning_tokens")
            or 0
        )
        self.usage["prompt_tokens"] += prompt
        self.usage["completion_tokens"] += completion
        self.usage["reasoning_tokens"] += reasoning
        self.usage["total_tokens"] += int(usage.get("total_tokens") or prompt + completion)
        self.usage["model_requests"] += 1
        _atomic_json(self.run_dir / "usage.json", self.usage)

    def _submission_script(self) -> Path:
        path = self.task_dir / "submit.sh"
        if not path.is_file():
            raise FileNotFoundError(f"generated task is missing submit.sh: {path}")
        return path

    def _parse_submission_response(self, output: str) -> dict[str, Any]:
        stripped = output.strip()
        if stripped:
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(value, dict):
                    return value

        decoder = json.JSONDecoder()
        candidates: list[dict[str, Any]] = []
        for index, character in enumerate(output):
            if character != "{":
                continue
            try:
                value, _end = decoder.raw_decode(output[index:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                candidates.append(value)
        result_candidates = [item for item in candidates if "exit_code" in item]
        if result_candidates:
            return result_candidates[-1]
        if not candidates:
            raise RuntimeError(f"submission returned no JSON object: {output[-4000:]}")
        return candidates[-1]

    def submit_candidate(
        self,
        remote_path: str,
        rationale: str,
        *,
        final: bool = False,
    ) -> dict[str, Any]:
        data = self.transport.get_bytes(self.container, remote_path)
        candidate = self._submit_bytes(remote_path, data, rationale, final=final)
        return asdict(candidate)

    def submit_local_candidate(
        self,
        local_source: Path,
        remote_path: str,
        rationale: str,
        *,
        final: bool = False,
    ) -> dict[str, Any]:
        """Submit preserved bytes when recovering an interrupted agent session."""
        source = local_source.expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"candidate file does not exist: {source}")
        candidate = self._submit_bytes(
            remote_path,
            source.read_bytes(),
            rationale,
            final=final,
        )
        return asdict(candidate)

    def _submit_bytes(
        self,
        remote_path: str,
        data: bytes,
        rationale: str,
        *,
        final: bool,
    ) -> Candidate:
        limit = self.max_submissions if final else max(0, self.max_submissions - 1)
        if len(self.candidates) >= limit:
            if final:
                raise RuntimeError(f"submission limit reached ({self.max_submissions})")
            raise RuntimeError(
                f"exploratory submission limit reached ({limit}); one slot is reserved for finish"
            )
        digest = hashlib.sha256(data).hexdigest()
        basename = SAFE_NAME_RE.sub("_", Path(remote_path).name) or "candidate.bin"
        sequence = len(self.candidates) + 1
        local_path = self.candidates_dir / f"{sequence:02d}-{digest[:12]}-{basename}"
        local_path.write_bytes(data)
        result = subprocess.run(
            ["bash", str(self._submission_script()), str(local_path)],
            cwd=self.task_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
            check=False,
            env={**os.environ},
        )
        response = self._parse_submission_response(result.stdout)
        response["_client"] = {
            "returncode": result.returncode,
            "stderr_tail": result.stderr[-2000:],
        }
        candidate = Candidate(
            sequence=sequence,
            remote_path=remote_path,
            local_path=str(local_path),
            sha256=digest,
            size=len(data),
            rationale=rationale,
            submitted_at=utc_now(),
            response=response,
            final=False,
        )
        self.candidates.append(candidate)
        _atomic_json(
            self.run_dir / "submissions.json",
            [asdict(item) for item in self.candidates],
        )
        if final:
            candidate = self._set_final(candidate)
        self.record_event("submission", asdict(candidate))
        return candidate

    def _set_final(self, candidate: Candidate) -> Candidate:
        finalized = replace(candidate, final=True)
        self.candidates = [
            replace(item, final=item.sequence == finalized.sequence)
            for item in self.candidates
        ]
        _atomic_json(
            self.run_dir / "submissions.json",
            [asdict(item) for item in self.candidates],
        )
        destination = self.final_dir / "poc.bin"
        shutil.copyfile(finalized.local_path, destination)
        _atomic_json(self.final_dir / "selection.json", asdict(finalized))
        return finalized

    def finish(
        self,
        status: str,
        summary: str,
        root_cause: str,
        final_candidate: str | None,
    ) -> dict[str, Any]:
        final_record: dict[str, Any] | None = None
        if final_candidate:
            matching = [item for item in self.candidates if item.remote_path == final_candidate]
            if matching:
                selected = matching[-1]
                if selected.sequence == self.candidates[-1].sequence:
                    selected = self._set_final(selected)
                else:
                    selected = self._submit_bytes(
                        selected.remote_path,
                        Path(selected.local_path).read_bytes(),
                        f"final re-submission of preserved candidate {selected.sequence}",
                        final=True,
                    )
                final_record = asdict(selected)
            else:
                final_record = self.submit_candidate(
                    final_candidate,
                    "final candidate selected at finish",
                    final=True,
                )
        self.finished = True
        self.finish_payload = {
            "status": status,
            "summary": summary,
            "root_cause": root_cause,
            "final_candidate": final_record,
            "finished_at": utc_now(),
        }
        _atomic_json(self.run_dir / "result.json", self.finish_payload)
        self.record_event("finish", self.finish_payload)
        return self.finish_payload
