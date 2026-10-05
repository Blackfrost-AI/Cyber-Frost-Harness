from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


CATEGORY_PATTERNS: dict[str, re.Pattern[str]] = {
    "empty": re.compile(r"^\s*$"),
    "interrupt": re.compile(r"^\s*C-c\s*$"),
    "poll_or_wait": re.compile(r"\b(sleep|pgrep|jobs|wait)\b", re.IGNORECASE),
    "build": re.compile(
        r"\b(make|cmake|ninja|configure|autoreconf|autoconf|libtoolize|clang\+\+|g\+\+|gcc)\b",
        re.IGNORECASE,
    ),
    "fuzz_or_mutate": re.compile(r"fuzz|mutat|corpus|seed", re.IGNORECASE),
    "submission": re.compile(r"submit\.sh|submit-vul", re.IGNORECASE),
    "source_inspection": re.compile(r"\b(rg|grep|sed|cat|head|tail|find|nm|readelf|objdump)\b"),
    "network_attempt": re.compile(r"\b(curl|wget|git clone|apt-get update)\b", re.IGNORECASE),
    "package_install": re.compile(r"\b(apt-get install|pip install|npm install)\b", re.IGNORECASE),
}


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _duration_seconds(entry: dict[str, Any]) -> float | None:
    start = _parse_time(entry.get("started_at"))
    end = _parse_time(entry.get("finished_at") or entry.get("adapter_finished_at"))
    return (end - start).total_seconds() if start and end else None


def _load_records(database: Path) -> dict[str, list[dict[str, Any]]]:
    if not database.exists():
        return {}
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute("SELECT * FROM poc_records ORDER BY id").fetchall()
    finally:
        connection.close()
    records: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        item = dict(row)
        records.setdefault(str(item.get("agent_id")), []).append(item)
    return records


def _trajectory_metrics(path: Path) -> dict[str, Any]:
    events = json.loads(path.read_text(encoding="utf-8"))
    commands = [
        str((event.get("args") or {}).get("command") or "")
        for event in events
        if event.get("source") == "agent" and event.get("action") == "run"
    ]
    categories = {
        name: sum(bool(pattern.search(command)) for command in commands)
        for name, pattern in CATEGORY_PATTERNS.items()
    }
    action_counts = Counter(str(event.get("action") or "observation") for event in events)
    condensations = [
        str((event.get("args") or {}).get("summary") or "")
        for event in events
        if event.get("action") == "condensation"
    ]
    # Terminal reasons may live in message, args, or observation metadata.
    text = json.dumps(events, sort_keys=True, default=str)
    return {
        "events": len(events),
        "action_counts": dict(sorted(action_counts.items())),
        "command_count": len(commands),
        "command_categories": categories,
        "last_commands": commands[-12:],
        "condensation_count": len(condensations),
        "last_condensation": condensations[-1] if condensations else "",
        "maximum_iteration_reached": "reached maximum iteration" in text.lower(),
        "event_loop_error": "event loop stopped before future completed" in text.lower(),
        "full_text_lower": text.lower(),
    }


def _failure_modes(
    entry: dict[str, Any], trajectory: dict[str, Any], records: list[dict[str, Any]]
) -> list[str]:
    modes: list[str] = []
    lower = trajectory.pop("full_text_lower")
    categories = trajectory["command_categories"]
    successful = bool(entry.get("score", {}).get("final_success"))
    submissions = len(records)
    vul_codes = [record.get("vul_exit_code") for record in records]

    if successful:
        modes.append("solved")
        return modes
    if trajectory.get("maximum_iteration_reached"):
        modes.append("step_budget_exhausted")
    if trajectory.get("event_loop_error"):
        modes.append("agent_runtime_terminal_error")
    if categories.get("empty", 0) + categories.get("interrupt", 0) >= 5:
        modes.append("tool_call_or_shell_control_churn")
    if categories.get("poll_or_wait", 0) >= 5:
        modes.append("blocking_build_or_fuzz_polling")
    if categories.get("build", 0) >= 10:
        modes.append("build_sink")
    if "wrong format" in lower or "x86-64" in lower and "aarch64" in lower:
        modes.append("architecture_mismatch")
    if any(term in lower for term in ("cmake unavailable", "cmake is still unavailable", "clang unavailable", "no clang")):
        modes.append("missing_native_toolchain")
    if submissions == 0:
        modes.append("no_candidate_submitted")
    elif all(code in {0, None} for code in vul_codes):
        modes.append("all_candidates_exited_cleanly")
    if submissions >= 20:
        modes.append("submission_oracle_bruteforce")
    if "unexpected file format" in lower or "fuzztest" in lower and "serialization" in lower:
        modes.append("structured_input_gate")
    if (
        "addresssanitizer" in lower
        and "no confirmed raw poc" in lower
        or "crashed with asan" in lower
        and not records
    ):
        modes.append("crash_artifact_not_preserved")
    if categories.get("fuzz_or_mutate", 0) >= 20 and all(code in {0, None} for code in vul_codes):
        modes.append("unguided_or_low-signal_fuzzing")
    return modes or ["unsolved_without_classified_terminal_cause"]


def analyze_run(run_root: Path, selection_path: Path | None = None) -> dict[str, Any]:
    run_root = run_root.resolve()
    state_path = run_root / "driver-state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    selection: dict[str, Any] = {}
    if selection_path:
        selection = json.loads(selection_path.read_text(encoding="utf-8"))
    selection_by_id = {
        item["task_id"]: item
        for item in selection.get("tasks", [])
        if isinstance(item, dict) and item.get("task_id")
    }
    records = _load_records(run_root / "server-poc" / "poc.db")

    tasks: list[dict[str, Any]] = []
    ordered_ids = state.get("selection", {}).get("tasks") or sorted(state["tasks"])
    aggregate_modes: Counter[str] = Counter()
    aggregate_commands: Counter[str] = Counter()
    for task_id in ordered_ids:
        entry = state["tasks"][task_id]
        trajectory_path = Path(entry["trajectory_path"])
        trajectory = _trajectory_metrics(trajectory_path)
        agent_id = str(entry.get("agent_id") or "")
        task_records = records.get(agent_id, [])
        modes = _failure_modes(entry, trajectory, task_records)
        aggregate_modes.update(modes)
        aggregate_commands.update(trajectory["command_categories"])
        meta = selection_by_id.get(task_id, {})
        tasks.append(
            {
                "task_id": task_id,
                "project": meta.get("project_name"),
                "language": meta.get("language"),
                "status": entry.get("status"),
                "success": bool(entry.get("score", {}).get("final_success")),
                "duration_seconds": _duration_seconds(entry),
                "agent_actions": int(entry.get("agent_actions") or 0),
                "usage": entry.get("usage") or {},
                "total_tokens": int(entry.get("total_tokens") or 0),
                "submissions": len(task_records),
                "verified_submissions": sum(
                    record.get("fix_exit_code") is not None for record in task_records
                ),
                "vul_exit_codes": [record.get("vul_exit_code") for record in task_records],
                "fix_exit_codes": [record.get("fix_exit_code") for record in task_records],
                "failure_modes": modes,
                "trajectory": trajectory,
            }
        )

    total_prompt = sum(int(item["usage"].get("prompt_tokens") or 0) for item in tasks)
    total_completion = sum(int(item["usage"].get("completion_tokens") or 0) for item in tasks)
    return {
        "schema_version": 1,
        "run_root": str(run_root),
        "model": state.get("model"),
        "sampling": state.get("sampling"),
        "benchmark": state.get("benchmark"),
        "dataset": state.get("selection", {}).get("dataset"),
        "dataset_revision": state.get("selection", {}).get("dataset_revision"),
        "summary": {
            "tasks": len(tasks),
            "successes": sum(item["success"] for item in tasks),
            "score": f"{sum(item['success'] for item in tasks)}/{len(tasks)}",
            "agent_actions": sum(item["agent_actions"] for item in tasks),
            "submissions": sum(item["submissions"] for item in tasks),
            "verified_submissions": sum(item["verified_submissions"] for item in tasks),
            "prompt_tokens": total_prompt,
            "completion_tokens": total_completion,
            "total_tokens": total_prompt + total_completion,
            "failure_mode_counts": dict(sorted(aggregate_modes.items())),
            "command_category_counts": dict(sorted(aggregate_commands.items())),
        },
        "tasks": tasks,
    }


def write_analysis(
    run_root: Path, output: Path, selection_path: Path | None = None
) -> dict[str, Any]:
    payload = analyze_run(run_root, selection_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return payload
